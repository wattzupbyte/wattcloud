/**
 * Unit tests for the OS share-sheet helpers in streamToDisk.ts and the
 * runtime-feature store in stores/byoCapabilities.ts.
 *
 * Verifies:
 * - bufferStreamToFile drains a ReadableStream into a File of correct
 *   bytes / mime / name, and rejects when the stream exceeds the
 *   configured ceiling.
 * - shareFilesViaOS calls navigator.share with the right payload, throws
 *   the expected typed errors when the API is missing or canShare
 *   refuses, and propagates AbortError on user cancel.
 * - bufferForWebShare composes the two correctly.
 * - detectByoCapabilities reports `webShareFiles: true` only when both
 *   share + canShare exist on navigator.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  bufferStreamToFile,
  shareFilesViaOS,
  bufferForWebShare,
  WebShareUnsupportedError,
  WebShareUnsupportedForFilesError,
  WEB_SHARE_RAM_LIMIT,
} from '../../src/lib/byo/streamToDisk';
import {
  byoCapabilities,
  detectByoCapabilities,
  __setByoCapabilitiesForTest,
} from '../../src/lib/byo/stores/byoCapabilities';

function streamOf(...chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  const queue = [...chunks];
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = queue.shift();
      if (next === undefined) controller.close();
      else controller.enqueue(next);
    },
  });
}

describe('bufferStreamToFile', () => {
  it('drains a stream into a File with correct bytes, name, and mime', async () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const file = await bufferStreamToFile(
      streamOf(data),
      'hello.bin',
      'application/octet-stream',
    );
    expect(file.name).toBe('hello.bin');
    expect(file.type).toBe('application/octet-stream');
    expect(file.size).toBe(5);
    const buf = new Uint8Array(await file.arrayBuffer());
    expect(Array.from(buf)).toEqual([1, 2, 3, 4, 5]);
  });

  it('joins multiple chunks in order', async () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    const c = new Uint8Array([4, 5, 6]);
    const file = await bufferStreamToFile(streamOf(a, b, c), 'multi', 'text/plain');
    expect(file.size).toBe(6);
    const buf = new Uint8Array(await file.arrayBuffer());
    expect(Array.from(buf)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('reports progress incrementally', async () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4]);
    const seen: number[] = [];
    await bufferStreamToFile(streamOf(a, b), 'p', 'text/plain', {
      onProgress: (n) => seen.push(n),
    });
    expect(seen).toEqual([3, 4]);
  });

  it('throws when the stream exceeds the ceiling', async () => {
    const tooBig = new Uint8Array(20);
    await expect(
      bufferStreamToFile(streamOf(tooBig), 'too-big', 'text/plain', { maxBytes: 10 }),
    ).rejects.toThrow(/too large/i);
  });

  it('aborts when signal fires before reading completes', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(
      bufferStreamToFile(streamOf(new Uint8Array([1])), 'x', 'text/plain', { signal: ac.signal }),
    ).rejects.toThrow(/abort/i);
  });

  it('default ceiling is WEB_SHARE_RAM_LIMIT (200 MiB)', () => {
    expect(WEB_SHARE_RAM_LIMIT).toBe(200 * 1024 * 1024);
  });
});

// ── shareFilesViaOS ────────────────────────────────────────────────────────

describe('shareFilesViaOS', () => {
  let originalNavigator: any;

  beforeEach(() => {
    originalNavigator = (globalThis as any).navigator;
  });

  afterEach(() => {
    (globalThis as any).navigator = originalNavigator;
    vi.restoreAllMocks();
  });

  function installNavigator(impl: { share?: any; canShare?: any }) {
    (globalThis as any).navigator = {
      ...(originalNavigator ?? {}),
      ...impl,
    };
  }

  function makeFile(name = 'a.txt', body = 'hello'): File {
    return new File([body], name, { type: 'text/plain' });
  }

  it('throws WebShareUnsupportedError when navigator.share is missing', async () => {
    installNavigator({ canShare: () => true });
    await expect(
      shareFilesViaOS([makeFile()], { title: 't', text: '' }),
    ).rejects.toBeInstanceOf(WebShareUnsupportedError);
  });

  it('throws WebShareUnsupportedError when navigator.canShare is missing', async () => {
    installNavigator({ share: vi.fn() });
    await expect(
      shareFilesViaOS([makeFile()], { title: 't', text: '' }),
    ).rejects.toBeInstanceOf(WebShareUnsupportedError);
  });

  it('throws WebShareUnsupportedForFilesError when canShare returns false', async () => {
    installNavigator({ share: vi.fn(), canShare: () => false });
    await expect(
      shareFilesViaOS([makeFile()], { title: 't', text: '' }),
    ).rejects.toBeInstanceOf(WebShareUnsupportedForFilesError);
  });

  it('calls navigator.share with files + title + text', async () => {
    const share = vi.fn(async () => {});
    installNavigator({ share, canShare: () => true });
    const file = makeFile();
    await shareFilesViaOS([file], { title: 'My title', text: 'My text' });
    expect(share).toHaveBeenCalledTimes(1);
    const arg = share.mock.calls[0][0];
    expect(arg.title).toBe('My title');
    expect(arg.text).toBe('My text');
    // Note: `files` is wiped in finally; assert on the share call before the
    // helper returned by capturing inside the mock.
  });

  it('drops the files reference after share resolves', async () => {
    let captured: ShareData | null = null;
    const share = vi.fn(async (data: ShareData) => {
      captured = data;
    });
    installNavigator({ share, canShare: () => true });
    await shareFilesViaOS([makeFile()], { title: 't', text: '' });
    expect(captured).not.toBeNull();
    // The same reference the helper passed in should now have files cleared.
    expect((captured as any).files).toBeUndefined();
  });

  it('drops the files reference even when share rejects', async () => {
    let captured: ShareData | null = null;
    const share = vi.fn(async (data: ShareData) => {
      captured = data;
      throw new DOMException('User cancelled', 'AbortError');
    });
    installNavigator({ share, canShare: () => true });
    await expect(
      shareFilesViaOS([makeFile()], { title: 't', text: '' }),
    ).rejects.toThrow(/cancel/i);
    expect((captured as any).files).toBeUndefined();
  });

  it('propagates AbortError on user cancel', async () => {
    const share = vi.fn(async () => {
      throw new DOMException('aborted', 'AbortError');
    });
    installNavigator({ share, canShare: () => true });
    await expect(
      shareFilesViaOS([makeFile()], { title: 't', text: '' }),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });
});

// ── bufferForWebShare composition ──────────────────────────────────────────

describe('bufferForWebShare', () => {
  let originalNavigator: any;

  beforeEach(() => {
    originalNavigator = (globalThis as any).navigator;
  });

  afterEach(() => {
    (globalThis as any).navigator = originalNavigator;
  });

  it('drains the stream and shares the resulting File', async () => {
    let receivedFiles: File[] | undefined;
    const share = vi.fn(async (data: ShareData) => {
      receivedFiles = data.files ? [...data.files] : undefined;
    });
    (globalThis as any).navigator = { share, canShare: () => true };

    const stream = streamOf(new Uint8Array([7, 8, 9]));
    await bufferForWebShare(stream, 'thing.bin', 'application/octet-stream', {
      title: 'thing',
      text: '',
    });

    expect(share).toHaveBeenCalledOnce();
    expect(receivedFiles).toBeDefined();
    expect(receivedFiles?.length).toBe(1);
    const f = receivedFiles![0];
    expect(f.name).toBe('thing.bin');
    expect(f.size).toBe(3);
  });
});

// ── byoCapabilities ────────────────────────────────────────────────────────

describe('detectByoCapabilities', () => {
  let originalNavigator: any;

  beforeEach(() => {
    originalNavigator = (globalThis as any).navigator;
    __setByoCapabilitiesForTest({ webShareFiles: false });
  });

  afterEach(() => {
    (globalThis as any).navigator = originalNavigator;
    __setByoCapabilitiesForTest({ webShareFiles: false });
  });

  it('reports webShareFiles=true when share + canShare exist', () => {
    (globalThis as any).navigator = { share: () => {}, canShare: () => true };
    const caps = detectByoCapabilities();
    expect(caps.webShareFiles).toBe(true);
    expect(get(byoCapabilities).webShareFiles).toBe(true);
  });

  it('reports webShareFiles=false when canShare is missing', () => {
    (globalThis as any).navigator = { share: () => {} };
    expect(detectByoCapabilities().webShareFiles).toBe(false);
  });

  it('reports webShareFiles=false when share is missing', () => {
    (globalThis as any).navigator = { canShare: () => true };
    expect(detectByoCapabilities().webShareFiles).toBe(false);
  });

  it('reports webShareFiles=false when navigator is undefined', () => {
    (globalThis as any).navigator = undefined;
    expect(detectByoCapabilities().webShareFiles).toBe(false);
  });
});
