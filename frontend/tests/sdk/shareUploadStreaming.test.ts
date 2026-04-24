/**
 * Unit tests for shareUploadStreaming helpers.
 *
 * Covers:
 * - peekHeaderAndResume: boundary alignment with single chunk, split across
 *   chunks, undersized stream.
 * - prependBytes: emits prefix once then passes the wrapped stream through.
 * - countingTap: reports the true byte total after the tapped stream is
 *   fully consumed.
 * - drainToBuffer: concatenates chunks in order.
 * - supportsRequestStreams: caches the result and survives repeated calls.
 */

import { describe, it, expect } from 'vitest';
import {
  peekHeaderAndResume,
  prependBytes,
  countingTap,
  drainToBuffer,
  supportsRequestStreams,
} from '../../src/lib/byo/shareUploadStreaming';

/** Build a ReadableStream that yields the supplied chunks in order. */
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

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      parts.push(value);
      total += value.byteLength;
    }
  }
  reader.releaseLock();
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

describe('peekHeaderAndResume', () => {
  it('extracts exactly N bytes when a single chunk holds more', async () => {
    const chunk = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const src = streamOf(chunk);
    const { header, body } = await peekHeaderAndResume(src, 4);
    expect(Array.from(header)).toEqual([1, 2, 3, 4]);
    const rest = await readAll(body);
    expect(Array.from(rest)).toEqual([5, 6, 7, 8, 9, 10]);
  });

  it('reassembles when the header spans multiple chunks', async () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5]);
    const c = new Uint8Array([6, 7, 8, 9, 10]);
    const src = streamOf(a, b, c);
    const { header, body } = await peekHeaderAndResume(src, 5);
    expect(Array.from(header)).toEqual([1, 2, 3, 4, 5]);
    const rest = await readAll(body);
    expect(Array.from(rest)).toEqual([6, 7, 8, 9, 10]);
  });

  it('throws when the stream ends before the header is complete', async () => {
    const src = streamOf(new Uint8Array([1, 2, 3]));
    await expect(peekHeaderAndResume(src, 5)).rejects.toThrow(/stream ended/);
  });

  it('handles exact boundary match (all bytes belong to header)', async () => {
    const src = streamOf(new Uint8Array([1, 2, 3, 4]));
    const { header, body } = await peekHeaderAndResume(src, 4);
    expect(Array.from(header)).toEqual([1, 2, 3, 4]);
    const rest = await readAll(body);
    expect(rest.byteLength).toBe(0);
  });
});

describe('prependBytes', () => {
  it('emits prefix as the first chunk and forwards the rest', async () => {
    const prefix = new Uint8Array([9, 9, 9]);
    const src = streamOf(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5]));
    const merged = prependBytes(prefix, src);
    const out = await readAll(merged);
    expect(Array.from(out)).toEqual([9, 9, 9, 1, 2, 3, 4, 5]);
  });

  it('passes through an empty inner stream (prefix only)', async () => {
    const prefix = new Uint8Array([0xaa, 0xbb]);
    const src = streamOf();
    const merged = prependBytes(prefix, src);
    const out = await readAll(merged);
    expect(Array.from(out)).toEqual([0xaa, 0xbb]);
  });
});

describe('countingTap', () => {
  it('reports the sum of all bytes flowing through the tap', async () => {
    const src = streamOf(
      new Uint8Array(100),
      new Uint8Array(50),
      new Uint8Array(25),
    );
    const { body, bytes } = countingTap(src);
    await readAll(body);
    expect(bytes()).toBe(175);
  });

  it('yields zero before the stream is consumed', async () => {
    const src = streamOf(new Uint8Array(10));
    const { bytes } = countingTap(src);
    expect(bytes()).toBe(0);
  });
});

describe('drainToBuffer', () => {
  it('concatenates chunks in the order they arrive', async () => {
    const src = streamOf(
      new Uint8Array([1, 2]),
      new Uint8Array([3, 4, 5]),
      new Uint8Array([6]),
    );
    const out = await drainToBuffer(src);
    expect(Array.from(out)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('returns an empty Uint8Array for an empty stream', async () => {
    const out = await drainToBuffer(streamOf());
    expect(out.byteLength).toBe(0);
  });
});

describe('supportsRequestStreams', () => {
  it('returns a boolean and caches the result across calls', () => {
    const first = supportsRequestStreams();
    const second = supportsRequestStreams();
    expect(typeof first).toBe('boolean');
    expect(second).toBe(first);
  });
});
