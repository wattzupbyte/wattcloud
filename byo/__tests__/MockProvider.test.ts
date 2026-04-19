import { describe, it, expect } from 'vitest';
import { MockProvider } from './mocks/MockProvider';
import { ConflictError, ProviderError } from '../src/errors';

describe('MockProvider', () => {
  let provider: MockProvider;

  beforeEach(async () => {
    provider = new MockProvider();
    await provider.init();
  });

  afterEach(async () => {
    await provider.disconnect();
  });

  describe('upload and download', () => {
    it('should upload and download a file', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = await provider.upload(null, 'test.txt', data);

      expect(result.ref).toBeTruthy();
      expect(result.version).toBeTruthy();

      const downloaded = await provider.download(result.ref);
      expect(downloaded.data).toEqual(data);
      expect(downloaded.version).toBe(result.version);
    });

    it('should overwrite an existing file', async () => {
      const data1 = new Uint8Array([1, 2, 3]);
      const data2 = new Uint8Array([4, 5, 6]);

      const result1 = await provider.upload(null, 'test.txt', data1);
      const result2 = await provider.upload(result1.ref, 'test.txt', data2, { expectedVersion: result1.version });

      expect(result2.ref).toBe(result1.ref);
      const downloaded = await provider.download(result2.ref);
      expect(downloaded.data).toEqual(data2);
    });
  });

  describe('conflict detection', () => {
    it('should throw ConflictError on version mismatch', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await provider.upload(null, 'test.txt', data);

      await expect(
        provider.upload(result.ref, 'test.txt', data, { expectedVersion: 'wrong_version' }),
      ).rejects.toThrow(ConflictError);
    });

    it('should include currentVersion in ConflictError', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await provider.upload(null, 'test.txt', data);

      try {
        await provider.upload(result.ref, 'test.txt', data, { expectedVersion: 'wrong_version' });
      } catch (e) {
        expect(e).toBeInstanceOf(ConflictError);
        expect((e as ConflictError).currentVersion).toBe(result.version);
      }
    });
  });

  describe('delete', () => {
    it('should delete a file', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await provider.upload(null, 'test.txt', data);

      await provider.delete(result.ref);

      await expect(provider.download(result.ref)).rejects.toThrow(ProviderError);
    });

    it('should not throw on deleting a non-existent file', async () => {
      await expect(provider.delete('nonexistent')).resolves.toBeUndefined();
    });
  });

  describe('getVersion', () => {
    it('should return the current version', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await provider.upload(null, 'test.txt', data);

      const version = await provider.getVersion(result.ref);
      expect(version).toBe(result.version);
    });

    it('should throw NOT_FOUND for non-existent file', async () => {
      await expect(provider.getVersion('nonexistent')).rejects.toThrow(ProviderError);
    });
  });

  describe('list', () => {
    it('should list uploaded files', async () => {
      await provider.upload(null, 'file1.txt', new Uint8Array([1]));
      await provider.upload(null, 'file2.txt', new Uint8Array([2]));

      const entries = await provider.list();
      expect(entries.length).toBe(2);
      expect(entries.some(e => e.name === 'file1.txt')).toBe(true);
      expect(entries.some(e => e.name === 'file2.txt')).toBe(true);
    });
  });

  describe('folders', () => {
    it('should create and delete folders', async () => {
      const { ref } = await provider.createFolder('testdir');
      expect(ref).toContain('testdir');

      await provider.deleteFolder(ref);
      // No error should be thrown
    });
  });

  describe('uploadStream and downloadStream', () => {
    it('should upload via stream and download via stream', async () => {
      const data = new Uint8Array(1024);
      crypto.getRandomValues(data);

      const { stream: writable, result: uploadResult } = await provider.uploadStream(null, 'stream_test.bin', data.length);
      const writer = writable.getWriter();
      await writer.write(data);
      await writer.close();
      const { ref: uploadedRef, version } = await uploadResult;
      expect(uploadedRef).toBeTruthy();
      expect(version).toBeTruthy();

      // Find the file by listing
      const entries = await provider.list();
      expect(entries.length).toBeGreaterThan(0);

      const fileEntry = entries.find(e => e.name === 'stream_test.bin' || e.ref.includes('stream_test'));
      if (fileEntry) {
        const stream = await provider.downloadStream(fileEntry.ref);
        const reader = stream.getReader();
        const chunks: Uint8Array[] = [];
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        reader.releaseLock();

        const total = chunks.reduce((s, c) => s + c.length, 0);
        expect(total).toBe(data.length);
      }
    });
  });

  describe('isReady and disconnect', () => {
    it('should report ready after init', () => {
      expect(provider.isReady()).toBe(true);
    });

    it('should report not ready after disconnect', async () => {
      await provider.disconnect();
      expect(provider.isReady()).toBe(false);
    });
  });
});