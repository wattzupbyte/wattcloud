import { describe, it, expect, afterEach } from 'vitest';
import { createProvider, getProvider, registerProvider, clearProvider, clearAllProviders, getDisplayName } from '../../src/lib/sdk/ProviderFactory';

describe('ProviderFactory', () => {
  afterEach(async () => {
    await clearAllProviders();
  });

  describe('createProvider', () => {
    it('should create a GDrive provider', () => {
      const provider = createProvider('gdrive', 'gdrive-1');
      expect(provider.type).toBe('gdrive');
      expect(provider.displayName).toBe('Google Drive');
    });

    it('should create a Dropbox provider', () => {
      const provider = createProvider('dropbox', 'dropbox-1');
      expect(provider.type).toBe('dropbox');
      expect(provider.displayName).toBe('Dropbox');
    });

    it('should create a OneDrive provider', () => {
      const provider = createProvider('onedrive', 'onedrive-1');
      expect(provider.type).toBe('onedrive');
      expect(provider.displayName).toBe('OneDrive');
    });

    it('should create a WebDAV provider', () => {
      const provider = createProvider('webdav', 'webdav-1');
      expect(provider.type).toBe('webdav');
      expect(provider.displayName).toBe('WebDAV');
    });

    it('should create an SFTP provider', () => {
      const provider = createProvider('sftp', 'sftp-1');
      expect(provider.type).toBe('sftp');
      expect(provider.displayName).toBe('SFTP');
    });

    it('should create an S3 provider (WASM shim)', () => {
      const provider = createProvider('s3', 's3-1');
      expect(provider.type).toBe('s3');
      expect(provider.displayName).toBe('S3');
    });

    it('should support two S3 instances with different provider_ids', () => {
      const p1 = createProvider('s3', 's3-bucket-a');
      const p2 = createProvider('s3', 's3-bucket-b');
      expect(p1).not.toBe(p2);
      expect(getProvider('s3-bucket-a')).toBe(p1);
      expect(getProvider('s3-bucket-b')).toBe(p2);
    });

    it('should support two instances of the same type with different provider_ids', () => {
      const p1 = createProvider('gdrive', 'gdrive-work');
      const p2 = createProvider('gdrive', 'gdrive-personal');
      expect(p1).not.toBe(p2);
      expect(getProvider('gdrive-work')).toBe(p1);
      expect(getProvider('gdrive-personal')).toBe(p2);
    });

    it('returns a fresh instance each call when no provider_id given', () => {
      // Without a providerId there is no safe cache slot — the previous
      // `'<type>:primary'` fallback let two unrelated callers share the same
      // instance, so init(newConfig) on one would mutate host/basePath of
      // the other in place. createProvider now skips the cache entirely
      // when providerId is omitted, and getProvider('primary') returns
      // undefined because nothing is registered under that legacy key.
      const p1 = createProvider('gdrive');
      const p2 = createProvider('gdrive');
      expect(p1).not.toBe(p2);
      expect(getProvider('primary')).toBeUndefined();
    });
  });

  describe('getProvider', () => {
    it('should return undefined before init', () => {
      const provider = getProvider('gdrive-unknown');
      expect(provider).toBeUndefined();
    });

    it('should return cached provider after creation by provider_id', () => {
      const created = createProvider('gdrive', 'gdrive-cached');
      const cached = getProvider('gdrive-cached');
      expect(cached).toBe(created);
    });
  });

  describe('registerProvider', () => {
    it('should allow registering an already-constructed instance', () => {
      const p = createProvider('dropbox', 'dropbox-reg');
      registerProvider('dropbox-reg2', p);
      expect(getProvider('dropbox-reg2')).toBe(p);
    });
  });

  describe('clearProvider', () => {
    it('should remove a provider from cache by provider_id', async () => {
      createProvider('gdrive', 'gdrive-clear');
      await clearProvider('gdrive-clear');
      expect(getProvider('gdrive-clear')).toBeUndefined();
    });
  });

  describe('clearAllProviders', () => {
    it('should remove all providers from cache', async () => {
      createProvider('gdrive', 'gdrive-all');
      createProvider('dropbox', 'dropbox-all');
      await clearAllProviders();
      expect(getProvider('gdrive-all')).toBeUndefined();
      expect(getProvider('dropbox-all')).toBeUndefined();
    });
  });

  describe('getDisplayName', () => {
    it('should return display names for all provider types', () => {
      expect(getDisplayName('gdrive')).toBe('Google Drive');
      expect(getDisplayName('dropbox')).toBe('Dropbox');
      expect(getDisplayName('onedrive')).toBe('OneDrive');
      expect(getDisplayName('webdav')).toBe('WebDAV');
      expect(getDisplayName('sftp')).toBe('SFTP');
      expect(getDisplayName('s3')).toBe('S3');
    });
  });
});
