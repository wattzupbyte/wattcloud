import { describe, it, expect } from 'vitest';
import { ProviderError, ConflictError, UnauthorizedError } from '../../src/lib/sdk/errors';

describe('errors', () => {
  describe('ProviderError', () => {
    it('should create error with code, message, and provider type', () => {
      const error = new ProviderError('NOT_FOUND', 'File not found', 'gdrive');
      expect(error.code).toBe('NOT_FOUND');
      expect(error.message).toBe('File not found');
      expect(error.providerType).toBe('gdrive');
      expect(error.name).toBe('ProviderError');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(ProviderError);
    });
  });

  describe('ConflictError', () => {
    it('should create error with currentVersion', () => {
      const error = new ConflictError('gdrive', 'etag123');
      expect(error.code).toBe('CONFLICT');
      expect(error.currentVersion).toBe('etag123');
      expect(error.message).toContain('etag123');
      expect(error.providerType).toBe('gdrive');
      expect(error.name).toBe('ConflictError');
      expect(error).toBeInstanceOf(ProviderError);
    });
  });

  describe('UnauthorizedError', () => {
    it('should create error with default message', () => {
      const error = new UnauthorizedError('dropbox');
      expect(error.code).toBe('UNAUTHORIZED');
      expect(error.message).toBe('Authentication expired');
      expect(error.providerType).toBe('dropbox');
      expect(error.name).toBe('UnauthorizedError');
      expect(error).toBeInstanceOf(ProviderError);
    });

    it('should create error with custom message', () => {
      const error = new UnauthorizedError('onedrive', 'Token refresh failed');
      expect(error.message).toBe('Token refresh failed');
    });
  });
});