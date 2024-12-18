import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { RateLimitService } from '../RateLimitService';
import { RateLimitError } from '@/lib/utils/errors';
import { supabase } from '@/lib/supabase';

jest.mock('@/lib/supabase');

describe('RateLimitService', () => {
  const mockIp = '127.0.0.1';
  const mockEmail = 'test@example.com';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('checkRateLimit', () => {
    it('should allow requests within limit', async () => {
      (supabase.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { attempt_count: 3 },
              error: null
            })
          })
        })
      });

      await expect(RateLimitService.checkRateLimit(mockIp, mockEmail))
        .resolves.not.toThrow();
    });

    it('should throw RateLimitError when limit exceeded', async () => {
      (supabase.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { attempt_count: 5 },
              error: null
            })
          })
        })
      });

      await expect(RateLimitService.checkRateLimit(mockIp, mockEmail))
        .rejects.toThrow(RateLimitError);
    });
  });

  describe('incrementAttempts', () => {
    it('should increment attempt counter', async () => {
      const mockRpc = jest.fn().mockResolvedValue({ error: null });
      (supabase.rpc as jest.Mock).mockReturnValue(mockRpc);

      await RateLimitService.incrementAttempts(mockIp, mockEmail);

      expect(mockRpc).toHaveBeenCalled();
    });
  });

  describe('resetAttempts', () => {
    it('should reset attempt counter', async () => {
      const mockDelete = jest.fn().mockReturnValue({
        eq: jest.fn().mockReturnValue({
          eq: jest.fn().mockResolvedValue({ error: null })
        })
      });
      (supabase.from as jest.Mock).mockReturnValue({
        delete: mockDelete
      });

      await RateLimitService.resetAttempts(mockIp, mockEmail);

      expect(mockDelete).toHaveBeenCalled();
    });
  });
});