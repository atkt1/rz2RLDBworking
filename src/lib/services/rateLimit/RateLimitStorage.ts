import { supabase } from '@/lib/supabase';
import type { RateLimitKey } from '@/lib/types/rateLimit';

export class RateLimitStorage {
  static async getAttempts(key: RateLimitKey): Promise<number> {
    try {
      const { data, error } = await supabase
        .from('failed_attempts')
        .select('attempt_count, last_reset')
        .eq('ip_address', key.ip)
        .eq('identifier', key.identifier)
        .maybeSingle();

      if (error) {
        console.error('Error getting attempts:', error);
        return 0;
      }

      if (!data) {
        return 0;
      }

      // Check if the 15-minute window has expired
      const lastReset = new Date(data.last_reset);
      const windowExpiry = new Date(lastReset.getTime() + (15 * 60 * 1000));
      
      if (new Date() > windowExpiry) {
        await this.resetAttempts(key);
        return 0;
      }

      return data.attempt_count || 0;
    } catch (error) {
      console.error('Error in getAttempts:', error);
      return 0;
    }
  }

  static async incrementAttempts(key: RateLimitKey): Promise<void> {
    try {
      const now = new Date().toISOString();
      
      const { error } = await supabase.rpc('increment_failed_attempts', {
        p_ip_address: key.ip,
        p_identifier: key.identifier,
        p_last_attempt: now
      });

      if (error) {
        console.error('Error incrementing attempts:', error);
        throw error;
      }
    } catch (error) {
      console.error('Error in incrementAttempts:', error);
      throw error;
    }
  }

  static async resetAttempts(key: RateLimitKey): Promise<void> {
    try {
      const { error } = await supabase
        .from('failed_attempts')
        .delete()
        .eq('ip_address', key.ip)
        .eq('identifier', key.identifier);

      if (error) {
        console.error('Error resetting attempts:', error);
        throw error;
      }
    } catch (error) {
      console.error('Error in resetAttempts:', error);
      throw error;
    }
  }
}