import { supabase } from '@/lib/supabase';
import { AuthError } from '@/lib/utils/errors';

export class RateLimitService {
  private static readonly MAX_ATTEMPTS = 5;
  private static readonly WINDOW_MINUTES = 15;

  static async incrementAttempt(ipAddress: string, identifier: string): Promise<number> {
    try {
      const { data, error } = await supabase.rpc(
        'increment_failed_attempts',
        {
          p_ip_address: ipAddress,
          p_identifier: identifier,
          p_last_attempt: new Date().toISOString()
        }
      );

      if (error) {
        console.error('Failed to increment attempts:', error);
        return 0;
      }

      return data || 0;
    } catch (error) {
      console.error('Error in incrementAttempt:', error);
      return 0;
    }
  }

  static async getCurrentAttempts(ipAddress: string, identifier: string): Promise<number> {
    try {
      const { data, error } = await supabase
        .from('failed_attempts')
        .select('attempt_count, last_reset')
        .eq('ip_address', ipAddress)
        .eq('identifier', identifier)
        .single();

      if (error) {
        console.error('Error fetching attempts:', error);
        return 0;
      }

      if (!data) return 0;

      const lastReset = new Date(data.last_reset);
      const windowExpiry = new Date(lastReset.getTime() + (this.WINDOW_MINUTES * 60 * 1000));

      if (new Date() > windowExpiry) {
        return 0;
      }

      return data.attempt_count;
    } catch (error) {
      console.error('Error in getCurrentAttempts:', error);
      return 0;
    }
  }

  static async checkRateLimit(ipAddress: string, identifier: string): Promise<void> {
    const attempts = await this.getCurrentAttempts(ipAddress, identifier);

    if (attempts >= this.MAX_ATTEMPTS) {
      throw new AuthError(
        'Too many failed attempts. Please try again later.',
        'auth/too-many-requests'
      );
    }

    const remainingAttempts = this.MAX_ATTEMPTS - attempts;
    if (remainingAttempts <= 2) {
      throw new AuthError(
        `${remainingAttempts} login attempts remaining before temporary lockout.`,
        'auth/attempts-remaining'
      );
    }
  }
}