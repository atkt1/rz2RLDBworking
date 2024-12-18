import { supabase } from '@/lib/supabase';
import type { AuthEventType } from '@/lib/types/auth';

export class AuditService {
  static async logAuthEvent(
    eventType: AuthEventType,
    details: Record<string, any>,
    ipAddress?: string
  ) {
    const { error } = await supabase.from('auth_logs').insert({
      event_type: eventType,
      ip_address: ipAddress,
      details,
      timestamp: new Date().toISOString()
    });

    if (error) {
      console.error('Failed to log auth event:', error);
    }
  }

  static async recordFailedAttempt(ipAddress: string) {
    const { data, error } = await supabase
      .from('failed_attempts')
      .select('*')
      .eq('ip_address', ipAddress)
      .single();

    if (error && error.code !== 'PGRST116') { // Record not found
      console.error('Failed to check failed attempts:', error);
      return;
    }

    if (data) {
      await supabase
        .from('failed_attempts')
        .update({
          attempt_count: data.attempt_count + 1,
          last_attempt_at: new Date().toISOString()
        })
        .eq('ip_address', ipAddress);
    } else {
      await supabase
        .from('failed_attempts')
        .insert({
          ip_address: ipAddress,
          attempt_count: 1,
          last_attempt_at: new Date().toISOString()
        });
    }
  }
}