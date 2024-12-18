import type { RateLimitConfig } from '@/lib/types/rateLimit';

export class RateLimitValidator {
  static isWithinWindow(lastResetTime: Date, windowMinutes: number): boolean {
    const windowExpiry = new Date(lastResetTime.getTime() + (windowMinutes * 60000));
    return new Date() <= windowExpiry;
  }

  static shouldResetAttempts(lastResetTime: Date, windowMinutes: number): boolean {
    return !this.isWithinWindow(lastResetTime, windowMinutes);
  }

  static isRateLimited(attempts: number, config: RateLimitConfig): boolean {
    return attempts >= config.maxAttempts;
  }
}