import { supabase } from '@/lib/supabase';
import { TokenService } from './TokenService';
import { CookieService } from './CookieService';
import { AuditService } from './AuditService';
import { RateLimitService } from './RateLimitService';
import { AuthError, AUTH_ERROR_CODES } from '@/lib/utils/errors';
import { hashPassword } from '@/lib/utils/crypto';
import { getClientIp } from '@/lib/utils/network';
import type { AuthResponse, UserSession } from '@/lib/types/auth';
import type { LoginInput, SignUpInput } from '@/lib/validation/auth';

export class AuthService {
  static async login({ email, password, deviceInfo }: LoginInput): Promise<AuthResponse> {
    try {
      const ipAddress = getClientIp();
      
      // Check rate limit before proceeding
      await RateLimitService.checkRateLimit(ipAddress, email.toLowerCase());

      // Hash password for comparison
      const passwordHash = await hashPassword(password);

      // Get user with plan information
      const { data: user, error: userError } = await supabase
        .from('users')
        .select(`
          id,
          email,
          firstname,
          lastname,
          password_hash,
          role,
          is_verified,
          plan_id
        `)
        .eq('email', email.toLowerCase())
        .single();

      if (userError || !user) {
        await this.handleFailedLogin(ipAddress, email, 'User not found');
        throw new AuthError(
          'Invalid email or password',
          AUTH_ERROR_CODES.INVALID_CREDENTIALS
        );
      }

      // Verify password
      if (user.password_hash !== passwordHash) {
        await this.handleFailedLogin(ipAddress, email, 'Invalid password');
        throw new AuthError(
          'Invalid email or password',
          AUTH_ERROR_CODES.INVALID_CREDENTIALS
        );
      }

      // Generate tokens
      const tokens = TokenService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role || 'user',
        planId: user.plan_id
      }, deviceInfo);

      // Store tokens in HTTP-only cookies
      CookieService.setAuthTokens(tokens.accessToken, tokens.refreshToken, tokens.expiresIn);

      // Log successful login
      await AuditService.logAuthEvent('LOGIN_SUCCESS', {
        userId: user.id,
        email: user.email,
        ipAddress
      });

      // Update last login timestamp
      await supabase
        .from('users')
        .update({ last_login: new Date().toISOString() })
        .eq('id', user.id);

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstname,
          lastName: user.lastname,
          role: user.role || 'user',
          isVerified: user.is_verified,
          planId: user.plan_id
        },
        tokens
      };
    } catch (error) {
      console.error('Login error:', error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        'Failed to log in',
        AUTH_ERROR_CODES.SERVER_ERROR,
        { originalError: error }
      );
    }
  }

  private static async handleFailedLogin(ipAddress: string, email: string, reason: string): Promise<void> {
    try {
      const attempts = await RateLimitService.incrementAttempt(ipAddress, email.toLowerCase());
      
      // Log the failed attempt
      await AuditService.logAuthEvent('LOGIN_FAILED', { 
        email, 
        reason,
        ipAddress,
        attemptCount: attempts
      });

      const remainingAttempts = 5 - attempts;
      if (remainingAttempts <= 0) {
        throw new AuthError(
          'Too many failed login attempts. Please try again after 15 minutes.',
          AUTH_ERROR_CODES.INVALID_CREDENTIALS
        );
      } else if (remainingAttempts <= 2) {
        throw new AuthError(
          `Invalid credentials. ${remainingAttempts} attempts remaining before temporary lockout.`,
          AUTH_ERROR_CODES.INVALID_CREDENTIALS
        );
      }
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      console.error('Error handling failed login:', error);
    }
  }

  // ... rest of the class implementation remains unchanged
}