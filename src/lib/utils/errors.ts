export class AuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export class RateLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RateLimitError';
  }
}

export const AUTH_ERROR_CODES = {
  INVALID_CREDENTIALS: 'auth/invalid-credentials',
  EMAIL_EXISTS: 'auth/email-exists',
  WEAK_PASSWORD: 'auth/weak-password',
  RATE_LIMIT: 'auth/rate-limit',
  NETWORK_ERROR: 'auth/network-error',
  SERVER_ERROR: 'auth/server-error',
  SIGNUP_FAILED: 'auth/signup-failed'
} as const;