export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface UserSession {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  isVerified: boolean;
  planId: number;
}

export interface AuthResponse {
  user: UserSession;
  tokens: AuthTokens;
}

export interface TokenPayload {
  userId: number;
  email: string;
  role: string;
  planId: number;
}

export interface RefreshTokenPayload extends TokenPayload {
  tokenId: string;
  deviceInfo?: string;
}

export type AuthEventType = 
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGOUT'
  | 'PASSWORD_RESET_REQUEST'
  | 'PASSWORD_RESET_SUCCESS'
  | 'TOKEN_REFRESH'
  | 'INVALID_TOKEN'
  | 'RATE_LIMIT_EXCEEDED';