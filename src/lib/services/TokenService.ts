import { ENV } from '@/lib/constants';
import type { TokenPayload, RefreshTokenPayload, AuthTokens } from '@/lib/types/auth';

// Use Web Crypto API instead of Node's crypto
const generateUUID = () => crypto.randomUUID();

export class TokenService {
  private static readonly ACCESS_TOKEN_EXPIRY = 15 * 60; // 15 minutes
  private static readonly REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days

  static generateTokens(payload: TokenPayload, deviceInfo?: string): AuthTokens {
    const accessToken = this.signToken(payload, ENV.JWT_SECRET, this.ACCESS_TOKEN_EXPIRY);
    
    const refreshTokenPayload: RefreshTokenPayload = {
      ...payload,
      tokenId: generateUUID(),
      deviceInfo
    };

    const refreshToken = this.signToken(refreshTokenPayload, ENV.REFRESH_SECRET, this.REFRESH_TOKEN_EXPIRY);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.ACCESS_TOKEN_EXPIRY
    };
  }

  private static signToken(payload: any, secret: string, expiresIn: number): string {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };

    const now = Math.floor(Date.now() / 1000);
    const exp = now + expiresIn;

    const encodedHeader = btoa(JSON.stringify(header));
    const encodedPayload = btoa(JSON.stringify({ ...payload, exp }));

    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = this.hmacSha256(data, secret);

    return `${data}.${signature}`;
  }

  private static async hmacSha256(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(data)
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }

  static async verifyToken(token: string, secret: string): Promise<any> {
    try {
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      const data = `${headerB64}.${payloadB64}`;
      
      const expectedSignature = await this.hmacSha256(data, secret);
      if (signatureB64 !== expectedSignature) {
        throw new Error('Invalid signature');
      }

      const payload = JSON.parse(atob(payloadB64));
      const now = Math.floor(Date.now() / 1000);

      if (payload.exp && payload.exp < now) {
        throw new Error('Token expired');
      }

      return payload;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  static decodeToken(token: string): any {
    try {
      const [, payloadB64] = token.split('.');
      return JSON.parse(atob(payloadB64));
    } catch {
      throw new Error('Invalid token format');
    }
  }
}