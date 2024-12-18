import { ENV } from '@/lib/constants';

interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
  domain?: string;
  maxAge?: number;
}

export class CookieService {
  private static readonly ACCESS_TOKEN_NAME = 'auth_token';
  private static readonly REFRESH_TOKEN_NAME = 'refresh_token';
  private static readonly CSRF_TOKEN_NAME = 'csrf_token';

  static setAuthTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    // Set access token with shorter expiry
    this.setCookie(this.ACCESS_TOKEN_NAME, accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: expiresIn
    });

    // Set refresh token with longer expiry (7 days)
    this.setCookie(this.REFRESH_TOKEN_NAME, refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60
    });

    // Set CSRF token (accessible via JavaScript)
    const csrfToken = this.generateCsrfToken();
    this.setCookie(this.CSRF_TOKEN_NAME, csrfToken, {
      httpOnly: false,
      secure: true,
      sameSite: 'Strict',
      maxAge: expiresIn
    });
  }

  static clearAuthTokens(): void {
    this.removeCookie(this.ACCESS_TOKEN_NAME);
    this.removeCookie(this.REFRESH_TOKEN_NAME);
    this.removeCookie(this.CSRF_TOKEN_NAME);
  }

  static getCsrfToken(): string | null {
    return this.getCookie(this.CSRF_TOKEN_NAME);
  }

  private static setCookie(name: string, value: string, options: CookieOptions = {}): void {
    const {
      httpOnly = true,
      secure = true,
      sameSite = 'Strict',
      path = '/',
      domain,
      maxAge
    } = options;

    let cookieString = `${name}=${encodeURIComponent(value)}`;
    
    if (httpOnly) cookieString += '; HttpOnly';
    if (secure) cookieString += '; Secure';
    if (sameSite) cookieString += `; SameSite=${sameSite}`;
    if (path) cookieString += `; Path=${path}`;
    if (domain) cookieString += `; Domain=${domain}`;
    if (maxAge) cookieString += `; Max-Age=${maxAge}`;

    document.cookie = cookieString;
  }

  private static getCookie(name: string): string | null {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [cookieName, cookieValue] = cookie.trim().split('=');
      if (cookieName === name) {
        return decodeURIComponent(cookieValue);
      }
    }
    return null;
  }

  private static removeCookie(name: string): void {
    this.setCookie(name, '', { maxAge: 0 });
  }

  private static generateCsrfToken(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}