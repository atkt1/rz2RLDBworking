import { jwtDecode } from 'jwt-decode';

interface JWTPayload {
  exp: number;
  user_id: number;
  role: string;
}

export const isTokenValid = (token: string): boolean => {
  try {
    const decoded = jwtDecode<JWTPayload>(token);
    return decoded.exp > Date.now() / 1000;
  } catch {
    return false;
  }
};

export const getTokenExpiration = (token: string): number | null => {
  try {
    const decoded = jwtDecode<JWTPayload>(token);
    return decoded.exp;
  } catch {
    return null;
  }
};