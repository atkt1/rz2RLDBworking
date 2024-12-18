export type AuthScreen = 'login' | 'signup' | 'forgot-password' | 'reset-password' | null;

export interface AuthNavigationProps {
  onNavigate: (screen: AuthScreen) => void;
}