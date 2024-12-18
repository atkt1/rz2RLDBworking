import { ROUTES } from '@/lib/constants/routes';

export const publicRoutes = [
  {
    path: ROUTES.HOME,
    protected: false
  },
  {
    path: ROUTES.LOGIN,
    protected: false
  },
  {
    path: ROUTES.SIGNUP,
    protected: false
  }
];

export const protectedRoutes = [
  {
    path: ROUTES.DASHBOARD,
    protected: true
  }
];