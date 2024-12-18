import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '@/lib/context/AuthContext';
import { ROUTES } from '@/lib/constants/routes';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { user } = useAuth();

  if (!user) {
    return <Navigate to={ROUTES.HOME} replace />;
  }

  return <>{children}</>;
};