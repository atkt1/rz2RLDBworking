import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { ProtectedRoute } from './ProtectedRoute';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { Dashboard } from '@/components/dashboard/Dashboard';
import { LandingPage } from '@/components/pages/LandingPage';
import { ROUTES } from '@/lib/constants/routes';

interface AppRoutesProps {
  onLogin: () => void;
  onSignUp: () => void;
}

export const AppRoutes: React.FC<AppRoutesProps> = ({ onLogin, onSignUp }) => {
  return (
    <Routes>
      <Route path={ROUTES.DASHBOARD} element={
        <ProtectedRoute>
          <DashboardLayout>
            <Dashboard />
          </DashboardLayout>
        </ProtectedRoute>
      } />
      <Route path={ROUTES.HOME} element={
        <LandingPage onLogin={onLogin} onSignUp={onSignUp} />
      } />
    </Routes>
  );
};