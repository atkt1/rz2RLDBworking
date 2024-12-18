import React, { useState } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { AppRoutes } from '@/components/routing/AppRoutes';
import { LoginForm } from '@/components/auth/LoginForm';
import { SignUpForm } from '@/components/auth/SignUpForm';
import { ForgotPasswordForm } from '@/components/auth/ForgotPasswordForm';
import { ResetPasswordForm } from '@/components/auth/ResetPasswordForm';
import type { AuthScreen } from '@/types/auth';

function App() {
  const [currentScreen, setCurrentScreen] = useState<AuthScreen>(null);

  const handleNavigate = (screen: AuthScreen) => {
    setCurrentScreen(screen);
  };

  const handleClose = () => {
    setCurrentScreen(null);
  };

  return (
    <BrowserRouter>
      {currentScreen ? (
        <>
          {currentScreen === 'login' && (
            <LoginForm onClose={handleClose} onNavigate={handleNavigate} />
          )}
          {currentScreen === 'signup' && (
            <SignUpForm onClose={handleClose} onNavigate={handleNavigate} />
          )}
          {currentScreen === 'forgot-password' && (
            <ForgotPasswordForm onClose={handleClose} onNavigate={handleNavigate} />
          )}
          {currentScreen === 'reset-password' && (
            <ResetPasswordForm onClose={handleClose} onNavigate={handleNavigate} />
          )}
        </>
      ) : (
        <AppRoutes 
          onLogin={() => handleNavigate('login')} 
          onSignUp={() => handleNavigate('signup')} 
        />
      )}
    </BrowserRouter>
  );
}

export default App;