import React from 'react';
import { createRoot } from 'react-dom/client';
import { AuthProvider } from '@/lib/context/AuthContext';
import { ThemeProvider } from '@/lib/context/ThemeContext';
import App from './App';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <ThemeProvider>
    <AuthProvider>
      <App />
    </AuthProvider>
  </ThemeProvider>
);