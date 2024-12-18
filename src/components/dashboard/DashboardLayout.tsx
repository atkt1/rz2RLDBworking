import React from 'react';
import { useTheme } from '@/lib/context/ThemeContext';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { cn } from '@/lib/utils';

interface DashboardLayoutProps {
  children: React.ReactNode;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <div className={cn(
      'min-h-screen transition-colors duration-300',
      isDark ? 'bg-gray-900' : 'bg-gradient-to-b from-blue-50 via-white to-white'
    )}>
      <TopBar />
      <div className="flex min-h-screen pt-16">
        <Sidebar />
        <main className={cn(
          'flex-1 px-16 py-10 ml-64 transition-colors duration-300 relative',
          isDark ? 'bg-gray-900' : 'bg-gradient-to-b from-blue-50 via-white to-white'
        )}>
          {/* Background elements for light theme */}
          {!isDark && (
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
              <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-100 rounded-full opacity-20" />
              <div className="absolute top-60 -left-20 w-60 h-60 bg-cyan-100 rounded-full opacity-20" />
            </div>
          )}
          {/* Content container with backdrop blur */}
          <div className={cn(
            'relative z-10 h-full rounded-xl p-8',
            isDark 
              ? 'bg-gray-800/50 backdrop-blur-sm border border-gray-700/50' 
              : 'bg-white/50 backdrop-blur-sm'
          )}>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};