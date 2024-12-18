import React from 'react';
import { useTheme } from '@/lib/context/ThemeContext';
import { Star, Bell, Sun, Moon } from 'lucide-react';
import { cn } from '@/lib/utils';

export const TopBar = () => {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <div className={cn(
      'h-16 border-b px-4 flex items-center justify-between fixed top-0 right-0 left-0 z-50 transition-colors duration-300',
      isDark ? 'bg-gray-900 border-gray-800' : 'bg-white/80 backdrop-blur-md border-gray-200'
    )}>
      <div className="flex items-center gap-2 pl-4">
        <div className="relative">
          <div className={cn(
            "absolute inset-0 rounded-lg opacity-50 blur-sm transform rotate-45",
            isDark ? 'bg-blue-500' : 'bg-blue-100'
          )} />
          <Star className={cn(
            "h-6 w-6 relative z-10",
            isDark ? 'text-blue-400' : 'text-blue-600'
          )} />
        </div>
        <span className={cn(
          "text-xl font-extrabold tracking-tight",
          isDark ? 'text-white' : 'bg-gradient-to-r from-blue-600 to-blue-500 bg-clip-text text-transparent'
        )}>
          Review<span className={isDark ? 'text-blue-400' : 'text-blue-600'}>Zone</span>
        </span>
      </div>

      <div className="flex items-center gap-4">
        <button 
          onClick={toggleTheme}
          className={cn(
            "p-2 rounded-lg transition-colors",
            isDark ? 'hover:bg-gray-800' : 'hover:bg-gray-100'
          )}
        >
          {isDark ? <Sun className="w-5 h-5 text-gray-300" /> : <Moon className="w-5 h-5 text-gray-600" />}
        </button>
        <button className={cn(
          "p-2 rounded-lg transition-colors relative",
          isDark ? 'hover:bg-gray-800' : 'hover:bg-gray-100'
        )}>
          <Bell className={isDark ? 'text-gray-300' : 'text-gray-600'} />
          <span className="absolute top-1 right-1 w-2 h-2 bg-blue-600 rounded-full" />
        </button>
        <div className={cn(
          "h-8 w-8 rounded-full bg-gradient-to-r from-blue-500 to-blue-600",
          "flex items-center justify-center text-white font-medium"
        )}>
          JD
        </div>
      </div>
    </div>
  );
};