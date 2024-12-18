import React from 'react';
import { Star } from 'lucide-react';

interface AuthCardProps {
  children: React.ReactNode;
  title: string;
  description: string;
}

export const AuthCard: React.FC<AuthCardProps> = ({ children, title, description }) => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-white flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background shapes */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-100 rounded-full opacity-20 animate-pulse" />
        <div className="absolute top-60 -left-20 w-60 h-60 bg-cyan-100 rounded-full opacity-20 animate-pulse delay-700" />
        <div className="absolute bottom-20 right-40 w-40 h-40 bg-blue-50 rounded-full opacity-30 animate-pulse delay-500" />
      </div>

      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center space-x-2 mb-6">
            <div className="relative">
              <div className="absolute inset-0 bg-blue-100 rounded-lg opacity-50 blur-sm transform rotate-45" />
              <Star className="h-8 w-8 text-blue-600 relative z-10" />
            </div>
            <span className="text-2xl font-extrabold bg-gradient-to-r from-blue-600 to-blue-500 bg-clip-text text-transparent tracking-tight">
              Review<span className="text-blue-600">Zone</span>
            </span>
          </div>
          <h1 className="text-2xl font-bold text-gray-900 mb-2">{title}</h1>
          <p className="text-gray-600">{description}</p>
        </div>
        
        <div className="bg-white/80 backdrop-blur-sm p-8 rounded-2xl shadow-lg border border-gray-100 relative">
          {children}
        </div>
      </div>
    </div>
  );
};