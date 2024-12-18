import React from 'react';
import { Star } from 'lucide-react';
import { Button } from '@/components/ui/Button';

interface NavbarProps {
  onLogin: () => void;
  onSignUp: () => void;
}

const Navbar: React.FC<NavbarProps> = ({ onLogin, onSignUp }) => {
  return (
    <nav className="fixed w-full bg-white/80 backdrop-blur-md z-50 py-4">
      <div className="container mx-auto px-4 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <div className="absolute inset-0 bg-blue-100 rounded-lg opacity-50 blur-sm transform rotate-45" />
            <Star className="h-6 w-6 text-blue-600 relative z-10" />
          </div>
          <span className="text-xl font-extrabold bg-gradient-to-r from-blue-600 to-blue-500 bg-clip-text text-transparent tracking-tight">
            Review<span className="text-blue-600">Zone</span>
          </span>
        </div>
        
        <div className="hidden md:flex items-center space-x-8">
          <a href="#features" className="text-gray-600 hover:text-blue-600 transition-colors">Features</a>
          <a href="#pricing" className="text-gray-600 hover:text-blue-600 transition-colors">Pricing</a>
          <Button variant="outline" onClick={onLogin}>Log in</Button>
          <Button variant="primary" onClick={onSignUp}>Sign up</Button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;