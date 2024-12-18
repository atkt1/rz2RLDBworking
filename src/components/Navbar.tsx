import React from 'react';
import { Star } from 'lucide-react';

const Navbar = () => {
  return (
    <nav className="fixed w-full bg-white/80 backdrop-blur-md z-50 py-4">
      <div className="container mx-auto px-4 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Star className="h-6 w-6 text-blue-600" />
          <span className="text-xl font-bold">ReviewZone</span>
        </div>
        
        <div className="hidden md:flex items-center space-x-8">
          <a href="#features" className="text-gray-600 hover:text-blue-600 transition-colors">Features</a>
          <a href="#pricing" className="text-gray-600 hover:text-blue-600 transition-colors">Pricing</a>
          <button className="text-gray-600 hover:text-blue-600 transition-colors">Log in</button>
          <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
            Sign up
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;