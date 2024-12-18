import React from 'react';
import { Star } from 'lucide-react';

const Footer = () => {
  return (
    <footer className="bg-white border-t border-gray-100">
      <div className="container mx-auto px-4 py-8">
        <div className="flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center space-x-2">
            <div className="relative">
              <div className="absolute inset-0 bg-blue-100 rounded-lg opacity-50 blur-sm transform rotate-45" />
              <Star className="h-6 w-6 text-blue-600 relative z-10" />
            </div>
            <span className="text-xl font-extrabold bg-gradient-to-r from-blue-600 to-blue-500 bg-clip-text text-transparent tracking-tight">
              Review<span className="text-blue-600">Zone</span>
            </span>
          </div>
          
          <div className="flex items-center gap-6">
            <a href="https://twitter.com" className="text-gray-500 hover:text-blue-600">
              Twitter
            </a>
            <a href="https://github.com" className="text-gray-500 hover:text-blue-600">
              GitHub
            </a>
          </div>
          
          <div className="text-sm text-gray-500">
            © 2024 ReviewZone.ai All rights reserved
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;