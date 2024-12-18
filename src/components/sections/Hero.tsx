import React from 'react';
import { ArrowRight, Play } from 'lucide-react';
import Button from '../ui/Button';

const Hero = () => {
  return (
    <div className="relative pt-32 pb-20 overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-blue-50 via-white to-white" />
      
      {/* Animated background shapes */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-100 rounded-full opacity-20 animate-pulse" />
        <div className="absolute top-60 -left-20 w-60 h-60 bg-cyan-100 rounded-full opacity-20 animate-pulse delay-700" />
      </div>

      <div className="container mx-auto px-4 text-center relative z-10">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-50 text-blue-600 mb-8">
          <span className="animate-pulse">🎉</span>
          <span className="text-sm font-medium">New: AI-Powered Review Analytics</span>
        </div>

        <h1 className="text-5xl md:text-7xl font-bold mb-6 leading-tight">
          <span className="bg-gradient-to-r from-blue-600 to-cyan-500 bg-clip-text text-transparent">
            Transform Your Customer Reviews
          </span>
          <br />
          <span className="bg-gradient-to-r from-blue-700 to-blue-500 bg-clip-text text-transparent">
            Into Business Growth
          </span>
        </h1>

        <p className="text-gray-600 text-lg md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed">
          Streamline your review collection process, boost your online presence, and turn
          satisfied customers into brand advocates with our AI-powered platform.
        </p>

        <div className="flex flex-col md:flex-row items-center justify-center gap-4">
          <Button variant="primary" icon={ArrowRight}>
            Start Free Trial
          </Button>
          <Button variant="secondary" icon={Play} iconPosition="left">
            Watch Demo
          </Button>
        </div>

        <div className="mt-16 flex items-center justify-center gap-8">
          <div className="flex -space-x-2">
            {[...Array(4)].map((_, i) => (
              <img
                key={i}
                src={`https://source.unsplash.com/random/100x100?face&${i}`}
                alt="User"
                className="w-10 h-10 rounded-full border-2 border-white"
              />
            ))}
          </div>
          <div className="text-left">
            <div className="text-2xl font-bold text-gray-900">2,000+</div>
            <div className="text-gray-600">Happy Customers</div>
          </div>
          <div className="h-12 w-px bg-gray-200" />
          <div className="text-left">
            <div className="text-2xl font-bold text-gray-900">4.9/5</div>
            <div className="text-gray-600">Customer Rating</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hero;