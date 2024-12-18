import React from 'react';
import { ArrowRight } from 'lucide-react';

const Hero = () => {
  return (
    <div className="pt-32 pb-20 bg-gradient-to-b from-blue-50 to-white">
      <div className="container mx-auto px-4 text-center">
        <h1 className="text-4xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-blue-600 to-cyan-500 bg-clip-text text-transparent">
          Transform Your Customer Reviews
          <br />
          <span className="text-blue-600">Into Business Growth</span>
        </h1>
        <p className="text-gray-600 text-lg md:text-xl max-w-2xl mx-auto mb-10">
          Streamline your review collection process, boost your online presence, and turn
          satisfied customers into brand advocates.
        </p>
        <div className="flex flex-col md:flex-row items-center justify-center gap-4">
          <button className="group bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-all flex items-center gap-2">
            Start Free Trial
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>
          <button className="text-gray-600 hover:text-blue-600 px-6 py-3 rounded-lg border border-gray-200 hover:border-blue-200 transition-colors">
            View Demo
          </button>
        </div>
      </div>
    </div>
  );
};

export default Hero;