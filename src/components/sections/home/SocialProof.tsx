import React from 'react';

export const SocialProof = () => {
  return (
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
  );
};