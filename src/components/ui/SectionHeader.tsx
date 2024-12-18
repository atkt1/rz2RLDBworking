import React from 'react';

interface SectionHeaderProps {
  title: string;
  description: string;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({ title, description }) => {
  return (
    <div className="text-center mb-16">
      <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
        {title}
      </h2>
      <p className="text-gray-600 max-w-2xl mx-auto">
        {description}
      </p>
    </div>
  );
};