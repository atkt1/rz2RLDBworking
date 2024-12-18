import React from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

interface CardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ icon: Icon, title, description, className }) => {
  return (
    <div className={cn(
      "p-8 rounded-2xl bg-white border border-gray-100 hover:border-blue-100",
      "hover:shadow-lg transition-all duration-300 group",
      "transform hover:-translate-y-1",
      className
    )}>
      <div className="relative mb-6">
        <div className="absolute inset-0 bg-blue-100 rounded-lg opacity-20 group-hover:scale-110 transition-transform" />
        <Icon className="w-12 h-12 text-blue-600 relative z-10 group-hover:scale-110 transition-transform" />
      </div>
      <h3 className="text-xl font-semibold mb-3 text-gray-900">{title}</h3>
      <p className="text-gray-600 leading-relaxed">{description}</p>
    </div>
  );
};