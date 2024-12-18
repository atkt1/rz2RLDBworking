import React from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline';
  icon?: LucideIcon;
  iconPosition?: 'left' | 'right';
}

export const Button: React.FC<ButtonProps> = ({
  children,
  className,
  variant = 'primary',
  icon: Icon,
  iconPosition = 'right',
  ...props
}) => {
  const baseStyles = "px-6 py-3 rounded-lg font-medium transition-all duration-300 flex items-center gap-2 group";
  
  const variants = {
    primary: "bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-700 hover:to-blue-600 text-white shadow-lg hover:shadow-xl",
    secondary: "bg-white text-gray-800 hover:bg-gray-50 border border-gray-200",
    outline: "border-2 border-blue-600 text-blue-600 hover:bg-blue-50"
  };

  return (
    <button 
      className={cn(baseStyles, variants[variant], className)}
      {...props}
    >
      {Icon && iconPosition === 'left' && (
        <Icon className="w-5 h-5 group-hover:translate-x-0.5 transition-transform" />
      )}
      {children}
      {Icon && iconPosition === 'right' && (
        <Icon className="w-5 h-5 group-hover:translate-x-0.5 transition-transform" />
      )}
    </button>
  );
};