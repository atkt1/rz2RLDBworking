import React from 'react';
import { useTheme } from '@/lib/context/ThemeContext';
import { MessageSquare, Star, Users, ArrowUpRight, TrendingUp, TrendingDown } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string;
  change: {
    value: string;
    positive: boolean;
  };
  icon: React.ElementType;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, change, icon: Icon }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <div className={cn(
      'rounded-xl p-6 border transition-colors duration-300',
      isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'
    )}>
      <div className="flex items-center justify-between mb-4">
        <div className={cn(
          'p-2 rounded-lg',
          isDark ? 'bg-gray-700' : 'bg-blue-50'
        )}>
          <Icon className={cn(
            'w-5 h-5',
            isDark ? 'text-blue-400' : 'text-blue-600'
          )} />
        </div>
        <div className={cn(
          'flex items-center gap-1 text-sm',
          change.positive ? 'text-green-500' : 'text-red-500'
        )}>
          {change.positive ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
          <span>{change.value}</span>
        </div>
      </div>
      <h3 className={cn(
        'text-sm font-medium mb-1',
        isDark ? 'text-gray-400' : 'text-gray-500'
      )}>
        {title}
      </h3>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
};

export const Dashboard = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const stats = [
    {
      title: 'Total Reviews',
      value: '2,847',
      change: { value: '+12.5% vs last month', positive: true },
      icon: MessageSquare
    },
    {
      title: 'Average Rating',
      value: '4.8',
      change: { value: '+0.2 vs last month', positive: true },
      icon: Star
    },
    {
      title: 'Active Customers',
      value: '1,249',
      change: { value: '-2.3% vs last month', positive: false },
      icon: Users
    },
    {
      title: 'Response Rate',
      value: '94%',
      change: { value: '+5.7% vs last month', positive: true },
      icon: ArrowUpRight
    }
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className={cn(
          'text-2xl font-bold mb-2',
          isDark ? 'text-white' : 'text-gray-900'
        )}>
          Dashboard Overview
        </h1>
        <p className={cn(
          'text-sm',
          isDark ? 'text-gray-400' : 'text-gray-600'
        )}>
          Track your review management metrics and performance
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => (
          <StatCard key={index} {...stat} />
        ))}
      </div>
    </div>
  );
};