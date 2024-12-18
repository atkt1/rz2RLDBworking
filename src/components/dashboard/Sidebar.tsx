import React from 'react';
import { useTheme } from '@/lib/context/ThemeContext';
import { 
  LayoutDashboard, Star, Package, FileSpreadsheet,
  Gift, ClipboardList, Upload, CheckSquare, QrCode
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavItemProps {
  icon: React.ElementType;
  label: string;
  active?: boolean;
}

const NavItem: React.FC<NavItemProps> = ({ icon: Icon, label, active }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button className={cn(
      'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200',
      'hover:scale-[1.02]',
      active ? (isDark ? 'bg-gray-800 text-white' : 'bg-blue-50 text-blue-600') 
      : (isDark ? 'text-gray-400 hover:bg-gray-800 hover:text-white' : 'text-gray-600 hover:bg-gray-100')
    )}>
      <Icon className="w-5 h-5" />
      <span className="font-medium">{label}</span>
    </button>
  );
};

const NavGroup: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="space-y-1.5">
      {children}
    </div>
  );
};

const Divider = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  
  return (
    <div className="px-4 py-4">
      <div className={cn(
        'h-px w-full',
        isDark ? 'bg-gradient-to-r from-transparent via-gray-700 to-transparent' 
        : 'bg-gradient-to-r from-transparent via-gray-200 to-transparent'
      )} />
    </div>
  );
};

export const Sidebar = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <div className={cn(
      'w-64 border-r fixed left-0 top-16 bottom-0 transition-colors duration-300',
      isDark ? 'bg-gray-900 border-gray-800' : 'bg-white/80 backdrop-blur-md border-gray-200'
    )}>
      <div className="space-y-6 pt-6 px-4">
        {/* Main Group */}
        <NavGroup>
          <NavItem icon={LayoutDashboard} label="Dashboard" active />
          <NavItem icon={Star} label="Reviews" />
        </NavGroup>

        <Divider />

        {/* Management Group */}
        <NavGroup>
          <NavItem icon={Package} label="Products" />
          <NavItem icon={FileSpreadsheet} label="Surveys" />
          <NavItem icon={QrCode} label="Package Inserts" />
          <NavItem icon={Gift} label="Giveaways" />
        </NavGroup>

        <Divider />

        {/* Orders Group */}
        <NavGroup>
          <NavItem icon={ClipboardList} label="Orders" />
          <NavItem icon={Upload} label="Upload Orders" />
          <NavItem icon={CheckSquare} label="Validate Reviews" />
        </NavGroup>
      </div>
    </div>
  );
};