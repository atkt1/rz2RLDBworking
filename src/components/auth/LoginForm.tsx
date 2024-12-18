import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthCard } from './AuthCard';
import { FormInput } from './FormInput';
import { Button } from '@/components/ui/Button';
import { X } from 'lucide-react';
import { loginSchema } from '@/lib/validation';
import { useFormValidation } from '@/hooks/useFormValidation';
import { AuthService } from '@/lib/services/AuthService';
import { useAuth } from '@/lib/context/AuthContext';
import { getDeviceInfo } from '@/lib/utils/device';
import { ROUTES } from '@/lib/constants/routes';
import type { AuthNavigationProps } from '@/types/auth';

interface LoginFormProps extends AuthNavigationProps {
  onClose: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ onClose, onNavigate }) => {
  const navigate = useNavigate();
  const { login: setAuthState } = useAuth();
  
  const { formData, errors, isSubmitting, handleChange, handleSubmit, setErrors } = useFormValidation({
    initialValues: { 
      email: '', 
      password: '',
      deviceInfo: getDeviceInfo()
    },
    validationSchema: loginSchema,
    onSubmit: async (values) => {
      try {
        const response = await AuthService.login(values);
        setAuthState(response);
        onClose(); // Close the login form before navigation
        navigate(ROUTES.DASHBOARD);
      } catch (error: any) {
        if (error.code === 'auth/invalid-credentials') {
          setErrors({ 
            submit: 'Invalid email or password' 
          });
        } else {
          setErrors({ 
            submit: 'An error occurred while logging in. Please try again.' 
          });
        }
        console.error('Login failed:', error);
      }
    }
  });

  return (
    <AuthCard
      title="Welcome back"
      description="Log in to your ReviewZone account"
    >
      <button
        onClick={onClose}
        className="absolute top-4 right-4 text-gray-400 hover:text-gray-600 transition-colors"
      >
        <X className="w-5 h-5" />
      </button>

      <form onSubmit={handleSubmit} className="space-y-6">
        {errors.submit && (
          <div className="p-3 text-sm text-red-600 bg-red-50 rounded-lg">
            {errors.submit}
          </div>
        )}
        
        <FormInput
          label="Email"
          type="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
          placeholder="john@company.com"
          error={errors.email}
          required
        />
        
        <div className="space-y-2">
          <FormInput
            label="Password"
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            placeholder="••••••••"
            error={errors.password}
            required
          />
          <div className="text-right">
            <button
              type="button"
              onClick={() => onNavigate('forgot-password')}
              className="text-sm text-blue-600 hover:text-blue-700"
            >
              Forgot password?
            </button>
          </div>
        </div>
        
        <Button 
          type="submit" 
          variant="primary" 
          className="w-full"
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Logging in...' : 'Log in'}
        </Button>
        
        <p className="text-center text-sm text-gray-600">
          Don't have an account?{' '}
          <button
            type="button"
            onClick={() => onNavigate('signup')}
            className="text-blue-600 hover:text-blue-700 font-medium"
          >
            Sign up
          </button>
        </p>
      </form>
    </AuthCard>
  );
}