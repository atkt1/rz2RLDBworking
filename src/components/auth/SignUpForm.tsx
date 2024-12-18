import React from 'react';
import { useAuth } from '@/lib/context/AuthContext';
import { useFormValidation } from '@/hooks/useFormValidation';
import { signUpSchema, type SignUpInput } from '@/lib/validation/auth';
import { AuthService } from '@/lib/services/AuthService';
import { AuthError } from '@/lib/utils/errors';
import { AuthCard } from './AuthCard';
import { FormInput } from './FormInput';
import { Button } from '@/components/ui/Button';
import { X } from 'lucide-react';
import { getDeviceInfo } from '@/lib/utils/device';

interface SignUpFormProps extends AuthNavigationProps {
  onClose: () => void;
}

export const SignUpForm: React.FC<SignUpFormProps> = ({ onClose, onNavigate }) => {
  const { login } = useAuth();
  const { formData, errors, isSubmitting, handleChange, handleSubmit, setErrors } = useFormValidation({
    initialValues: {
      firstName: '',
      lastName: '',
      email: '',
      password: '',
      deviceInfo: getDeviceInfo()
    },
    validationSchema: signUpSchema,
    onSubmit: async (values: SignUpInput) => {
      try {
        const response = await AuthService.signUp(values);
        login(response);
        onClose();
      } catch (error) {
        if (error instanceof AuthError) {
          switch (error.code) {
            case 'auth/email-exists':
              setErrors({ email: 'This email is already registered' });
              break;
            case 'auth/weak-password':
              setErrors({ password: 'Password is too weak' });
              break;
            default:
              setErrors({ 
                submit: 'Failed to create account. Please try again.' 
              });
          }
        } else {
          setErrors({ 
            submit: 'An unexpected error occurred. Please try again.' 
          });
        }
        console.error('Signup failed:', error);
      }
    }
  });

  return (
    <AuthCard
      title="Create your account"
      description="Start managing your customer reviews effectively"
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

        <div className="grid grid-cols-2 gap-4">
          <FormInput
            label="First Name"
            type="text"
            name="firstName"
            value={formData.firstName}
            onChange={handleChange}
            placeholder="John"
            error={errors.firstName}
            required
          />
          <FormInput
            label="Last Name"
            type="text"
            name="lastName"
            value={formData.lastName}
            onChange={handleChange}
            placeholder="Doe"
            error={errors.lastName}
            required
          />
        </div>
        
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
        
        <Button 
          type="submit" 
          variant="primary" 
          className="w-full"
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Creating Account...' : 'Create Account'}
        </Button>
        
        <p className="text-center text-sm text-gray-600">
          Already have an account?{' '}
          <button
            type="button"
            onClick={() => onNavigate('login')}
            className="text-blue-600 hover:text-blue-700 font-medium"
          >
            Log in
          </button>
        </p>
      </form>
    </AuthCard>
  );
};