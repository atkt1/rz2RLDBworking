import React from 'react';
import { AuthCard } from './AuthCard';
import { FormInput } from './FormInput';
import { Button } from '@/components/ui/Button';
import { X } from 'lucide-react';
import { useFormValidation } from '@/hooks/useFormValidation';
import { forgotPasswordSchema } from '@/lib/validation';
import type { AuthNavigationProps } from '@/types/auth';

interface ForgotPasswordFormProps extends AuthNavigationProps {
  onClose: () => void;
}

export const ForgotPasswordForm: React.FC<ForgotPasswordFormProps> = ({ onClose, onNavigate }) => {
  const { formData, errors, handleChange, handleSubmit } = useFormValidation({
    initialValues: { email: '' },
    validationSchema: forgotPasswordSchema,
    onSubmit: (values) => {
      console.log('Form submitted:', values);
    }
  });

  return (
    <AuthCard
      title="Reset your password"
      description="Enter your email and we'll send you instructions to reset your password"
    >
      <button
        onClick={onClose}
        className="absolute top-4 right-4 text-gray-400 hover:text-gray-600 transition-colors"
      >
        <X className="w-5 h-5" />
      </button>
      <form onSubmit={handleSubmit} className="space-y-6">
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
        
        <Button type="submit" variant="primary" className="w-full">
          Send Reset Link
        </Button>

        <p className="text-center text-sm text-gray-600">
          Remember your password?{' '}
          <button
            type="button"
            onClick={() => onNavigate('login')}
            className="text-blue-600 hover:text-blue-700 font-medium"
          >
            Back to Login
          </button>
        </p>
      </form>
    </AuthCard>
  );
};