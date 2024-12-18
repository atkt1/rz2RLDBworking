import React from 'react';
import { AuthCard } from './AuthCard';
import { FormInput } from './FormInput';
import { Button } from '@/components/ui/Button';

export const ResetPasswordForm = () => {
  return (
    <AuthCard
      title="Set new password"
      description="Enter your new password below"
    >
      <form className="space-y-6">
        <FormInput
          label="New Password"
          type="password"
          placeholder="••••••••"
          required
        />
        
        <FormInput
          label="Confirm Password"
          type="password"
          placeholder="••••••••"
          required
        />
        
        <Button variant="primary" className="w-full">
          Reset Password
        </Button>
        
        <p className="text-center text-sm text-gray-600">
          Remember your password?{' '}
          <a href="/login" className="text-blue-600 hover:text-blue-700 font-medium">
            Log in
          </a>
        </p>
      </form>
    </AuthCard>
  );
};