import { z } from 'zod';

export const loginSchema = z.object({
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .min(1, 'Password is required')
});

export const signUpSchema = z.object({
  firstName: z.string()
    .min(2, 'First name must be at least 2 characters')
    .min(1, 'First name is required'),
  lastName: z.string()
    .min(2, 'Last name must be at least 2 characters')
    .min(1, 'Last name is required'),
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .min(1, 'Password is required')
});

export const forgotPasswordSchema = z.object({
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required')
});

export const resetPasswordSchema = z.object({
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .min(1, 'Password is required'),
  confirmPassword: z.string()
    .min(1, 'Please confirm your password')
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"]
});