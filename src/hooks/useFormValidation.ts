import { useState } from 'react';
import { z } from 'zod';

interface UseFormValidationProps<T> {
  initialValues: T;
  validationSchema: z.ZodSchema<any>;
  onSubmit: (values: T) => Promise<void>;
}

export function useFormValidation<T extends Record<string, any>>({
  initialValues,
  validationSchema,
  onSubmit
}: UseFormValidationProps<T>) {
  const [formData, setFormData] = useState<T>(initialValues);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }

    // Validate field on change
    try {
      validationSchema.pick({ [name]: true }).parse({ [name]: value });
    } catch (error) {
      if (error instanceof z.ZodError) {
        const fieldError = error.errors[0]?.message;
        if (fieldError) {
          setErrors(prev => ({ ...prev, [name]: fieldError }));
        }
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    try {
      const validatedData = await validationSchema.parseAsync(formData);
      setErrors({});
      await onSubmit(validatedData);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const formattedErrors: Record<string, string> = {};
        error.errors.forEach((err) => {
          if (err.path[0]) {
            formattedErrors[err.path[0].toString()] = err.message;
          }
        });
        setErrors(formattedErrors);
      }
      console.error('Form validation failed:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return {
    formData,
    errors,
    isSubmitting,
    handleChange,
    handleSubmit,
    setErrors
  };
}