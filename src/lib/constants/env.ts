export const ENV = {
  API_URL: import.meta.env.VITE_API_URL,
  JWT_SECRET: import.meta.env.VITE_JWT_SECRET,
  REFRESH_SECRET: import.meta.env.VITE_REFRESH_SECRET,
  SUPABASE_URL: import.meta.env.VITE_SUPABASE_URL,
  SUPABASE_ANON_KEY: import.meta.env.VITE_SUPABASE_ANON_KEY,
  STRIPE_PUBLIC_KEY: import.meta.env.VITE_STRIPE_PUBLIC_KEY,
  STORAGE_KEY: import.meta.env.VITE_STORAGE_KEY
} as const;