-- Create plan_name enum if it doesn't exist
DO $$ BEGIN
    CREATE TYPE plan_name AS ENUM ('Unpaid', 'Enterprise', 'Starter', 'Professional');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create plans table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.plans (
    id SERIAL PRIMARY KEY,
    name plan_name NOT NULL UNIQUE,
    amount_paid INTEGER DEFAULT 0,
    current_reviews_count INTEGER DEFAULT 0,
    max_review_count INTEGER,
    plan_frequency frequency,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default plans if they don't exist
INSERT INTO public.plans (name, amount_paid, max_review_count, plan_frequency)
VALUES
    ('Unpaid', 0, 5, 'Monthly'),
    ('Starter', 2900, 20, 'Monthly'),
    ('Professional', 7900, 100, 'Monthly'),
    ('Enterprise', 12500, 250, 'Monthly')
ON CONFLICT (name) DO NOTHING;