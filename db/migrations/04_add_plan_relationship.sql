-- Add plan_id column to users table if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'users' 
        AND column_name = 'plan_id'
    ) THEN
        ALTER TABLE public.users 
        ADD COLUMN plan_id INTEGER;
    END IF;
END $$;

-- Add foreign key constraint if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_users_plan'
    ) THEN
        ALTER TABLE public.users
        ADD CONSTRAINT fk_users_plan
        FOREIGN KEY (plan_id)
        REFERENCES public.plans(id)
        ON DELETE SET NULL;
    END IF;
END $$;

-- Update existing users to have the Unpaid plan
UPDATE public.users u
SET plan_id = p.id
FROM public.plans p
WHERE p.name = 'Unpaid'
AND u.plan_id IS NULL;