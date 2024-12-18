-- First, remove any existing foreign key constraints related to plans
DO $$ 
BEGIN
    -- Drop the old constraint if it exists (using the original name)
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_plan'
        AND table_name = 'users'
    ) THEN
        ALTER TABLE public.users
        DROP CONSTRAINT fk_plan;
    END IF;

    -- Drop the new constraint if it exists
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_users_plan'
        AND table_name = 'users'
    ) THEN
        ALTER TABLE public.users
        DROP CONSTRAINT fk_users_plan;
    END IF;

    -- Now add the single, correct constraint
    ALTER TABLE public.users
    ADD CONSTRAINT fk_users_plan
    FOREIGN KEY (plan_id)
    REFERENCES public.plans(id)
    ON DELETE SET NULL;

END $$;