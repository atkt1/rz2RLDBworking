-- First, remove the incorrect foreign key constraint on the id column
DO $$ 
BEGIN
    -- Drop the constraint that incorrectly links users.id to plans.id
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints 
        WHERE constraint_name = 'users_id_fkey'
        AND table_name = 'users'
    ) THEN
        ALTER TABLE public.users
        DROP CONSTRAINT users_id_fkey;
    END IF;

    -- Drop other plan-related constraints if they exist
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_plan'
        AND table_name = 'users'
    ) THEN
        ALTER TABLE public.users
        DROP CONSTRAINT fk_plan;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_users_plan'
        AND table_name = 'users'
    ) THEN
        ALTER TABLE public.users
        DROP CONSTRAINT fk_users_plan;
    END IF;

    -- Now add the correct constraint on plan_id column
    ALTER TABLE public.users
    ADD CONSTRAINT fk_users_plan
    FOREIGN KEY (plan_id)
    REFERENCES public.plans(id)
    ON DELETE SET NULL;

END $$;