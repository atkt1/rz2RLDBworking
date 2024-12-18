-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    device_info TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token)
);

-- Create auth_logs table
CREATE TABLE IF NOT EXISTS public.auth_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES public.users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    device_info TEXT,
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create failed_attempts table
CREATE TABLE IF NOT EXISTS public.failed_attempts (
    id SERIAL PRIMARY KEY,
    ip_address TEXT NOT NULL,
    attempt_count INTEGER DEFAULT 1,
    last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address)
);

-- Create function to automatically clean up expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM public.refresh_tokens
    WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Create function to create user with default plan
CREATE OR REPLACE FUNCTION create_user_with_plan(
    p_email TEXT,
    p_firstname TEXT,
    p_lastname TEXT,
    p_password_hash TEXT,
    p_plan_name TEXT
)
RETURNS TABLE (
    id INTEGER,
    email TEXT,
    firstname TEXT,
    lastname TEXT,
    role TEXT,
    plan_id INTEGER
) AS $$
DECLARE
    v_plan_id INTEGER;
    v_user_id INTEGER;
BEGIN
    -- Get the plan ID
    SELECT id INTO v_plan_id
    FROM public.plans
    WHERE name = p_plan_name;

    -- Insert the user
    INSERT INTO public.users (
        email,
        firstname,
        lastname,
        password_hash,
        role,
        is_active,
        is_verified,
        created_at
    )
    VALUES (
        p_email,
        p_firstname,
        p_lastname,
        p_password_hash,
        'user',
        true,
        false,
        CURRENT_TIMESTAMP
    )
    RETURNING id INTO v_user_id;

    -- Return the user details
    RETURN QUERY
    SELECT 
        u.id,
        u.email,
        u.firstname,
        u.lastname,
        u.role,
        p.id as plan_id
    FROM public.users u
    JOIN public.plans p ON p.id = v_plan_id
    WHERE u.id = v_user_id;
END;
$$ LANGUAGE plpgsql;