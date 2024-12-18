-- Drop the existing function
DROP FUNCTION IF EXISTS create_user_with_plan;

-- Recreate the function with correct return types
CREATE OR REPLACE FUNCTION create_user_with_plan(
    p_email character varying,
    p_firstname character varying,
    p_lastname character varying,
    p_password_hash text,
    p_plan_name plan_name
)
RETURNS TABLE (
    id integer,
    email character varying,
    firstname character varying,
    lastname character varying,
    role character varying,
    plan_id integer
) AS $$
DECLARE
    v_plan_id INTEGER;
    v_user_id INTEGER;
BEGIN
    -- Get the plan ID for the given plan name
    SELECT plans.id INTO v_plan_id
    FROM plans
    WHERE plans.name = p_plan_name;

    IF v_plan_id IS NULL THEN
        RAISE EXCEPTION 'Invalid plan name: %', p_plan_name;
    END IF;

    -- Insert the new user
    INSERT INTO users (
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
        LOWER(p_email),
        p_firstname,
        p_lastname,
        p_password_hash,
        'user',
        TRUE,
        FALSE,
        CURRENT_TIMESTAMP
    )
    RETURNING users.id INTO v_user_id;

    -- Return the user details
    RETURN QUERY
    SELECT 
        u.id,
        u.email,
        u.firstname,
        u.lastname,
        u.role,
        v_plan_id AS plan_id
    FROM users u
    WHERE u.id = v_user_id;
END;
$$ LANGUAGE plpgsql;