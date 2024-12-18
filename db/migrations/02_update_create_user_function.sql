-- Drop the existing function if it exists
DROP FUNCTION IF EXISTS create_user_with_plan;

-- Create the updated function with fixed column references
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
    -- Get the plan ID for the given plan name
    SELECT plans.id INTO v_plan_id
    FROM plans
    WHERE plans.name = p_plan_name::plan_name;

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

    -- Return the user details with fully qualified column names
    RETURN QUERY
    SELECT 
        users.id,
        users.email,
        users.firstname,
        users.lastname,
        users.role,
        v_plan_id AS plan_id
    FROM users
    WHERE users.id = v_user_id;
END;
$$ LANGUAGE plpgsql;