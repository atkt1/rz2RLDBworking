-- Create failed_attempts table if it doesn't exist
CREATE TABLE IF NOT EXISTS failed_attempts (
    id SERIAL,
    ip_address TEXT NOT NULL,
    identifier VARCHAR NOT NULL DEFAULT 'anonymous',
    attempt_count INTEGER DEFAULT 1,
    last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address, identifier)
);

-- Create or replace the increment_failed_attempts function
CREATE OR REPLACE FUNCTION increment_failed_attempts(
    p_ip_address TEXT,
    p_identifier TEXT,
    p_last_attempt TIMESTAMP
)
RETURNS void AS $$
DECLARE
    v_current_count INTEGER;
BEGIN
    INSERT INTO failed_attempts (
        ip_address,
        identifier,
        attempt_count,
        last_attempt_at,
        last_reset
    )
    VALUES (
        p_ip_address,
        p_identifier,
        1,
        p_last_attempt,
        p_last_attempt
    )
    ON CONFLICT (ip_address, identifier)
    DO UPDATE SET
        attempt_count = CASE
            WHEN failed_attempts.last_reset + INTERVAL '15 minutes' < p_last_attempt THEN 1
            ELSE failed_attempts.attempt_count + 1
        END,
        last_attempt_at = p_last_attempt,
        last_reset = CASE
            WHEN failed_attempts.last_reset + INTERVAL '15 minutes' < p_last_attempt THEN p_last_attempt
            ELSE failed_attempts.last_reset
        END;
END;
$$ LANGUAGE plpgsql;