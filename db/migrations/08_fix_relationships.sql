-- Drop existing incorrect foreign key constraints
DO $$ 
BEGIN
    -- Reviews
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'reviews_id_fkey') THEN
        ALTER TABLE reviews DROP CONSTRAINT reviews_id_fkey;
    END IF;
    
    -- Products
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'products_id_fkey') THEN
        ALTER TABLE products DROP CONSTRAINT products_id_fkey;
    END IF;
    
    -- Package Inserts
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'package_inserts_id_fkey') THEN
        ALTER TABLE package_inserts DROP CONSTRAINT package_inserts_id_fkey;
    END IF;
    
    -- Coupons
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'coupons_id_fkey') THEN
        ALTER TABLE coupons DROP CONSTRAINT coupons_id_fkey;
    END IF;
    
    -- Vouchers
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'vouchers_id_fkey') THEN
        ALTER TABLE vouchers DROP CONSTRAINT vouchers_id_fkey;
    END IF;
    
    -- Orders
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'orders_id_fkey') THEN
        ALTER TABLE orders DROP CONSTRAINT orders_id_fkey;
    END IF;
END $$;

-- Add necessary columns and constraints for Reviews
ALTER TABLE reviews 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD COLUMN IF NOT EXISTS survey_id INTEGER,
ADD CONSTRAINT fk_reviews_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
ADD CONSTRAINT fk_reviews_survey FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE;

-- Add necessary columns and constraints for Products
ALTER TABLE products 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD COLUMN IF NOT EXISTS survey_id INTEGER,
ADD COLUMN IF NOT EXISTS logo_id INTEGER,
ADD CONSTRAINT fk_products_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
ADD CONSTRAINT fk_products_survey FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
ADD CONSTRAINT fk_products_logo FOREIGN KEY (logo_id) REFERENCES logos(id) ON DELETE SET NULL;

-- Add necessary columns and constraints for Surveys
ALTER TABLE surveys 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD COLUMN IF NOT EXISTS background_id INTEGER,
ADD CONSTRAINT fk_surveys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
ADD CONSTRAINT fk_surveys_background FOREIGN KEY (background_id) REFERENCES survey_backgrounds(id) ON DELETE SET NULL;

-- Add necessary columns and constraints for Package Inserts
ALTER TABLE package_inserts 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD COLUMN IF NOT EXISTS survey_id INTEGER,
ADD CONSTRAINT fk_package_inserts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
ADD CONSTRAINT fk_package_inserts_survey FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE;

-- Add necessary columns and constraints for Coupons
ALTER TABLE coupons 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD CONSTRAINT fk_coupons_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Add necessary columns and constraints for Vouchers
ALTER TABLE vouchers 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD CONSTRAINT fk_vouchers_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Add necessary columns and constraints for Orders
ALTER TABLE orders 
ADD COLUMN IF NOT EXISTS user_id INTEGER,
ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Add NOT NULL constraints where appropriate
DO $$ 
BEGIN
    -- Reviews
    ALTER TABLE reviews ALTER COLUMN user_id SET NOT NULL;
    ALTER TABLE reviews ALTER COLUMN survey_id SET NOT NULL;
    
    -- Products
    ALTER TABLE products ALTER COLUMN user_id SET NOT NULL;
    
    -- Surveys
    ALTER TABLE surveys ALTER COLUMN user_id SET NOT NULL;
    
    -- Package Inserts
    ALTER TABLE package_inserts ALTER COLUMN user_id SET NOT NULL;
    ALTER TABLE package_inserts ALTER COLUMN survey_id SET NOT NULL;
    
    -- Coupons
    ALTER TABLE coupons ALTER COLUMN user_id SET NOT NULL;
    
    -- Vouchers
    ALTER TABLE vouchers ALTER COLUMN user_id SET NOT NULL;
    
    -- Orders
    ALTER TABLE orders ALTER COLUMN user_id SET NOT NULL;
EXCEPTION
    WHEN others THEN
        -- Handle any errors (like existing NULL values)
        RAISE NOTICE 'Error setting NOT NULL constraints. Make sure all existing rows have valid values.';
END $$;