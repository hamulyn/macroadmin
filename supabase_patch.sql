-- ============================================
-- BLADE & SOUL MACRO v7.0 - COMPLETE DATABASE SCHEMA
-- Enhanced Version with Full Features
-- ============================================

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- DROP EXISTING TABLES (for clean install)
-- ============================================
DROP TABLE IF EXISTS public.activity_logs CASCADE;
DROP TABLE IF EXISTS public.preset_ratings CASCADE;
DROP TABLE IF EXISTS public.user_blocks CASCADE;
DROP TABLE IF EXISTS public.presets CASCADE;
DROP TABLE IF EXISTS public.profiles CASCADE;
DROP TABLE IF EXISTS public.app_config CASCADE;

-- ============================================
-- USERS PROFILE TABLE (Enhanced)
-- ============================================
CREATE TABLE public.profiles (
    id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
    nickname VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(20) DEFAULT 'trial' CHECK (role IN ('trial', 'user', 'premium', 'admin')),
    permissions TEXT[] DEFAULT '{}',
    device_id VARCHAR(255),
    app_version VARCHAR(20),
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    trial_expiry DATE,
    is_trial BOOLEAN DEFAULT true,
    is_blocked BOOLEAN DEFAULT false,
    block_reason TEXT,
    blocked_at TIMESTAMP WITH TIME ZONE,
    blocked_by UUID REFERENCES auth.users(id),
    total_downloads INTEGER DEFAULT 0,
    total_uploads INTEGER DEFAULT 0,
    reputation_score INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================
-- PRESETS TABLE (Enhanced with new features)
-- ============================================
CREATE TABLE public.presets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    build_type VARCHAR(20) DEFAULT 'both' CHECK (build_type IN ('puncture', 'hybrid', 'both')),
    ping_range VARCHAR(50) DEFAULT '0-50ms',
    exact_ping INTEGER,
    is_public BOOLEAN DEFAULT false,
    settings JSONB NOT NULL,
    author_name VARCHAR(100),
    version VARCHAR(20),
    downloads INTEGER DEFAULT 0,
    rating DECIMAL(3,2) DEFAULT 0,
    rating_count INTEGER DEFAULT 0,
    tags TEXT[] DEFAULT '{}',
    youtube_url TEXT,
    discord_url TEXT,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_user_preset_name UNIQUE(user_id, name)
);

-- ============================================
-- PRESET RATINGS TABLE
-- ============================================
CREATE TABLE public.preset_ratings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    preset_id UUID REFERENCES public.presets(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5) NOT NULL,
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_user_preset_rating UNIQUE(preset_id, user_id)
);

-- ============================================
-- USER BLOCKS TABLE
-- ============================================
CREATE TABLE public.user_blocks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    blocked_by UUID REFERENCES auth.users(id) NOT NULL,
    reason TEXT NOT NULL,
    block_type VARCHAR(20) DEFAULT 'temporary' CHECK (block_type IN ('temporary', 'permanent')),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================
-- ACTIVITY LOGS TABLE
-- ============================================
CREATE TABLE public.activity_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    device_id VARCHAR(255),
    ip_address INET,
    version VARCHAR(20),
    metadata JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================
-- APP CONFIG TABLE (Enhanced)
-- ============================================
CREATE TABLE public.app_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES auth.users(id)
);

-- Insert default app config with v7.0 values
INSERT INTO public.app_config (key, value, description) VALUES
    ('latest_version', '7.0.0', 'Latest application version'),
    ('maintenance_mode', 'false', 'Enable maintenance mode'),
    ('announcement', 'Welcome to BNS Macro v7.0! New features: Enhanced preset system, cloud sync, and admin panel.', 'Global announcement message'),
    ('trial_days', '7', 'Default trial period in days'),
    ('max_presets_trial', '3', 'Maximum presets for trial users'),
    ('max_presets_premium', '100', 'Maximum presets for premium users'),
    ('update_url', 'https://github.com/yourusername/bns-macro/releases', 'URL for updates'),
    ('discord_url', 'https://discord.gg/bns-macro', 'Discord community URL'),
    ('min_version', '6.0.0', 'Minimum supported version'),
    ('force_update', 'false', 'Force users to update')
ON CONFLICT (key) DO UPDATE SET 
    value = EXCLUDED.value,
    updated_at = NOW();

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================
CREATE INDEX IF NOT EXISTS idx_profiles_nickname ON public.profiles(nickname);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_profiles_blocked ON public.profiles(is_blocked);
CREATE INDEX IF NOT EXISTS idx_presets_user_id ON public.presets(user_id);
CREATE INDEX IF NOT EXISTS idx_presets_public ON public.presets(is_public);
CREATE INDEX IF NOT EXISTS idx_presets_rating ON public.presets(rating DESC);
CREATE INDEX IF NOT EXISTS idx_presets_downloads ON public.presets(downloads DESC);
CREATE INDEX IF NOT EXISTS idx_presets_created ON public.presets(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_presets_build_type ON public.presets(build_type);
CREATE INDEX IF NOT EXISTS idx_presets_ping_range ON public.presets(ping_range);
CREATE INDEX IF NOT EXISTS idx_preset_ratings_preset ON public.preset_ratings(preset_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON public.activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON public.activity_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON public.activity_logs(action);

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.presets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.preset_ratings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_config ENABLE ROW LEVEL SECURITY;

-- Drop existing policies
DROP POLICY IF EXISTS "Users can view their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Public profiles are viewable" ON public.profiles;
DROP POLICY IF EXISTS "Public presets are viewable" ON public.presets;
DROP POLICY IF EXISTS "Users can create presets" ON public.presets;
DROP POLICY IF EXISTS "Users can update their own presets" ON public.presets;
DROP POLICY IF EXISTS "Users can delete their own presets" ON public.presets;
DROP POLICY IF EXISTS "Ratings are viewable" ON public.preset_ratings;
DROP POLICY IF EXISTS "Users can create ratings" ON public.preset_ratings;
DROP POLICY IF EXISTS "Users can update their own ratings" ON public.preset_ratings;
DROP POLICY IF EXISTS "Users can view their own logs" ON public.activity_logs;
DROP POLICY IF EXISTS "Users can create logs" ON public.activity_logs;
DROP POLICY IF EXISTS "App config is publicly readable" ON public.app_config;
DROP POLICY IF EXISTS "Admins can update app config" ON public.app_config;

-- Profiles policies
CREATE POLICY "Users can view their own profile" ON public.profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update their own profile" ON public.profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Public profiles are viewable" ON public.profiles
    FOR SELECT USING (true);

-- Presets policies
CREATE POLICY "Public presets are viewable" ON public.presets
    FOR SELECT USING (is_public = true OR auth.uid() = user_id);

CREATE POLICY "Users can create presets" ON public.presets
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own presets" ON public.presets
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own presets" ON public.presets
    FOR DELETE USING (auth.uid() = user_id);

-- Ratings policies
CREATE POLICY "Ratings are viewable" ON public.preset_ratings
    FOR SELECT USING (true);

CREATE POLICY "Users can create ratings" ON public.preset_ratings
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own ratings" ON public.preset_ratings
    FOR UPDATE USING (auth.uid() = user_id);

-- Activity logs policies
CREATE POLICY "Users can view their own logs" ON public.activity_logs
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can create logs" ON public.activity_logs
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- App config policies
CREATE POLICY "App config is publicly readable" ON public.app_config
    FOR SELECT USING (true);

CREATE POLICY "Admins can update app config" ON public.app_config
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM public.profiles
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- ============================================
-- FUNCTIONS
-- ============================================

-- Enhanced function to handle new user registration
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    trial_days_config INTEGER;
BEGIN
    -- Get trial days from config
    SELECT COALESCE(value::INTEGER, 7) INTO trial_days_config
    FROM public.app_config
    WHERE key = 'trial_days';

    INSERT INTO public.profiles (
        id,
        email,
        nickname,
        display_name,
        role,
        trial_expiry,
        is_trial,
        device_id,
        app_version,
        registered_at
    ) VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'nickname', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'role', 'trial'),
        CURRENT_DATE + INTERVAL '1 day' * trial_days_config,
        true,
        NEW.raw_user_meta_data->>'device_id',
        NEW.raw_user_meta_data->>'app_version',
        NOW()
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger for new user registration
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Function to update preset rating
CREATE OR REPLACE FUNCTION public.update_preset_rating()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE public.presets
    SET 
        rating = (
            SELECT AVG(rating)::DECIMAL(3,2)
            FROM public.preset_ratings
            WHERE preset_id = COALESCE(NEW.preset_id, OLD.preset_id)
        ),
        rating_count = (
            SELECT COUNT(*)
            FROM public.preset_ratings
            WHERE preset_id = COALESCE(NEW.preset_id, OLD.preset_id)
        ),
        updated_at = NOW()
    WHERE id = COALESCE(NEW.preset_id, OLD.preset_id);
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Trigger for rating updates
DROP TRIGGER IF EXISTS update_preset_rating_trigger ON public.preset_ratings;
CREATE TRIGGER update_preset_rating_trigger
    AFTER INSERT OR UPDATE OR DELETE ON public.preset_ratings
    FOR EACH ROW EXECUTE FUNCTION public.update_preset_rating();

-- Function to increment preset downloads
CREATE OR REPLACE FUNCTION public.increment_preset_downloads(preset_uuid UUID)
RETURNS void AS $$
BEGIN
    UPDATE public.presets
    SET 
        downloads = downloads + 1,
        updated_at = NOW()
    WHERE id = preset_uuid;
    
    -- Update author's total downloads
    UPDATE public.profiles
    SET 
        total_downloads = total_downloads + 1,
        updated_at = NOW()
    WHERE id = (SELECT user_id FROM public.presets WHERE id = preset_uuid);
END;
$$ LANGUAGE plpgsql;

-- Enhanced function to get admin statistics
CREATE OR REPLACE FUNCTION public.get_admin_stats()
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'users_total', (SELECT COUNT(*) FROM public.profiles),
        'trials_total', (SELECT COUNT(*) FROM public.profiles WHERE role = 'trial'),
        'premium_total', (SELECT COUNT(*) FROM public.profiles WHERE role IN ('premium', 'admin')),
        'blocked_total', (SELECT COUNT(*) FROM public.profiles WHERE is_blocked = true),
        'presets_public', (SELECT COUNT(*) FROM public.presets WHERE is_public = true),
        'presets_private', (SELECT COUNT(*) FROM public.presets WHERE is_public = false),
        'downloads_total', (SELECT COALESCE(SUM(downloads), 0) FROM public.presets),
        'rating_avg', (SELECT COALESCE(AVG(rating), 0)::DECIMAL(3,2) FROM public.presets WHERE rating > 0),
        'rating_count', (SELECT COUNT(*) FROM public.preset_ratings),
        'activity_24h', (SELECT COUNT(*) FROM public.activity_logs WHERE timestamp > NOW() - INTERVAL '24 hours'),
        'activity_7d', (SELECT COUNT(*) FROM public.activity_logs WHERE timestamp > NOW() - INTERVAL '7 days'),
        'latest_version', (SELECT value FROM public.app_config WHERE key = 'latest_version'),
        'maintenance_mode', (SELECT value FROM public.app_config WHERE key = 'maintenance_mode'),
        'new_users_today', (SELECT COUNT(*) FROM public.profiles WHERE created_at > CURRENT_DATE),
        'new_users_week', (SELECT COUNT(*) FROM public.profiles WHERE created_at > CURRENT_DATE - INTERVAL '7 days'),
        'top_downloads', (
            SELECT COALESCE(json_agg(
                json_build_object(
                    'id', id,
                    'name', name,
                    'author', author_name,
                    'downloads', downloads,
                    'rating', rating,
                    'build_type', build_type
                ) ORDER BY downloads DESC
            ), '[]'::json)
            FROM (
                SELECT id, name, author_name, downloads, rating, build_type
                FROM public.presets
                WHERE is_public = true
                ORDER BY downloads DESC
                LIMIT 10
            ) t
        ),
        'top_rated', (
            SELECT COALESCE(json_agg(
                json_build_object(
                    'id', id,
                    'name', name,
                    'author', author_name,
                    'rating', rating,
                    'rating_count', rating_count
                ) ORDER BY rating DESC, rating_count DESC
            ), '[]'::json)
            FROM (
                SELECT id, name, author_name, rating, rating_count
                FROM public.presets
                WHERE is_public = true AND rating > 0
                ORDER BY rating DESC, rating_count DESC
                LIMIT 5
            ) t
        ),
        'recent_activities', (
            SELECT COALESCE(json_agg(
                json_build_object(
                    'user_id', user_id,
                    'action', action,
                    'details', details,
                    'timestamp', timestamp
                ) ORDER BY timestamp DESC
            ), '[]'::json)
            FROM (
                SELECT user_id, action, details, timestamp
                FROM public.activity_logs
                ORDER BY timestamp DESC
                LIMIT 20
            ) t
        )
    ) INTO result;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check if user is admin
CREATE OR REPLACE FUNCTION public.is_admin(user_uuid UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = user_uuid AND role = 'admin'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Enhanced function to toggle user block
CREATE OR REPLACE FUNCTION public.toggle_user_block(
    target_user_id UUID,
    admin_user_id UUID,
    block_status BOOLEAN,
    block_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN AS $$
BEGIN
    -- Check if admin
    IF NOT public.is_admin(admin_user_id) THEN
        RAISE EXCEPTION 'Unauthorized: Admin access required';
    END IF;
    
    -- Update user block status
    UPDATE public.profiles
    SET 
        is_blocked = block_status,
        block_reason = CASE WHEN block_status THEN block_reason ELSE NULL END,
        blocked_at = CASE WHEN block_status THEN NOW() ELSE NULL END,
        blocked_by = CASE WHEN block_status THEN admin_user_id ELSE NULL END,
        updated_at = NOW()
    WHERE id = target_user_id;
    
    -- Log block action
    IF block_status THEN
        INSERT INTO public.user_blocks (user_id, blocked_by, reason, block_type)
        VALUES (target_user_id, admin_user_id, block_reason, 'temporary');
        
        INSERT INTO public.activity_logs (user_id, action, details, metadata)
        VALUES (admin_user_id, 'user_blocked', 
                'Blocked user: ' || target_user_id, 
                jsonb_build_object('target_user', target_user_id, 'reason', block_reason));
    ELSE
        INSERT INTO public.activity_logs (user_id, action, details, metadata)
        VALUES (admin_user_id, 'user_unblocked', 
                'Unblocked user: ' || target_user_id,
                jsonb_build_object('target_user', target_user_id));
    END IF;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to clean old activity logs
CREATE OR REPLACE FUNCTION public.clean_old_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM public.activity_logs
    WHERE timestamp < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Function to check maintenance mode
CREATE OR REPLACE FUNCTION public.check_maintenance_mode()
RETURNS BOOLEAN AS $$
DECLARE
    maintenance_status TEXT;
BEGIN
    SELECT value INTO maintenance_status
    FROM public.app_config
    WHERE key = 'maintenance_mode';
    
    RETURN maintenance_status = 'true';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get user preset count
CREATE OR REPLACE FUNCTION public.get_user_preset_count(user_uuid UUID)
RETURNS INTEGER AS $$
BEGIN
    RETURN (
        SELECT COUNT(*)
        FROM public.presets
        WHERE user_id = user_uuid
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check preset limit
CREATE OR REPLACE FUNCTION public.check_preset_limit(user_uuid UUID)
RETURNS BOOLEAN AS $$
DECLARE
    user_role TEXT;
    preset_count INTEGER;
    max_presets INTEGER;
BEGIN
    -- Get user role
    SELECT role INTO user_role
    FROM public.profiles
    WHERE id = user_uuid;
    
    -- Get current preset count
    SELECT COUNT(*) INTO preset_count
    FROM public.presets
    WHERE user_id = user_uuid;
    
    -- Get max presets based on role
    IF user_role = 'trial' THEN
        SELECT value::INTEGER INTO max_presets
        FROM public.app_config
        WHERE key = 'max_presets_trial';
    ELSE
        SELECT value::INTEGER INTO max_presets
        FROM public.app_config
        WHERE key = 'max_presets_premium';
    END IF;
    
    RETURN preset_count < COALESCE(max_presets, 100);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Update timestamps function
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add update triggers
DROP TRIGGER IF EXISTS update_profiles_updated_at ON public.profiles;
CREATE TRIGGER update_profiles_updated_at 
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

DROP TRIGGER IF EXISTS update_presets_updated_at ON public.presets;
CREATE TRIGGER update_presets_updated_at 
    BEFORE UPDATE ON public.presets
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

DROP TRIGGER IF EXISTS update_preset_ratings_updated_at ON public.preset_ratings;
CREATE TRIGGER update_preset_ratings_updated_at 
    BEFORE UPDATE ON public.preset_ratings
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

DROP TRIGGER IF EXISTS update_app_config_updated_at ON public.app_config;
CREATE TRIGGER update_app_config_updated_at 
    BEFORE UPDATE ON public.app_config
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- ============================================
-- VIEWS FOR EASIER DATA ACCESS
-- ============================================

-- View for active users
CREATE OR REPLACE VIEW public.active_users AS
SELECT 
    id,
    nickname,
    email,
    role,
    last_login,
    total_downloads,
    total_uploads,
    reputation_score
FROM public.profiles
WHERE is_blocked = false;

-- View for popular presets
CREATE OR REPLACE VIEW public.popular_presets AS
SELECT 
    p.id,
    p.name,
    p.author_name,
    p.build_type,
    p.ping_range,
    p.downloads,
    p.rating,
    p.rating_count,
    p.created_at
FROM public.presets p
WHERE p.is_public = true
    AND p.rating >= 4.0
ORDER BY p.downloads DESC, p.rating DESC;

-- ============================================
-- INITIAL ADMIN SETUP
-- ============================================
-- After creating your first user account, run this command to make it admin:
-- UPDATE public.profiles SET role = 'admin' WHERE email = 'your-admin-email@example.com';

-- ============================================
-- SCHEDULED JOBS (Run these periodically)
-- ============================================
-- Clean old logs (run daily):
-- SELECT public.clean_old_logs();

-- Update trial expired users (run daily):
-- UPDATE public.profiles 
-- SET role = 'expired', is_trial = false 
-- WHERE trial_expiry < CURRENT_DATE AND role = 'trial';
