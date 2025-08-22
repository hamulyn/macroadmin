-- ============================================
-- BLADE & SOUL MACRO - SUPABASE DATABASE SCHEMA
-- Version: 6.0.0
-- ============================================

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- USERS PROFILE TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS public.profiles (
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
-- PRESETS TABLE (Shared Configurations)
-- ============================================
CREATE TABLE IF NOT EXISTS public.presets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    build_type VARCHAR(20) DEFAULT 'both' CHECK (build_type IN ('puncture', 'hybrid', 'both')),
    ping_range VARCHAR(50) DEFAULT '0-50ms',
    is_public BOOLEAN DEFAULT false,
    settings JSONB NOT NULL, -- Stores only sleeps and loops
    author_name VARCHAR(100),
    version VARCHAR(20),
    downloads INTEGER DEFAULT 0,
    rating DECIMAL(3,2) DEFAULT 0,
    rating_count INTEGER DEFAULT 0,
    tags TEXT[] DEFAULT '{}',
    youtube_url TEXT,
    discord_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_user_preset_name UNIQUE(user_id, name)
);

-- ============================================
-- PRESET RATINGS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS public.preset_ratings (
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
CREATE TABLE IF NOT EXISTS public.user_blocks (
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
CREATE TABLE IF NOT EXISTS public.activity_logs (
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
-- APP CONFIG TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS public.app_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES auth.users(id)
);

-- Insert default app config
INSERT INTO public.app_config (key, value, description) VALUES
    ('latest_version', '6.0.0', 'Latest application version'),
    ('maintenance_mode', 'false', 'Enable maintenance mode'),
    ('announcement', '', 'Global announcement message'),
    ('trial_days', '7', 'Default trial period in days'),
    ('max_presets_trial', '3', 'Maximum presets for trial users'),
    ('max_presets_premium', '100', 'Maximum presets for premium users')
ON CONFLICT (key) DO NOTHING;

-- ============================================
-- INDEXES
-- ============================================
CREATE INDEX IF NOT EXISTS idx_profiles_nickname ON public.profiles(nickname);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_presets_user_id ON public.presets(user_id);
CREATE INDEX IF NOT EXISTS idx_presets_public ON public.presets(is_public);
CREATE INDEX IF NOT EXISTS idx_presets_rating ON public.presets(rating DESC);
CREATE INDEX IF NOT EXISTS idx_presets_downloads ON public.presets(downloads DESC);
CREATE INDEX IF NOT EXISTS idx_presets_created ON public.presets(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_preset_ratings_preset ON public.preset_ratings(preset_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON public.activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON public.activity_logs(timestamp DESC);

-- ============================================
-- ROW LEVEL SECURITY
-- ============================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.presets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.preset_ratings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_config ENABLE ROW LEVEL SECURITY;

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

-- ============================================
-- FUNCTIONS
-- ============================================

-- Function to handle new user registration
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (
        id,
        email,
        nickname,
        display_name,
        role,
        trial_expiry,
        is_trial,
        device_id,
        app_version
    ) VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'nickname', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'role', 'trial'),
        CURRENT_DATE + INTERVAL '7 days',
        true,
        NEW.raw_user_meta_data->>'device_id',
        NEW.raw_user_meta_data->>'app_version'
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
        )
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
    SET downloads = downloads + 1
    WHERE id = preset_uuid;
    
    -- Update author's total downloads
    UPDATE public.profiles
    SET total_downloads = total_downloads + 1
    WHERE id = (SELECT user_id FROM public.presets WHERE id = preset_uuid);
END;
$$ LANGUAGE plpgsql;

-- Function to get admin statistics
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
        'latest_version', (SELECT value FROM public.app_config WHERE key = 'latest_version'),
        'top_downloads', (
            SELECT COALESCE(json_agg(
                json_build_object(
                    'id', id,
                    'name', name,
                    'author', author_name,
                    'downloads', downloads,
                    'rating', rating
                ) ORDER BY downloads DESC
            ), '[]'::json)
            FROM (
                SELECT id, name, author_name, downloads, rating
                FROM public.presets
                WHERE is_public = true
                ORDER BY downloads DESC
                LIMIT 5
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

-- Function to block/unblock user
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
        blocked_by = CASE WHEN block_status THEN admin_user_id ELSE NULL END
    WHERE id = target_user_id;
    
    -- Log block action
    IF block_status THEN
        INSERT INTO public.user_blocks (user_id, blocked_by, reason)
        VALUES (target_user_id, admin_user_id, block_reason);
    END IF;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to clean old activity logs
CREATE OR REPLACE FUNCTION public.clean_old_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM public.activity_logs
    WHERE timestamp < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Update timestamps function
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add update triggers
CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_presets_updated_at BEFORE UPDATE ON public.presets
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_preset_ratings_updated_at BEFORE UPDATE ON public.preset_ratings
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- ============================================
-- INITIAL ADMIN USER (Update after first login)
-- ============================================
-- After creating your first user, run this to make them admin:
-- UPDATE public.profiles SET role = 'admin' WHERE email = 'your-email@example.com';
