-- ==========================================================
-- Inicialización SEGURA de la base de datos sofias_demo
-- SOFÍA - Sociedad de Fomento a la Industria Automotriz
-- Base de datos SEGURA para producción
-- ==========================================================

-- -------------------------
-- TABLA: users
-- -------------------------
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- Contraseñas hasheadas
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    nit VARCHAR(20),
    ci VARCHAR(15),
    phone VARCHAR(15),
    address TEXT,
    role VARCHAR(20) DEFAULT 'user',
    active BOOLEAN DEFAULT TRUE,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_role CHECK (role IN ('admin', 'user', 'auditor', 'guest')),
    CONSTRAINT chk_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- -------------------------
-- TABLA: taxpayers
-- -------------------------
CREATE TABLE IF NOT EXISTS taxpayers (
    id SERIAL PRIMARY KEY,
    nit VARCHAR(20) UNIQUE NOT NULL,
    business_name VARCHAR(200) NOT NULL,
    legal_rep VARCHAR(100) NOT NULL,
    activity VARCHAR(100) NOT NULL,
    address TEXT NOT NULL,
    phone VARCHAR(15),
    email VARCHAR(100) NOT NULL,
    tax_category VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    CONSTRAINT chk_nit CHECK (LENGTH(nit) >= 10),
    CONSTRAINT chk_tax_category CHECK (tax_category IN ('Gran Contribuyente', 'Régimen General', 'Régimen Simplificado'))
);

-- -------------------------
-- TABLA: tax_declarations
-- -------------------------
CREATE TABLE IF NOT EXISTS tax_declarations (
    id SERIAL PRIMARY KEY,
    taxpayer_id INTEGER NOT NULL REFERENCES taxpayers(id) ON DELETE RESTRICT,
    period VARCHAR(7) NOT NULL, -- YYYY-MM
    gross_income DECIMAL(15,2) NOT NULL CHECK (gross_income >= 0),
    deductions DECIMAL(15,2) NOT NULL CHECK (deductions >= 0),
    tax_amount DECIMAL(15,2) NOT NULL CHECK (tax_amount >= 0),
    status VARCHAR(20) DEFAULT 'pending',
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    approved_by INTEGER REFERENCES users(id),
    CONSTRAINT chk_status CHECK (status IN ('pending', 'approved', 'rejected', 'under_review')),
    CONSTRAINT chk_period CHECK (period ~ '^\d{4}-(0[1-9]|1[0-2])$'),
    CONSTRAINT unique_taxpayer_period UNIQUE (taxpayer_id, period)
);

-- -------------------------
-- TABLA: vehicles
-- -------------------------
CREATE TABLE IF NOT EXISTS vehicles (
    id SERIAL PRIMARY KEY,
    taxpayer_id INTEGER NOT NULL REFERENCES taxpayers(id) ON DELETE RESTRICT,
    vin VARCHAR(17) UNIQUE NOT NULL,
    brand VARCHAR(50) NOT NULL,
    model VARCHAR(50) NOT NULL,
    year INTEGER NOT NULL,
    color VARCHAR(30) NOT NULL,
    license_plate VARCHAR(15) UNIQUE NOT NULL,
    engine_number VARCHAR(50) NOT NULL,
    chassis_number VARCHAR(50) NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    registered_by INTEGER REFERENCES users(id),
    CONSTRAINT chk_vin CHECK (LENGTH(vin) = 17 AND vin ~ '^[A-HJ-NPR-Z0-9]{17}$'),
    CONSTRAINT chk_year CHECK (year BETWEEN 1900 AND EXTRACT(YEAR FROM CURRENT_DATE) + 1),
    CONSTRAINT chk_license_plate CHECK (license_plate ~ '^\d{4}-[A-Z]{3}$')
);

-- -------------------------
-- TABLA: system_logs
-- -------------------------
CREATE TABLE IF NOT EXISTS system_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'success',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_log_action CHECK (action IN ('login', 'logout', 'create', 'update', 'delete', 'view', 'failed_login')),
    CONSTRAINT chk_log_status CHECK (status IN ('success', 'failed', 'warning'))
);

-- -------------------------
-- VISTAS
-- -------------------------
CREATE OR REPLACE VIEW user_taxpayer_view AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.full_name,
    u.nit,
    u.phone,
    u.role,
    u.active,
    t.business_name,
    t.activity,
    t.tax_category
FROM users u
LEFT JOIN taxpayers t ON u.nit = t.nit
WHERE u.active = TRUE;

-- -------------------------
-- ÍNDICES
-- -------------------------
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(active);
CREATE INDEX idx_taxpayers_nit ON taxpayers(nit);
CREATE INDEX idx_vehicles_vin ON vehicles(vin);
CREATE INDEX idx_vehicles_license ON vehicles(license_plate);
CREATE INDEX idx_tax_declarations_period ON tax_declarations(period);
CREATE INDEX idx_tax_declarations_status ON tax_declarations(status);
CREATE INDEX idx_system_logs_user ON system_logs(user_id);
CREATE INDEX idx_system_logs_created ON system_logs(created_at);

-- -------------------------
-- TRIGGERS: updated_at automático
-- -------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_taxpayers_updated_at BEFORE UPDATE ON taxpayers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- -------------------------
-- FUNCIONES: login fallido
-- -------------------------
CREATE OR REPLACE FUNCTION log_failed_login(username_param VARCHAR, ip_param VARCHAR)
RETURNS VOID AS $$
BEGIN
    INSERT INTO system_logs (user_id, action, resource, ip_address, status)
    SELECT id, 'failed_login', 'users', ip_param, 'failed'
    FROM users WHERE username = username_param;
END;
$$ LANGUAGE plpgsql;

-- -------------------------
-- FINAL
-- -------------------------
SELECT 'Base de datos SOFÍA SEGURA inicializada correctamente' AS status;
