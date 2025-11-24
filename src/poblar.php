<?php
$host = 'sofia_db_seguro';
$dbname = 'sofias_demo';
$user = 'admin';
$pass = 'admin';
$port = '5432';

try {
    $db = new PDO("pgsql:host=$host;port=$port;dbname=$dbname", $user, $pass);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "🔗 Conectado a la base de datos '$dbname'.\n";
} catch (PDOException $e) {
    echo "❌ ERROR: " . $e->getMessage() . "\n";
    exit(1);
}

echo "=== 🚀 Iniciando carga de datos en PostgreSQL... ===\n";

try {
    // ---- GENERAR HASHES ----
    $hash_admin   = password_hash("Admin@2024!", PASSWORD_BCRYPT);
    $hash_demo    = password_hash("Demo@2024!", PASSWORD_BCRYPT);
    $hash_juan    = password_hash("JuanP@2024!", PASSWORD_BCRYPT);
    $hash_auditor = password_hash("Audit@2024!", PASSWORD_BCRYPT);

    // ---- INSERTAR USUARIOS ----
    $sql_users = "
    INSERT INTO users (username, password, email, full_name, nit, ci, role) VALUES
    ('admin', :admin, 'admin@sofia.com.bo', 'Administrador SOFÍA', '1020304050', '12345678', 'admin'),
    ('demo', :demo, 'demo@sofia.com.bo', 'Usuario Demostración', '2030405060', '23456789', 'user'),
    ('juan.perez', :juan, 'juan.perez@sofia.com.bo', 'Juan Carlos Pérez Mamani', '3040506070', '34567890', 'user'),
    ('auditor', :auditor, 'auditor@sofia.com.bo', 'Auditor Sistemas', '5060708090', '56789012', 'auditor');
    ";
    $stmt = $db->prepare($sql_users);
    $stmt->execute([
        ':admin'   => $hash_admin,
        ':demo'    => $hash_demo,
        ':juan'    => $hash_juan,
        ':auditor' => $hash_auditor
    ]);
    echo "✅ Usuarios insertados correctamente.\n";

    // ---- INSERTAR EMPRESAS ----
    $db->exec("
        INSERT INTO taxpayers (nit, business_name, legal_rep, activity, address, phone, email, tax_category, created_by) VALUES
        ('10234567890', 'Importadora Automotriz Bolivia S.A.', 'María Elena Quispe Condori', 'Importación de Vehículos', 'Av. Blanco Galindo Km 4, Cochabamba', '4-4123456', 'ventas@importadora.bo', 'Gran Contribuyente', 1),
        ('20345678901', 'Concesionaria Premium Motors LTDA', 'Carlos Alberto Mamani Ticona', 'Venta de Vehículos Nuevos', 'Av. Cristo Redentor 1234, Santa Cruz', '3-3234567', 'contacto@premiummotors.bo', 'Régimen General', 1),
        ('30456789012', 'Taller Mecánico El Experto SRL', 'Ana Lucía Condori Flores', 'Servicio Técnico Automotriz', 'Calle México 567, La Paz', '2-2345678', 'taller@elexperto.bo', 'Régimen Simplificado', 1),
        ('40567890123', 'Repuestos Originales S.A.', 'Roberto Ticona Apaza', 'Venta de Repuestos', 'Zona Industrial, El Alto', '2-2456789', 'ventas@repuestos.bo', 'Régimen General', 1),
        ('50678901234', 'Lubricantes y Servicios Express EIRL', 'Patricia Mamani Cruz', 'Cambio de Aceite y Lubricación', 'Av. Petrolera Km 3, Santa Cruz', '3-3567890', 'express@lubricantes.bo', 'Régimen Simplificado', 1);
    ");
    echo "✅ Empresas insertadas.\n";

    // ---- INSERTAR DECLARACIONES FISCALES ----
    $db->exec("
        INSERT INTO tax_declarations (taxpayer_id, period, gross_income, deductions, tax_amount, status, approved_by) VALUES
        (1, '2024-01', 2850000.50, 285000.00, 427500.00, 'approved', 1),
        (1, '2024-02', 3120000.25, 312000.00, 468000.50, 'approved', 1),
        (2, '2024-01', 1450000.00, 145000.00, 217500.00, 'pending', NULL),
        (2, '2024-02', 1620000.75, 162000.00, 243000.15, 'approved', 1),
        (3, '2024-01', 450000.80, 45000.00, 67500.45, 'approved', 1),
        (3, '2024-02', 480000.40, 48000.00, 72000.25, 'under_review', NULL),
        (4, '2024-01', 980000.60, 98000.00, 147000.30, 'approved', 1),
        (4, '2024-02', 1050000.90, 105000.00, 157500.55, 'pending', NULL),
        (5, '2024-01', 320000.50, 32000.00, 48000.25, 'approved', 1),
        (5, '2024-02', 380000.75, 38000.00, 57000.40, 'approved', 1);
    ");
    echo "✅ Declaraciones fiscales insertadas.\n";

    // ---- INSERTAR VEHÍCULOS ----
    $db->exec("
        INSERT INTO vehicles (taxpayer_id, vin, brand, model, year, color, license_plate, engine_number, chassis_number, registered_by) VALUES
        (1, '1HGBH41JXMN109186', 'Toyota', 'Land Cruiser Prado', 2024, 'Blanco', '1234-ABC', 'LC-4521-2024', 'JT-8745-2024', 1),
        (1, '2FMDK3GC2BBB12345', 'Nissan', 'X-Trail', 2024, 'Gris', '2345-BCD', 'NS-7845-2024', 'NI-5632-2024', 1),
        (2, '3GNDA13D76S123456', 'Chevrolet', 'Tracker', 2023, 'Rojo', '3456-CDE', 'CH-4521-2023', 'GM-8965-2023', 1),
        (2, '4T1BF1FK8CU123456', 'Hyundai', 'Tucson', 2024, 'Negro', '4567-DEF', 'HY-7412-2024', 'HM-6523-2024', 1),
        (3, '5FNRL5H40BB123456', 'Honda', 'CR-V', 2023, 'Azul', '5678-EFG', 'HD-8523-2023', 'HN-9874-2023', 1),
        (4, '1G1ZD5ST8BF123456', 'Mazda', 'CX-5', 2024, 'Plata', '6789-FGH', 'MZ-7412-2024', 'MA-5632-2024', 1),
        (5, 'WBADT43452G123456', 'Suzuki', 'Vitara', 2023, 'Verde', '7890-GHI', 'SZ-4785-2023', 'SU-8521-2023', 1);
    ");
    echo "✅ Vehículos insertados.\n";

    // ---- CREAR LOGS ----
    $db->exec("
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
    ");
    echo "📄 Tabla system_logs verificada.\n";

    // ---- INSERTAR LOGS ----
    $db->exec("
        INSERT INTO system_logs (user_id, action, resource, ip_address, user_agent, status) VALUES
        (1, 'login', 'users', '192.168.1.100', 'Mozilla/5.0 Chrome', 'success'),
        (2, 'view', 'vehicles', '10.0.0.5', 'Mozilla/5.0 Firefox', 'success'),
        (NULL, 'failed_login', 'users', '192.168.1.200', 'BadBot/1.0', 'failed'),
        (1, 'create', 'vehicles', '172.18.0.1', 'Docker Container', 'success'),
        (2, 'view', 'tax_declarations', '192.168.1.105', 'Mozilla/5.0 Safari', 'success');
    ");
    echo "✅ Logs insertados.\n";

    echo "\n🎉 PROCESO COMPLETADO SIN ERRORES 🎉\n";

} catch (Exception $e) {
    echo "❌ ERROR: " . $e->getMessage() . "\n";
    exit(1);
}
