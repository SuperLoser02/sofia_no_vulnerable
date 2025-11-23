<?php
// ARCHIVO VULNERABLE PARA AUDITORIA - NUNCA usar en producción
// ============================================================
// SOFÍA - Sociedad de Fomento a la Industria Automotriz
// Sistema de Información Vulnerable

// VULNERABILIDAD: no verificar autenticación
session_start();

// VULNERABILIDAD: información del sistema expuesta públicamente
echo "<h1>Información del Sistema - SOFÍA</h1>";
echo "<p><strong>Sociedad de Fomento a la Industria Automotriz</strong></p>";

// VULNERABILIDAD: phpinfo completo expuesto
if (isset($_GET['phpinfo'])) {
    phpinfo();
    exit();
}

// VULNERABILIDAD: variables del sistema expuestas
echo "<h2>Variables del Sistema SOFÍA</h2>";
echo "<pre>";
echo "Sistema: SOFÍA - Gestión Automotriz\n";
echo "PHP Version: " . PHP_VERSION . "\n";
echo "Server Software: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
echo "Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "\n";
echo "Server Admin: " . ($_SERVER['SERVER_ADMIN'] ?? 'No definido') . "\n";
echo "Database Host: db (PostgreSQL)\n";
echo "Database Name: sofias_demo\n";
echo "Database User: admin\n";
echo "Database Password: admin\n";
echo "Módulos: Empresas Automotrices, Vehículos, Declaraciones Fiscales\n";
echo "</pre>";

// VULNERABILIDAD: mostrar variables de entorno
echo "<h2>Variables de Entorno (peligrosas)</h2>";
echo "<pre>";
foreach ($_ENV as $key => $value) {
    if (strpos(strtolower($key), 'pass') !== false || 
        strpos(strtolower($key), 'key') !== false || 
        strpos(strtolower($key), 'secret') !== false ||
        strpos(strtolower($key), 'db') !== false) {
        echo "$key = $value\n";
    }
}
echo "</pre>";

// VULNERABILIDAD: mostrar archivos del sistema
echo "<h2>Estructura de Archivos</h2>";
if (isset($_GET['dir'])) {
    $dir = $_GET['dir'];
    echo "<h3>Contenido de: $dir</h3>";
    echo "<pre>";
    $files = scandir($dir);
    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        $type = is_dir($path) ? '[DIR]' : '[FILE]';
        $size = is_file($path) ? filesize($path) : 0;
        echo "$type $file ($size bytes)\n";
    }
    echo "</pre>";
}

// VULNERABILIDAD: SQL directo sin autenticación
if (isset($_GET['sql'])) {
    require_once 'config/database.php';
    $database = new Database();
    $db = $database->getConnection();
    
    echo "<h2>Ejecutor SQL Directo - SOFÍA</h2>";
    echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid red;'>";
    echo "<strong>PELIGRO:</strong> Ejecutando SQL sin validación en base de datos SOFÍA<br>";
    echo "Query: " . htmlspecialchars($_GET['sql']) . "<br>";
    
    try {
        $result = $db->query($_GET['sql']);
        if ($result) {
            echo "<table border='1' style='border-collapse: collapse; margin-top: 10px;'>";
            $first = true;
            while ($row = $result->fetch(PDO::FETCH_ASSOC)) {
                if ($first) {
                    echo "<tr>";
                    foreach (array_keys($row) as $column) {
                        echo "<th style='padding: 5px; background: #f0f0f0;'>$column</th>";
                    }
                    echo "</tr>";
                    $first = false;
                }
                echo "<tr>";
                foreach ($row as $value) {
                    echo "<td style='padding: 5px;'>" . htmlspecialchars($value) . "</td>";
                }
                echo "</tr>";
            }
            echo "</table>";
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
    echo "</div>";
}

// VULNERABILIDAD: mostrar logs del sistema
if (isset($_GET['logs'])) {
    echo "<h2>Logs del Sistema SOFÍA</h2>";
    $log_files = [
        '/var/log/apache2/error.log',
        '/var/log/apache2/access.log',
        'error.log',
        '../error.log'
    ];
    
    foreach ($log_files as $log_file) {
        if (file_exists($log_file)) {
            echo "<h3>$log_file</h3>";
            echo "<pre>" . htmlspecialchars(tail($log_file, 20)) . "</pre>";
        }
    }
}

function tail($file, $lines = 10) {
    $handle = fopen($file, "r");
    if (!$handle) return "";
    
    $linecounter = $lines;
    $pos = -2;
    $beginning = false;
    $text = array();
    
    while ($linecounter > 0) {
        $t = " ";
        while ($t != "\n") {
            if (fseek($handle, $pos, SEEK_END) == -1) {
                $beginning = true;
                break;
            }
            $t = fgetc($handle);
            $pos--;
        }
        $linecounter--;
        if ($beginning) {
            rewind($handle);
        }
        $text[$lines-$linecounter-1] = fgets($handle);
        if ($beginning) break;
    }
    fclose($handle);
    return array_reverse($text);
}

// VULNERABILIDAD: formulario de test sin validación
?>
<!DOCTYPE html>
<html>
<head>
    <title>Sistema de Información SOFÍA - Vulnerable</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #1976d2; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .danger { background: #ffebee; border: 1px solid #f44336; padding: 10px; margin: 10px 0; }
        .form { background: #e3f2fd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        input, textarea { width: 100%; padding: 5px; margin: 5px 0; box-sizing: border-box; }
        button { background: #f44336; color: white; padding: 10px; border: none; cursor: pointer; }
        button:hover { background: #d32f2f; }
        .success { background: #c8e6c9; border: 1px solid #4caf50; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>

<div class="header">
    <h1>🚗 SOFÍA - Sistema de Información</h1>
    <p>Sociedad de Fomento a la Industria Automotriz</p>
</div>

<div class="danger">
    <h2>⚠️ SISTEMA VULNERABLE PARA AUDITORÍA ⚠️</h2>
    <p>Este archivo contiene múltiples vulnerabilidades intencionadas para demostración y aprendizaje.</p>
    <p><strong>Módulos:</strong> Gestión de Empresas Automotrices, Registro de Vehículos, Declaraciones Fiscales</p>
</div>

<div class="form">
    <h3>Panel de Pruebas de Vulnerabilidades SOFÍA</h3>
    
    <h4>1. Information Disclosure</h4>
    <a href="?phpinfo=1">Ver PHPInfo completo</a><br>
    <a href="?dir=.">Listar archivos directorio actual</a><br>
    <a href="?dir=..">Listar archivos directorio padre</a><br>
    <a href="?dir=/var/www/html">Listar archivos web root</a><br>
    <a href="?logs=1">Ver logs del sistema</a><br>
    
    <h4>2. Local File Inclusion</h4>
    <form method="GET">
        <input type="text" name="file" placeholder="Ruta del archivo (ej: /etc/passwd, config/database.php)" value="<?php echo htmlspecialchars($_GET['file'] ?? ''); ?>">
        <button type="submit">Leer Archivo</button>
    </form>
    
    <h4>3. Command Injection</h4>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Comando del sistema (ej: ls -la, cat /etc/passwd)" value="<?php echo htmlspecialchars($_GET['cmd'] ?? ''); ?>">
        <button type="submit">Ejecutar Comando</button>
    </form>
    
    <h4>4. SQL Injection Directo</h4>
    <form method="GET">
        <textarea name="sql" rows="3" placeholder="SELECT * FROM users; SELECT * FROM vehicles; etc."><?php echo htmlspecialchars($_GET['sql'] ?? ''); ?></textarea>
        <button type="submit">Ejecutar Query SQL</button>
    </form>
    <small style="color: #666;">Ejemplos: <code>SELECT * FROM users</code>, <code>SELECT * FROM vehicles</code>, <code>SELECT * FROM taxpayers</code></small>
    
    <h4>5. Logs del Sistema SOFÍA</h4>
    <form method="GET">
        <input type="hidden" name="show_logs" value="1">
        <button type="submit">Ver Logs del Sistema</button>
    </form>
    
    <h4>6. Debug del Sistema</h4>
    <form method="GET">
        <input type="hidden" name="debug_system" value="1">
        <button type="submit">Mostrar Debug Completo</button>
    </form>
</div>

<?php if (isset($_GET['show_logs'])): ?>
<div class="form">
    <h3>📋 Logs del Sistema SOFÍA</h3>
    <div style='background: #ffcdd2; padding: 15px; border: 1px solid #f44336; margin: 10px 0;'>
        <strong>⚠️ VULNERABILIDAD CRÍTICA:</strong> Logs del sistema SOFÍA expuestos sin autenticación.
    </div>
    
    <h4>📊 Estadísticas de Acceso</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
Sistema: SOFÍA - Sociedad de Fomento a la Industria Automotriz
Servidor Web: <?php echo $_SERVER['SERVER_SOFTWARE']; ?>
Tiempo actual: <?php echo date('Y-m-d H:i:s'); ?>
IP del cliente: <?php echo $_SERVER['REMOTE_ADDR']; ?>
User Agent: <?php echo $_SERVER['HTTP_USER_AGENT']; ?>
Método HTTP: <?php echo $_SERVER['REQUEST_METHOD']; ?>
Base de Datos: sofias_demo (PostgreSQL)
    </pre>
    
    <h4>🔐 Intentos de Login SOFÍA (Simulados)</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
2025-11-23 14:25:33 - LOGIN SUCCESS - User: admin - Módulo: Panel Admin SOFÍA - IP: 192.168.1.100
2025-11-23 14:24:15 - LOGIN FAILED - User: admin - Password: admin123 - IP: 192.168.1.200
2025-11-23 14:23:45 - LOGIN FAILED - User: root - Password: root - IP: 10.0.0.5
2025-11-23 14:22:10 - LOGIN SUCCESS - User: auditor - Módulo: Gestión Vehículos - IP: 192.168.1.150
2025-11-23 14:20:55 - SQL INJECTION ATTEMPT - Query: ' OR 1=1-- - Tabla: users - IP: 192.168.1.200
2025-11-23 14:18:30 - VEHICLE REGISTERED - VIN: 1HGBH41JXMN109186 - User: demo - IP: 192.168.1.105
2025-11-23 14:15:10 - TAX DECLARATION - Taxpayer: Importadora Automotriz Bolivia S.A. - Amount: 427500.00 Bs
    </pre>
    
    <h4>💾 Actividad de Base de Datos SOFÍA</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
SELECT * FROM users WHERE username = 'admin' AND password = 'admin123'
UPDATE users SET last_login = NOW() WHERE id = 1
SELECT COUNT(*) FROM taxpayers WHERE tax_category = 'Gran Contribuyente'
SELECT * FROM vehicles WHERE brand = 'Toyota' ORDER BY registered_at DESC
SELECT SUM(tax_amount) FROM tax_declarations WHERE period = '2024-02'
INSERT INTO vehicles (vin, brand, model) VALUES ('1HGBH41JXMN109186', 'Toyota', 'Land Cruiser')
SELECT t.business_name, COUNT(v.id) FROM taxpayers t LEFT JOIN vehicles v ON t.id = v.taxpayer_id GROUP BY t.id
    </pre>
    
    <h4>🚗 Actividad de Módulos SOFÍA</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
[EMPRESAS] Nuevo registro: Importadora Automotriz Bolivia S.A. - NIT: 10234567890
[VEHÍCULOS] Registro VIN: 1HGBH41JXMN109186 - Toyota Land Cruiser Prado 2024
[DECLARACIONES] Nueva declaración fiscal: Periodo 2024-02 - Monto: 427500.00 Bs
[USUARIOS] Nuevo usuario: juan.perez - Rol: user - Email: juan.perez@sofia.com.bo
[REPORTES] Generación de reporte mensual - Periodo: 2024-02 - Usuario: admin
    </pre>
</div>
<?php endif; ?>

<?php if (isset($_GET['debug_system'])): ?>
<div class="form">
    <h3>🔍 DEBUG - Estado del Sistema SOFÍA</h3>
    
    <h4>Información del Sistema:</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
Sistema: SOFÍA - Sociedad de Fomento a la Industria Automotriz
Versión: 1.0 (Vulnerable para Auditoría)
Base de Datos: sofias_demo
Motor: PostgreSQL 15
Usuario DB: admin
Password DB: admin
Host DB: db (Docker Container)
    </pre>
    
    <h4>Estado de la Sesión:</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
<?php 
session_start();
print_r($_SESSION ?? ['status' => 'No hay sesión activa']);
?>
    </pre>
    
    <h4>Prueba de Conexión DB:</h4>
    <?php
    try {
        require_once 'config/database.php';
        $database = new Database();
        $db = $database->getConnection();
        
        if ($db) {
            echo "<div class='success'>";
            echo "✅ Conexión DB SOFÍA: OK<br>";
            
            $result = $db->query("SELECT COUNT(*) as count FROM users");
            $count = $result->fetch(PDO::FETCH_ASSOC);
            echo "👤 Usuarios en DB: " . $count['count'] . "<br>";
            
            $result = $db->query("SELECT COUNT(*) as count FROM taxpayers");
            $count = $result->fetch(PDO::FETCH_ASSOC);
            echo "🏢 Empresas Automotrices en DB: " . $count['count'] . "<br>";
            
            $result = $db->query("SELECT COUNT(*) as count FROM vehicles");
            $count = $result->fetch(PDO::FETCH_ASSOC);
            echo "🚗 Vehículos Registrados en DB: " . $count['count'] . "<br>";
            
            $result = $db->query("SELECT COUNT(*) as count FROM tax_declarations");
            $count = $result->fetch(PDO::FETCH_ASSOC);
            echo "📊 Declaraciones Fiscales en DB: " . $count['count'] . "<br>";
            
            echo "</div>";
        } else {
            echo "<div class='danger'>❌ Conexión DB: FALLO</div>";
        }
    } catch (Exception $e) {
        echo "<div class='danger'>❌ Error DB: " . $e->getMessage() . "</div>";
    }
    ?>
    
    <h4>Archivos del Sistema:</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
<?php
    $files = ['config/database.php', 'inicio.php', 'login.php', 'index.php', 'logout.php', 'info.php'];
    foreach ($files as $file) {
        if (file_exists($file)) {
            echo "✅ $file existe (" . filesize($file) . " bytes)\n";
        } else {
            echo "❌ $file NO existe\n";
        }
    }
?>
    </pre>
    
    <h4>Configuración PHP:</h4>
    <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
PHP Version: <?php echo PHP_VERSION; ?>
Display Errors: <?php echo ini_get('display_errors') ? 'ON (VULNERABLE)' : 'OFF'; ?>
Error Reporting: <?php echo error_reporting(); ?>
Max Execution Time: <?php echo ini_get('max_execution_time'); ?>s
Memory Limit: <?php echo ini_get('memory_limit'); ?>
Upload Max Filesize: <?php echo ini_get('upload_max_filesize'); ?>
    </pre>
</div>
<?php endif; ?>

<div class="danger">
    <h3>🔓 Ejemplos de Explotación SOFÍA:</h3>
    <ul>
        <li><strong>SQL Injection:</strong> <code>SELECT * FROM users WHERE username='admin'--</code></li>
        <li><strong>Ver contraseñas:</strong> <code>SELECT username, password FROM users</code></li>
        <li><strong>Ver vehículos:</strong> <code>SELECT * FROM vehicles WHERE vin LIKE '%HGBH%'</code></li>
        <li><strong>Datos fiscales:</strong> <code>SELECT * FROM tax_declarations ORDER BY tax_amount DESC</code></li>
        <li><strong>File Inclusion:</strong> <code>../../../etc/passwd</code></li>
        <li><strong>Command Injection:</strong> <code>ls -la; cat /etc/passwd</code></li>
        <li><strong>Directory Traversal:</strong> <code>../config/database.php</code></li>
    </ul>
</div>

<div style="background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 10px 0;">
    <h3>📚 Módulos del Sistema SOFÍA:</h3>
    <ul>
        <li><strong>Empresas Automotrices:</strong> Gestión de importadoras, concesionarias y talleres</li>
        <li><strong>Registro de Vehículos:</strong> Control de VIN, marcas, modelos y placas</li>
        <li><strong>Declaraciones Fiscales:</strong> Reportes financieros y tributarios del sector automotriz</li>
        <li><strong>Usuarios y Roles:</strong> Sistema de autenticación y permisos</li>
        <li><strong>Auditoría y Logs:</strong> Registro de actividades del sistema</li>
    </ul>
</div>

<p><a href="inicio.php" style="background: #1976d2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">← Volver al Panel de Control SOFÍA</a></p>

<div style="text-align: center; margin-top: 30px; padding: 20px; background: #e0e0e0; color: #666;">
    <small>
        SOFÍA - Sociedad de Fomento a la Industria Automotriz<br>
        Sistema Vulnerable para Auditoría de Seguridad<br>
        ⚠️ NUNCA USAR EN PRODUCCIÓN REAL ⚠️
    </small>
</div>

</body>
</html>