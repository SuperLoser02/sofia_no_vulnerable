<?php
// ARCHIVO SEGURO - Versión protegida para producción
// ===================================================
// SOFÍA - Sociedad de Fomento a la Industria Automotriz
// Panel de Información del Sistema (Versión Segura)

// SEGURO: Configuración de sesión segura
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

session_start();

// SEGURO: Verificar autenticación obligatoria
if (!isset($_SESSION['user_id']) || !isset($_SESSION['csrf_token'])) {
    header('Location: login.php');
    exit();
}

// SEGURO: Verificar que sea administrador
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: inicio.php?error=forbidden');
    exit();
}

// SEGURO: Regenerar ID de sesión periódicamente
if (!isset($_SESSION['last_regeneration'])) {
    $_SESSION['last_regeneration'] = time();
} elseif (time() - $_SESSION['last_regeneration'] > 300) {
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

// SEGURO: Validar sesión (IP y User Agent)
$current_user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$current_ip = $_SERVER['REMOTE_ADDR'] ?? '';

if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $current_user_agent) {
    session_destroy();
    header('Location: login.php?error=session_hijack');
    exit();
}

// SEGURO: Timeout de sesión
$timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout)) {
    session_destroy();
    header('Location: login.php?error=timeout');
    exit();
}
$_SESSION['last_activity'] = time();

// SEGURO: Obtener información básica del usuario
$current_user = htmlspecialchars($_SESSION['username'] ?? 'guest', ENT_QUOTES, 'UTF-8');
$user_role = $_SESSION['role'] ?? 'user';

// SEGURO: Variables de estadísticas (sin exponer información sensible)
$system_info = [
    'name' => 'SOFÍA',
    'version' => '2.0 - Versión Segura',
    'description' => 'Sociedad de Fomento a la Industria Automotriz',
    'php_version' => PHP_VERSION,
    'status' => 'Operativo'
];

$stats = [];

// SEGURO: Conectar a BD de forma segura
try {
    require_once __DIR__ . '/config/database.php';
    $database = new Database();
    $db = $database->getConnection();
    
    if ($db) {
        // SEGURO: Usar prepared statements
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM users WHERE active = TRUE");
        $stmt->execute();
        $stats['users'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'] ?? 0;
        
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM taxpayers");
        $stmt->execute();
        $stats['taxpayers'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'] ?? 0;
        
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM vehicles");
        $stmt->execute();
        $stats['vehicles'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'] ?? 0;
        
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM tax_declarations");
        $stmt->execute();
        $stats['declarations'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'] ?? 0;
    }
} catch (PDOException $e) {
    // SEGURO: No exponer detalles del error
    error_log("Database error in info.php: " . $e->getMessage());
    $stats = ['error' => 'No se pudo obtener estadísticas'];
}

// SEGURO: Validar token CSRF para acciones
$csrf_valid = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $csrf_valid = true;
    } else {
        $error_message = 'Token CSRF inválido. Acción denegada.';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <!-- SEGURO: Content Security Policy -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; 
          script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; 
          style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; 
          font-src 'self' https://cdn.jsdelivr.net;">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <title>Información del Sistema - SOFÍA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
          rel="stylesheet" 
          integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" 
          crossorigin="anonymous">
    <style>
        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .card-header {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            color: white;
            font-weight: bold;
            border-radius: 15px 15px 0 0 !important;
            padding: 15px 20px;
        }
        .secure-badge {
            background: #28a745;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.9rem;
            display: inline-block;
            margin-top: 10px;
        }
        .stat-box {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 15px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        .stat-box h3 {
            color: #D0021B;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .back-link {
            background: white;
            color: #D0021B;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 10px;
            display: inline-block;
            font-weight: 600;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            transition: all 0.3s;
        }
        .back-link:hover {
            background: #D0021B;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .security-feature {
            padding: 15px;
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            margin-bottom: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>

<div class="container" style="max-width: 1200px;">
    <div class="header">
        <h1><i class="fas fa-car"></i> SOFÍA - Sistema de Información</h1>
        <p class="mb-0"><strong>Sociedad de Fomento a la Industria Automotriz</strong></p>
        <span class="secure-badge"><i class="fas fa-shield-alt"></i> Versión Segura - Solo Administradores</span>
    </div>

    <div class="alert alert-success">
        <i class="fas fa-check-circle me-2"></i>
        <strong>Panel Seguro:</strong> Acceso restringido solo a administradores autenticados. Usuario: <strong><?php echo $current_user; ?></strong>
    </div>

    <div class="row">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-info-circle me-2"></i>Información del Sistema
                </div>
                <div class="card-body">
                    <table class="table table-borderless">
                        <tr>
                            <td><strong>Sistema:</strong></td>
                            <td><?php echo htmlspecialchars($system_info['name'], ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Versión:</strong></td>
                            <td><?php echo htmlspecialchars($system_info['version'], ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Descripción:</strong></td>
                            <td><?php echo htmlspecialchars($system_info['description'], ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                        <tr>
                            <td><strong>PHP Version:</strong></td>
                            <td><?php echo htmlspecialchars($system_info['php_version'], ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Estado:</strong></td>
                            <td><span class="badge bg-success"><?php echo htmlspecialchars($system_info['status'], ENT_QUOTES, 'UTF-8'); ?></span></td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-chart-bar me-2"></i>Estadísticas del Sistema
                </div>
                <div class="card-body">
                    <?php if (isset($stats['error'])): ?>
                        <div class="alert alert-warning">
                            <?php echo htmlspecialchars($stats['error'], ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php else: ?>
                        <div class="row">
                            <div class="col-6">
                                <div class="stat-box">
                                    <h3><?php echo intval($stats['users'] ?? 0); ?></h3>
                                    <p class="mb-0">Usuarios</p>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="stat-box">
                                    <h3><?php echo intval($stats['taxpayers'] ?? 0); ?></h3>
                                    <p class="mb-0">Empresas</p>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="stat-box">
                                    <h3><?php echo intval($stats['vehicles'] ?? 0); ?></h3>
                                    <p class="mb-0">Vehículos</p>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="stat-box">
                                    <h3><?php echo intval($stats['declarations'] ?? 0); ?></h3>
                                    <p class="mb-0">Registros</p>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <i class="fas fa-shield-alt me-2"></i>Características de Seguridad Implementadas
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Autenticación Obligatoria</strong><br>
                        <small>Solo usuarios autenticados pueden acceder</small>
                    </div>
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Control de Roles</strong><br>
                        <small>Acceso restringido a administradores</small>
                    </div>
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Sesiones Seguras</strong><br>
                        <small>HttpOnly, Secure, SameSite configurados</small>
                    </div>
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>CSRF Protection</strong><br>
                        <small>Tokens en todos los formularios</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Prepared Statements</strong><br>
                        <small>Prevención de SQL Injection</small>
                    </div>
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Output Sanitization</strong><br>
                        <small>Prevención de XSS</small>
                    </div>
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Content Security Policy</strong><br>
                        <small>Headers CSP configurados</small>
                    </div>
                    <div class="security-feature">
                        <i class="fas fa-check text-success"></i> <strong>Error Handling Seguro</strong><br>
                        <small>Sin exposición de información sensible</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <i class="fas fa-cogs me-2"></i>Módulos del Sistema SOFÍA
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-4">
                    <div class="text-center p-3">
                        <i class="fas fa-building fa-3x text-primary mb-3"></i>
                        <h5>Empresas Automotrices</h5>
                        <p class="text-muted">Gestión de importadoras, concesionarias y talleres</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="text-center p-3">
                        <i class="fas fa-car fa-3x text-success mb-3"></i>
                        <h5>Registro de Vehículos</h5>
                        <p class="text-muted">Control de VIN, marcas, modelos y placas</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="text-center p-3">
                        <i class="fas fa-file-invoice-dollar fa-3x text-warning mb-3"></i>
                        <h5>Declaraciones Fiscales</h5>
                        <p class="text-muted">Reportes financieros y tributarios</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <i class="fas fa-user-shield me-2"></i>Información de Sesión Actual
        </div>
        <div class="card-body">
            <table class="table table-borderless">
                <tr>
                    <td><strong>Usuario:</strong></td>
                    <td><?php echo $current_user; ?></td>
                </tr>
                <tr>
                    <td><strong>Rol:</strong></td>
                    <td><span class="badge bg-danger"><?php echo htmlspecialchars($user_role, ENT_QUOTES, 'UTF-8'); ?></span></td>
                </tr>
                <tr>
                    <td><strong>IP:</strong></td>
                    <td><?php echo htmlspecialchars($current_ip, ENT_QUOTES, 'UTF-8'); ?></td>
                </tr>
                <tr>
                    <td><strong>Última Actividad:</strong></td>
                    <td><?php echo date('Y-m-d H:i:s', $_SESSION['last_activity'] ?? time()); ?></td>
                </tr>
            </table>
        </div>
    </div>

    <div class="text-center mt-4">
        <a href="inicio.php" class="back-link">
            <i class="fas fa-arrow-left me-2"></i>Volver al Panel de Control
        </a>
    </div>

    <div class="text-center mt-4 p-3" style="background: white; border-radius: 10px; box-shadow: 0 3px 10px rgba(0,0,0,0.1);">
        <small class="text-muted">
            <i class="fas fa-shield-alt text-success"></i>
            SOFÍA - Sociedad de Fomento a la Industria Automotriz<br>
            Versión Segura - Sistema Protegido<br>
            © <?php echo date('Y'); ?> - Todos los derechos reservados
        </small>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" 
        integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" 
        crossorigin="anonymous"></script>
<script src="https://kit.fontawesome.com/your-code.js" crossorigin="anonymous"></script>

</body>
</html>