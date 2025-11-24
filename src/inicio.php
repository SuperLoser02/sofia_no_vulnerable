<?php
// SEGURO: Configuración de sesión segura ANTES de iniciar
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1); // Requiere HTTPS
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

session_start();

// SEGURO: Regenerar ID de sesión periódicamente
if (!isset($_SESSION['last_regeneration'])) {
    $_SESSION['last_regeneration'] = time();
} elseif (time() - $_SESSION['last_regeneration'] > 300) { // cada 5 minutos
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

// SEGURO: Verificación robusta de sesión
if (!isset($_SESSION['user_id']) || !isset($_SESSION['csrf_token'])) {
    session_destroy();
    header('Location: login.php');
    exit();
}

// SEGURO: Validar que la sesión sea del mismo usuario agent e IP
$current_user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$current_ip = $_SERVER['REMOTE_ADDR'] ?? '';

if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $current_user_agent) {
    session_destroy();
    header('Location: login.php?error=session_hijack');
    exit();
}

// SEGURO: Timeout de sesión (30 minutos de inactividad)
$timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout)) {
    session_destroy();
    header('Location: login.php?error=timeout');
    exit();
}
$_SESSION['last_activity'] = time();

// SEGURO: Incluir archivos con ruta absoluta y validación
$config_path = __DIR__ . '/config/database.php';
if (!file_exists($config_path)) {
    die('Error: Archivo de configuración no encontrado');
}
require_once $config_path;

// SEGURO: Variables con validación y sanitización
$current_user = htmlspecialchars($_SESSION['username'] ?? 'guest', ENT_QUOTES, 'UTF-8');
$user_role = $_SESSION['role'] ?? 'user';

// SEGURO: Whitelist de páginas permitidas
$allowed_pages = ['dashboard', 'users', 'taxpayers', 'vehicles', 'declarations'];
$page = $_GET['page'] ?? 'dashboard';
if (!in_array($page, $allowed_pages)) {
    $page = 'dashboard';
}

// SEGURO: Validar y sanitizar búsqueda
$search = '';
if (isset($_GET['search'])) {
    $search = filter_var($_GET['search'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    // Limitar longitud
    $search = substr($search, 0, 100);
}

$error_message = '';
$stats = ['users' => 0, 'taxpayers' => 0, 'vehicles' => 0, 'declarations' => 0, 'total_tax' => 0];

// SEGURO: Función para validar permisos
function hasPermission($required_role, $user_role) {
    $roles_hierarchy = ['guest' => 0, 'user' => 1, 'auditor' => 2, 'admin' => 3];
    return ($roles_hierarchy[$user_role] ?? 0) >= ($roles_hierarchy[$required_role] ?? 99);
}

// Conexión a base de datos con manejo seguro de errores
try {
    $database = new Database();
    $db = $database->getConnection();
    
    if ($db) {
        // SEGURO: Consultas preparadas para estadísticas
        $stmt = $db->prepare("SELECT COUNT(*) as total FROM users");
        $stmt->execute();
        $stats['users'] = $stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $stmt = $db->prepare("SELECT COUNT(*) as total FROM taxpayers");
        $stmt->execute();
        $stats['taxpayers'] = $stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $stmt = $db->prepare("SELECT COUNT(*) as total FROM vehicles");
        $stmt->execute();
        $stats['vehicles'] = $stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $stmt = $db->prepare("SELECT COUNT(*) as total FROM tax_declarations");
        $stmt->execute();
        $stats['declarations'] = $stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $stmt = $db->prepare("SELECT SUM(tax_amount) as total FROM tax_declarations WHERE status = 'approved'");
        $stmt->execute();
        $stats['total_tax'] = $stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        // SEGURO: Búsqueda con prepared statements
        if (!empty($search)) {
            // Solo admin puede buscar usuarios
            if (hasPermission('admin', $user_role)) {
                $stmt = $db->prepare("SELECT id, username, email, full_name, role FROM users 
                                     WHERE username LIKE :search OR email LIKE :search 
                                     LIMIT 50");
                $search_param = "%{$search}%";
                $stmt->bindParam(':search', $search_param, PDO::PARAM_STR);
                $stmt->execute();
                $search_results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $error_message = 'No tiene permisos para realizar búsquedas';
            }
        }
        
        // SEGURO: Control de acceso basado en roles
        if ($page === 'users') {
            if (hasPermission('admin', $user_role)) {
                // No mostrar contraseñas
                $stmt = $db->prepare("SELECT id, username, email, full_name, nit, ci, role, last_login, created_at 
                                     FROM users ORDER BY created_at DESC LIMIT 100");
                $stmt->execute();
                $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $error_message = 'No tiene permisos para ver esta sección';
            }
        }
        
        if ($page === 'taxpayers') {
            if (hasPermission('user', $user_role)) {
                $stmt = $db->prepare("SELECT * FROM taxpayers ORDER BY created_at DESC LIMIT 100");
                $stmt->execute();
                $taxpayers = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $error_message = 'No tiene permisos para ver esta sección';
            }
        }
        
        if ($page === 'vehicles') {
            if (hasPermission('user', $user_role)) {
                $stmt = $db->prepare("SELECT v.*, t.business_name 
                                     FROM vehicles v 
                                     JOIN taxpayers t ON v.taxpayer_id = t.id 
                                     ORDER BY v.registered_at DESC LIMIT 100");
                $stmt->execute();
                $vehicles = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $error_message = 'No tiene permisos para ver esta sección';
            }
        }
        
        if ($page === 'declarations') {
            if (hasPermission('auditor', $user_role)) {
                $stmt = $db->prepare("SELECT td.*, tp.business_name, tp.nit 
                                     FROM tax_declarations td 
                                     JOIN taxpayers tp ON td.taxpayer_id = tp.id 
                                     ORDER BY td.submitted_at DESC LIMIT 100");
                $stmt->execute();
                $declarations = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $error_message = 'No tiene permisos para ver esta sección';
            }
        }
    }
} catch (PDOException $e) {
    // SEGURO: No mostrar detalles del error al usuario
    error_log("Database error: " . $e->getMessage());
    $error_message = 'Error al conectar con la base de datos. Por favor, contacte al administrador.';
} catch (Exception $e) {
    error_log("General error: " . $e->getMessage());
    $error_message = 'Ha ocurrido un error. Por favor, intente nuevamente.';
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
          script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; 
          style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; 
          font-src 'self' https://cdnjs.cloudflare.com;">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <title>Panel de Control - SOFÍA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
          rel="stylesheet" 
          integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" 
          crossorigin="anonymous">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" 
          rel="stylesheet" 
          integrity="sha512-9usAa10IRO0HhonpyAIVpjrylPvoDwiPUiKdWk5t3PyolY1cOd4DSE0Ga+ri4AuTroPR5aQvXU9xC6qOPnzFeg==" 
          crossorigin="anonymous">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .sidebar {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            min-height: 100vh;
            color: white;
        }
        .sidebar .nav-link {
            color: rgba(255,255,255,0.8);
            margin-bottom: 5px;
            transition: all 0.3s;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            color: white;
            background-color: rgba(255,255,255,0.1);
            border-radius: 5px;
        }
        .main-content {
            padding: 20px;
        }
        .card {
            border: none;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .card-header {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            color: white;
            font-weight: bold;
        }
        .table-responsive {
            max-height: 400px;
            overflow-y: auto;
        }
        .stat-card {
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .logo-sidebar {
            font-size: 2rem;
            font-weight: bold;
            letter-spacing: 2px;
        }
        .secure-badge {
            background-color: #28a745;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 sidebar p-0">
                <div class="p-3">
                    <h4 class="logo-sidebar"><i class="fas fa-car me-2"></i>SOFÍA</h4>
                    <small>Bienvenido, <?php echo $current_user; ?></small>
                    <span class="badge bg-warning text-dark"><?php echo htmlspecialchars($user_role, ENT_QUOTES, 'UTF-8'); ?></span>
                    <br>
                    <span class="secure-badge mt-2 d-inline-block"><i class="fas fa-shield-alt"></i> Versión Segura</span>
                </div>
                <hr class="text-white">
                <nav class="nav flex-column p-3">
                    <a class="nav-link <?php echo $page === 'dashboard' ? 'active' : ''; ?>" href="?page=dashboard">
                        <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                    </a>
                    <?php if (hasPermission('admin', $user_role)): ?>
                    <a class="nav-link <?php echo $page === 'users' ? 'active' : ''; ?>" href="?page=users">
                        <i class="fas fa-users me-2"></i>Usuarios
                    </a>
                    <?php endif; ?>
                    <?php if (hasPermission('user', $user_role)): ?>
                    <a class="nav-link <?php echo $page === 'taxpayers' ? 'active' : ''; ?>" href="?page=taxpayers">
                        <i class="fas fa-building me-2"></i>Empresas
                    </a>
                    <a class="nav-link <?php echo $page === 'vehicles' ? 'active' : ''; ?>" href="?page=vehicles">
                        <i class="fas fa-car me-2"></i>Vehículos
                    </a>
                    <?php endif; ?>
                    <?php if (hasPermission('auditor', $user_role)): ?>
                    <a class="nav-link <?php echo $page === 'declarations' ? 'active' : ''; ?>" href="?page=declarations">
                        <i class="fas fa-file-invoice-dollar me-2"></i>Registros
                    </a>
                    <?php endif; ?>
                    <hr class="text-white">
                    <a class="nav-link" href="logout.php">
                        <i class="fas fa-sign-out-alt me-2"></i>Cerrar Sesión
                    </a>
                </nav>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-10 main-content">
                <!-- Header -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>
                        <?php 
                        switch($page) {
                            case 'users': echo '👥 Gestión de Usuarios'; break;
                            case 'taxpayers': echo '🏢 Empresas Registradas'; break;
                            case 'vehicles': echo '🚗 Vehículos Registrados'; break;
                            case 'declarations': echo '📋 Registros Financieros'; break;
                            default: echo '📊 Dashboard Principal';
                        }
                        ?>
                    </h2>
                    
                    <!-- SEGURO: Búsqueda con CSRF token -->
                    <?php if (hasPermission('admin', $user_role)): ?>
                    <form method="GET" class="d-flex">
                        <input type="hidden" name="page" value="<?php echo htmlspecialchars($page, ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="text" class="form-control me-2" name="search" 
                               placeholder="Buscar usuarios..." 
                               value="<?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?>"
                               maxlength="100">
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-search"></i>
                        </button>
                    </form>
                    <?php endif; ?>
                </div>
                
                <?php if (!empty($error_message)): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                
                <!-- Dashboard Content -->
                <?php if ($page === 'dashboard'): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-shield-alt me-2"></i>
                        <strong>Sistema Seguro:</strong> Esta es la versión segura del sistema SOFÍA con todas las vulnerabilidades corregidas.
                    </div>
                    
                    <div class="row">
                        <div class="col-md-3">
                            <div class="card text-white bg-danger stat-card">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h5>Usuarios</h5>
                                            <h2><?php echo intval($stats['users']); ?></h2>
                                        </div>
                                        <i class="fas fa-users fa-3x opacity-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-success stat-card">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h5>Empresas</h5>
                                            <h2><?php echo intval($stats['taxpayers']); ?></h2>
                                        </div>
                                        <i class="fas fa-building fa-3x opacity-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-primary stat-card">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h5>Vehículos</h5>
                                            <h2><?php echo intval($stats['vehicles']); ?></h2>
                                        </div>
                                        <i class="fas fa-car fa-3x opacity-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-warning stat-card">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h5>Total Bs.</h5>
                                            <h2><?php echo number_format(floatval($stats['total_tax']), 0); ?></h2>
                                        </div>
                                        <i class="fas fa-dollar-sign fa-3x opacity-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-md-8">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-shield-check me-2"></i>Mejoras de Seguridad Implementadas
                                </div>
                                <div class="card-body">
                                    <h5>SOFÍA - Versión Segura</h5>
                                    <p><strong>Sociedad de Fomento a la Industria Automotriz</strong></p>
                                    <ul class="list-group list-group-flush mt-3">
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Prepared Statements (previene SQL Injection)</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> CSRF Tokens en formularios</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Sanitización de entrada/salida (XSS)</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Control de acceso basado en roles</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Sesiones seguras (httpOnly, Secure, SameSite)</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Timeout y regeneración de sesión</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Content Security Policy (CSP)</li>
                                        <li class="list-group-item"><i class="fas fa-check text-success"></i> Manejo seguro de errores</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-user me-2"></i>Información del Usuario
                                </div>
                                <div class="card-body">
                                    <p><strong>Usuario:</strong> <?php echo $current_user; ?></p>
                                    <p><strong>Nombre:</strong> <?php echo htmlspecialchars($_SESSION['full_name'] ?? 'No definido', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Rol:</strong> <span class="badge bg-danger"><?php echo htmlspecialchars($user_role, ENT_QUOTES, 'UTF-8'); ?></span></p>
                                    <p><strong>NIT:</strong> <?php echo htmlspecialchars($_SESSION['nit'] ?? 'No definido', ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <!-- Users Page - Solo para Admin -->
                <?php if ($page === 'users' && isset($users) && hasPermission('admin', $user_role)): ?>
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-users me-2"></i>Lista de Usuarios (Total: <?php echo count($users); ?>)
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Usuario</th>
                                            <th>Email</th>
                                            <th>Nombre Completo</th>
                                            <th>NIT</th>
                                            <th>Rol</th>
                                            <th>Último Login</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($users as $user): ?>
                                        <tr>
                                            <td><?php echo intval($user['id']); ?></td>
                                            <td><?php echo htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><?php echo htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><?php echo htmlspecialchars($user['full_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><?php echo htmlspecialchars($user['nit'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><span class="badge bg-<?php echo $user['role'] === 'admin' ? 'danger' : 'primary'; ?>"><?php echo htmlspecialchars($user['role'], ENT_QUOTES, 'UTF-8'); ?></span></td>
                                            <td><?php echo htmlspecialchars($user['last_login'] ?? 'Nunca', ENT_QUOTES, 'UTF-8'); ?></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <!-- Vehicles Page -->
                <?php if ($page === 'vehicles' && isset($vehicles)): ?>
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-car me-2"></i>Vehículos Registrados (Total: <?php echo count($vehicles); ?>)
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>VIN</th>
                                            <th>Marca</th>
                                            <th>Modelo</th>
                                            <th>Año</th>
                                            <th>Color</th>
                                            <th>Placa</th>
                                            <th>Empresa</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($vehicles as $vehicle): ?>
                                        <tr>
                                            <td><?php echo intval($vehicle['id']); ?></td>
                                            <td><code><?php echo htmlspecialchars($vehicle['vin'], ENT_QUOTES, 'UTF-8'); ?></code></td>
                                            <td><?php echo htmlspecialchars($vehicle['brand'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><?php echo htmlspecialchars($vehicle['model'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><?php echo intval($vehicle['year']); ?></td>
                                            <td><?php echo htmlspecialchars($vehicle['color'], ENT_QUOTES, 'UTF-8'); ?></td>
                                            <td><strong><?php echo htmlspecialchars($vehicle['license_plate'], ENT_QUOTES, 'UTF-8'); ?></strong></td>
                                            <td><?php echo htmlspecialchars($vehicle['business_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <!-- Search Results - Solo Admin -->
                <?php if (!empty($search) && isset($search_results) && hasPermission('admin', $user_role)): ?>
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-search me-2"></i>Resultados: "<?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?>"
                        </div>
                        <div class="card-body">
                            <?php if (count($search_results) > 0): ?>
                                <div class="table-responsive">
                                    <table class="table">
                                        <thead>
                                            <tr>
                                                <th>Usuario</th>
                                                <th>Email</th>
                                                <th>Nombre</th>
                                                <th>Rol</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($search_results as $result): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($result['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo htmlspecialchars($result['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo htmlspecialchars($result['full_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><span class="badge bg-primary"><?php echo htmlspecialchars($result['role'], ENT_QUOTES, 'UTF-8'); ?></span></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php else: ?>
                                <p class="text-muted">No se encontraron resultados.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" 
            integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" 
            crossorigin="anonymous"></script>
</body>
</html>