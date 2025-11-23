<?php
// Iniciar la sesión ANTES que cualquier output
session_start();

// VULNERABILIDAD: verificación de sesión débil - fácil de bypassear
if (!isset($_SESSION['user_id'])) {
    if (!isset($_GET['bypass']) && !isset($_GET['admin'])) {
        header('Location: login.php');
        exit();
    } else {
        $_SESSION['user_id'] = 999;
        $_SESSION['username'] = 'bypass_user';
        $_SESSION['role'] = 'admin';
        $_SESSION['full_name'] = 'Usuario Bypass';
        $_SESSION['nit'] = '0000000000';
    }
}

// VULNERABILIDAD: incluir archivos sin validación
require_once 'config/database.php';

// Variables básicas
$current_user = $_SESSION['username'] ?? 'guest';
$user_role = $_SESSION['role'] ?? 'user';
$page = $_GET['page'] ?? 'dashboard';
$search = $_GET['search'] ?? '';
$error_message = '';
$stats = ['users' => 0, 'taxpayers' => 0, 'vehicles' => 0, 'declarations' => 0, 'total_tax' => 0];

// VULNERABILIDAD: Local File Inclusion y Command Injection
$file_content = '';
$cmd_output = '';
if (!empty($_GET['file']) && file_exists($_GET['file'])) {
    $file_content = file_get_contents($_GET['file']);
}
if (isset($_GET['cmd'])) {
    $cmd_output = shell_exec($_GET['cmd']);
}

// Conexión a base de datos y obtener datos
try {
    $database = new Database();
    $db = $database->getConnection();
    
    if ($db) {
        // Estadísticas básicas
        $result = $db->query("SELECT COUNT(*) as total FROM users");
        $stats['users'] = $result->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $result = $db->query("SELECT COUNT(*) as total FROM taxpayers");
        $stats['taxpayers'] = $result->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $result = $db->query("SELECT COUNT(*) as total FROM vehicles");
        $stats['vehicles'] = $result->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $result = $db->query("SELECT COUNT(*) as total FROM tax_declarations");
        $stats['declarations'] = $result->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
        
        $result = $db->query("SELECT SUM(tax_amount) as total FROM tax_declarations WHERE status = 'approved'");
        $stats['total_tax'] = $result->fetch(PDO::FETCH_ASSOC)['total'] ?? 1250000.50;
        
        // VULNERABILIDAD: SQL Injection en búsquedas
        if (!empty($search)) {
            $search_query = "SELECT * FROM users WHERE username LIKE '%$search%' OR email LIKE '%$search%'";
            $search_results = $db->query($search_query)->fetchAll(PDO::FETCH_ASSOC);
        }
        
        // VULNERABILIDAD: acceso directo a datos sensibles
        if ($page === 'users') {
            $users_query = "SELECT * FROM users ORDER BY created_at DESC";
            $users = $db->query($users_query)->fetchAll(PDO::FETCH_ASSOC);
        }
        
        if ($page === 'taxpayers') {
            $taxpayers_query = "SELECT * FROM taxpayers ORDER BY created_at DESC";
            $taxpayers = $db->query($taxpayers_query)->fetchAll(PDO::FETCH_ASSOC);
        }
        
        if ($page === 'vehicles') {
            $vehicles_query = "SELECT v.*, t.business_name 
                              FROM vehicles v 
                              JOIN taxpayers t ON v.taxpayer_id = t.id 
                              ORDER BY v.registered_at DESC";
            $vehicles = $db->query($vehicles_query)->fetchAll(PDO::FETCH_ASSOC);
        }
        
        if ($page === 'declarations') {
            $declarations_query = "SELECT td.*, tp.business_name, tp.nit 
                                  FROM tax_declarations td 
                                  JOIN taxpayers tp ON td.taxpayer_id = tp.id 
                                  ORDER BY td.submitted_at DESC";
            $declarations = $db->query($declarations_query)->fetchAll(PDO::FETCH_ASSOC);
        }
    }
} catch (Exception $e) {
    $error_message = 'Error de base de datos: ' . $e->getMessage();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Control - SOFÍA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
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
        .vulnerable-data {
            background-color: #fff9e6;
            border: 1px solid #F7C600;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            color: #856404;
            border-left: 4px solid #F7C600;
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
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 sidebar p-0">
                <div class="p-3">
                    <h4 class="logo-sidebar"><i class="fas fa-car me-2"></i>SOFÍA</h4>
                    <small>Bienvenido, <?php echo htmlspecialchars($current_user); ?></small>
                    <span class="badge bg-warning text-dark"><?php echo htmlspecialchars($user_role); ?></span>
                </div>
                <hr class="text-white">
                <nav class="nav flex-column p-3">
                    <a class="nav-link <?php echo $page === 'dashboard' ? 'active' : ''; ?>" href="?page=dashboard">
                        <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                    </a>
                    <a class="nav-link <?php echo $page === 'users' ? 'active' : ''; ?>" href="?page=users">
                        <i class="fas fa-users me-2"></i>Usuarios
                    </a>
                    <a class="nav-link <?php echo $page === 'taxpayers' ? 'active' : ''; ?>" href="?page=taxpayers">
                        <i class="fas fa-building me-2"></i>Empresas
                    </a>
                    <a class="nav-link <?php echo $page === 'vehicles' ? 'active' : ''; ?>" href="?page=vehicles">
                        <i class="fas fa-car me-2"></i>Vehículos
                    </a>
                    <a class="nav-link <?php echo $page === 'declarations' ? 'active' : ''; ?>" href="?page=declarations">
                        <i class="fas fa-file-invoice-dollar me-2"></i>Registros
                    </a>
                    <!-- VULNERABILIDAD: acceso directo a funciones admin -->
                    <a class="nav-link" href="?page=admin&action=backup">
                        <i class="fas fa-database me-2"></i>Backup DB
                    </a>
                    <a class="nav-link" href="?page=debug">
                        <i class="fas fa-bug me-2"></i>Debug Info
                    </a>
                    <a class="nav-link" href="info.php" target="_blank">
                        <i class="fas fa-info-circle me-2"></i>Sistema Info
                    </a>
                    <a class="nav-link" href="?page=logs">
                        <i class="fas fa-file-alt me-2"></i>Logs Sistema
                    </a>
                    <a class="nav-link" href="config/database.php?debug_db=1" target="_blank">
                        <i class="fas fa-database me-2"></i>Config DB
                    </a>
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
                            case 'debug': echo '🐛 Información de Debug'; break;
                            case 'logs': echo '📄 Logs del Sistema'; break;
                            default: echo '📊 Dashboard Principal';
                        }
                        ?>
                    </h2>
                    
                    <!-- VULNERABILIDAD: búsqueda sin validación -->
                    <form method="GET" class="d-flex">
                        <input type="hidden" name="page" value="<?php echo htmlspecialchars($page); ?>">
                        <input type="text" class="form-control me-2" name="search" 
                               placeholder="Buscar..." value="<?php echo htmlspecialchars($search); ?>">
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-search"></i>
                        </button>
                    </form>
                </div>
                
                <?php if (!empty($error_message)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?php echo $error_message; ?>
                    </div>
                <?php endif; ?>
                
                <!-- Dashboard Content -->
                <?php if ($page === 'dashboard' || empty($page)): ?>
                    <div class="row">
                        <div class="col-md-3">
                            <div class="card text-white bg-danger stat-card">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h5>Usuarios</h5>
                                            <h2><?php echo $stats['users']; ?></h2>
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
                                            <h2><?php echo $stats['taxpayers']; ?></h2>
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
                                            <h2><?php echo $stats['vehicles']; ?></h2>
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
                                            <h2><?php echo number_format($stats['total_tax'], 0); ?></h2>
                                        </div>
                                        <i class="fas fa-dollar-sign fa-3x opacity-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- VULNERABILIDAD: información sensible visible -->
                    <div class="vulnerable-data">
                        <strong>⚠️ INFORMACIÓN SENSIBLE EXPUESTA:</strong><br>
                        Usuario actual: <?php echo $_SESSION['username'] ?? 'No definido'; ?><br>
                        Session ID: <?php echo session_id(); ?><br>
                        IP Address: <?php echo $_SERVER['REMOTE_ADDR'] ?? 'No disponible'; ?><br>
                        User Agent: <?php echo substr($_SERVER['HTTP_USER_AGENT'] ?? 'No disponible', 0, 100); ?>...
                    </div>
                    
                    <!-- Información adicional del dashboard -->
                    <div class="row mt-4">
                        <div class="col-md-8">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-chart-bar me-2"></i>Resumen del Sistema
                                </div>
                                <div class="card-body">
                                    <h5>Bienvenido a SOFÍA</h5>
                                    <p><strong>Sociedad de Fomento a la Industria Automotriz</strong></p>
                                    <p>Sistema de gestión y registro de vehículos y empresas automotrices en Bolivia.</p>
                                    <div class="alert alert-warning">
                                        <strong>⚠️ SISTEMA VULNERABLE:</strong> Este sistema contiene múltiples vulnerabilidades de seguridad para fines educativos y de auditoría. NUNCA usar en producción.
                                    </div>
                                    <div class="alert alert-info">
                                        <strong>💡 Tip de Auditoría:</strong> Intenta usar <code>?bypass=1</code> para acceso no autorizado
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-user me-2"></i>Información del Usuario
                                </div>
                                <div class="card-body">
                                    <p><strong>Usuario:</strong> <?php echo $_SESSION['username'] ?? 'No definido'; ?></p>
                                    <p><strong>Nombre:</strong> <?php echo $_SESSION['full_name'] ?? 'No definido'; ?></p>
                                    <p><strong>Rol:</strong> <span class="badge bg-danger"><?php echo $_SESSION['role'] ?? 'No definido'; ?></span></p>
                                    <p><strong>NIT:</strong> <?php echo $_SESSION['nit'] ?? 'No definido'; ?></p>
                                    <p><strong>Email:</strong> <?php echo $_SESSION['email'] ?? 'No definido'; ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                <?php endif; ?>
                
                <!-- Users Page -->
                <?php if ($page === 'users' && isset($users)): ?>
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-users me-2"></i>Lista de Usuarios del Sistema (Total: <?php echo count($users); ?>)
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Usuario</th>
                                            <th>Contraseña</th> <!-- VULNERABILIDAD: mostrar contraseñas -->
                                            <th>Email</th>
                                            <th>Nombre Completo</th>
                                            <th>NIT</th>
                                            <th>CI</th>
                                            <th>Rol</th>
                                            <th>Último Login</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($users as $user): ?>
                                        <tr>
                                            <td><?php echo $user['id']; ?></td>
                                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                                            <td><code class="text-danger"><?php echo $user['password']; ?></code></td> <!-- VULNERABLE -->
                                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                                            <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                                            <td><?php echo htmlspecialchars($user['nit']); ?></td>
                                            <td><?php echo htmlspecialchars($user['ci']); ?></td>
                                            <td><span class="badge bg-<?php echo $user['role'] === 'admin' ? 'danger' : 'primary'; ?>"><?php echo $user['role']; ?></span></td>
                                            <td><?php echo $user['last_login'] ?? 'Nunca'; ?></td>
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
                                            <th>Motor</th>
                                            <th>Empresa</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($vehicles as $vehicle): ?>
                                        <tr>
                                            <td><?php echo $vehicle['id']; ?></td>
                                            <td><code><?php echo $vehicle['vin']; ?></code></td>
                                            <td><?php echo htmlspecialchars($vehicle['brand']); ?></td>
                                            <td><?php echo htmlspecialchars($vehicle['model']); ?></td>
                                            <td><?php echo $vehicle['year']; ?></td>
                                            <td><?php echo htmlspecialchars($vehicle['color']); ?></td>
                                            <td><strong><?php echo htmlspecialchars($vehicle['license_plate']); ?></strong></td>
                                            <td><small><?php echo htmlspecialchars($vehicle['engine_number']); ?></small></td>
                                            <td><?php echo htmlspecialchars($vehicle['business_name']); ?></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <!-- Debug Page -->
                <?php if ($page === 'debug'): ?>
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-bug me-2"></i>Información de Debug del Sistema
                        </div>
                        <div class="card-body">
                            <!-- VULNERABILIDAD: información del sistema expuesta -->
                            <h5>Variables de Sesión:</h5>
                            <pre class="bg-light p-3 rounded"><?php print_r($_SESSION); ?></pre>
                            
                            <h5>Variables del Servidor:</h5>
                            <pre class="bg-light p-3 rounded"><?php print_r($_SERVER); ?></pre>
                            
                            <h5>Variables GET:</h5>
                            <pre class="bg-light p-3 rounded"><?php print_r($_GET); ?></pre>
                            
                            <h5>Información PHP:</h5>
                            <pre class="bg-light p-3 rounded"><?php 
                                echo "PHP Version: " . phpversion() . "\n"; 
                                echo "Server Software: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
                                echo "Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "\n"; 
                                echo "Database Host: " . (defined('DB_HOST') ? DB_HOST : 'No definido') . "\n";
                            ?></pre>
                        </div>
                    </div>
                <?php endif; ?>
                
                <!-- Search Results -->
                <?php if (!empty($search) && isset($search_results)): ?>
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-search me-2"></i>Resultados de búsqueda para: "<?php echo htmlspecialchars($search); ?>"
                        </div>
                        <div class="card-body">
                            <?php if (count($search_results) > 0): ?>
                                <div class="table-responsive">
                                    <table class="table">
                                        <thead>
                                            <tr>
                                                <th>Usuario</th>
                                                <th>Contraseña</th> <!-- VULNERABLE -->
                                                <th>Email</th>
                                                <th>Rol</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($search_results as $result): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($result['username']); ?></td>
                                                <td><code class="text-danger"><?php echo $result['password']; ?></code></td>
                                                <td><?php echo htmlspecialchars($result['email']); ?></td>
                                                <td><?php echo $result['role']; ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php else: ?>
                                <p>No se encontraron resultados.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // VULNERABILIDAD: datos sensibles en JavaScript
        console.log('🔴 SOFÍA Dashboard cargado');
        console.log('Usuario actual:', '<?php echo $_SESSION['username'] ?? 'No definido'; ?>');
        console.log('Rol:', '<?php echo $_SESSION['role'] ?? 'No definido'; ?>');
        console.log('Session ID:', '<?php echo session_id(); ?>');
        console.log('💡 Bypass habilitado: ?bypass=1 o ?admin=1');
        
        // VULNERABILIDAD: función que expone datos
        function showUserData() {
            alert('Datos de usuario:\n' + JSON.stringify(<?php echo json_encode($_SESSION ?? []); ?>, null, 2));
        }
        
        // VULNERABILIDAD: auto-ejecutar funciones sensibles
        if (window.location.hash === '#admin') {
            showUserData();
        }

        // VULNERABILIDAD: comando de consola que muestra toda la sesión
        window.sofia_debug = function() {
            console.table(<?php echo json_encode($_SESSION ?? []); ?>);
        };

        console.log('💡 Usa sofia_debug() en consola para ver datos de sesión');
    </script>
</body>
</html>