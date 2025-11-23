<?php
/**
 * Logout Seguro - SOFÍA
 * Sociedad de Fomento a la Industria Automotriz
 * Cierre de Sesión Seguro
 */

// SEGURO: Configuración segura de sesiones
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

session_start();

// SEGURO: Verificar que existe una sesión activa
if (!isset($_SESSION['user_id']) || !isset($_SESSION['authenticated'])) {
    // No hay sesión activa, redirigir a login
    header('Location: login.php');
    exit();
}

// SEGURO: Validar token CSRF para logout
$csrf_valid = false;
if (isset($_GET['token']) && isset($_SESSION['csrf_token'])) {
    $csrf_valid = hash_equals($_SESSION['csrf_token'], $_GET['token']);
}

// Si no hay token válido, mostrar confirmación
if (!$csrf_valid) {
    // Generar token CSRF si no existe
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirmar Cierre de Sesión - SOFÍA</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .confirm-container {
                background: white;
                padding: 50px;
                border-radius: 20px;
                box-shadow: 0 15px 50px rgba(0,0,0,0.4);
                text-align: center;
                max-width: 500px;
            }
            .btn-logout {
                background: #D0021B;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 10px;
                font-weight: bold;
            }
            .btn-logout:hover {
                background: #A00115;
                color: white;
            }
            .btn-cancel {
                background: #6c757d;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 10px;
                font-weight: bold;
            }
            .btn-cancel:hover {
                background: #5a6268;
                color: white;
            }
        </style>
    </head>
    <body>
        <div class="confirm-container">
            <h3 class="mb-4">🚗 SOFÍA</h3>
            <h4 class="mb-4">¿Desea cerrar su sesión?</h4>
            <p class="text-muted mb-4">
                Usuario: <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong><br>
                <small>Esta acción cerrará su sesión actual</small>
            </p>
            <div class="d-flex gap-3 justify-content-center">
                <a href="logout.php?token=<?php echo urlencode($_SESSION['csrf_token']); ?>" class="btn btn-logout">
                    <i class="fas fa-sign-out-alt me-2"></i>Cerrar Sesión
                </a>
                <a href="inicio.php" class="btn btn-cancel">
                    <i class="fas fa-times me-2"></i>Cancelar
                </a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit();
}

// Token CSRF válido, proceder con el logout

// SEGURO: Registrar logout en logs (sin información sensible)
require_once 'config/database.php';
try {
    $database = new Database();
    $db = $database->getConnection();
    
    if ($db) {
        $user_id = $_SESSION['user_id'];
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 255);
        
        $query = "INSERT INTO system_logs (user_id, action, resource, ip_address, user_agent, status) 
                  VALUES (:user_id, 'logout', 'users', :ip, :user_agent, 'success')";
        
        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':user_agent', $user_agent);
        $stmt->execute();
        
        // SEGURO: Log en servidor sin información sensible
        error_log('SOFIA: User logout - ID: ' . $user_id . ' IP: ' . $ip);
    }
} catch (Exception $e) {
    // SEGURO: Solo log en servidor
    error_log('SOFIA LOGOUT LOG ERROR: ' . $e->getMessage());
}

// SEGURO: Guardar información mínima para mensaje (sin datos sensibles)
$username = $_SESSION['username'] ?? 'Usuario';

// SEGURO: Limpiar todas las variables de sesión
$_SESSION = array();

// SEGURO: Destruir la cookie de sesión
if (isset($_COOKIE[session_name()])) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

// SEGURO: Destruir la sesión
session_destroy();

// SEGURO: Iniciar nueva sesión para mostrar mensaje
session_start();
session_regenerate_id(true);

// Guardar mensaje de logout exitoso
$_SESSION['logout_success'] = true;
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sesión Cerrada - SOFÍA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
          rel="stylesheet"
          integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" 
          crossorigin="anonymous">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" 
          rel="stylesheet"
          integrity="sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN" 
          crossorigin="anonymous">
    <!-- SEGURO: Content Security Policy -->
    <meta http-equiv="Content-Security-Policy" 
          content="default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdnjs.cloudflare.com;">
    <style>
        body {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .logout-container {
            background: white;
            padding: 50px;
            border-radius: 20px;
            box-shadow: 0 15px 50px rgba(0,0,0,0.4);
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        .spinner-border {
            width: 3.5rem;
            height: 3.5rem;
            color: #D0021B;
        }
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
        }
        .system-name {
            color: #D0021B;
            font-weight: bold;
            font-size: 1.5rem;
            margin-bottom: 10px;
        }
        .success-icon {
            font-size: 4rem;
            color: #28a745;
            margin-bottom: 20px;
        }
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .btn-return {
            background: #D0021B;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 10px;
            text-decoration: none;
            display: inline-block;
            margin-top: 20px;
            font-weight: bold;
        }
        .btn-return:hover {
            background: #A00115;
            color: white;
        }
    </style>
</head>
<body>
    <div class="logout-container">
        <div class="success-icon">
            <i class="fas fa-check-circle"></i>
        </div>
        
        <div class="system-name">
            SOFÍA
        </div>
        <p class="text-muted mb-4" style="font-size: 0.9rem;">
            Sociedad de Fomento a la Industria Automotriz
        </p>
        
        <h4 class="mb-3">Sesión Cerrada</h4>
        <p class="text-muted mb-4">
            Su sesión ha sido cerrada correctamente.<br>
            Gracias por utilizar el sistema SOFÍA.
        </p>
        
        <div class="alert alert-success" role="alert">
            <i class="fas fa-info-circle me-2"></i>
            <small>
                Su sesión ha finalizado de forma segura.<br>
                Todos los datos han sido protegidos.
            </small>
        </div>
        
        <!-- SEGURO: Sin información sensible expuesta -->
        <div class="info-box">
            <small class="text-muted">
                <i class="fas fa-shield-alt me-1"></i>
                Sistema cerrado de forma segura<br>
                <i class="fas fa-clock me-1"></i>
                <?php echo date('d/m/Y H:i:s'); ?>
            </small>
        </div>
        
        <a href="login.php" class="btn-return">
            <i class="fas fa-sign-in-alt me-2"></i>Volver al inicio de sesión
        </a>
        
        <div class="mt-4">
            <small class="text-muted">
                <a href="index.php" style="text-decoration: none; color: #6c757d;">
                    <i class="fas fa-home me-1"></i>Ir al inicio
                </a>
            </small>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" 
            integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" 
            crossorigin="anonymous"></script>
    
    <script>
        // SEGURO: Redirección automática después de 5 segundos
        setTimeout(function() {
            window.location.href = 'login.php';
        }, 5000);
        
        // SEGURO: Limpiar historial para prevenir volver atrás
        if (window.history && window.history.pushState) {
            window.history.pushState(null, null, window.location.href);
            window.onpopstate = function () {
                window.history.pushState(null, null, window.location.href);
            };
        }
        
        // SEGURO: Limpiar caché del navegador
        if ('caches' in window) {
            caches.keys().then(function(names) {
                names.forEach(function(name) {
                    caches.delete(name);
                });
            });
        }
    </script>
</body>
</html>