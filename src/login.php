<?php
/**
 * Login Seguro - SOFÍA
 * Sociedad de Fomento a la Industria Automotriz
 * Sistema Seguro de Autenticación
 */

// SEGURO: Configuración segura de sesiones
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1); // Solo HTTPS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

session_start();

// SEGURO: Regenerar ID de sesión periódicamente
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} else if (time() - $_SESSION['created'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}

// Redirigir a inicio si ya está logueado
if (isset($_SESSION['user_id']) && isset($_SESSION['authenticated'])) {
    header('Location: inicio.php');
    exit();
}

// SEGURO: Incluir archivo validado
require_once 'config/database.php';

$error_message = '';
$success_message = '';

// SEGURO: Generar token CSRF si no existe
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// SEGURO: Rate limiting básico
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt'] = time();
}

// Resetear intentos después de 15 minutos
if (time() - $_SESSION['last_attempt'] > 900) {
    $_SESSION['login_attempts'] = 0;
}

// Procesar formulario de login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // SEGURO: Verificar token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error_message = 'Sesión inválida. Por favor, intente nuevamente.';
        error_log('SOFIA SECURITY: CSRF token mismatch from IP: ' . $_SERVER['REMOTE_ADDR']);
    }
    // SEGURO: Rate limiting - máximo 5 intentos
    else if ($_SESSION['login_attempts'] >= 5) {
        $error_message = 'Demasiados intentos fallidos. Por favor, espere 15 minutos.';
        error_log('SOFIA SECURITY: Rate limit exceeded from IP: ' . $_SERVER['REMOTE_ADDR']);
    }
    else {
        // SEGURO: Sanitizar y validar entrada
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        // SEGURO: Validar que no estén vacíos
        if (empty($username) || empty($password)) {
            $error_message = 'Por favor complete todos los campos.';
            $_SESSION['login_attempts']++;
            $_SESSION['last_attempt'] = time();
        }
        // SEGURO: Validar formato de username (solo alfanuméricos, puntos y guiones)
        else if (!preg_match('/^[a-zA-Z0-9._-]{3,50}$/', $username)) {
            $error_message = 'Formato de usuario inválido.';
            $_SESSION['login_attempts']++;
            $_SESSION['last_attempt'] = time();
            error_log('SOFIA SECURITY: Invalid username format from IP: ' . $_SERVER['REMOTE_ADDR']);
        }
        else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                if (!$db) {
                    throw new Exception("Error de conexión al sistema");
                }
                
                // SEGURO: Crear instancia de User y autenticar
                $user = new User($db);
                
                if ($user->authenticate($username, $password)) {
                    // Autenticación exitosa
                    
                    // SEGURO: Regenerar ID de sesión después del login
                    session_regenerate_id(true);
                    
                    // SEGURO: Establecer variables de sesión
                    $_SESSION['user_id'] = $user->id;
                    $_SESSION['username'] = $user->username;
                    $_SESSION['email'] = $user->email;
                    $_SESSION['full_name'] = $user->full_name;
                    $_SESSION['role'] = $user->role;
                    $_SESSION['authenticated'] = true;
                    $_SESSION['login_time'] = time();
                    $_SESSION['last_activity'] = time();
                    
                    // SEGURO: Resetear intentos fallidos
                    $_SESSION['login_attempts'] = 0;
                    
                    // SEGURO: Redirección validada
                    $redirect = 'inicio.php';
                    if (isset($_GET['redirect'])) {
                        $safe_redirect = filter_var($_GET['redirect'], FILTER_SANITIZE_URL);
                        // Solo permitir rutas internas
                        if (strpos($safe_redirect, 'http') === false && strpos($safe_redirect, '//') === false) {
                            $redirect = $safe_redirect;
                        }
                    }
                    
                    header("Location: " . $redirect);
                    exit();
                    
                } else {
                    // Autenticación fallida
                    $_SESSION['login_attempts']++;
                    $_SESSION['last_attempt'] = time();
                    
                    // SEGURO: Mensaje genérico sin revelar información
                    $error_message = 'Credenciales incorrectas. Por favor, verifique sus datos.';
                    
                    // SEGURO: Delay progresivo para prevenir brute force
                    sleep(min($_SESSION['login_attempts'], 3));
                }
                
            } catch (Exception $e) {
                // SEGURO: Mensaje genérico al usuario
                $error_message = 'Error al procesar la solicitud. Intente nuevamente.';
                
                // SEGURO: Log detallado solo en servidor
                error_log('SOFIA LOGIN ERROR: ' . $e->getMessage());
            }
        }
    }
    
    // SEGURO: Regenerar token CSRF después de cada intento
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SOFÍA</title>
    <!-- SEGURO: CDN con integrity checks -->
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
          content="default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;">
    <style>
        body {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            min-height: 100vh;
            font-family: 'Arial', sans-serif;
        }
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            max-width: 450px;
            width: 100%;
        }
        .login-header {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .login-header h3 {
            font-size: 3rem;
            font-weight: bold;
            letter-spacing: 3px;
            margin-bottom: 10px;
        }
        .login-body {
            padding: 40px;
        }
        .form-control {
            border-radius: 10px;
            padding: 12px 15px;
            border: 2px solid #e9ecef;
            margin-bottom: 20px;
        }
        .form-control:focus {
            border-color: #D0021B;
            box-shadow: 0 0 0 0.2rem rgba(208, 2, 27, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #D0021B 0%, #A00115 100%);
            border: none;
            border-radius: 10px;
            padding: 12px;
            font-weight: bold;
            width: 100%;
            color: white;
            transition: all 0.3s;
        }
        .btn-login:hover {
            background: linear-gradient(135deg, #A00115 0%, #7a000f 100%);
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(208, 2, 27, 0.3);
        }
        .btn-login:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .alert {
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .back-link {
            color: #D0021B;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .security-info {
            background: #e8f5e9;
            padding: 10px;
            border-radius: 5px;
            margin-top: 15px;
            font-size: 0.8rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <h3>SOFÍA</h3>
                <p class="mb-0">Sistema de Información Administrativa</p>
                <small>Sociedad de Fomento a la Industria Automotriz</small>
            </div>
            <div class="login-body">
                
                <?php if ($error_message): ?>
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?php echo htmlspecialchars($error_message); ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($success_message): ?>
                    <div class="alert alert-success" role="alert">
                        <i class="fas fa-check-circle me-2"></i>
                        <?php echo htmlspecialchars($success_message); ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($_SESSION['login_attempts'] >= 3): ?>
                    <div class="alert alert-warning" role="alert">
                        <i class="fas fa-exclamation-circle me-2"></i>
                        Ha realizado <?php echo $_SESSION['login_attempts']; ?> intentos fallidos.
                        <?php if ($_SESSION['login_attempts'] >= 5): ?>
                            Cuenta bloqueada temporalmente.
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                
                <!-- SEGURO: Formulario con token CSRF -->
                <form method="POST" action="" autocomplete="off">
                    <!-- SEGURO: Token CSRF oculto -->
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    
                    <div class="mb-3">
                        <label for="username" class="form-label">
                            <i class="fas fa-user me-2"></i>Usuario
                        </label>
                        <input type="text" 
                               class="form-control" 
                               id="username" 
                               name="username" 
                               placeholder="Ingrese su usuario" 
                               required
                               autocomplete="username"
                               maxlength="50"
                               pattern="[a-zA-Z0-9._-]{3,50}"
                               title="Usuario debe tener entre 3 y 50 caracteres (letras, números, puntos, guiones)"
                               <?php echo ($_SESSION['login_attempts'] >= 5) ? 'disabled' : ''; ?>>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">
                            <i class="fas fa-lock me-2"></i>Contraseña
                        </label>
                        <input type="password" 
                               class="form-control" 
                               id="password" 
                               name="password" 
                               placeholder="Ingrese su contraseña" 
                               required
                               autocomplete="current-password"
                               <?php echo ($_SESSION['login_attempts'] >= 5) ? 'disabled' : ''; ?>>
                    </div>
                    
                    <button type="submit" 
                            class="btn btn-login" 
                            <?php echo ($_SESSION['login_attempts'] >= 5) ? 'disabled' : ''; ?>>
                        <i class="fas fa-sign-in-alt me-2"></i>Iniciar Sesión
                    </button>
                </form>
                
                <div class="text-center mt-4">
                    <small class="text-muted">
                        <a href="index.php" class="back-link">
                            <i class="fas fa-arrow-left me-1"></i>Volver al inicio
                        </a>
                    </small>
                </div>
                
                <!-- SEGURO: Información de seguridad -->
                <div class="security-info">
                    <i class="fas fa-shield-alt me-1"></i>
                    <small>Conexión segura protegida</small>
                </div>
            </div>
        </div>
    </div>
    
    <!-- SEGURO: JavaScript con integrity check -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" 
            integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" 
            crossorigin="anonymous"></script>
    
    <script>
        // SEGURO: Sin información sensible en JavaScript
        // SEGURO: Timeout de sesión del lado del cliente
        let sessionTimeout;
        
        function resetSessionTimeout() {
            clearTimeout(sessionTimeout);
            // Advertir después de 25 minutos de inactividad
            sessionTimeout = setTimeout(function() {
                alert('Su sesión está por expirar por inactividad.');
            }, 25 * 60 * 1000);
        }
        
        // SEGURO: Prevenir auto-completado de contraseñas en navegador
        document.getElementById('password').setAttribute('autocomplete', 'off');
        
        // SEGURO: Limpiar campos al cargar
        window.onload = function() {
            document.getElementById('password').value = '';
        };
        
        // SEGURO: Validación del lado del cliente
        document.querySelector('form').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            
            if (username.length < 3 || username.length > 50) {
                e.preventDefault();
                alert('El usuario debe tener entre 3 y 50 caracteres.');
                return false;
            }
            
            if (password.length === 0) {
                e.preventDefault();
                alert('Por favor ingrese su contraseña.');
                return false;
            }
        });
    </script>
</body>
</html>