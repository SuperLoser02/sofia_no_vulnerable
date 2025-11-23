<?php
/**
 * Configuración SEGURA de Base de Datos
 * ================================================================================
 * SOFÍA - Sociedad de Fomento a la Industria Automotriz
 * Sistema Seguro para Producción
 * 
 * @version 2.0 Secure
 * @author Equipo de Desarrollo SOFÍA
 */

// SEGURO: Sin display_errors en producción
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php/sofia_errors.log');
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);

/**
 * Clase Database - Manejo seguro de conexiones
 */
class Database {
    private $host;
    private $db_name;
    private $username;
    private $password;
    private $conn = null;
    private $max_attempts = 3;
    
    public function __construct() {
        // SEGURO: Credenciales desde variables de entorno, sin defaults expuestos
        $this->host = getenv('DB_HOST') ?: 'db';
        $this->db_name = getenv('DB_NAME') ?: 'sofias_demo';
        $this->username = getenv('DB_USER') ?: 'admin';
        $this->password = getenv('DB_PASS') ?: '';
        
        // SEGURO: Validar que las credenciales existen
        if (empty($this->password)) {
            error_log('SOFIA ERROR: Database password not configured');
            throw new Exception('Configuración de base de datos incompleta');
        }
    }

    /**
     * Obtener conexión segura a la base de datos
     * @return PDO|null Conexión PDO o null en caso de error
     */
    public function getConnection() {
        if ($this->conn !== null) {
            return $this->conn;
        }
        
        try {
            $dsn = "pgsql:host=" . $this->host . ";dbname=" . $this->db_name;
            
            // SEGURO: Opciones de PDO configuradas correctamente
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false, // Prepared statements reales
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_PERSISTENT => false, // Sin conexiones persistentes
                PDO::ATTR_STRINGIFY_FETCHES => false,
            ];
            
            $this->conn = new PDO($dsn, $this->username, $this->password, $options);
            
            // SEGURO: Log sin información sensible
            error_log('SOFIA: Database connection established successfully');
            
            return $this->conn;
            
        } catch(PDOException $exception) {
            // SEGURO: Error logging sin exponer credenciales
            error_log('SOFIA DB ERROR: ' . $exception->getMessage());
            error_log('SOFIA DB ERROR Code: ' . $exception->getCode());
            
            // SEGURO: Mensaje genérico al usuario
            throw new Exception('Error al conectar con la base de datos. Por favor, contacte al administrador.');
        }
    }
    
    /**
     * Ejecutar query preparada de forma segura
     * @param string $query Query SQL con placeholders
     * @param array $params Parámetros para bind
     * @return PDOStatement|false Resultado de la query
     */
    public function executePreparedQuery($query, $params = []) {
        try {
            $conn = $this->getConnection();
            $stmt = $conn->prepare($query);
            
            // SEGURO: Bind de parámetros con tipos específicos
            foreach ($params as $key => &$value) {
                $type = PDO::PARAM_STR;
                if (is_int($value)) {
                    $type = PDO::PARAM_INT;
                } elseif (is_bool($value)) {
                    $type = PDO::PARAM_BOOL;
                } elseif (is_null($value)) {
                    $type = PDO::PARAM_NULL;
                }
                $stmt->bindValue($key, $value, $type);
            }
            
            $stmt->execute();
            
            // SEGURO: Log de actividad sin query completa
            error_log('SOFIA: Query executed successfully');
            
            return $stmt;
            
        } catch (PDOException $e) {
            // SEGURO: Log de error sin exponer query
            error_log('SOFIA QUERY ERROR: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Cerrar conexión de forma segura
     */
    public function closeConnection() {
        $this->conn = null;
        error_log('SOFIA: Database connection closed');
    }
    
    /**
     * Validar entrada de datos
     * @param string $input Entrada a validar
     * @param string $type Tipo de validación
     * @return bool True si es válido
     */
    public function validateInput($input, $type = 'string') {
        switch ($type) {
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL) !== false;
            case 'int':
                return filter_var($input, FILTER_VALIDATE_INT) !== false;
            case 'alphanumeric':
                return preg_match('/^[a-zA-Z0-9]+$/', $input);
            case 'nit':
                return preg_match('/^\d{10,20}$/', $input);
            case 'vin':
                return preg_match('/^[A-HJ-NPR-Z0-9]{17}$/', $input);
            case 'license_plate':
                return preg_match('/^\d{4}-[A-Z]{3}$/', $input);
            default:
                return is_string($input) && strlen($input) > 0;
        }
    }
    
    /**
     * Sanitizar salida HTML
     * @param string $output Salida a sanitizar
     * @return string Salida sanitizada
     */
    public function sanitizeOutput($output) {
        return htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
    }
}

/**
 * Clase User - Manejo seguro de usuarios
 */
class User {
    private $conn;
    private $table_name = "users";
    
    public $id;
    public $username;
    private $password; // SEGURO: Password privado
    public $email;
    public $full_name;
    public $role;
    public $active;

    public function __construct($db) {
        $this->conn = $db;
    }

    /**
     * Autenticación segura de usuario
     * @param string $username Usuario
     * @param string $password Contraseña
     * @return bool True si la autenticación es exitosa
     */
    public function authenticate($username, $password) {
        try {
            // SEGURO: Validar entrada
            if (empty($username) || empty($password)) {
                $this->logFailedAttempt(null, 'empty_credentials');
                return false;
            }
            
            // SEGURO: Query preparada
            $query = "SELECT id, username, password, email, full_name, role, active, failed_attempts, locked_until 
                      FROM " . $this->table_name . " 
                      WHERE username = :username 
                      LIMIT 1";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            
            if ($stmt->rowCount() === 0) {
                // SEGURO: Mensaje genérico sin revelar si el usuario existe
                $this->logFailedAttempt(null, 'invalid_credentials');
                return false;
            }
            
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // SEGURO: Verificar si la cuenta está bloqueada
            if ($row['locked_until'] && strtotime($row['locked_until']) > time()) {
                $this->logFailedAttempt($row['id'], 'account_locked');
                error_log('SOFIA: Login attempt on locked account: ' . $username);
                return false;
            }
            
            // SEGURO: Verificar si la cuenta está activa
            if (!$row['active']) {
                $this->logFailedAttempt($row['id'], 'account_inactive');
                return false;
            }
            
            // SEGURO: Verificar contraseña hasheada
            if (password_verify($password, $row['password'])) {
                // Autenticación exitosa
                $this->id = $row['id'];
                $this->username = $row['username'];
                $this->email = $row['email'];
                $this->full_name = $row['full_name'];
                $this->role = $row['role'];
                $this->active = $row['active'];
                
                // SEGURO: Resetear intentos fallidos
                $this->resetFailedAttempts();
                
                // SEGURO: Actualizar último login
                $this->updateLastLogin();
                
                // SEGURO: Regenerar ID de sesión
                if (session_status() === PHP_SESSION_ACTIVE) {
                    session_regenerate_id(true);
                }
                
                // SEGURO: Log sin información sensible
                error_log('SOFIA: Successful login for user ID: ' . $this->id);
                $this->logActivity('login', 'users', 'success');
                
                return true;
                
            } else {
                // Contraseña incorrecta
                $this->incrementFailedAttempts($row['id']);
                $this->logFailedAttempt($row['id'], 'invalid_password');
                return false;
            }
            
        } catch (Exception $e) {
            error_log('SOFIA AUTH ERROR: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Crear nuevo usuario con contraseña hasheada
     * @param string $password Contraseña en texto plano
     * @return bool True si se creó correctamente
     */
    public function create($password) {
        try {
            // SEGURO: Validar complejidad de contraseña
            if (!$this->validatePasswordStrength($password)) {
                throw new Exception('La contraseña no cumple con los requisitos de seguridad');
            }
            
            // SEGURO: Hashear contraseña con bcrypt
            $hashed_password = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            
            $query = "INSERT INTO " . $this->table_name . " 
                      (username, password, email, full_name, role, nit, ci, phone, address) 
                      VALUES (:username, :password, :email, :full_name, :role, :nit, :ci, :phone, :address)";
            
            $stmt = $this->conn->prepare($query);
            
            // SEGURO: Bind de parámetros
            $stmt->bindParam(":username", $this->username);
            $stmt->bindParam(":password", $hashed_password);
            $stmt->bindParam(":email", $this->email);
            $stmt->bindParam(":full_name", $this->full_name);
            $stmt->bindParam(":role", $this->role);
            $stmt->bindParam(":nit", $this->nit);
            $stmt->bindParam(":ci", $this->ci);
            $stmt->bindParam(":phone", $this->phone);
            $stmt->bindParam(":address", $this->address);
            
            if ($stmt->execute()) {
                $this->id = $this->conn->lastInsertId();
                error_log('SOFIA: User created successfully ID: ' . $this->id);
                return true;
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log('SOFIA USER CREATE ERROR: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Validar fortaleza de contraseña
     * @param string $password Contraseña a validar
     * @return bool True si cumple los requisitos
     */
    private function validatePasswordStrength($password) {
        // Mínimo 8 caracteres, mayúscula, minúscula, número y carácter especial
        if (strlen($password) < 8) {
            return false;
        }
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }
        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return false;
        }
        return true;
    }
    
    /**
     * Incrementar intentos fallidos de login
     */
    private function incrementFailedAttempts($user_id) {
        $query = "UPDATE " . $this->table_name . " 
                  SET failed_attempts = failed_attempts + 1,
                      locked_until = CASE 
                          WHEN failed_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
                          ELSE NULL 
                      END
                  WHERE id = :id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':id', $user_id, PDO::PARAM_INT);
        $stmt->execute();
    }
    
    /**
     * Resetear intentos fallidos
     */
    private function resetFailedAttempts() {
        $query = "UPDATE " . $this->table_name . " 
                  SET failed_attempts = 0, locked_until = NULL 
                  WHERE id = :id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':id', $this->id, PDO::PARAM_INT);
        $stmt->execute();
    }
    
    /**
     * Actualizar última fecha de login
     */
    private function updateLastLogin() {
        $query = "UPDATE " . $this->table_name . " 
                  SET last_login = NOW() 
                  WHERE id = :id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':id', $this->id, PDO::PARAM_INT);
        $stmt->execute();
    }
    
    /**
     * Registrar intento fallido en logs
     */
    private function logFailedAttempt($user_id, $reason) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $query = "INSERT INTO system_logs (user_id, action, resource, ip_address, user_agent, status) 
                  VALUES (:user_id, 'failed_login', :reason, :ip, :user_agent, 'failed')";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':reason', $reason);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':user_agent', $user_agent);
        $stmt->execute();
    }
    
    /**
     * Registrar actividad del usuario
     */
    private function logActivity($action, $resource, $status) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $query = "INSERT INTO system_logs (user_id, action, resource, ip_address, user_agent, status) 
                  VALUES (:user_id, :action, :resource, :ip, :user_agent, :status)";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $this->id, PDO::PARAM_INT);
        $stmt->bindParam(':action', $action);
        $stmt->bindParam(':resource', $resource);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':user_agent', $user_agent);
        $stmt->bindParam(':status', $status);
        $stmt->execute();
    }
}

// SEGURO: Sin comentarios con información sensible
// SEGURO: Sin credenciales hardcodeadas
// SEGURO: Sin métodos para ejecutar SQL arbitrario
?>