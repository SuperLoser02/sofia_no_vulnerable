<?php
/**
 * seed-users.php
 * Inserta usuarios con contraseñas hasheadas AUTOMÁTICAMENTE
 */

$users = [
    ['admin', 'Admin@2024!', 'admin@sofia.com.bo', 'Administrador SOFÍA', '1020304050', '12345678', 'admin'],
    ['demo', 'Demo@2024!', 'demo@sofia.com.bo', 'Usuario Demostración', '2030405060', '23456789', 'user'],
    ['juan.perez', 'JuanP@2024!', 'juan.perez@sofia.com.bo', 'Juan Carlos Pérez Mamani', '3040506070', '34567890', 'user'],
    ['auditor', 'Audit@2024!', 'auditor@sofia.com.bo', 'Auditor Sistemas', '5060708090', '56789012', 'auditor'],
];

try {
    // Conectar a PostgreSQL
    $conn = pg_connect("host=localhost dbname=sofias_demo user=admin password=admin");

    if (!$conn) {
        throw new Exception("Error de conexión a PostgreSQL");
    }
    
    echo "✅ Conectado a PostgreSQL\n";
    
    foreach ($users as $user) {
        list($username, $password, $email, $full_name, $nit, $ci, $role) = $user;
        
        // Generar hash con bcrypt (cost 12)
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        // Preparar query
        $query = "INSERT INTO users (username, password, email, full_name, nit, ci, role) 
                  VALUES ($1, $2, $3, $4, $5, $6, $7)";
        
        $result = pg_query_params($conn, $query, [
            $username,
            $hash,
            $email,
            $full_name,
            $nit,
            $ci,
            $role
        ]);
        
        if ($result) {
            echo "✅ Usuario '$username' creado (password: $password)\n";
        } else {
            echo "❌ Error al crear usuario '$username': " . pg_last_error($conn) . "\n";
        }
    }
    
    pg_close($conn);
    echo "🎉 Todos los usuarios creados exitosamente\n";
    
} catch (Exception $e) {
    echo "❌ ERROR: " . $e->getMessage() . "\n";
    exit(1);
}
