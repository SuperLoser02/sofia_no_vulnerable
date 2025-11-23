<?php
session_start();
// Si el usuario ya está logueado, redirigir al dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: inicio.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Avícola Sofia Plus - Empresa de Alimentos Bolivia</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
    <nav>
        <a href="#" class="logo">
            <img src="https://sofia.com.bo/cdn/shop/files/Logos_Sofia.png?v=1752153647&width=80" alt="Logo Sofía" style="height:80px; width:auto;">
        </a>
        <ul class="nav-links">
            <li><a href="#inicio">Inicio</a></li>
            <li><a href="#nosotros">Nosotros</a></li>
            <li><a href="#sostenibilidad">Sostenibilidad</a></li>
            <li><a href="#empleo">Únete</a></li>
        </ul>
    </nav>
</header>


    <!-- ===== HERO CON VIDEO ===== -->
    <section class="hero" id="inicio">
        <video class="hero-video" autoplay muted loop playsinline>
            <source src="recursos/video1.mp4" type="video/mp4">
        </video>
        <div class="hero-overlay"></div>
        <div class="hero-content">
            <h1>Somos una empresa de alimentos orgullosamente boliviana</h1>
            <p>Nuestro compromiso es con nuestros colaboradores, las familias bolivianas y nuestro entorno.</p>
        </div>
    </section>

    <!-- ===== NOSOTROS ===== -->
    <div class="container">
        <section class="section" id="nosotros">
            <h2>¿Quiénes somos?</h2>
            <p>Nacimos hace más de 40 años como un pequeño emprendimiento familiar. Con el paso del tiempo y mucha dedicación fuimos creciendo para convertirnos en un referente dentro de la industria de alimentos en Bolivia.</p>
        </section>

        <!-- ===== CARDS CON FONDOS ===== -->
        <div class="cards-grid">
            <div class="card card-bg-1">
                <div class="card-content">
                    <h3>Sostenibilidad</h3>
                    <p>Te invitamos a conocer los pasos que estamos dando para construir un futuro más sostenible y comprometido con el bienestar de todos.</p>
                </div>
            </div>

            <div class="card card-bg-2">
                <div class="card-content">
                    <h3>Únete al equipo</h3>
                    <p>En Sofía apostamos por personas como tú dispuestas a aportar creatividad, iniciativa y agilidad. Ven y conoce las opciones de desarrollo profesional que te brindamos.</p>
                </div>
            </div>

            <div class="card card-bg-3">
                <div class="card-content">
                    <h3>Nuestro Compromiso</h3>
                    <p>Acepta el reto de formar parte de una de las empresas líderes en su rubro, con más de 47 años de trayectoria en Bolivia.</p>
                </div>
            </div>
        </div>
    </div>

    <!-- ===== IMAGE BANNER ===== -->
    <div class="image-banner">
        <h2>Nuestras marcas, tus aliados</h2>
    </div>

    <!-- ===== STATS ===== -->
    <section class="stats">
        <div class="stats-grid">
            <div class="stat-item">
                <div class="stat-content">
                    <h3>+3000</h3>
                    <p>Colaboradores creciendo juntos</p>
                </div>
            </div>
            <div class="stat-item">
                <div class="stat-content">
                    <h3>+47</h3>
                    <p>Años aportando valor agregado y economía local</p>
                </div>
            </div>
            <div class="stat-item">
                <div class="stat-content">
                    <h3>+30000</h3>
                    <p>Empleos indirectos a nivel nacional</p>
                </div>
            </div>
        </div>
    </section>

    <!-- ===== CTA ===== -->
    <section class="cta" id="empleo">
        <div class="container">
            <h2>¿Listo para formar parte de nuestro equipo?</h2>
            <p>Únete a una empresa que valora tu talento y compromiso</p>
            <a href="#" class="cta-button">Postúlate Ahora</a>
        </div>
    </section>

    <!-- ===== VIDEO DE CIERRE ===== -->
    <section class="closing-video">
        <video autoplay muted loop playsinline>
            <source src="recursos/video2.mp4" type="video/mp4">
        </video>
        <div class="closing-video-overlay"></div>
        <div class="closing-video-content">
            <h2>Gracias por visitarnos</h2>
        </div>
    </section>
    <a href="login.php" class="login-float" title="Iniciar sesión">
        &#128100; <!-- ícono de persona simple -->
    </a>

    <!-- ===== FOOTER ===== -->
    <footer>
        <p>&copy; 2024 Avícola Sofia Plus. Todos los derechos reservados.</p>
        <p>Empresa boliviana de alimentos</p>
        <div class="social-links">
            <a href="https://www.facebook.com/SofiaAlPaso" target="_blank">Facebook</a> |
            <a href="https://www.instagram.com/sofia_al_paso" target="_blank">Instagram</a> |
            <a href="https://www.tiktok.com/@sofiaalpaso" target="_blank">TikTok</a> |
            <a href="https://bo.linkedin.com/company/sofia-ltda" target="_blank">LinkedIn</a>
        </div>
    </footer>


</body>
</html>
