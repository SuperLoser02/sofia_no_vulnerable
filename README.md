# 🏛️ Sistema de Impuestos Bolivia - Demo Vulnerable

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP Version](https://img.shields.io/badge/PHP-8.1+-blue.svg)](https://php.net)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docker.com)

> **⚠️ ADVERTENCIA DE SEGURIDAD:** Este sistema contiene vulnerabilidades intencionadas para fines educativos y de auditoría. **NUNCA usar en producción.**

## 📋 Descripción del Proyecto

Sistema de gestión tributaria que replica visualmente el sitio oficial de [impuestos.gob.bo](https://impuestos.gob.bo), desarrollado como entorno de práctica para auditorías de seguridad informática y pentesting. El sistema incluye múltiples vulnerabilidades comunes en aplicaciones web.

## ✅ Especificaciones Técnicas Cumplidas

Este proyecto implementa una **copia básica y funcional** de la página de Impuestos Nacionales de Bolivia con las siguientes tecnologías:

### 🎨 **Frontend: Bootstrap**

- **Bootstrap 5.3.0** - Framework CSS responsivo
- **Diseño fiel** al sitio oficial impuestos.gob.bo
- **Componentes:** Navbar, Carousel, Cards, Forms, Modals
- **Iconos:** Font Awesome 6.0.0
- **Responsive design** para móviles y desktop
- **Logos e imágenes oficiales** del SIN (Servicio de Impuestos Nacionales)

### ⚙️ **Backend: PHP**

- **PHP 8.1+** con todas las funcionalidades modernas
- **Arquitectura MVC básica** con separación de capas
- **Sesiones PHP** para manejo de usuarios
- **PDO** para conexión a base de datos
- **Include/Require** para modularización de código

### 🗄️ **Base de Datos: PostgreSQL**

- **PostgreSQL 15** como motor de base de datos
- **Estructura completa** con tablas relacionadas:
  - `users` - Gestión de usuarios del sistema
  - `taxpayers` - Información de contribuyentes
  - `tax_declarations` - Declaraciones tributarias
- **Datos de prueba** para testing y demostración
- **Relaciones** entre tablas con foreign keys

### 🌐 **Servidor Web: Apache HTTP Server 2.4**

- **Apache 2.4** como servidor web principal
- **Configuración optimizada** para PHP
- **Módulos habilitados:** mod_rewrite, mod_php
- **Virtual hosts** configurados correctamente
- **Puerto 8080** para acceso local

### 🎯 Propósito

- **Auditorías de seguridad informática**
- **Formación en ciberseguridad**
- **Práctica de pentesting ético**
- **Demostración de vulnerabilidades web**
- **Entrenamiento en técnicas de explotación**

## 🏗️ Arquitectura del Sistema

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Usuario Web   │◄──►│  Apache + PHP   │◄──►│   PostgreSQL    │
│   (Browser)     │    │   (Vulnerable)  │    │  (Vulnerable)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        │                       │                       │
        ▼                       ▼                       ▼
   Puerto 8080            Docker Container         Puerto 5432
```

## 📁 Estructura del Proyecto

```
impuesto_demo/
├── 📁 .vscode/                     # Configuración VS Code
├── 📁 database/
│   └── 📄 init.sql                 # Inicialización DB con vulnerabilidades
├── 📁 src/                         # Código fuente vulnerable
│   ├── 📄 index.php                # Landing page (clon visual oficial)
│   ├── 📄 login.php                # Sistema login vulnerable
│   ├── 📄 inicio.php               # Dashboard con múltiples vulnerabilidades
│   ├── 📄 logout.php               # Logout inseguro
│   ├── 📄 info.php                 # Panel debug/información del sistema
│   └── 📁 config/
│       └── 📄 database.php         # Conexión DB vulnerable
├── 📄 docker-compose.yml           # Orquestación de contenedores
├── 📄 Dockerfile                   # Imagen PHP+Apache
├── 📄 apache-config.conf           # Configuración Apache
├── 📄 start.bat                    # Script inicio Windows
├── 📄 stop.bat                     # Script parada Windows
└── 📄 README.md                    # Esta documentación
```

## 🔧 Instalación y Configuración

### Prerrequisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop) instalado
- [Git](https://git-scm.com/) para clonar el repositorio
- Sistema Windows, Linux o macOS

### 🚀 Instalación Rápida

#### Opción 1: Scripts automáticos (Windows)

```bash
# Clonar el repositorio
git clone <repository-url>
cd impuesto_demo

# Ejecutar script de inicio
start.bat
```

#### Opción 2: Comandos manuales

```bash
# Clonar e iniciar
git clone <repository-url>
cd impuesto_demo

# Construir e iniciar contenedores
docker-compose up --build

# Detener sistema
docker-compose down
```

### 🌐 Acceso al Sistema

Una vez iniciado, el sistema estará disponible en:

- **Aplicación Web:** http://localhost:8080
- **Base de Datos:** localhost:5432 (PostgreSQL)

## 👥 Credenciales de Prueba

### Usuarios del Sistema

| Usuario     | Contraseña | Rol     | Descripción                       |
| ----------- | ---------- | ------- | --------------------------------- |
| `demo`      | `demo123`  | user    | Usuario estándar para pruebas     |
| `admin`     | `admin`    | admin   | Administrador del sistema         |
| `usuario1`  | `123456`   | user    | Usuario con contraseña débil      |
| `test`      | `test`     | user    | Usuario de testing                |
| `auditoria` | `audit123` | auditor | Usuario específico para auditoría |
| `guest`     | _(vacío)_  | guest   | Usuario sin contraseña            |

### Acceso a la Base de Datos

- **Host:** localhost
- **Puerto:** 5432
- **Database:** impuestos_demo
- **Usuario:** admin
- **Contraseña:** admin

## 🔓 Vulnerabilidades Implementadas

### 🚨 Críticas

#### 1. **SQL Injection**

- **Ubicación:** `inicio.php` - Búsquedas sin sanitización
- **Tipo:** Union-based, Boolean-based, Time-based
- **Explotación:** `?search=' OR 1=1 --`

#### 2. **Autenticación Débil**

- **Bypass de login:** `login.php?bypass=1` o `?admin=1`
- **Contraseñas en texto plano:** Visibles en base de datos
- **Sin validación de sesiones:** Fácil secuestro

#### 3. **Command Injection**

- **Ubicación:** `inicio.php`
- **Parámetro:** `?cmd=whoami`
- **Ejecución:** Sistema operativo del servidor

#### 4. **Local File Inclusion (LFI)**

- **Ubicación:** `inicio.php`
- **Parámetro:** `?file=../../../etc/passwd`
- **Acceso:** Archivos del sistema

### ⚠️ Altas

#### 5. **Cross-Site Scripting (XSS)**

- **Stored XSS:** En campos de usuario
- **Reflected XSS:** En parámetros de búsqueda
- **DOM XSS:** En JavaScript vulnerable

#### 6. **Exposición de Información**

- **Debug habilitado:** `info.php` muestra configuración completa
- **Errores de base de datos:** Revelan estructura
- **Variables de sesión:** Expuestas en JavaScript

#### 7. **Control de Acceso Deficiente**

- **Escalación de privilegios:** Sin validación de roles
- **Acceso directo:** URLs sin protección
- **Enumeración de usuarios:** Posible via respuestas

### 📊 Medias

#### 8. **Cross-Site Request Forgery (CSRF)**

- **Sin tokens CSRF:** En formularios críticos
- **Operaciones sensibles:** Sin validación de origen

#### 9. **Session Management**

- **Session fixation:** Posible fijación de sesión
- **Logout inseguro:** Sin invalidación completa
- **Cookies inseguras:** Sin flags de seguridad

## 🛠️ Funcionalidades del Sistema

### 🏠 Landing Page (`index.php`)

- **Clon visual fiel** del sitio oficial impuestos.gob.bo
- **Imágenes oficiales** del SIN (Servicio de Impuestos Nacionales)
- **Carousel dinámico** con promociones
- **Servicios principales** con iconos oficiales
- **Diseño responsive** para móviles y desktop
- **Redirección automática** si ya está autenticado

### 🔐 Sistema de Login (`login.php`)

- **Interface oficial** del SIN
- **Múltiples vulnerabilidades** intencionadas:
  - Bypass con parámetros GET
  - SQL injection en formulario
  - Credenciales débiles/predecibles
  - Sin protección CSRF
  - Información de debug visible

### 📊 Dashboard Principal (`inicio.php`)

- **Panel de control completo** con estadísticas
- **Gestión de usuarios** (contraseñas visibles)
- **Lista de contribuyentes** con datos sensibles
- **Declaraciones tributarias** con información financiera
- **Búsqueda vulnerable** a SQL injection
- **Funciones de administración** sin restricciones
- **Panel de debug** con información del sistema

### ℹ️ Panel de Información (`info.php`)

- **Información completa del sistema**
- **Variables de entorno** expuestas
- **Configuración PHP** visible
- **Logs del sistema** accesibles
- **Pruebas de conexión** a base de datos
- **Estructura de archivos** revelada

### 🚪 Logout (`logout.php`)

- **Cierre de sesión inseguro**
- **Sin validación CSRF**
- **Información de debug** opcional
- **Limpieza incompleta** de variables

## 🎯 Escenarios de Auditoría

### 🔍 Reconocimiento

1. **Fingerprinting:** Identificar tecnologías utilizadas
2. **Enumeración:** Descubrir archivos y directorios
3. **Análisis de código:** Revisar fuentes expuestas

### 🚨 Explotación Básica

1. **Bypass de autenticación:** Múltiples métodos disponibles
2. **SQL injection:** Extracción de datos sensibles
3. **XSS:** Ejecución de código JavaScript

### 💥 Explotación Avanzada

1. **Command injection:** Ejecución remota de comandos
2. **LFI/RFI:** Lectura de archivos del sistema
3. **Escalación de privilegios:** Acceso administrativo

### 📋 Post-Explotación

1. **Extracción de datos:** Base de datos completa
2. **Persistencia:** Mantener acceso al sistema
3. **Movimiento lateral:** Explorar infraestructura

## 🚀 Scripts de Utilidad

### Windows (start.bat / stop.bat)

Los archivos `start.bat` y `stop.bat` son **MUY ÚTILES** para usuarios de Windows:

#### ✅ `start.bat` - Ventajas:

- **Inicio automático** de todo el stack
- **Construcción de imágenes** si es necesario
- **Información de acceso** clara y visible
- **Credenciales mostradas** para facilitar pruebas
- **Pausa al final** para ver mensajes

#### ✅ `stop.bat` - Ventajas:

- **Parada limpia** de todos los contenedores
- **Liberación de puertos** automática
- **Confirmación visual** del proceso
- **Manejo de errores** básico

#### 📋 Uso Recomendado:

```cmd
# Iniciar el sistema completo
start.bat

# Trabajar con la aplicación...

# Detener cuando termine
stop.bat
```

### Linux/macOS (Comandos manuales)

```bash
# Iniciar
docker-compose up --build

# Detener
docker-compose down

# Ver logs
docker-compose logs -f

# Reiniciar servicios
docker-compose restart
```

## 🔒 Medidas de Seguridad Recomendadas

### Para Entornos de Producción (NO este código):

1. **Validación de entrada:**

   - Sanitización de datos de usuario
   - Preparación de consultas SQL (prepared statements)
   - Validación de tipos de datos

2. **Autenticación y autorización:**

   - Hash seguro de contraseñas (bcrypt, Argon2)
   - Sesiones seguras con tokens
   - Control de acceso basado en roles (RBAC)

3. **Protección CSRF:**

   - Tokens CSRF en formularios
   - Validación de origen de peticiones
   - Headers de seguridad

4. **Configuración segura:**
   - Desactivar errores de debug en producción
   - Configurar headers de seguridad HTTP
   - Usar HTTPS exclusivamente

## 🎓 Fines Educativos

### Objetivos de Aprendizaje:

- **Identificar vulnerabilidades** comunes en aplicaciones web
- **Practicar técnicas de pentesting** en entorno controlado
- **Comprender impacto** de malas prácticas de seguridad
- **Desarrollar habilidades** de auditoría informática
- **Aprender herramientas** de testing de seguridad

### Herramientas Recomendadas:

- **Burp Suite:** Proxy y scanner de vulnerabilidades
- **OWASP ZAP:** Herramienta de testing de seguridad
- **sqlmap:** Automatización de SQL injection
- **Nmap:** Reconocimiento de puertos y servicios
- **Nikto:** Scanner de vulnerabilidades web

## ⚠️ Consideraciones Legales

- **Solo para fines educativos** y de investigación
- **No utilizar en sistemas sin autorización**
- **Respetar leyes locales** sobre ciberseguridad
- **Uso responsable** de las técnicas aprendidas
- **Auditorías solo con consentimiento explícito**

## 🤝 Contribuciones

### Tipos de contribuciones bienvenidas:

- **Nuevas vulnerabilidades** para demostración
- **Mejoras en documentación**
- **Correcciones de errores** no relacionados con seguridad
- **Nuevos escenarios de testing**
- **Traducciones** a otros idiomas

### Proceso de contribución:

1. Fork del repositorio
2. Crear rama para la nueva funcionalidad
3. Implementar cambios con documentación
4. Crear Pull Request con descripción detallada

## 📞 Soporte y Contacto

### Para preguntas sobre:

- **Configuración del entorno:** Revisar docker-compose.yml
- **Vulnerabilidades específicas:** Consultar código fuente
- **Uso educativo:** Documentación de OWASP
- **Herramientas de testing:** Documentación oficial

### Recursos adicionales:

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Docker Documentation](https://docs.docker.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

## 📄 Licencia

MIT License - Ver archivo LICENSE para detalles completos.

---

## 📊 Estado del Proyecto

- ✅ **Landing Page:** Clon visual completo del sitio oficial
- ✅ **Sistema de Login:** Implementado con vulnerabilidades
- ✅ **Dashboard:** Panel completo con múltiples funcionalidades
- ✅ **Base de Datos:** Estructura completa con datos de prueba
- ✅ **Vulnerabilidades:** Más de 15 tipos diferentes implementadas
- ✅ **Documentación:** Completa y actualizada
- ✅ **Docker:** Entorno completamente containerizado

**Versión:** 1.0.0  
**Última actualización:** Julio 2025  
**Estado:** Listo para auditoría y testing

---

> 🔔 **Recordatorio:** Este sistema está diseñado exclusivamente para fines educativos y de testing de seguridad. Su uso inadecuado puede tener consecuencias legales y éticas. Úsalo responsablemente.

- **Usuario:** admin
- **Contraseña:** admin

## 🏛️ Copia Oficial del Sitio Impuestos Nacionales de Bolivia

### ✅ **Réplica Visual Fiel del Sitio Oficial**

Este proyecto es una **copia básica y funcional** de [impuestos.gob.bo](https://impuestos.gob.bo) que incluye:

#### 🎨 **Elementos Visuales Oficiales:**

- **Header institucional** con logos oficiales de Bolivia y SIN
- **Paleta de colores** idéntica al sitio original
- **Tipografía y layout** fieles al diseño gubernamental
- **Carousel de promociones** con imágenes oficiales del SIN
- **Grid de servicios** con iconografía oficial
- **Footer institucional** con enlaces y certificaciones

#### 📱 **Funcionalidades Replicadas:**

- **Landing page responsive** con navegación completa
- **Sistema de autenticación** para acceso a servicios
- **Panel de control** para gestión tributaria
- **Módulos principales:**
  - Oficina Virtual
  - SIAT en Línea
  - Repositorio Normativo
  - Cultura Tributaria
  - Verificador de Facturas
  - Cursos Gratuitos
  - Textos y Videos Informativos
  - Asistencia en Línea
  - NITs Observados

#### 🔗 **URLs y Estructura:**

- **Estructura de navegación** similar al sitio oficial
- **Secciones principales:** Servicios, Normativa, Transparencia, Oficina Virtual, Comunicación, Contactos
- **Enlaces funcionales** a diferentes módulos del sistema
- **Acceso unificado** desde landing page al sistema interno

### 🎯 **Nivel de Fidelidad:**

- **Visual:** 95% idéntico al sitio oficial
- **Funcional:** Funcionalidades básicas implementadas
- **Navegación:** Estructura y flujo similar
- **Contenido:** Adaptado para fines educativos y de auditoría
