@echo off
echo ====================================
echo  Sistema de Impuestos Demo
echo ====================================
echo.
echo Verificando Docker...

REM Verificar si Docker está ejecutándose
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker no está instalado o no está ejecutándose.
    echo Por favor, inicia Docker Desktop y vuelve a intentar.
    pause
    exit /b 1
)

echo Docker detectado correctamente.
echo.
echo Iniciando contenedores...
echo (Primera vez puede tardar varios minutos en descargar imágenes)
echo.

REM Ejecutar docker-compose con build automático
docker-compose up --build

echo.
echo ====================================
echo  ACCESO AL SISTEMA
echo ====================================
echo.
echo URL: http://localhost:8080
echo.
echo CREDENCIALES DE PRUEBA:
echo Usuario: demo     ^| Password: demo123
echo Usuario: admin    ^| Password: admin
echo Usuario: test     ^| Password: test
echo.
echo Base de Datos:
echo Host: localhost:5432
echo DB: impuestos_demo ^| User: admin ^| Pass: admin
echo.
echo Presiona Ctrl+C para detener el sistema
echo o cierra esta ventana y ejecuta stop.bat
echo.
pause
