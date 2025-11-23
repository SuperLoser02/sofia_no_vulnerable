@echo off
echo ====================================
echo  Deteniendo Sistema de Impuestos Demo
echo ====================================
echo.

REM Verificar si Docker está ejecutándose
docker --version >nul 2>&1
if errorlevel 1 (
    echo ADVERTENCIA: Docker no parece estar ejecutándose.
    echo Los contenedores podrían ya estar detenidos.
    echo.
)

echo Deteniendo y removiendo contenedores...
docker-compose down

echo.
echo Limpiando recursos (opcional)...
echo ¿Deseas eliminar también las imágenes y volúmenes? (s/N)
set /p cleanup="Respuesta: "

if /i "%cleanup%"=="s" (
    echo Eliminando imágenes del proyecto...
    docker-compose down --rmi all --volumes --remove-orphans
    echo Limpieza completa realizada.
) else (
    echo Solo se detuvieron los contenedores.
    echo Las imágenes se mantienen para inicio más rápido.
)

echo.
echo ====================================
echo  Sistema detenido correctamente
echo ====================================
echo.
echo Para reiniciar, ejecuta: start.bat
echo.
pause
