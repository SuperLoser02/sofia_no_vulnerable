FROM php:8.2-apache

# Instalar extensiones necesarias para PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Habilitar mod_rewrite de Apache
RUN a2enmod rewrite

# Establecer el directorio de trabajo
WORKDIR /var/www/html

# Copiar archivos de configuración de Apache si es necesario
COPY apache-config.conf /etc/apache2/sites-available/000-default.conf

# Cambiar permisos
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html

# Exponer puerto 80
EXPOSE 80
