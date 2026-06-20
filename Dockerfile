FROM php:8.1-apache

# Install PHP extensions + system tools
RUN apt-get update && apt-get install -y \
        libzip-dev libicu-dev libxml2-dev libonig-dev \
        zip unzip git curl \
    && docker-php-ext-install zip intl mbstring xml \
    && rm -rf /var/lib/apt/lists/*

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Apache modules
RUN a2enmod rewrite headers alias

# Apache vhost — serves app at /blacklist/cyberwebeyeos/ (matches hardcoded paths)
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf

WORKDIR /var/www/html

# Install PHP deps (separate layer for cache)
COPY composer.json ./
RUN composer install --no-dev --optimize-autoloader --no-interaction --no-scripts

# Copy application code
COPY . .

# Permissions
RUN chown -R www-data:www-data /var/www/html \
    && find /var/www/html -type d -exec chmod 755 {} \; \
    && find /var/www/html -type f -exec chmod 644 {} \;

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2-foreground"]
