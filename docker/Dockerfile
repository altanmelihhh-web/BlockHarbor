FROM php:8.5-fpm-alpine

# PHP extensions + build deps for composer + npm asset pipeline
RUN apk add --no-cache \
        postgresql-dev \
        oniguruma-dev \
        icu-dev \
        libzip-dev \
        zlib-dev \
        bash \
        git \
        unzip \
        nodejs \
        npm \
    && docker-php-ext-install \
        pdo \
        pdo_pgsql \
        mbstring \
        intl \
        opcache \
        zip \
    && rm -rf /var/cache/apk/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Dependency layer (cached unless composer/npm manifests change)
COPY composer.json composer.lock package.json package-lock.json ./
RUN composer install --no-dev --optimize-autoloader --no-scripts --no-interaction \
    && npm ci --no-audit --no-fund

# Source layer
COPY . .

# Build assets, drop node_modules to keep the runtime image small
RUN npm run build \
    && rm -rf node_modules \
    && chown -R www-data:www-data /app

COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/zz-app.conf

USER www-data
