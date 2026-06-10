FROM php:8.1-fpm-alpine

RUN apk add --no-cache \
        postgresql-dev \
        oniguruma-dev \
        icu-dev \
        libzip-dev \
        zlib-dev \
        bash \
    && docker-php-ext-install \
        pdo \
        pdo_pgsql \
        mbstring \
        intl \
        opcache \
    && rm -rf /var/cache/apk/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/zz-app.conf

USER www-data
