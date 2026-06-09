# Contributing to cwe-admin

Thanks for your interest! This is an early-stage project; the contributor
workflow will be expanded in P7.

## Dev setup

Two equally-supported paths — pick one:

### Native (host)
1. Install Apache + PHP 8.1+ + PostgreSQL 14+ + composer + node
2. `composer install && npm install && npm run build`
3. `vendor/bin/phinx migrate && vendor/bin/phinx seed:run`
4. Configure Apache vhost (see `docker/apache/cwe-admin.conf.template`)

### Docker
1. `docker compose up -d`
2. `docker compose exec php composer install`
3. `docker compose exec php vendor/bin/phinx migrate`
4. `docker compose exec php vendor/bin/phinx seed:run`

## Workflow

5. `composer test` runs PHPUnit
6. `composer stan` runs PHPStan (level 8)
7. `composer psalm` runs Psalm
8. `npm run build` produces `public/assets/`

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.
