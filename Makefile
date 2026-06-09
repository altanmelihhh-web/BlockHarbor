.PHONY: install migrate seed test stan psalm audit build dev fresh apache-reload

install:
	composer install --no-progress --prefer-dist
	npm install --no-audit --no-fund

migrate:
	vendor/bin/phinx migrate

seed:
	vendor/bin/phinx seed:run

test:
	vendor/bin/phpunit --colors=always

stan:
	vendor/bin/phpstan analyse

psalm:
	vendor/bin/psalm

audit:
	composer audit

build:
	npm run build

dev:
	npm run dev

apache-reload:
	sudo apachectl configtest && sudo systemctl reload apache2

fresh:
	-vendor/bin/phinx rollback -t 0
	vendor/bin/phinx migrate
	vendor/bin/phinx seed:run
