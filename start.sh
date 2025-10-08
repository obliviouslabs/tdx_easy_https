#!/bin/sh
export ACME_EMAIL="username@example.com"
export SERVER_DOMAIN="www.example.com"

docker-compose pull
docker-compose build
docker-compose up -d