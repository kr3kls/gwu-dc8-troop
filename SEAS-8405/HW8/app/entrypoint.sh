#!/bin/sh

# Create required nginx runtime directories
mkdir -p /run/nginx
mkdir -p /var/lib/nginx/tmp/client_body
mkdir -p /var/lib/nginx/tmp/fastcgi
mkdir -p /var/lib/nginx/tmp/proxy
mkdir -p /var/lib/nginx/tmp/scgi
mkdir -p /var/lib/nginx/tmp/uwsgi
mkdir -p /var/lib/nginx/logs
mkdir -p /var/log/nginx

# Start nginx and Flask
nginx
python app.py