# ---------- Stage 1: Builder ----------
FROM python:3.13-alpine AS builder

# Install build dependencies
RUN apk add --no-cache build-base

# Set workdir
WORKDIR /install

# Copy requirements and install to a temp directory
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/deps -r requirements.txt


# ---------- Stage 2: Runtime ----------
FROM python:3.13-alpine

# Install runtime dependencies
RUN apk add --no-cache nginx wget && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

# Set workdir
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install/deps /usr/local

# Copy app and config
COPY . .
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh

# Set correct ownership for nginx and app files
RUN chmod +x /entrypoint.sh && \
    mkdir -p /var/lib/nginx /var/log/nginx /run/nginx && \
    chown -R appuser:appgroup /app /var/lib/nginx /var/log/nginx /run /entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port for nginx to listen
EXPOSE 15000

# Health check to ensure app is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1:15000/ || exit 1

# Start both nginx and Flask
ENTRYPOINT ["/entrypoint.sh"]