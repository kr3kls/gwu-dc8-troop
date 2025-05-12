# Use an official Python runtime as a parent image
FROM python:3.13-alpine AS base

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Create a non-root user and group for security
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

# Install runtime dependencies
RUN apk add --no-cache nginx wget

# Copy only requirements.txt first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh

# Set correct ownership for nginx and app files
RUN chmod +x /entrypoint.sh && \
    mkdir -p /var/lib/nginx /var/log/nginx /run/nginx && \
    chown -R appuser:appuser /app /var/lib/nginx /var/log/nginx /run /entrypoint.sh

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the port the app runs on (Gunicorn will bind to this)
EXPOSE 5000

# Start both nginx and Flask
ENTRYPOINT ["/entrypoint.sh"]
