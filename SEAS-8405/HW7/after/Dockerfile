FROM python:3.12-alpine

# Install nginx and dependencies
RUN apk add --no-cache nginx && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and nginx config
COPY . .
COPY nginx.conf /etc/nginx/nginx.conf

# Create necessary directories and assign correct ownership
RUN mkdir -p /run/nginx && \
    chown -R appuser:appgroup /app /var/lib/nginx /var/log/nginx /run/nginx

# Switch to non-root user
USER appuser

EXPOSE 15000

# Start both nginx and flask (note: no process supervision)
CMD ["sh", "-c", "nginx && python app.py"]