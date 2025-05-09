FROM python:3.12-alpine

RUN apk add --no-cache nginx && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY nginx.conf /etc/nginx/nginx.conf

RUN chown -R appuser:appgroup /app && \
    chown -R appuser:appgroup /var/lib/nginx && \
    chown -R appuser:appgroup /var/log/nginx

USER appuser

EXPOSE 80

CMD ["sh", "-c", "nginx && python app.py"]
