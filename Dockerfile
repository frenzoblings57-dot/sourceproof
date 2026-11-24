FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY sourceproof.py openapi.json README.md ./
# Run unprivileged: the service fetches third-party pages and must not hold root.
RUN useradd --system --no-create-home --uid 10001 sourceproof
USER sourceproof
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import sys,urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]
CMD ["python3", "sourceproof.py", "--host", "0.0.0.0", "--port", "8080"]
