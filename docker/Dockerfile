FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=2 MKL_NUM_THREADS=2
WORKDIR /app
COPY requirements-runtime.txt requirements-runtime.txt
RUN --mount=type=secret,id=proxy_ca,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca REQUESTS_CA_BUNDLE=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir --upgrade pip==26.2.1 && pip install --no-cache-dir -r requirements-runtime.txt
COPY . /app
RUN useradd --no-log-init --uid 10001 --create-home soc && mkdir -p runtime && chown soc:soc runtime && chmod -R a+rX /app/src /app/app /app/configs /app/migrations /app/alembic.ini /app/pyproject.toml
USER 10001:10001
CMD ["uvicorn", "src.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
