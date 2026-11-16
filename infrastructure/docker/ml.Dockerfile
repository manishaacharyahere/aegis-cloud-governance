# Aegis ML worker: anomaly detection and forecasting on a schedule.
FROM python:3.13.17-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY ml/pyproject.toml ./
COPY ml/aegis_ml ./aegis_ml
RUN pip install . && useradd --uid 10001 --no-create-home aegis
USER 10001
ENTRYPOINT ["python", "-m", "aegis_ml.worker"]
