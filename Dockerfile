FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV GLINET_LOG_ANALYZER_HOST=0.0.0.0
ENV GLINET_LOG_ANALYZER_PORT=8000
ENV GLINET_LOG_ANALYZER_DATA_DIR=/data

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir .

EXPOSE 8000
VOLUME ["/data"]

CMD ["uvicorn", "glinet_log_analyzer.asgi:app", "--host", "0.0.0.0", "--port", "8000"]
