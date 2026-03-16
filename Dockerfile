FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (cppcheck is optional but useful when available)
RUN apt-get update \
    && apt-get install -y --no-install-recommends cppcheck curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel_agent/ sentinel_agent/
COPY sentinel_run.py ./sentinel_run.py
COPY samples/ samples/

EXPOSE 8000

CMD ["uvicorn", "sentinel_agent.api:app", "--host", "0.0.0.0", "--port", "8000"]
