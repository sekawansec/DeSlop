FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install --with-deps chromium
COPY src ./src
COPY pyproject.toml README.md LICENSE NOTICE ./
RUN pip install --no-cache-dir -e . --no-deps

ENV DESLOP_CONFIG_DIR=/app/config/programs
EXPOSE 8000
CMD ["uvicorn", "deslop.web.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
