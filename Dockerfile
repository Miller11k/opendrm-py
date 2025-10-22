FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -U pip && \
    if [ -f requirements.txt ]; then pip install -r requirements.txt; \
    elif [ -f pyproject.toml ]; then pip install .; fi
EXPOSE 8000
CMD ["python", "-m", "drm.main"]
