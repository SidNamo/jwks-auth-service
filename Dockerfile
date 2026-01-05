# Start with a lightweight Python 3.11 image
FROM python:3.11.10

# Set the working directory in the container to /app
WORKDIR /app

# Copy only the necessary files to leverage Docker caching for dependencies
COPY pyproject.toml poetry.lock /app/

# Install Poetry
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/* \
    && pip install poetry \
    && poetry config virtualenvs.in-project true \
    && poetry install --no-root

# Copy the entire project into the container
COPY . /app

# Set environment to deployment (Docker compose 에서 관리)
# ENV ENVIRONMENT=loc

# Command to start the FastAPI app without running alembic upgrade
# 마지막 root path 를 실제 traefik 의 root path 와 맞춰줘야 함.
CMD ["poetry", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "80", "--root-path", "/fastapi1"]