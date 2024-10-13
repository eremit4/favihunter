FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.cargo/bin
ENV UV_PYTHON=3.11

# Install required packages and uv python package manager
RUN apt update && apt install curl -y --no-install-suggests && curl --proto '=https' --tlsv1.2 -LsSf https://github.com/astral-sh/uv/releases/download/0.4.20/uv-installer.sh | sh && uv python install $UV_PYTHON

# Copy the source code to the container
COPY . /app

# Set the working directory
WORKDIR /app

# Install the required packages
RUN uv sync

# Run the application
ENTRYPOINT ["uv", "run", "/app/favihunter.py"]