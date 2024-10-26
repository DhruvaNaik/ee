# Start from a base Python image that GitHub recommends
FROM mcr.microsoft.com/vscode/devcontainers/python:3.9

# Install build-essential tools and other dependencies
RUN apt-get update && \
    apt-get install -y build-essential libffi-dev libssl-dev

# Install necessary Python packages and upgrade pip
RUN pip install --upgrade pip && \
    pip install pycryptodome oqs-python

# Set the working directory inside the container
WORKDIR /workspace

# Set up a virtual environment (recommended to keep dependencies isolated)
RUN python3 -m venv /workspace/crypto_env

# Activate the virtual environment and install the necessary Python packages
RUN /bin/bash -c "source /workspace/crypto_env/bin/activate && \
    pip install --upgrade pip && \
    pip install pycryptodome oqs-python"

# By default, open a bash shell in the container
CMD [ "bash" ]
