# WRAITH Cell — Docker Deployment
# One container = one cell. Lightweight, portable, unkillable.
FROM python:3.11-slim

LABEL maintainer="WRAITH Security <wraith@wraith.one>"
LABEL version="1.0.0"
LABEL description="WRAITH Cell — AI Security Organism"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV WRAITH_HOME=/opt/wraith

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create WRAITH directory
RUN mkdir -p $WRAITH_HOME/cell $WRAITH_HOME/cell/wraith_agents

# Copy cell code
COPY cell/ $WRAITH_HOME/cell/

# Set working directory
WORKDIR $WRAITH_HOME/cell

# Run WRAITH Cell
CMD ["python", "cell_core.py"]
