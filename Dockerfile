FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash mcpuser

# Create data directory for SQLite (auth database)
RUN mkdir -p /app/data && chown mcpuser:mcpuser /app/data

# Copy the rest of the application
COPY . /app/

USER mcpuser

# Expose port for HTTP transport
EXPOSE 8080

# Health check (python-based, no curl needed in slim image)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run with HTTP transport (Streamable HTTP)
CMD ["python", "docketbird_mcp.py", "--transport", "http", "--host", "0.0.0.0", "--port", "8080"]
