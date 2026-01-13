# Use official Python slim image for smaller size
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements first (cache layer)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ src/

# Expose port 8000
EXPOSE 8000

# Run the server
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]