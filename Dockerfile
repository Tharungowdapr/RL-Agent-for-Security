# Stage 1: Build the React frontend
FROM node:18 AS frontend-builder
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Build the FastAPI backend
FROM python:3.11-slim

# Hugging Face Spaces require running as a non-root user (uid 1000)
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# Copy requirements and install
COPY --chown=user:user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all python source
COPY --chown=user:user . .

# Copy built frontend from Stage 1 into the location the python server expects
COPY --from=frontend-builder --chown=user:user /frontend/dist ./frontend/dist

# Ensure the threat intel cache directory exists and is writable
RUN mkdir -p threat_intel/cache

# Pre-fetch the CVE data dictionary so it's backed into the image
RUN python -c "from threat_intel.cve_loader import load_cves; load_cves()" || true

# Hugging Face Spaces expose port 7860
EXPOSE 7860

# Start Uvicorn
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "7860"]
