FROM python:3.10-slim

WORKDIR /agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY inference.py .

CMD ["python", "inference.py"]