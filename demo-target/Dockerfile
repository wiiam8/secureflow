# Old base image on purpose, so Trivy has OS package vulnerabilities to report.
FROM python:3.9-slim-buster
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 5000
CMD ["python", "-m", "app.main"]
