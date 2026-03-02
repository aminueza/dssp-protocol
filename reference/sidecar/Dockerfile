FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir psutil requests

COPY dssp_sidecar/ dssp_sidecar/

ENTRYPOINT ["python", "-m", "dssp_sidecar.main"]
