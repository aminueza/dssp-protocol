FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir psutil requests

COPY dsp_sidecar/ dsp_sidecar/

ENTRYPOINT ["python", "-m", "dsp_sidecar.main"]
