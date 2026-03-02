FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir requests

COPY demo_agent.py .

CMD ["python", "demo_agent.py"]
