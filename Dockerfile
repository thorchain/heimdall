FROM python:3.8-slim
WORKDIR /app
ENV PYTHONPATH /app

RUN apt-get update && apt-get install -y libsecp256k1-0 build-essential

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
