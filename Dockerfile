FROM python:3.8-alpine

COPY requirements.txt .
RUN apk add gcc musl-dev python3-dev libffi-dev openssl-dev

RUN pip install -r requirements.txt
