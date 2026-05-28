FROM python:3.14-slim
WORKDIR /app
ENV PYTHONPATH=/app
COPY ./server/* ./server/
COPY generator.py .
COPY requirements.txt .
RUN pip install -r requirements.txt
EXPOSE 9001
CMD ["python", "server/server.py"]