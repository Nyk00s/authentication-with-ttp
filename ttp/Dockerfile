FROM python:3.14-slim
WORKDIR /app
ENV PYTHONPATH=/app
COPY ./ttp/* ./ttp/
COPY generator.py .
COPY requirements.txt .
RUN pip install -r requirements.txt
EXPOSE 9000
CMD ["python",  "ttp/ttp.py"]