FROM python:3.6.15 

WORKDIR /innometrics-backend

COPY . .
RUN pip install setuptools==57.1
RUN pip install -r requirements.txt

ENV INNOMETRICS_BACKEND_PATH "/innometrics-backend"
ENV PYTHONPATH "${PYTHONPATH}:${INNOMETRICS_BACKEND_PATH}:${INNOMETRICS_BACKEND_PATH}/api:${INNOMETRICS_BACKEND_PATH}/db"

CMD ["python3", "api/app.py"]