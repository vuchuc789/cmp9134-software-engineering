FROM python:3.13


WORKDIR /code


COPY ./requirements.txt /code/requirements.txt


RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt


COPY ./src /code/app

EXPOSE 5000

ENV ENV=prod
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=5000

CMD ["python", "app/main.py"]
