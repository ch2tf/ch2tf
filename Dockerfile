FROM python:3.11-buster
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
COPY docker_entrypoint.sh /usr/src/app/

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /usr/src/app

ENTRYPOINT ["sh", "/usr/src/app/docker_entrypoint.sh"]
