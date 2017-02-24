FROM python:2.7

RUN apt-get update && apt-get install -y \
        locales \
        libsasl2-dev \
        python-dev \
        libldap2-dev \
        libssl-dev \
        sqlite3 \
    && apt-get clean && rm -rf /var/lib/apt/lists/

RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    /usr/sbin/update-locale

ENV LC_ALL en_US.UTF-8

ADD docker_requirements.txt /app/docker_requirements.txt

WORKDIR /app/

RUN pip install -r docker_requirements.txt

COPY . /app/

# Install the database
RUN sqlite3 /tmp/base.db < base_schema.sql

CMD ["bash", "run_server_dev.sh"]
