# How to use wavecrack with docker

Docker can be used to avoid the need of a full VM with all the dependencies
installed. This guide helps to setup a working environment to develop locally.
Half of the instructions here can be useful for non-Docker users.

## Installation

Head to https://docs.docker.com/engine/installation/windows/.

To avoid proxy headaches, you can chose to add the following line to your
`C:\Windows\System32\drivers\etc\hosts` file:

    192.168.99.100    localdocker

This assume the IP of the Docker-machine you are running is 192.168.99.100. You
can check it with:

    docker-machine.exe ip

## Setting up the server

Create the `app_settings.py` (from the example). In `app_settings.py`, you'll need to set the DEBUG flag and the RabbitMQ address:

    # Display errors
    DEBUG = True
    # Address of the RabbitMQ server
    celery_broker_url='amqp://guest:guest@rabbit:5672//'

Then, it's quite easy:

    # In the code folder
    docker-compose.exe up

This should spawn the necessary docker containers. You can confirm the RabbitMQ
server is running by going to http://192.168.99.100:15672/ (user: guest, no
password or same as username).

Then, head to http://192.168.99.100:5000/.

You can restart or stop the containers:

    docker-compose.exe restart
    docker-compose.exe stop
