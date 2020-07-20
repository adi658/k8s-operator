FROM python:3.5.2

ENV TZ=Asia/Shanghai

RUN apt-get update \
    && apt-get install -y cron \
    && apt-get autoremove -y

COPY ./cronpy /etc/cron.d/cronpy
CMD ["cron", "-f"]
