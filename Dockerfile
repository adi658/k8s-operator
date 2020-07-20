FROM python:3.7

RUN apt-get update
RUN apt-get install -y nano cron

RUN pip install requests pyyaml pyopenssl simplejson
RUN pip install kubernetes

COPY python/entrypoint.py /entrypoint.py
COPY python/sectigo_pycert.py /sectigo_pycert.py
COPY python/t.py /t.py
RUN chmod +x /t.py 


# RUN touch /var/log/cron.log
# RUN crontab -l | { cat; echo "*/1 * * * * touch ~/ccc"; } | crontab -

ADD renew-cron /root/
RUN crontab /root/renew-cron
RUN touch /var/log/cron.log
# RUN service cron start
# RUN /etc/init.d/cron start 

ENTRYPOINT service cron start && python /entrypoint.py && tail -f /dev/null