FROM python:3.7

RUN pip install requests pyyaml pyopenssl simplejson
RUN pip install kubernetes

COPY python/entrypoint.py /entrypoint.py
COPY python/sectigo_pycert.py /sectigo_pycert.py

ENTRYPOINT python /entrypoint.py && tail -f /dev/null