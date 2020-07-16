FROM python:3.7

COPY python/entrypoint.py /entrypoint.py
COPY python/sectigo_pycert.py /sectigo_pycert.py

RUN pip install requests pyyaml pyopenssl simplejson
RUN pip install kubernetes

ENTRYPOINT python /entrypoint.py && tail -f /dev/null
