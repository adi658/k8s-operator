FROM python:3.7
COPY cert.py /cert.py
COPY entrypoint.py /entrypoint.py
# COPY secret-patch-template.json /secret-patch-template.json
# COPY sectigo_ssl.crt /sectigo_ssl.crt
# COPY sectigo_ssl.key /sectigo_ssl.key
RUN pip install requests
RUN pip install kubernetes
ENTRYPOINT python /entrypoint.py && tail -f /dev/null
