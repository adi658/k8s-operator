import requests
import subprocess
import os
import json
import logging
import sys
# import cert as c 
import time
import requests
import base64
import os 
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException


import sys 
import glob, os
import shutil
import os,sys,inspect,simplejson
from os import path
from os.path import exists, join, isdir
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir) 
import sectigo_pycert as p

log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
log.addHandler(out_hdlr)
log.setLevel(logging.INFO)


def getToken():
    token = ""
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as file:
        token = file.read().replace('\n', '')
    return token

def getConfiguration():
    ApiToken = getToken()
    configuration = client.Configuration()
    configuration.host = "https://"+os.getenv("KUBERNETES_SERVICE_HOST")+":"+str(os.getenv("KUBERNETES_SERVICE_PORT"))
    configuration.api_key={"authorization":"Bearer "+ ApiToken}
    configuration.verify_ssl=False
    configuration.debug = True
    client.Configuration.set_default(configuration)
    kubeApi = client.CoreV1Api(client.ApiClient(configuration))
    return kubeApi


def getExistingSecret(secretName):
    print(" ------------ getExistingSecret Start ------------")

    # HOST = getHost()
    # headers = getHeaders()

    # url = HOST+"/api/v1/namespaces/default/secrets/"+secretName
    # print(url)

    # response = requests.request("GET", url, headers=headers, verify=getCaCert())
    # obj = json.loads(response.text)
    kubeApi = getConfiguration()
    readSecret = kubeApi.read_namespaced_secret(secretName,'default').data

    return readSecret

    obj = getExistingSecret('sectigo-ssl-a1')
    print(obj)
    if 'data' in obj.keys():
        dataObj = obj["data"]

        if 'tls.crt' in dataObj.keys():
            encodedCert = dataObj["tls.crt"]

