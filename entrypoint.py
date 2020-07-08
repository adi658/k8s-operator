import requests
import os
import json
import logging
import sys
# import cert as c 
import time
import requests
import base64
import os 
from kubernetes import client, config
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

# Set Connection Parameters
connectDictionary = {
        'sectigo_cm_user': 'manish.bhardwaj@trianz.com',
        'sectigo_cm_password': 'Trianz@123',
        'sectigo_cm_uri': 'Trianz-poc-ux',
        'sectigo_cm_base_url': 'https://cert-manager.com/'
}
response = p.SetConnectionParameters(connectDictionary)

# Configure Logger
log_params = {
    # 'sectigo_logger_file_path'       : 'log/sectigo_pycert.log',
    # 'sectigo_logger_stdout_flag'     : True,
    # 'sectigo_logger_max_file_size'   : 10000000, # 10 MB
    # 'sectigo_logger_max_num_backups' : 10
}
response = p.ConfigureLogger(log_params)

def encode_base64(content):
    message_bytes = content.encode('ascii')
    base64_cert = base64.b64encode(message_bytes)
    encodedStr = str(base64_cert,'utf-8')
    return encodedStr

def getToken():
    token = ""
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as file:
        token = file.read().replace('\n', '')
    return token

def getHost():
    KUBERNETES_SERVICE_HOST=os.getenv("KUBERNETES_SERVICE_HOST")
    KUBERNETES_SERVICE_PORT=os.getenv("KUBERNETES_SERVICE_PORT")
    HOST = "https://"+KUBERNETES_SERVICE_HOST+":"+KUBERNETES_SERVICE_PORT
    return HOST

def getCaCert():
    cacert = ""
    with open('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'r') as file:
        token = file.read().replace('\n', '')
    # return cacert
    return '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'

def getHeaders():
    token = getToken()
    headers = {
        "Authorization": "Bearer "+token,
        'Accept': 'application/json',
        'Connection': 'close',
        'Content-Type': 'application/json'
    }
    return headers

def getConfiguration():
    ApiToken = getToken()
    configuration = client.Configuration()
    configuration.host = "https://"+os.getenv("KUBERNETES_SERVICE_HOST")+":"+str(os.getenv("KUBERNETES_SERVICE_PORT"))
    configuration.api_key={"authorization":"Bearer "+ ApiToken}
    configuration.verify_ssl=False
    configuration.debug = True
    return configuration

# Works 
def getExistingSecret(secretName):
    print(" ------------ getExistingSecret Start ------------")

    HOST = getHost()
    headers = getHeaders()

    url = HOST+"/api/v1/namespaces/default/secrets/"+secretName
    print(url)

    response = requests.request("GET", url, headers=headers, verify=getCaCert())
    obj = json.loads(response.text)
    return obj

def update_pre_cert_details(response, domain, secretName, resourceVersion):
    print(" ------------ inside update_pre_cert_details function ------------")
    encodedCert = ""
    encodedKey = ""
    encodedCsr = ""
    encodedSslId = ""

    if 'certificate' in response.keys():
        cert = response["certificate"]
        encodedCert = encode_base64(cert)

    if 'private_key' in response.keys():
        private_key = response["private_key"]
        encodedKey = encode_base64(private_key)

    if 'csr' in response.keys():
        csr = response["csr"]
        print("-======================== CSR: ")
        print(csr)
        encodedCsr = encode_base64(csr)

    if 'ssl_id' in response.keys():
        sslId = str(response["ssl_id"])
        encodedSslId = encode_base64(sslId)
    
    encodedResourceVersion = encode_base64(resourceVersion) 
    encodedSecretName = encode_base64(secretName)
    # encodedDomain = encode_base64(domain)

    # HOST = getHost()
    # headers = getHeaders()

    # url = HOST+"/api/v1/namespaces/default/secrets"
    # print(url)
    
    # payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedCert+"\", \"tls.key\": \""+encodedKey+"\", \"tls.csr\": \""+encodedCsr+"\", \"sslId\": \""+encodedSslId+"\" }, \"type\": \"Opaque\" }"

    # response = requests.request("POST", url, data = payload, headers=headers, verify=getCaCert())
    # print(response.text.encode('utf8'))

    configuration = getConfiguration()
    pretty = 'true'
    exact = True
    export = True
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": "default" }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "tls.csr": encodedCsr, "sslId": encodedSslId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }
    print("+++++++++++++++++++++++++++++++++++++++++++")
    print(payload)
    client.Configuration.set_default(configuration)
    kubeApi = client.CoreV1Api(client.ApiClient(configuration))
    allPods = kubeApi.create_namespaced_secret('default', payload)
    print("======================================= allpods")
    print(allPods)    
    print("=======================================")


def update_post_cert_details(response, domain, secretName, resourceVersion):

    print("------------------------- inside update_post_cert_details function ------------------------------")

    encodedCert = ""
    encodedKey = ""
    encodedCsr = ""
    encodedSslId = ""

    # Get existing values from secret if available and assign them as default.. 
    obj = getExistingSecret(secretName)
    if 'data' in obj.keys():
        dataObj = obj["data"]

        if 'tls.crt' in dataObj.keys():
            encodedCert = dataObj["tls.crt"]
        if 'tls.csr' in dataObj.keys():
            encodedCsr = dataObj["tls.csr"]
        if 'tls.key' in dataObj.keys():
            encodedKey = dataObj["tls.key"]
        if 'sslId' in dataObj.keys():
            encodedSslId = dataObj["sslId"]

    # Check if new values are present in the collect response.. If yes update.. If no, leave as it is... To check if it should be made blank.. 
    if 'scm_response' in response.keys():
        if 'body' in response["scm_response"].keys():
            cert = response["scm_response"]["body"]
            encodedCert = encode_base64(cert)
        else: 
            print("No certificate in response.")
    else: 
        print("No certificate in response.")

    if 'ssl_id' in response.keys():
        sslId = str(response["ssl_id"])
        encodedSslId = encode_base64(sslId)

    encodedResourceVersion = encode_base64(resourceVersion) 
    # encodedDomain = encode_base64(domain)

    # HOST = getHost()
    # headers = getHeaders()

    # url = HOST+"/api/v1/namespaces/default/secrets/"+secretName
    # print(url)
    # payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedKey+"\", \"tls.key\": \""+encodedKey+"\", \"tls.csr\": \""+encodedCsr+"\", \"sslId\": \""+encodedSslId+"\" }, \"type\": \"Opaque\" }"
    # print(payload)

    # response = requests.request("PUT", url, data = payload, headers=headers, verify=getCaCert())
    # print(response.text.encode('utf8'))

    configuration = getConfiguration()
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": "default" }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "tls.csr": encodedCsr, "sslId": encodedSslId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }
    client.Configuration.set_default(configuration)
    kubeApi = client.CoreV1Api(client.ApiClient(configuration))

    allPods = kubeApi.patch_namespaced_secret(secretName, 'default', payload)
    print("=======================================")
    print(allPods)    
    print("=======================================")


def event_loop1():
    print("testing...")

def event_loop():
    HOST = getHost()
    headers = getHeaders()

    log.info("Starting the service")
    url = HOST+'/apis/sectigo.com/v1/sectigok8soperator?watch=true'
    print(url)
    r = requests.get(url, headers=headers, stream=True, verify=getCaCert())
    print("======================= 1")
    print(r)
    print("======================= 2")
    print(r.text)
    print("======================= 3")

    for line in r.iter_lines():
        obj = json.loads(line)
        event_type = obj['type']    # ADDED, MODIFIED, DELETED

        domain = obj['object']['spec']['domain']
        secretName = obj['object']['spec']['sectigo_ssl_cert_file_name']
        resourceVersion = obj['object']['metadata']['resourceVersion']
        sectigo_cert_type = (obj['object']['spec']['sectigo_cert_type']).upper()
        enroll_dict = obj['object']['spec']

        if event_type == "ADDED":

            # Check if secret already exsts -> 
            secretExists = False
            obj = getExistingSecret(secretName)
            if 'metadata' in obj.keys():
                metaObj = obj["metadata"]
                if 'name' in metaObj.keys():
                    secretExists = True 
            
            # if yes, do not add new .. Check if crt if valid.. (not null)
            if secretExists == True:
                print(" ------------ Secret \""+secretName+"\" already exists ------------")
                certExists = False
                if 'data' in obj.keys():
                    dataObj = obj["data"]

                    if 'tls.crt' in dataObj.keys():
                        encodedCert = dataObj["tls.crt"]
                        print("--------- 1 Checking if secrt is empty")
                        if encodedCert != "":
                            print("--------- 2  secrt is not empty")
                            certExists = True

                print("--------- 3 Checking secret end")
            
                # Since secret is presnet, if cert is null or does not exist in secret, download it
                if certExists == False:
                    print("------------ Cert does not exist in secret: \""+secretName+"\". Collecting ------------")
                    #########3 read sslid from secret and decode it from base64
                    collect_dict = {
                        'sectigo_ssl_cert_ssl_id': 1874599, 
                        'sectigo_ssl_cert_format_type': 'x509CO', 
                        'sectigo_loop_period': 30, 
                        'sectigo_max_timeout': 6000
                    }
                    collect_response = p.CollectCertificate(collect_dict, sectigo_cert_type)
                    print("------------ COLLECT - collect_response - start ")
                    print(collect_response)
                    print("------------ sslid: ")
                    print(collect_response["ssl_id"])
                    update_post_cert_details(collect_response, domain, secretName, resourceVersion)
                    print("------------ COLLECT - collect_response - end 1")

            else: 
                log.info(" ------------ Creation detected ------------")
                enroll_response = p.EnrollCertificate(enroll_dict, sectigo_cert_type)
                print("------------ ENROLL - response - start ")
                print(enroll_response)
                print(enroll_response["ssl_id"])

                update_pre_cert_details(enroll_response, domain, secretName, resourceVersion)
                # print("--------- EXITING ----------")
                # exit(1)

                print("------------ ENROLL - response - end")

                # 2. CollectCertificate Sample Operation - SSL
                print("#######################################################")
                print("2. CollectCertificate Sample Opertaion - SSL")
                collect_dict = {
                    'sectigo_ssl_cert_ssl_id': enroll_response["ssl_id"], 
                    'sectigo_ssl_cert_format_type': 'x509CO', 
                    'sectigo_loop_period': 30, 
                    'sectigo_max_timeout': 6000
                }
                collect_response = p.CollectCertificate(collect_dict, sectigo_cert_type)
                print("------------ COLLECT - collect_response - start ")
                print(collect_response)
                print("------------ sslid: ")
                print(collect_response["ssl_id"])
                update_post_cert_details(collect_response, domain, secretName, resourceVersion)
                print("------------ COLLECT - collect_response - end 2")

        elif event_type == "DELETED":
            log.info(" ------------ Deletion detected ------------")
            # c.delete_cert(domain, secretName)

        elif event_type == "MODIFIED":
            log.info(" ------------ Update detected 1 ------------")
            # c.update_cert(domain, secretName)
            log.info(" ------------ Update detected 3 ------------")

def main():
    HOSTNAME = os.getenv("HOSTNAME")
    url = "http://localhost:4040"
    response = requests.get(url, stream=True)
    resp = json.loads(response.text)
    leaderHost = resp['name']
    print(leaderHost)
    print(HOSTNAME)

    if leaderHost == HOSTNAME:
        print("This is the leader pod")
        print("------------------------ NEW FLOW ----------------------------")
        event_loop()
    else:
        print("This is NOT the leader pod. LeaderPod: "+leaderHost)
        time.sleep(10)
        main()

main()