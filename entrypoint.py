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

def getToken():
  token = ""
  with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as file:
      token = file.read().replace('\n', '')
  return token

# Works 
def getExistingSecret(secretName):
    print(" ------------------------ getExistingSecret Start ------------------------")

    token = getToken()

    url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets/"+secretName
    print("======================================")
    print(url)
    print("======================================")

    # headers = {
    #     "Authorization": "Bearer "+token,
    #     'Accept': 'application/json',
    #     'Connection': 'close',
    #     'Content-Type': 'application/json'
    # }

    response = requests.request("GET", url, verify=False)
    obj = json.loads(response.text)
    # dataObj = obj["data"]

    return obj

def update_pre_cert_details(response, domain, secretName):

    print("------------------------- inside update_pre_cert_details function ------------------------------")
    print(domain)
    print(response)
    print(secretName)
    print("-==-=------------------ log 1")
    encodedCert = ""
    encodedKey = ""
    encodedCsr = ""
    encodedSslId = ""

    print("-==-=------------------ log 2")
    if 'certificate' in response.keys():
        print("-==-=------------------ log 3")
        cert = response["certificate"]
        message_bytes = cert.encode('ascii')
        base64_cert = base64.b64encode(message_bytes)
        encodedCert = str(base64_cert,'utf-8')

    if 'private_key' in response.keys():
        print("-==-=------------------ log 4")
        private_key = response["private_key"]
        key_bytes = private_key.encode('ascii')
        base64_key = base64.b64encode(key_bytes)
        encodedKey = str(base64_key,'utf-8')

    if 'csr' in response.keys():
        print("-==-=------------------ log 5")
        csr = response["csr"]
        csr_bytes = csr.encode('ascii')
        base64_csr = base64.b64encode(csr_bytes)
        encodedCsr = str(base64_csr,'utf-8')

    if 'ssl_id' in response.keys():
        print("-==-=------------------ log 6")
        sslId = str(response["ssl_id"])
        sslId_bytes = sslId.encode('ascii')
        base64_sslId = base64.b64encode(sslId_bytes)
        encodedSslId = str(base64_sslId,'utf-8')

    print("---------------crt ")
    print(encodedCert)
    print("---------------key")
    print(encodedKey)
    print("--------------- csr")
    print(encodedCsr)
    print("---------------sslid")
    print(encodedSslId)

    secretName_bytes = secretName.encode('ascii')
    base64_secretName = base64.b64encode(secretName_bytes)
    encodedSecretName = str(base64_secretName,'utf-8')

    domain_bytes = domain.encode('ascii')
    base64_domain = base64.b64encode(domain_bytes)
    encodedDomain = str(base64_domain,'utf-8')

    token = getToken()

    url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets"
    #url ="https://kubernetes.default/api/v1/namespaces/default/secrets"
    print("======================================")
    print(url)
    print("======================================")
    payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedCert+"\", \"tls.key\": \""+encodedKey+"\", \"tls.csr\": \""+encodedCsr+"\", \"sslId\": \""+encodedSslId+"\" }, \"type\": \"Opaque\" }"
    # headers = {
    #     "Authorization": "Bearer "+token,
    #     'Accept': 'application/json',
    #     'Content-Type': 'application/json'
    # }

    response = requests.request("POST", url, data = payload, verify=False)
    print(response.text.encode('utf8'))

    print("------------------------- end of update_pre_cert_details function ------------------------------")

def update_post_cert_details(response, domain, secretName):

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
        if 'certificate' in response["scm_response"].keys():
            cert = response["scm_response"]["certificate"]
            message_bytes = cert.encode('ascii')
            base64_cert = base64.b64encode(message_bytes)
            encodedCert = str(base64_cert,'utf-8')
        else: 
            print("No certificate in response.")
    else: 
        print("No certificate in response.")

    if 'ssl_id' in response.keys():
        sslId = str(response["ssl_id"])
        sslId_bytes = sslId.encode('ascii')
        base64_sslId = base64.b64encode(sslId_bytes)
        encodedSslId = str(base64_sslId,'utf-8')

    print("---------------")
    print(encodedCert)
    print(encodedSslId)

    # secretName_bytes = secretName.encode('ascii')
    # base64_secretName = base64.b64encode(secretName_bytes)
    # encodedSecretName = str(base64_secretName,'utf-8')

    domain_bytes = domain.encode('ascii')
    base64_domain = base64.b64encode(domain_bytes)
    encodedDomain = str(base64_domain,'utf-8')

    token = getToken()

    url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets/"+secretName
    #url ="https://kubernetes.default/api/v1/namespaces/default/secrets"
    print("======================================")
    print(url)
    print("======================================")
    payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedKey+"\", \"tls.key\": \""+encodedKey+"\", \"tls.csr\": \""+encodedCsr+"\", \"sslId\": \""+encodedSslId+"\" }, \"type\": \"Opaque\" }"
    # headers = {
    #     "Authorization": "Bearer "+token,
    #     'Accept': 'application/json',
    #     'Content-Type': 'application/json'
    # }

    response = requests.request("PUT", url, data = payload, verify=False)
    print(response.text.encode('utf8'))

def event_loop():

    log.info("Starting the service")
    url = 'http://3.211.68.242:8001/apis/sectigo.com/v1alpha1/sectigok8soperator?watch=true'
    r = requests.get(url, stream=True)
    # We issue the request to the API endpoint and keep the conenction open
    print("-------------")
    print("-------------")
    for line in r.iter_lines():
        obj = json.loads(line)
        event_type = obj['type']    # ADDED, MODIFIED, DELETED

        print(obj)
        print(event_type)
        print("-----------------------------------------------------------------")

        domain = obj['object']['spec']['domain']
        secretName = obj['object']['spec']['secretName']
        sectigo_cert_type = (obj['object']['spec']['sectigo_cert_type']).upper()
        enroll_dict = obj['object']['spec']
        print(domain)
        print(secretName)

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
                print("------------------------Secret \""+secretName+"\" already exists ------------------------")
                certExists = False
                if 'data' in obj.keys():
                    dataObj = obj["data"]

                    if 'tls.crt' in dataObj.keys():
                        encodedCert = dataObj["tls.crt"]
                        print("--------- 1 Checking if secrt is empty")
                        if encodedCert != "":
                            print("--------- 2  secrt is not empty")
                            certExists = True

                print("--------- 3 Checking secret ebd")
            
                # Since secret is presnet, if cert is null or does not exist in secret, download it
                if certExists == False:
                    print("------------------------Cert does not exist in secret: \""+secretName+"\". Collecting ------------------------")
                    #########3 read sslid from secret and decode it from base64
                    collect_dict = {
                        'sectigo_ssl_cert_ssl_id': 1874599, 
                        'sectigo_ssl_cert_format_type': 'x509CO', 
                        'sectigo_loop_period': 30, 
                        'sectigo_max_timeout': 6000
                    }
                    collect_response = p.CollectCertificate(collect_dict, sectigo_cert_type)
                    print("--------------------------------- COLLECT - collect_response - start ")
                    print(collect_response)
                    # 
                    print("--------------- sslid: ")
                    print(collect_response["ssl_id"])
                    update_post_cert_details(collect_response, domain, secretName)
                    print("--------------------------------- COLLECT - collect_response - end")

            else: 
                log.info(" ------------------------ Creation detected ------------------------")
                enroll_response = p.EnrollCertificate(enroll_dict, sectigo_cert_type)
                print("--------------------------------- ENROLL - response - start ")
                print(enroll_response)
                print(enroll_response["ssl_id"])

                update_pre_cert_details(enroll_response, domain, secretName)

                print("--------------------------------- ENROLL - response - end")

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
                print("--------------------------------- COLLECT - collect_response - start ")
                print(collect_response)
                print("--------------- sslid: ")
                print(collect_response["ssl_id"])
                update_post_cert_details(collect_response, domain, secretName)
                print("--------------------------------- COLLECT - collect_response - end")

        elif event_type == "DELETED":
            log.info(" ------------------------ Deletion detected ------------------------")
            # c.delete_cert(domain, secretName)

        elif event_type == "MODIFIED":
            log.info(" ------------------------ Update detected 1------------------------")
            # c.update_cert(domain, secretName)
            log.info(" ------------------------ Update detected 3------------------------")

def main():
    HOSTNAME = os.getenv("HOSTNAME")
    url = "http://localhost:4040"
    response = requests.get(url, stream=True)
    resp = json.loads(response.text)
    leaderHost = resp['name']
    print(leaderHost)
    print(HOSTNAME)

    # url = "http://3.211.68.242:8001/api/v1/namespaces/default/endpoints/sectigok8soperator"

    # r = requests.get(url, stream=True)
    # resp = json.loads(r.text)
    # leaderHostJson = json.loads(resp['metadata']['annotations']['control-plane.alpha.kubernetes.io/leader'])
    # print("------------------")
    # print(leaderHostJson)
    # leaderHost = leaderHostJson['holderIdentity']

    # print("------------------")
    # print(leaderHost)
    # print("------------------")
    # print(HOSTNAME)

    if leaderHost == HOSTNAME:
        print("This is the leader pod")
        event_loop()
    else:
        print("This is NOT the leader pod. LeaderPod: "+leaderHost)
        time.sleep(5)
        main()
main()

