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

def getConfigurationForWatch():
    ApiToken = getToken()
    configuration = client.Configuration()
    configuration.host = "https://"+os.getenv("KUBERNETES_SERVICE_HOST")+":"+str(os.getenv("KUBERNETES_SERVICE_PORT"))
    configuration.api_key={"authorization":"Bearer "+ ApiToken}
    configuration.verify_ssl=False
    configuration.debug = True
    client.Configuration.set_default(configuration)
    kubeApi = client.CustomObjectsApi(client.ApiClient(configuration))
    return kubeApi


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

def getresourceVersionCompleted():
    kubeApi = getConfiguration()
    cfmp = kubeApi.read_namespaced_config_map('sectigo-operator-config', 'default', pretty='true',exact=True, export=True)
    print("------------------------ NEW FLOW ----------------------------")
    return cfmp

def readSecretForCertId(certType, secretName):
    kubeApi = getConfiguration()
    readSecret = kubeApi.read_namespaced_secret(secretName,'default').data
    certId = base64.b64decode(readSecret['certId'])
    return str(certId,'utf-8')

# # Works 
def getExistingSecret(secretName):
    print(" ------------ getExistingSecret Start ------------")

    # HOST = getHost()
    # headers = getHeaders()

    # url = HOST+"/api/v1/namespaces/default/secrets/"+secretName
    # print(url)

    # response = requests.request("GET", url, headers=headers, verify=getCaCert())
    # obj = json.loads(response.text)
    kubeApi = getConfiguration()
    try:
        readSecret = kubeApi.read_namespaced_secret(secretName,'default')
        return readSecret
    except Exception:
        return 0
 
def update_config_map(resourceVersion):
    # delete configmaps
    kubeApi = getConfiguration()
    cfmap1 = kubeApi.delete_namespaced_config_map('sectigo-operator-config', 'default')

    # create configmaps with completed resourceVersion number
    kubeApi = getConfiguration()
    payload = {"apiVersion": "v1","data": {"namespace": "default","resourceVersionCompleted": resourceVersion},"kind": "ConfigMap","metadata": {"name": "sectigo-operator-config","namespace": "default","selfLink": "/api/v1/namespaces/default/configmaps/sectigo-operator-config"}}
    cfmap1 = kubeApi.create_namespaced_config_map('default', payload)
    # print("********** replaced secret: "+resourceVersion)
    # print(cfmap1)    
    # print("=======================================")

def update_pre_cert_details(certType, response, secretName, resourceVersion):
    print(" ------------ inside update_pre_cert_details function ------------")
    encodedCert = ""
    encodedKey = ""
    encodedCsr = ""
    encodedCertId = ""

    if 'certificate' in response.keys():
        cert = response["certificate"]
        encodedCert = encode_base64(cert)

    if 'private_key' in response.keys():
        private_key = response["private_key"]
        encodedKey = encode_base64(private_key)

    if 'csr' in response.keys():
        csr = response["csr"]
        # print("-======================== CSR: ")
        # print(csr)
        encodedCsr = encode_base64(csr)

    certId = ""
    if certType=="SSL":
        if 'ssl_id' in response.keys():
            certId = str(response["ssl_id"])
    elif certType=="CLIENT":
        if 'orderNumber' in response.keys():
            certId = str(response["orderNumber"])

    encodedCertId = encode_base64(certId)
    
    encodedResourceVersion = encode_base64(resourceVersion) 
    encodedSecretName = encode_base64(secretName)

    kubeApi = getConfiguration()
    pretty = 'true'
    exact = True
    export = True
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": "default" }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "certId": encodedCertId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }
    # print("+++++++++++++++++++++++++++++++++++++++++++")
    # print(payload)
    allPods = kubeApi.create_namespaced_secret('default', payload)
    # print("======================================= allpods")
    # print(allPods)    
    # print("=======================================")

def update_post_cert_details(certType, response, secretName, resourceVersion, cfmpData):

    print("------------------------- inside update_post_cert_details function ------------------------------")

    encodedCert = ""
    encodedKey = ""
    encodedCertId = ""

    # Get existing values from secret if available and assign them as default.. 
    dataObj = getExistingSecret(secretName)
    dataObj = dataObj.data

    if 'tls.crt' in dataObj.keys():
        encodedCert = base64.b64decode(dataObj["tls.crt"])
        encodedCert = str(encodedCert,'utf-8')
    if 'tls.key' in dataObj.keys():
        encodedKey = base64.b64decode(dataObj["tls.key"])
        encodedKey = str(encodedKey,'utf-8')
    if 'certId' in dataObj.keys():
        encodedCertId = base64.b64decode(dataObj["certId"])
        encodedCertId = str(encodedCertId,'utf-8')

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
        certId = str(response["ssl_id"])
        encodedCertId = encode_base64(certId)
    elif 'orderNumber' in response.keys():
        certId = str(response["orderNumber"])
        encodedCertId = encode_base64(certId)

    encodedResourceVersion = encode_base64(resourceVersion) 

    kubeApi = getConfiguration()
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": "default" }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "certId": encodedCertId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }

    allPods = kubeApi.patch_namespaced_secret(secretName, 'default', payload)
    print("********** patched named seceret")
    # print(allPods)    
    print("**********")

    update_config_map(resourceVersion)

def collect(certType, response, secretName, resourceVersion, cfmpData):

    # 2. CollectCertificate Sample Operation - SSL
    # print("#######################################################")
    # print("2. CollectCertificate Sample Opertaion - SSL")

    collect_dict = {}
    if certType == "SSL":
        print("========================= ")
        print(response["ssl_id"])
        collect_dict = {
            'sectigo_ssl_cert_ssl_id': response["ssl_id"], 
            'sectigo_ssl_cert_format_type': 'x509CO', 
            'sectigo_loop_period': 30, 
            'sectigo_max_timeout': 6000
        }
    elif certType == "CLIENT":
        print("========================= ")
        print(response["orderNumber"])
        collect_dict = {
            'sectigo_client_cert_order_number': response["orderNumber"], 
            'sectigo_client_cert_format_type': 'x509CO', 
            'sectigo_loop_period': 30, 
            'sectigo_max_timeout': 6000
        }

    # print("------------ COLLECT - collect_response - start ")
    collect_response = p.CollectCertificate(collect_dict, certType)
    # print(collect_response)

    return collect_response

def delete_secret(secretName):
    kubeApi = getConfiguration()
    deletesecret = kubeApi.delete_namespaced_secret(secretName, 'default')

def event_loop1():
    print("testing...")

def event_loop(resourceVersionCompleted,cfmpData):
    HOST = getHost()
    headers = getHeaders()

    # log.info("Starting the service")
    # # url = HOST+'/apis/sectigo.com/v1/sectigok8soperator?watch=true&allowWatchBookmarks=true&resourceVersion='+resourceVersionCompleted
    # url = 'http://3.211.68.242:8001/apis/sectigo.com/v1/sectigok8soperator?watch=true&allowWatchBookmarks=true&resourceVersion='+resourceVersionCompleted
    # print("------- Watch URL: ")
    # print(url)
    # # r = requests.get(url, headers=headers, stream=True, verify=getCaCert())
    # r = requests.get(url, stream=True, verify=getCaCert())
    # print("======================= 1")
    # print(r)
    # print("======================= 2")
    # print(r.text)
    # print("======================= 3")
    # for line in r.iter_lines():

    kubeApi = getConfigurationForWatch()
    ct = 1

    print("")
    print("")
    print("")
    print("")
    print("")
    print("############################ resourceVersionCompleted before for loop start ############################")
    print(resourceVersionCompleted)

    for line in watch.Watch().stream(kubeApi.list_cluster_custom_object, 'sectigo.com', 'v1', 'sectigok8soperator', watch=True, resource_version=resourceVersionCompleted):
        print("")
        print("")
        print("############################ resourceVersionCompleted inside event loop ############################")
        print(resourceVersionCompleted)
        # print("======================= 0 - event line")
        # print(line)
        # print("======================= 0-1 - event line")
        # obj = json.loads(line)
        obj = line
        event_type = obj['type']    # ADDED, MODIFIED, DELETED
        # print("======================= 1")
        # print(event_type)
        # print("======================= 2")
        # print(resourceVersionCompleted)
        # print("======================= 3")

        secretName = ""
        resourceVersion = ""
        certType = ""
        enroll_dict = {}

        if event_type == "ADDED" or event_type == "MODIFIED" or event_type == "DELETED":

            
            certType = (obj['object']['spec']['sectigo_cert_type']).upper()
            secretName = ""
            if certType == "SSL":
                secretName = obj['object']['spec']['sectigo_ssl_cert_file_name']
            elif certType == "CLIENT":
                secretName = obj['object']['spec']['sectigo_client_cert_file_name']
    
            resourceVersion = obj['object']['metadata']['resourceVersion']
            enroll_dict = obj['object']['spec']
            
            print("-------------------- current working on -----------------")
            print(resourceVersion)

        if event_type == "ADDED":

            obj = getExistingSecret(secretName)
            if obj != 0:
                # secret exists 
                print(" ------------ Secret \""+secretName+"\" already exists ------------")
                certExists = False
                dataObj = obj.data

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
                    #########3 read certid from secret and decode it from base64
                    certId = readSecretForCertId(certType, secretName)
                    collect_dict = {}
                    if certType == "SSL":
                        collect_dict = {
                            'sectigo_ssl_cert_ssl_id': certId, 
                            'sectigo_ssl_cert_format_type': 'x509CO', 
                            'sectigo_loop_period': 30, 
                            'sectigo_max_timeout': 6000
                        }
                    elif certType == "CLIENT":
                        collect_dict = {
                            'sectigo_client_cert_order_number': certId, 
                            'sectigo_client_cert_format_type': 'x509CO', 
                            'sectigo_loop_period': 30, 
                            'sectigo_max_timeout': 6000
                        }

                    collect_response = p.CollectCertificate(collect_dict, certType)
                    print("------------ COLLECT - collect_response - start ")
                    # print(collect_response)
                    update_post_cert_details(certType, collect_response, secretName, resourceVersion, cfmpData)
                    print("------------ COLLECT - collect_response - end 1")

            else: 
                log.info(" ------------ Creation detected - start ------------")
                enroll_response = p.EnrollCertificate(enroll_dict, certType)

                print("------------ ENROLL - response - start ")
                # print(enroll_response)
                update_pre_cert_details(certType, enroll_response, secretName, resourceVersion)
                print("------------ ENROLL - response - end")

                print("------------ COLLECT - response - start ")
                print("------------ sleeping 30 secs ")
                time.sleep(30)
                collect_response = collect(certType, enroll_response, secretName, resourceVersion, cfmpData)
                print("------------ COLLECT - response - end ")
                update_post_cert_details(certType, collect_response, secretName, resourceVersion, cfmpData)
                # time.sleep(30)
                log.info(" ------------ Creation detected - end ------------")

        elif event_type == "DELETED":
            log.info(" ------------ Deletion detected - start ------------")
            # call revoke api here and pass params
            certId = readSecretForCertId(certType, secretName)
            revoke_dict = {}
            revoke_dict['sectigo_revoke_reason'] = obj['object']['spec']['sectigo_revoke_reason']

            if certType == "SSL":
                revoke_dict['sectigo_ssl_cert_ssl_id'] = certId
            elif certType == "CLIENT":
                revoke_dict['sectigo_client_cert_order_number'] = certId

            revoke_response = p.RevokeCertificate(revoke_dict, certType)
            print("************************ delete response *************** ")
            print(revoke_response)
            delete_secret(secretName)
            update_config_map(resourceVersion)
            log.info(" ------------ Deletion detected - end ------------")

        elif event_type == "MODIFIED":
            log.info(" ------------ Update detected start ------------")
            # call replace api here and pass params
            certId = readSecretForCertId(certType, secretName)
            replace_dict = {}
            replace_dict['sectigo_replace'] = obj['object']['spec']['sectigo_replace']
            replace_dict['sectigo_replace_reason'] = obj['object']['spec']['sectigo_replace_reason']
            replace_dict['sectigo_csr'] = obj['object']['spec']['sectigo_csr']

            if certType == "SSL":
                replace_dict['sectigo_ssl_cert_ssl_id'] = certId
                replace_dict['sectigo_ssl_cert_common_name'] = obj['object']['spec']['sectigo_ssl_cert_common_name']
                replace_dict['sectigo_ssl_cert_subject_alt_names'] = obj['object']['spec']['sectigo_ssl_cert_subject_alt_names']
                replace_dict['sectigo_ssl_cert_revoke_on_replace'] = obj['object']['spec']['sectigo_ssl_cert_revoke_on_replace']
            elif certType == "CLIENT":
                replace_dict['sectigo_client_cert_order_number'] = certId
                replace_dict['sectigo_client_cert_common_name'] = obj['object']['spec']['sectigo_client_cert_common_name']
                replace_dict['sectigo_client_cert_subject_alt_names'] = obj['object']['spec']['sectigo_client_cert_subject_alt_names']
                replace_dict['sectigo_client_cert_revoke_on_replace'] = obj['object']['spec']['sectigo_client_cert_revoke_on_replace']

            print("############################ REPLACE - response - start ")
            replace_response = p.ReplaceCertificate(replace_dict, certType)
            # print(replace_response)
            print("############################ REPLACE - response - end ")
            print("############################ COLLECT - response - start ")
            collect_response = collect(certType, replace_response, secretName, resourceVersion, cfmpData)
            print("############################ COLLECT - response - end ")
            update_post_cert_details(certType, collect_response, secretName, resourceVersion, cfmpData)
            log.info("############################ Update detected - end ------------")

        elif event_type == "ERROR":
            # event_loop(resourceVersionCompleted,cfmpData)
            oldVersionId = obj['object']['message']    # ADDED, MODIFIED, DELETED

        cfmp = getresourceVersionCompleted()
        cfmpData = cfmp.data
        resourceVersionCompleted = cfmpData['resourceVersionCompleted']    # ADDED, MODIFIED, DELETED

        print("============= end for loop =============== ")
        print("============= sleeping for 30 secs =============== ")
        time.sleep(30)
    print("============= outside for loop =============== ")

    print("========== resourceVersionCompleted after this loop ============= ")
    print(resourceVersionCompleted)
    print("========== loop complete - sleep 10 sec and call event_loop() ============= ")
    time.sleep(10)

    event_loop(resourceVersionCompleted,cfmpData)

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

        # print("*********************************************************")
        # p = subprocess.Popen([sys.executable, 'ct.py'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # print(p)
        # print("*********************************************************")

        cfmp = getresourceVersionCompleted()
        cfmpData = cfmp.data
        resourceVersionCompleted = cfmpData['resourceVersionCompleted']    # ADDED, MODIFIED, DELETED
        event_loop(resourceVersionCompleted,cfmpData)

    else:
        print("This is NOT the leader pod. LeaderPod: "+leaderHost)
        time.sleep(10)
        main()

main()
