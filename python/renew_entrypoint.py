#!/usr/local/bin/python
import os 
import re
import base64
import requests
import os
import json
import logging

from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from os import path
from os.path import exists, join, isdir

import sectigo_pycert as s 
from datetime import datetime

print("Cron job has run at {0} with environment variable ".format(str(datetime.now())))

param_dict = {}
response = '{"id":"12345"}'
param_dict["certFilePath"] = '/root/'
param_dict["certFileName"] = 'aaa'
print("================== 00 ")
w = s.write_to_ids_file(param_dict,'ssl',response)
print("================== 11 ")
print(param_dict)
print("================== 22 ")
cert_ids_file_full_path = param_dict["certFilePath"]+param_dict["certFileName"]+"123.ids"
print("================== 33 ")
msg = s.getMessages("ProceedCertValidCheck")
print("================== 44 ")
print(msg)
print("================== 55 ")
f = open(cert_ids_file_full_path, 'w')
print("================== 66 ")
f.write(str(response))
print("================== 77 ")
print("================== 78 ")

# ------------------------------------------------------

def getToken():
    """
    Get K8S Token inside the container  
    INPUT: 
        content - content to be encoded 
    Return: 
        encoded token string 
    """

    token = ""
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as file:
        token = file.read().replace('\n', '')
    return token

def getEnvVars(getKey):
    data = {}
    content = ""

    print("======== log 101")
    filename = "/proc/1/task/1/environ"
    print("======== log 101-1")
    if exists(filename):
        print(filename+"exists")
    else: 
        print(filename+" does not exists")
    print("======== log 101-2")
    with open(filename, 'r') as file:
        print("======== log 102")
        content = file.read()
        print("======== log 102-1")
        print(content)
    print("======== log 103")

    regex = "KUBERNETES_SERVICE_HOST=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    print("======== log 104")
    match = re.search(regex, content)  
    print("======== log 105")
    contentArr =  match.group(0).split("=")
    print("======== log 106")
    data[contentArr[0]] = contentArr[1] 
    print("======== log 107")

    regex = "KUBERNETES_SERVICE_PORT=\d+"
    print("======== log 108")
    match = re.search(regex, content)  
    print("======== log 109")
    contentArr =  match.group(0).split("=")
    print("======== log 110")
    data[contentArr[0]] = contentArr[1] 
    print("======== log 111")

    return data[getKey]

def getHost():
    """
    Get HOST env variables 
    INPUT: 
        - 
    Return: 
        HOST 
    """

    print("log 2-3-1")
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        KUBERNETES_SERVICE_HOST=os.getenv("KUBERNETES_SERVICE_HOST")
    else: 
        KUBERNETES_SERVICE_HOST = getEnvVars('KUBERNETES_SERVICE_HOST')

    print("log 2-3-2")
    if os.getenv("KUBERNETES_SERVICE_PORT"):
        KUBERNETES_SERVICE_PORT=os.getenv("KUBERNETES_SERVICE_PORT")
    else: 
        KUBERNETES_SERVICE_PORT = getEnvVars('KUBERNETES_SERVICE_PORT')

    print("log 2-3-3")
    HOST = "https://"+KUBERNETES_SERVICE_HOST+":"+KUBERNETES_SERVICE_PORT

    print("log 2-3-4")
    print(HOST)
    return HOST

def getCaCert():
    """
    Get ca cert present inside the container
    INPUT: 
        -
    Return: 
        path to the cacert 
    """

    cacert = ""
    # with open('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'r') as file:
    #     token = file.read().replace('\n', '')
    return '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'

def getHeaders():
    """
    Build Header for request
    INPUT: 
        -
    Return: 
        header json 
    """

    token = getToken()
    headers = {
        "Authorization": "Bearer "+token,
        'Accept': 'application/json',
        'Connection': 'close',
        'Content-Type': 'application/json'
    }
    return headers

def getConfiguration(operation):
    """
    configuration for all other operations excluding watch
    INPUT: 
        -
    Return: 
        watch object 
    """

    print("log 2-1")
    ApiToken = getToken()
    print("log 2-2")
    configuration = client.Configuration()
    print("log 2-3")
    # configuration.host = "https://"+os.getenv("KUBERNETES_SERVICE_HOST")+":"+str(os.getenv("KUBERNETES_SERVICE_PORT"))
    configuration.host = getHost()
    print("log 2-4")
    configuration.api_key={"authorization":"Bearer "+ ApiToken}
    configuration.verify_ssl=False
    configuration.debug = True
    client.Configuration.set_default(configuration)
    if operation != "watch":
        kubeApi = client.CoreV1Api(client.ApiClient(configuration))
        return kubeApi
    else:
        kubeApi = client.CustomObjectsApi(client.ApiClient(configuration))
        return kubeApi

def getExistingSecret(secretName, namespace):
    """
    Get existing Secret 
    INPUT: 
        secretName - name of the secret 
    Return: 
        full secret Object 
    """
    
    print(" ------------ getExistingSecret Start ------------")
    kubeApi = getConfiguration('')
    try:
        readSecret = kubeApi.read_namespaced_secret(secretName, namespace)
        return readSecret
    except Exception:
        return 0

def encode_base64(content):
    """
    Encode the string to base64 format 
    INPUT: 
        content - content to be encoded 
    Return: 
        encoded string 
    """

    message_bytes = content.encode('ascii')
    base64_cert = base64.b64encode(message_bytes)
    encodedStr = str(base64_cert,'utf-8')
    return encodedStr

def update_post_cert_details(certType, response, secretName, resourceVersion, namespace):
    """
    Update secret with cert details - after collect.
    INPUT: 
        certType - SSL/CLIENT
        response - enroll response
        secretName - name of the secret to be updated
        resourceVersion - resource version of current events
        cfmpData - config map data object
    Return: 
        status - boolean
    """

    print("------------------------- inside update_post_cert_details function ------------------------------")

    encodedCert = ""
    encodedKey = ""
    encodedCertId = ""

    # Get existing values from secret if available and assign them.. 
    dataObj = getExistingSecret(secretName, namespace)
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

    kubeApi = getConfiguration('')
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": namespace }, "data": { "tls.crt": encodedCert, "certId": encodedCertId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }

    status = False
    try:
        allPods = kubeApi.patch_namespaced_secret(secretName, namespace, payload)
        status = True
    except Exception:
        status = False 
    
    return status 

def collect(certType, response):
    """
    Collect operation 
    INPUT: 
        certType - SSL/CLIENT
        response - enroll/replace response
        secretName - name of the secret to be updated
        resourceVersion - resource version of current events
        cfmpData - config map data object
    Return: 
        Collect Repsonse
    """

    collect_dict = {}
    if certType == "SSL":
        collect_dict = {
            'sectigo_ssl_cert_ssl_id': response["ssl_id"], 
            'sectigo_ssl_cert_format_type': 'x509CO', 
            'sectigo_loop_period': 30, 
            'sectigo_max_timeout': 6000
        }
    elif certType == "CLIENT":
        collect_dict = {
            'sectigo_client_cert_order_number': response["orderNumber"], 
            'sectigo_loop_period': 30, 
            'sectigo_max_timeout': 6000
        }

    collect_response = s.CollectCertificate(collect_dict, certType)
    return collect_response

def renew_loop():
    print("======== Inside Renew Loop 1========")

    test_params = {
        'sectigo_cm_user'     : 'manish.bhardwaj@trianz.com',
        'sectigo_cm_password' : 'Trianz@123',
        'sectigo_cm_uri'      : 'Trianz-poc-ux',
        'sectigo_cm_base_url' : 'https://cert-manager.com/'
    }
    testResponse = s.SetConnectionParameters(test_params)

    print("log 1")
    # Configure Logger
    log_params = {
        # 'sectigo_logger_file_path'       : 'log/sectigo_pycert.log',
        # 'sectigo_logger_stdout_flag'     : True,
        # 'sectigo_logger_max_file_size'   : 10000000, # 10 MB
        # 'sectigo_logger_max_num_backups' : 10
    }
    response = s.ConfigureLogger(log_params)

    print("log 2")

    # get custom resource 
    kubeApi = getConfiguration('watch')
    print("log 3")
    crd = kubeApi.list_cluster_custom_object('sectigo.com','v1','sectigok8soperator')
    print("CRD: ")
    print(crd)

    if crd == "":
        print("No custom resources found for kind 'sectigok8soperator'. Kindly deploy the custom resources first")

    for i in crd['items']:
        print("")
        print("====================================")
        print(i['spec']['secretName'])
        print(i['spec']['sectigo_secret_deploy_namespace'])
        secretName = i['spec']['secretName']
        sectigo_secret_deploy_namespace = i['spec']['sectigo_secret_deploy_namespace']
        
        secret = getExistingSecret(secretName, sectigo_secret_deploy_namespace)
        if secret != 0:
            certType = (i['spec']['sectigo_cert_type']).upper()
            decodedCert = str(base64.b64decode(secret.data['tls.crt']),'utf-8')
            decodedCertId = str(base64.b64decode(secret.data['certId']),'utf-8')
            decodedResourceVersion = str(base64.b64decode(secret.data['resourceVersion']),'utf-8')
            print(decodedCert)
            print(decodedCertId)
            print(decodedResourceVersion)

            if decodedCert!= "" and decodedCertId!= "":
                print("")

                # check validity 

                # Renew if expired. 
                renew_request = {}
                renew_request["sectigo_cm_base_url"] = 'https://cert-manager.com/'
                if certType == "SSL":
                    renew_request["sectigo_ssl_cert_ssl_id"] = decodedCertId
                elif certType == "CLIENT":
                    renew_request["sectigo_client_cert_order_number"] =  int(decodedCertId)

                print("----Renew Request:")
                print(renew_request)
                print("----")
                renew_response = ""
                try: 
                    renew_response = s.RenewCertificate(renew_request, certType)
                    
                    newCertId = ""
                    if certType == "SSL":
                        newCertId = renew_response["ssl_id"] 
                    elif certType == "CLIENT":
                        newCertId = renew_response["orderNumber"]

                    print("Old certId: "+str(decodedCertId))
                    print("New certId: "+str(newCertId))

                    print("\n\nCollecting Certificate... ")
                    collect_response = collect(certType, renew_response)

                    print("\n\nUpdating Cert Details In Secret after ENROLL/COLLECT... ")
                    status = update_post_cert_details(certType, collect_response, secretName, decodedResourceVersion, sectigo_secret_deploy_namespace)

                except Exception as err:
                    print("Error occured with renew for : "+str(decodedCertId)+" \n\nError: "+json.dumps(renew_response))
        
        else: 
            print("\n\nSecrets related to kind 'sectigok8soperator' do not exist yet. ")

    print("Cron job ended at {0} with environment variable ".format(str(datetime.now())))

def main():
    """
    Main Function 
    """

    print("========= Inside main functino ")
    HOSTNAME = ""
    if os.getenv("HOSTNAME"):
        print("========= Inside main functino - 1 ")
        HOSTNAME = os.getenv("HOSTNAME")
    else: 
        print("========= Inside main functino - 2 ")
        with open('/etc/hostname', 'r') as file:
            HOSTNAME = file.read().replace('\n', '')

    print("=========HOSTNAME: ")
    print(HOSTNAME)

    url = "http://localhost:4040"
    response = requests.get(url, stream=True)
    print("================== 8-1")
    resp = json.loads(response.text)
    print("================== 8-2")
    leaderHost = resp['name']
    print("================== 8-4")
    print(leaderHost)
    print("================== 8-5")
    print(HOSTNAME)
    print("================== 8-6")

    if leaderHost == HOSTNAME:
        print("This is the leader pod")
        renew_loop()
    else:
        print("On Standby. This is NOT the leader pod. LeaderPod: "+leaderHost+". Waiting for 30 secs before next check")
        time.sleep(30)
        main()

print("================== 8 ")
main()
print("================== 9 ")
