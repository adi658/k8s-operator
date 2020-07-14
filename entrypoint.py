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
    client.Configuration.set_default(configuration)
    kubeApi = client.CoreV1Api(client.ApiClient(configuration))
    return kubeApi

def getresourceVersionCompleted():
    kubeApi = getConfiguration()
    cfmp = kubeApi.read_namespaced_config_map('sectigo-operator-config', 'default', pretty='true',exact=True, export=True)
    print("------------------------ NEW FLOW ----------------------------")
    return cfmp

def readSecretForCertId(secretName):
    kubeApi = getConfiguration()
    readSecret = kubeApi.read_namespaced_secret(secretName,'default').data
    certId = base64.b64decode(readSecret['sslId'])
    return str(certId,'utf-8')

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

def update_config_map(resourceVersion):
    # delete configmaps
    kubeApi = getConfiguration()
    cfmap1 = kubeApi.delete_namespaced_config_map('sectigo-operator-config', 'default')

    # create configmaps with completed resourceVersion number
    kubeApi = getConfiguration()
    payload = {"apiVersion": "v1","data": {"namespace": "default","resourceVersionCompleted": resourceVersion},"kind": "ConfigMap","metadata": {"name": "sectigo-operator-config","namespace": "default","selfLink": "/api/v1/namespaces/default/configmaps/sectigo-operator-config"}}
    cfmap1 = kubeApi.create_namespaced_config_map('default', payload)
    print("********** replaced secret: "+resourceVersion)
    print(cfmap1)    
    print("=======================================")

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

    if 'orderNumber' in response.keys():
        sslId = str(response["orderNumber"])
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

    kubeApi = getConfiguration()
    pretty = 'true'
    exact = True
    export = True
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": "default" }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "tls.csr": encodedCsr, "sslId": encodedSslId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }
    print("+++++++++++++++++++++++++++++++++++++++++++")
    print(payload)
    allPods = kubeApi.create_namespaced_secret('default', payload)
    print("======================================= allpods")
    print(allPods)    
    print("=======================================")


def update_post_cert_details(response, secretName, resourceVersion, cfmpData):

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

    if 'orderNumber' in response.keys():
        sslId = str(response["orderNumber"])
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

    kubeApi = getConfiguration()
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": "default" }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "tls.csr": encodedCsr, "sslId": encodedSslId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }

    allPods = kubeApi.patch_namespaced_secret(secretName, 'default', payload)
    print("********** patched named seceret")
    print(allPods)    
    print("**********")

    update_config_map(resourceVersion)

def collect(response, sectigo_cert_type, secretName, resourceVersion, cfmpData):

    # 2. CollectCertificate Sample Operation - SSL
    print("#######################################################")
    print("2. CollectCertificate Sample Opertaion - SSL")
    collect_dict = {
        'sectigo_client_cert_order_number': response["orderNumber"], 
        'sectigo_client_cert_format_type': 'x509CO', 
        'sectigo_loop_period': 30, 
        'sectigo_max_timeout': 6000
    }
    collect_response = p.CollectCertificate(collect_dict, sectigo_cert_type)
    # collect_response = {"status": "SUCCESS", "message": "The received status code from SCM implies that the collect request has succeeded - StatusOK", "timestamp": "2020-07-09T18:21:09.088860", "category": "SSL", "operation": "Collect", "scm_response": {"status_code": 200, "status": "SUCCESS", "body": "-----BEGIN CERTIFICATE-----\nMIIFvDCCBKSgAwIBAgIQfNycI/ncP39VILd/dPIvUzANBgkqhkiG9w0BAQsFADCB\ngzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\nA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKTAnBgNV\nBAMTIFRlc3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIwMDcwNzAw\nMDAwMFoXDTIxMDcwNzIzNTk1OVowgdcxCzAJBgNVBAYTAlVTMQ4wDAYDVQQREwU5\nNTA1NDETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLU2FudGEgQ2xhcmEx\nEzARBgNVBAkTClN1aXRlIDEyNTAxIjAgBgNVBAkTGTI1MzAgTWlzc2lvbiBDb2xs\nZWdlIEJsdmQxGjAYBgNVBAoTEVRyaWFueiBDb25zdWx0aW5nMR4wHAYDVQQLExVU\ncmlhbnogQ2xvdWQgU2VydmljZXMxGDAWBgNVBAMTD3RyaWFuemNsb3VkLmNvbTCC\nASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIuSmNq6iXsUlEEysKflYMp\nyoTpu2SIU34tAmf2fVORTqfNlMGAC8rq5VKRZXkRnRAyFYbA4zEoPVVB7b4yPBBP\n6oJKkEGlOl4KRLzK8yaVKEEybFY3SObAFe2tR8OFpH66Nw87eJ11p2D1BeDwvmdY\nlz/6C+kG1VFRWWgzReXlAXverqYfGbr9ICeXc8kHCXzjtsRtFesLcINQbOxLNiAs\nuVZHhcSdNQLtQchW2MJDyjc9xmA3ZjC0tQxgb8o0yvgrDjYRyRjYtBwBpOtRBLdP\n4HZLSIxqORPEfppAhx/SDAu9KUtiXtKtVYhG2DHT5loFzkZmxVScnyQvhJ2Pa+kC\nAwEAAaOCAdQwggHQMB8GA1UdIwQYMBaAFIaGHcsGJX0nAVdr5Wo40OREr5MyMB0G\nA1UdDgQWBBTv44qYIPeSwFJYXE8/EnjZstTwvDAOBgNVHQ8BAf8EBAMCBaAwDAYD\nVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwQAYDVR0g\nBDkwNzA1BgwrBgEEAbIxAQIBAwQwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0\naWdvLmNvbS9DUFMwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5jb21vZG9j\nYS5jb20vVGVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHsGCCsGAQUF\nBwEBBG8wbTBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5jb21vZG9jYS5jb20vVGVz\ndFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3J0MCQGCCsGAQUFBzABhhhodHRw\nOi8vb2NzcC5jb21vZG9jYS5jb20wRgYDVR0RBD8wPYIPdHJpYW56Y2xvdWQuY29t\nghRhcHAxLnRyaWFuemNsb3VkLmNvbYIUYXBwMi50cmlhbnpjbG91ZC5jb20wDQYJ\nKoZIhvcNAQELBQADggEBAKsidi1Il47a8f+qAuKP/xxB0Gm8nxNU4esJOX5m6MQp\nP5gI7M3iatmKp+sRDq/QtCPYZE/ey/Q4m0zvQW0LzlFasPe1HdET0d2iaQDqyzC5\nCKrWIMLC0WLe1tM9q/ePwaAru4h3ip9CJ2/EMZ/jyzqDbRAi+lSV6F6EOPv8ef+9\noBIay5Dju9huXORYlzIAD5efrhXg5gAoBcZr+zK9lDrKmVXEe9d3o+2GJxZLrK6x\nDVRr++zINEyMgz80S1z0Rt0d5dG+IS7tgg9seoBNvreGSsMOYZlOorfPLJR8VdLG\nxwfVoq4KMxuDUpIAGF8UusAFI5ZTCwL2gxfSZTluUpU=\n-----END CERTIFICATE-----\n"}, "orderNumber": 1874599}
    print("------------ COLLECT - collect_response - start ")
    print(collect_response)
    print("------------ sslid: ")
    print(collect_response["orderNumber"])
    update_post_cert_details(collect_response, secretName, resourceVersion, cfmpData)
    print("------------ COLLECT - collect_response - end 2")
    time.sleep(30)

def delete_secret(secretName):
    kubeApi = getConfiguration()
    deletesecret = kubeApi.delete_namespaced_secret(secretName, 'default')


def event_loop1():
    print("testing...")

def event_loop(resourceVersionCompleted,cfmpData):
    HOST = getHost()
    headers = getHeaders()

    log.info("Starting the service")
    # url = HOST+'/apis/sectigo.com/v1/sectigok8soperator?watch=true&allowWatchBookmarks=true&resourceVersion='+resourceVersionCompleted
    url = 'http://3.211.68.242:8001/apis/sectigo.com/v1/sectigok8soperator?watch=true&allowWatchBookmarks=true&resourceVersion='+resourceVersionCompleted
    print("------- Watch URL: ")
    print(url)
    # r = requests.get(url, headers=headers, stream=True, verify=getCaCert())
    r = requests.get(url, stream=True, verify=getCaCert())
    print("======================= 1")
    print(r)
    print("======================= 2")
    print(r.text)
    print("======================= 3")

    for line in r.iter_lines():
        obj = json.loads(line)
        event_type = obj['type']    # ADDED, MODIFIED, DELETED

        domain = obj['object']['spec']['domain']
        secretName = obj['object']['spec']['sectigo_client_cert_file_name']
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
                    certId = readSecretForCertId(secretName)
                    collect_dict = {
                        'sectigo_client_cert_order_number': certId, 
                        'sectigo_client_cert_format_type': 'x509CO', 
                        'sectigo_loop_period': 30, 
                        'sectigo_max_timeout': 6000
                    }
                    collect_response = p.CollectCertificate(collect_dict, sectigo_cert_type)
                    # collect_response = {"status": "SUCCESS", "message": "The received status code from SCM implies that the collect request has succeeded - StatusOK", "timestamp": "2020-07-09T18:21:09.088860", "category": "SSL", "operation": "Collect", "scm_response": {"status_code": 200, "status": "SUCCESS", "body": "-----BEGIN CERTIFICATE-----\nMIIFvDCCBKSgAwIBAgIQfNycI/ncP39VILd/dPIvUzANBgkqhkiG9w0BAQsFADCB\ngzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\nA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKTAnBgNV\nBAMTIFRlc3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIwMDcwNzAw\nMDAwMFoXDTIxMDcwNzIzNTk1OVowgdcxCzAJBgNVBAYTAlVTMQ4wDAYDVQQREwU5\nNTA1NDETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLU2FudGEgQ2xhcmEx\nEzARBgNVBAkTClN1aXRlIDEyNTAxIjAgBgNVBAkTGTI1MzAgTWlzc2lvbiBDb2xs\nZWdlIEJsdmQxGjAYBgNVBAoTEVRyaWFueiBDb25zdWx0aW5nMR4wHAYDVQQLExVU\ncmlhbnogQ2xvdWQgU2VydmljZXMxGDAWBgNVBAMTD3RyaWFuemNsb3VkLmNvbTCC\nASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIuSmNq6iXsUlEEysKflYMp\nyoTpu2SIU34tAmf2fVORTqfNlMGAC8rq5VKRZXkRnRAyFYbA4zEoPVVB7b4yPBBP\n6oJKkEGlOl4KRLzK8yaVKEEybFY3SObAFe2tR8OFpH66Nw87eJ11p2D1BeDwvmdY\nlz/6C+kG1VFRWWgzReXlAXverqYfGbr9ICeXc8kHCXzjtsRtFesLcINQbOxLNiAs\nuVZHhcSdNQLtQchW2MJDyjc9xmA3ZjC0tQxgb8o0yvgrDjYRyRjYtBwBpOtRBLdP\n4HZLSIxqORPEfppAhx/SDAu9KUtiXtKtVYhG2DHT5loFzkZmxVScnyQvhJ2Pa+kC\nAwEAAaOCAdQwggHQMB8GA1UdIwQYMBaAFIaGHcsGJX0nAVdr5Wo40OREr5MyMB0G\nA1UdDgQWBBTv44qYIPeSwFJYXE8/EnjZstTwvDAOBgNVHQ8BAf8EBAMCBaAwDAYD\nVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwQAYDVR0g\nBDkwNzA1BgwrBgEEAbIxAQIBAwQwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0\naWdvLmNvbS9DUFMwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5jb21vZG9j\nYS5jb20vVGVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHsGCCsGAQUF\nBwEBBG8wbTBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5jb21vZG9jYS5jb20vVGVz\ndFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3J0MCQGCCsGAQUFBzABhhhodHRw\nOi8vb2NzcC5jb21vZG9jYS5jb20wRgYDVR0RBD8wPYIPdHJpYW56Y2xvdWQuY29t\nghRhcHAxLnRyaWFuemNsb3VkLmNvbYIUYXBwMi50cmlhbnpjbG91ZC5jb20wDQYJ\nKoZIhvcNAQELBQADggEBAKsidi1Il47a8f+qAuKP/xxB0Gm8nxNU4esJOX5m6MQp\nP5gI7M3iatmKp+sRDq/QtCPYZE/ey/Q4m0zvQW0LzlFasPe1HdET0d2iaQDqyzC5\nCKrWIMLC0WLe1tM9q/ePwaAru4h3ip9CJ2/EMZ/jyzqDbRAi+lSV6F6EOPv8ef+9\noBIay5Dju9huXORYlzIAD5efrhXg5gAoBcZr+zK9lDrKmVXEe9d3o+2GJxZLrK6x\nDVRr++zINEyMgz80S1z0Rt0d5dG+IS7tgg9seoBNvreGSsMOYZlOorfPLJR8VdLG\nxwfVoq4KMxuDUpIAGF8UusAFI5ZTCwL2gxfSZTluUpU=\n-----END CERTIFICATE-----\n"}, "orderNumber": 1874599}
                    print("------------ COLLECT - collect_response - start ")
                    print(collect_response)
                    print("------------ sslid: ")
                    print(collect_response["orderNumber"])
                    update_post_cert_details(collect_response, secretName, resourceVersion, cfmpData)
                    print("------------ COLLECT - collect_response - end 1")

            else: 
                log.info(" ------------ Creation detected ------------")
                enroll_response = p.EnrollCertificate(enroll_dict, sectigo_cert_type)
                # enroll_response = {"status": "SUCCESS", "message": "The received status code from SCM implies that the enroll request has succeeded - StatusOK", "timestamp": "2020-07-09T18:21:08.124104", "category": "SSL", "operation": "Enroll", "orderNumber": 369321690, "csr": "-----BEGIN CERTIFICATE REQUEST-----MIIDJDCCAgwCAQAwgZYxGDAWBgNVBAMMD3RyaWFuemNsb3VkLmNvbTELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAlVTMQwwCgYDVQQHDANCTFIxDjAMBgNVBAoMBU1ZT1JHMRMwEQYDVQQLDApNWU9SR19VTklUMS0wKwYJKoZIhvcNAQkBFh5hZGl0eWEuYmhhbmdsZUB0cmlhbnpjbG91ZC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKoEBVxW8P4xDUUjAfXoHTeCk4cL1ZxU1UY3RtcQxXJXm501KyipbRHqSMhqI5yzOwFMXEoxzA1fpRtc0JIzmPgdBWr7FblLDcojl6ihTl38HCx86MaQ9FHtAzvdG0q9D/H/jaaPOtA06Ab7yS2DtkOgJmEEHhnvBTElgS/qtVMrbTE9yehVc532q9B9fBgLpEH4BcnmMvZbYqUlZTMlYE7hTwRn0dJ3tN5wtLnuQmY3Wrj3dHXqlCGwWWAbuGai/Bk1ANW7q03yrRqr7ByOCoX0Bckad5XgYtb4wHrAQrGoa40iI78msUoh3+CP/750uSNpgDztPN/Nk7cPG8mZFxAgMBAAGgSDBGBgkqhkiG9w0BCQ4xOTA3MDUGA1UdEQQuMCyCFGFwcDEudHJpYW56Y2xvdWQuY29tghRhcHAyLnRyaWFuemNsb3VkLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAxtqIKtWw4JaTlcLbwtawGRRCGlUF7r1dryTL5g/FOE0P99pTvrCxm8Kgc2gleCVOhCihNXVml+LA5ty3katVnugRFRPMSYhDXOERvPs6MrDlP7fSd0Ug/mOFuujKIojXmDkN2YvkaB54XHgeK1VJKHNx9+SDBIzhh1uIV2vkS6PGJYt24Yf1N+oMcjrATOIOsINXjEoZuo/JE24FNTCIEawRoTZLeUV3WhMnsv323TSpw8rkfq57PlGiL0+qlzzOIjRQ8wVBQZpB1RKMhEIsP+wd71pC3LD9Tjr0t3Je6dLkg3pKKLtnrRGD9Sw7N8e6tKoGe0nmJ593Wul8/Dw+fQ==-----END CERTIFICATE REQUEST-----", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDKoEBVxW8P4xDU\nUjAfXoHTeCk4cL1ZxU1UY3RtcQxXJXm501KyipbRHqSMhqI5yzOwFMXEoxzA1fpR\ntc0JIzmPgdBWr7FblLDcojl6ihTl38HCx86MaQ9FHtAzvdG0q9D/H/jaaPOtA06A\nb7yS2DtkOgJmEEHhnvBTElgS/qtVMrbTE9yehVc532q9B9fBgLpEH4BcnmMvZbYq\nUlZTMlYE7hTwRn0dJ3tN5wtLnuQmY3Wrj3dHXqlCGwWWAbuGai/Bk1ANW7q03yrR\nqr7ByOCoX0Bckad5XgYtb4wHrAQrGoa40iI78msUoh3+CP/750uSNpgDztPN/Nk7\ncPG8mZFxAgMBAAECggEAZzp1DD1lc4aO0Fx+v7x6D64r8eEd1lo6Jz/z1L2/N7aT\n6SPMAcGxTCB8XEtK4n6veolap+8heuyIdpBUQM99R6su5LrldG6wG/dZqSAnvWTd\nZco9ZDMx4FjuYS3XZGAUPaWgNkU5v27r02sZewZGW61iA3VM2xEKBohV7ndn+iLP\n8mWHwij2INVZ8rX8W5F2oFYEZE75bhL+568hcl10qKexYmkIQ8N/Jgvr1GBkZ/2w\nglwzmvm7fzgFrlPfZi+FktrB3ZLUMcVoSstl4s/ykvhxlBankTfhwvcaodTu6lpa\n1C2yi01Ivlyv7cMzvtbG2BZy/YdO/Y9pKAuTvHXdMQKBgQDqIx550wDk91cJKBHv\no5ZQo2DGso26LzN5B6wgKGupE2oI/nufsNA06YPawyEUoO39UqjedR7IzMHzeeCq\nU+87RHVRqKBo42yL6zOGXJGchUXf/pHRA/zUp+NgKHJaiKfLVBTiJ8pY25ThqYP2\nGI6WwibWTgnpCuRPfLJLbzA/xwKBgQDdi+EwUKYmbj21tVkpN3rxLJgLkLTCqcvi\n8iUVXqWfANE6BmJKmer9FGhzTH/zlgEi1vp8jNVvGIuL0eWGJ9ifRSR1on7DmSA5\n32n/FmF1AJKUMeUBHvzCC9AXryNzuQLmtdtJJjjok3xVnSb2jO49JfUcnX3ppr0X\nQl+bG4+VBwKBgQCHe8jvz7SNyb5YcxJl6/BYOyIN+FZgrV2IpHLqrNkXnj9WcwPQ\nNT1V0OZWmWE0EaeFVeaXy4gDw9BbdmQVy7n8PrHwjbY825T9Jh3Lmxc7TjdP1XxF\nSZxs5bWB+AWr87W8x6vJ7iJ95poxNqlAp5cjD7fvfHrpmj7g7BQz6GQwEwKBgEoO\nXwj6fH+uLByYcSRw8jy6Dl0XUwUbIxdKoBDDoZND/6xow+RyDPXqI3wfH0o6Y0jV\nGcgWf6XyS3tCf3nXyfZ7c1OLLNqPThFqWBE31v34Ygb9orI8PHtU3Yt9NNmTB6A9\nO/74st8zpcUskgCqXVy9WnDlSFiZLu4edrzvepBzAoGBAMp25wYQ667Ru4h60jw6\nkP1N7wZGWN56u05yJtuJEFyMO9J9J/8OJbY4FRDl0ubXfQYj4oDwEmlv8sJXejAb\nqhDxCl38FuvQX9ilaP5bNGJUKkYheDtkIUaAF7aWiC0PBOabaMCrYipzST84a+Ip\nkIxqv8+7yR4fiaGTw+Fl6OFx\n-----END PRIVATE KEY-----\n", "scm_response": {"status_code": 200, "body": "{\"sslId\":369321690,\"renewId\":\"oMcXwoFbOvTtJ9ugX5z2\"}", "status": "SUCCESS"}}

                print("------------ ENROLL - response - start ")
                print(enroll_response)
                print(enroll_response["orderNumber"])

                update_pre_cert_details(enroll_response, domain, secretName, resourceVersion)
                # print("--------- EXITING ----------")
                # exit(1)

                print("------------ ENROLL - response - end")
                collect(enroll_response, sectigo_cert_type, secretName, resourceVersion, cfmpData)

            print("ending execution")
        elif event_type == "DELETED":
            log.info(" ------------ Deletion detected ------------")
            # call revoke api here and pass params
            certId = readSecretForCertId(secretName)
            revoke_dict = {}
            revoke_dict['sectigo_revoke_reason'] = obj['object']['spec']['sectigo_revoke_reason']
            revoke_dict['sectigo_client_cert_order_number'] = certId

            revoke_response = p.RevokeCertificate(revoke_dict, sectigo_cert_type)
            print("************************ Replace response *************** ")
            print(revoke_response)
            delete_secret(secretName)
            # c.update_cert(domain, secretName)
            update_config_map(resourceVersion)
            # c.delete_cert(domain, secretName)

        elif event_type == "MODIFIED":
            log.info(" ------------ Update detected 1 ------------")
            # call replace api here and pass params
            certId = readSecretForCertId(secretName)
            replace_dict = {}
            replace_dict['sectigo_replace'] = obj['object']['spec']['sectigo_replace']
            replace_dict['sectigo_replace_reason'] = obj['object']['spec']['sectigo_replace_reason']
            replace_dict['sectigo_client_cert_common_name'] = obj['object']['spec']['sectigo_client_cert_common_name']
            replace_dict['sectigo_csr'] = obj['object']['spec']['sectigo_csr']
            replace_dict['sectigo_client_cert_order_number'] = certId
            replace_dict['sectigo_client_cert_subject_alt_names'] = obj['object']['spec']['sectigo_client_cert_subject_alt_names']
            replace_dict['sectigo_client_cert_revoke_on_replace'] = obj['object']['spec']['sectigo_client_cert_revoke_on_replace']

            replace_response = p.ReplaceCertificate(replace_dict, sectigo_cert_type)
            print("************************ Replace response *************** ")
            print(replace_response)
            collect(replace_response, sectigo_cert_type, secretName, resourceVersion, cfmpData)
            # c.update_cert(domain, secretName)
            log.info(" ------------ Update detected 3 ------------")

    cfmp = getresourceVersionCompleted()
    cfmpData = cfmp.data
    resourceVersionCompleted = cfmpData['resourceVersionCompleted']    # ADDED, MODIFIED, DELETED

    print("========== loop complete ============= ")
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

        cfmp = getresourceVersionCompleted()
        cfmpData = cfmp.data
        resourceVersionCompleted = cfmpData['resourceVersionCompleted']    # ADDED, MODIFIED, DELETED
        event_loop(resourceVersionCompleted,cfmpData)

    else:
        print("This is NOT the leader pod. LeaderPod: "+leaderHost)
        time.sleep(10)
        main()

main()