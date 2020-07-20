import requests
import subprocess
import os
import json
import logging
import sys
import time
import requests
import base64
import os 
import inspect 
import glob
import shutil
import sectigo_pycert as p

from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from os import path
from os.path import exists, join, isdir

#------------------------------------------------------

operatorNamespace = 'default'
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir) 

log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
log.addHandler(out_hdlr)
log.setLevel(logging.INFO)

#------------------------------------------------------

# Set Connection Parameters
connectDictionary = {
        'sectigo_cm_user': 'manish.bhardwaj@trianz.com',
        'sectigo_cm_password': 'Trianz@123',
        'sectigo_cm_uri': 'Trianz-poc-ux',
        'sectigo_cm_base_url': 'https://cert-manager.com/'
}
response = p.SetConnectionParameters(connectDictionary)

#------------------------------------------------------

# Configure Logger
log_params = {
    # 'sectigo_logger_file_path'       : 'log/sectigo_pycert.log',
    # 'sectigo_logger_stdout_flag'     : True,
    # 'sectigo_logger_max_file_size'   : 10000000, # 10 MB
    # 'sectigo_logger_max_num_backups' : 10
}
response = p.ConfigureLogger(log_params)

#------------------------------------------------------ FUNCTIONS related to K8S Operator

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

def getHost():
    """
    Get HOST env variables 
    INPUT: 
        - 
    Return: 
        HOST 
    """

    KUBERNETES_SERVICE_HOST=os.getenv("KUBERNETES_SERVICE_HOST")
    KUBERNETES_SERVICE_PORT=os.getenv("KUBERNETES_SERVICE_PORT")
    HOST = "https://"+KUBERNETES_SERVICE_HOST+":"+KUBERNETES_SERVICE_PORT
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

    ApiToken = getToken()
    configuration = client.Configuration()
    configuration.host = "https://"+os.getenv("KUBERNETES_SERVICE_HOST")+":"+str(os.getenv("KUBERNETES_SERVICE_PORT"))
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

def getresourceVersionCompleted():
    """
    Get conpleted resourceVersion of event
    INPUT: 
        -
    Return: 
        full config map object
    """

    global operatorNamespace
    kubeApi = getConfiguration('')
    cfmp = kubeApi.read_namespaced_config_map('sectigo-operator-config', operatorNamespace, pretty='true',exact=True, export=True)
    print("------------------------ NEW FLOW ----------------------------")
    return cfmp

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

def getCertIdFromSecret(certType, secretName, namespace):
    """
    Read secret and get the certID of the certificate present in it
    INPUT: 
        certType - SSL/CLIENT
        secretName - name of the secret 
    Return: 
        certId in str format
    """

    kubeApi = getConfiguration('')
    readSecret = kubeApi.read_namespaced_secret(secretName, namespace).data
    certId = base64.b64decode(readSecret['certId'])
    return str(certId,'utf-8')

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
 
def delete_secret(secretName, namespace):
    """
    Delete Secret 
    INPUT: 
        secretName - name of the secret to be deleted 
    Return: 
        -
    """
    
    kubeApi = getConfiguration('')
    try: 
        deletesecret = kubeApi.delete_namespaced_secret(secretName, namespace)
        return True
    except Exception:
        return False
    
def update_config_map(resourceVersion):
    """
    Update COnfig map 
    INPUT: 
        resourceVersion - resource version of current events (that was completed) 
    Return: 
        -
    """
    global operatorNamespace
    # delete configmaps before udate
    kubeApi = getConfiguration('')
    cfmap1 = kubeApi.delete_namespaced_config_map('sectigo-operator-config', operatorNamespace)

    # create configmaps with completed resourceVersion number
    kubeApi = getConfiguration('')
    selfLink = "/api/v1/namespaces/"+operatorNamespace+"/configmaps/sectigo-operator-config"
    payload = {"apiVersion": "v1","data": {"namespace": operatorNamespace,"resourceVersionCompleted": resourceVersion},"kind": "ConfigMap","metadata": {"name": "sectigo-operator-config","namespace": operatorNamespace, "selfLink": selfLink}}
    cfmap1 = kubeApi.create_namespaced_config_map(operatorNamespace, payload)

def update_pre_cert_details(certType, response, secretName, resourceVersion, namespace):
    """
    Update secret with cert details - after enroll and prior to collect.
    INPUT: 
        certType - SSL/CLIENT
        response - enroll response
        secretName - name of the secret to be updated
        resourceVersion - resource version of current events
    Return: 
        - 
    """

    print(" ------------ inside update_pre_cert_details function ------------")
    certId = ""
    encodedCert = ""
    encodedKey = ""
    encodedCertId = ""

    if 'certificate' in response.keys():
        cert = response["certificate"]
        encodedCert = encode_base64(cert)

    if 'private_key' in response.keys():
        private_key = response["private_key"]
        encodedKey = encode_base64(private_key)

    if certType=="SSL":
        if 'ssl_id' in response.keys():
            certId = str(response["ssl_id"])
    elif certType=="CLIENT":
        if 'orderNumber' in response.keys():
            certId = str(response["orderNumber"])
    encodedCertId = encode_base64(certId)
    
    encodedResourceVersion = encode_base64(resourceVersion) 
    encodedSecretName = encode_base64(secretName)

    kubeApi = getConfiguration('')
    payload = { "kind": "Secret", "apiVersion": "v1", "metadata": { "name": secretName, "namespace": namespace }, "data": { "tls.crt": encodedCert, "tls.key": encodedKey, "certId": encodedCertId, "resourceVersion": encodedResourceVersion }, "type": "Opaque" }
    allPods = kubeApi.create_namespaced_secret(namespace, payload)

def update_post_cert_details(certType, response, secretName, resourceVersion, cfmpData, namespace):
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
    
    print("############################################ exception: ")
    print(status)
    return status 

def collect(certType, response, secretName, resourceVersion, cfmpData):
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
            'sectigo_client_cert_format_type': 'x509CO', 
            'sectigo_loop_period': 30, 
            'sectigo_max_timeout': 6000
        }

    collect_response = p.CollectCertificate(collect_dict, certType)
    return collect_response

def event_loop(resourceVersionCompleted,cfmpData):
    """
    Event Loop 
    INPUT: 
        resourceVersionCompleted    - resource Version of the event that has been completed
        cfmpData                    - sectigo-config map data 
    Return: 
        -
    """

    HOST = getHost()
    headers = getHeaders()

    kubeApi = getConfiguration('watch')
    ct = 1

    print("")
    print("")
    print("")
    print("############################ resourceVersionCompleted before for loop start ############################")
    print(resourceVersionCompleted)

    for line in watch.Watch().stream(kubeApi.list_cluster_custom_object, 'sectigo.com', 'v1', 'sectigok8soperator', watch=True, resource_version=resourceVersionCompleted):
        print("")
        print("")
        enroll_dict = {}
        certType = ""
        secretName = ""
        resourceVersion = ""
        namespace = ""

        obj = line
        event_type = obj['type'] #ADDED, MODIFIED, DELETED, ERROR

        if event_type == "ADDED" or event_type == "MODIFIED" or event_type == "DELETED":

            secretName = ""
            certType = (obj['object']['spec']['sectigo_cert_type']).upper()
            
            if certType == "SSL":
                secretName = obj['object']['spec']['secretName']
            elif certType == "CLIENT":
                secretName = obj['object']['spec']['secretName']
    
            resourceVersion = obj['object']['metadata']['resourceVersion']
            enroll_dict = obj['object']['spec']
            namespace = obj['object']['spec']['sectigo_secret_deploy_namespace']
            
        print("\n\nEvent:"+event_type+"\n\n")
        if event_type == "ADDED":

            print("\n\nChecking if secret \""+secretName+"\" already exists...")
            obj = getExistingSecret(secretName, namespace)

            if obj != 0:    # secret exists | (0 = secret does not exist)
                print("\nSecret \""+secretName+"\" already exists!")
                certExists = False
                dataObj = obj.data

                if 'tls.crt' in dataObj.keys():
                    encodedCert = dataObj["tls.crt"]
                    if encodedCert != "":
                        certExists = True

                print("\nCert Exists??: ")
                print(certExists)
            
                # COLLECT-CERT if SECRET is present and certExists = FALSE
                if certExists == False:
                    print("\n\nSecret Exists but CERT does not exist in secret: \""+secretName+"\". Collecting...")

                    # read CERTID from secret and decode it from base64
                    certId = getCertIdFromSecret(certType, secretName, namespace)
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

                    print("\n\nCollecting Certificate... ")
                    collect_response = p.CollectCertificate(collect_dict, certType)

                    print("\n\nUpdating Cert Details In Secret after COLLECT... ")
                    status = update_post_cert_details(certType, collect_response, secretName, resourceVersion, cfmpData, namespace)

                    if status == True:
                        print("\n\nUpdating ConfigMap with ResourceVersion after COLLECT... ")
                        update_config_map(resourceVersion)

            else: 
                print("\n\nSecret \""+secretName+"\" does not exists...")
                print("\nEnrolling Certificate... ")
                enroll_response = p.EnrollCertificate(enroll_dict, certType)

                print("\n\nUpdating Cert Details In Secret before COLLECT... ")
                update_pre_cert_details(certType, enroll_response, secretName, resourceVersion, namespace)

                print("\n\nCollecting Certificate... ")
                collect_response = collect(certType, enroll_response, secretName, resourceVersion, cfmpData)

                print("\n\nUpdating Cert Details In Secret after ENROLL/COLLECT... ")
                status = update_post_cert_details(certType, collect_response, secretName, resourceVersion, cfmpData, namespace)

                if status == True:
                    print("\n\nUpdating ConfigMap with ResourceVersion after ENROLL/COLLECT... ")
                    update_config_map(resourceVersion)

        elif event_type == "DELETED":
            print("\n\nRevoking Certificate... ")

            certId = getCertIdFromSecret(certType, secretName, namespace)
            revoke_dict = {}
            revoke_dict['sectigo_revoke_reason'] = obj['object']['spec']['sectigo_revoke_reason']

            if certType == "SSL":
                revoke_dict['sectigo_ssl_cert_ssl_id'] = certId
            elif certType == "CLIENT":
                revoke_dict['sectigo_client_cert_order_number'] = certId

            revoke_response = p.RevokeCertificate(revoke_dict, certType)

            print("\n\nDeleting Secret after Revoke... ")
            status = delete_secret(secretName, namespace)

            if status == True:
                print("\n\nUpdating ConfigMap with ResourceVersion after REVOKE... ")
                update_config_map(resourceVersion)

        elif event_type == "MODIFIED":
            print("\n\nReplacing Certificate... ")

            certId = getCertIdFromSecret(certType, secretName, namespace)
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

            replace_response = p.ReplaceCertificate(replace_dict, certType)

            print("\n\nCollecting Certificate... ")
            collect_response = collect(certType, replace_response, secretName, resourceVersion, cfmpData)

            print("\n\nUpdating Cert Details In Secret after REPLACE and COLLECT... ")
            status = update_post_cert_details(certType, collect_response, secretName, resourceVersion, cfmpData, namespace)

            if status == True:
                print("\n\nUpdating ConfigMap with ResourceVersion after REPLACE... ")
                update_config_map(resourceVersion)

        elif event_type == "ERROR":
            # oldVersionId = obj['object']['message']
            print("\n\nError Occured... ")

        cfmp = getresourceVersionCompleted()
        cfmpData = cfmp.data
        resourceVersionCompleted = cfmpData['resourceVersionCompleted']

        print("")
        print("Event Loop complete for resVersion: "+resourceVersionCompleted+"- Waiting 10 sec before checking for next events in the set")
        time.sleep(10)

    print("")
    print("Event Loop complete for resVersion: "+resourceVersionCompleted+"- Waiting 10 sec before calling the event loop again")
    time.sleep(10)
    event_loop(resourceVersionCompleted,cfmpData)

def main():
    """
    Main Function 
    """

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
        print("On Standby. This is NOT the leader pod. LeaderPod: "+leaderHost+". Waiting for 30 secs before next check")
        time.sleep(30)
        main()

main()
