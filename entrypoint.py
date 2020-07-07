import requests
import os
import json
import logging
import sys
import cert as c 
import time


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
            log.info(" ------------------------ Creation detected ------------------------")
            enroll_response = p.EnrollCertificate(enroll_dict, sectigo_cert_type)
            print("--------------------------------- ENROLL - response - start ")
            print(enroll_response)
            print(enroll_response["ssl_id"])
            print("--------------------------------- ENROLL - response - end")

            # 2. CollectCertificate Sample Operation - SSL
            print("#######################################################")
            print("2. CollectCertificate Sample Opertaion - SSL")
            collect_dict = {
                'sectigo_ssl_cert_ssl_id': enroll_response["ssl_id"], 
                'sectigo_ssl_cert_format_type': 'x509CO', 
                'sectigo_loop_period': 30, 
                'sectigo_max_timeout': 600
            }
            collect_response = p.CollectCertificate(collect_dict, sectigo_cert_type)
            print("--------------------------------- COLLECT - collect_response - start ")
            print(response)
            print("--------------------------------- COLLECT - collect_response - end")

        elif event_type == "DELETED":
            log.info(" ------------------------ Deletion detected ------------------------")
            c.delete_cert(domain, secretName)

        elif event_type == "MODIFIED":
            log.info(" ------------------------ Update detected 1------------------------")
            c.update_cert(domain, secretName)
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
        event_loop()
    else:
        time.sleep(5)
        main()
main()