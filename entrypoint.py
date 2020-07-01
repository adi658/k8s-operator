import requests
import os
import json
import logging
import sys
import cert as c 

log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
log.addHandler(out_hdlr)
log.setLevel(logging.INFO)

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
        print(domain)
        print(secretName)

        if event_type == "ADDED":
            log.info(" ------------------------ Creation detected ------------------------")
            c.create_cert(domain, secretName)

        elif event_type == "DELETED":
            log.info(" ------------------------ Deletion detected ------------------------")
            c.delete_cert(domain, secretName)

        elif event_type == "MODIFIED":
            log.info(" ------------------------ Update detected 1------------------------")
            c.update_cert(domain, secretName)
            log.info(" ------------------------ Update detected 3------------------------")

event_loop()