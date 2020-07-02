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

            import sys 
            import glob, os
            import shutil
            import os,sys,inspect,simplejson
            from os import path
            from os.path import exists, join, isdir

            current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
            parent_dir = os.path.dirname(current_dir)
            sys.path.insert(0, parent_dir) 

            import pycert as p

            # Set Connection Parameters
            connectDictionary = {
                    'sectigo_cm_user': 'myuser',
                    'sectigo_cm_password': 'mypassword',
                    'sectigo_cm_uri': 'myuri',
                    'sectigo_cm_base_url': 'https://myca.mydomain.com/'
            }
            response = p.SetConnectionParameters(connectDictionary)

            certCategory = "SSL"
            # 1. EnrollCertificate Sample Operation - SSL
            print("#######################################################")
            print("1. EnrollCertificate Sample Operation - SSL")
            enrollDictionary = {
                'sectigo_cm_org_id': 9941,
                'sectigo_ssl_cert_type': 248,
                'sectigo_ssl_cert_validity': 365,
                'sectigo_ssl_cert_custom_fields': [],
                'sectigo_ssl_cert_external_requester': '',
                'sectigo_ssl_cert_comments': 'Test Cert for Sectigo',
                'sectigo_ssl_cert_num_servers': 0,
                'sectigo_ssl_cert_server_type': -1,
                'sectigo_ssl_cert_subject_alt_names': 'app1.mycompanydomain.com,app2.mycompanydomain.com',
                
                'sectigo_csr': '-----BEGIN CERTIFICATE REQUEST-----MIIDLDCCAhQCAQAwgY0xCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTEMMAoGA1UEBwwDQkxSMQ8wDQYDVQQKDAZUcmlhbnoxDjAMBgNVBAsMBUNsb3VkMSgwJgYJKoZIhvcNAQkBFhlhZGl0eWEuYmhhbmdsZUB0cmlhbnouY29tMRgwFgYDVQQDDA90cmlhbnpjbG91ZC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHHYidO2qFUswl7XttFmMhyYMB7aisytuDwelPUCZEjR1jqePmlUI07RWkKfAcM0Y7410euWqlDZG6mtVRrUAINfwrUaCSJJz/2wMEzQ8UKoV/FOZJXcDw56LZiOBvW5xLhuQBl+uNUZOzjWbaDwq8oIIcYn3hTW8dnwlrxjaHoj1I3mc5cQoaQelYwASPgBPzMXd+h30bCeHEXGZ/C1rU8Dpepmo7c96pvxqiLJL4Mvweh4gwbB/WYwSmTalWhisEI3WHJUyvFupeYPlYePB3CLB9oeDxq7iVRfJCwGBjwGCmFRSGJGqwpCsZbWX3cZRwqQai/Nz4EfzKawz/NAi1AgMBAAGgWTBXBgkqhkiG9w0BCQ4xSjBIMEYGA1UdEQQ/MD2CHHB1cHBldC1zbGF2ZS50cmlhbnpjbG91ZC5jb22CHXB1cHBldC1zbGF2ZTIudHJpYW56Y2xvdWQuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQClTwiVAFVb3aG7kQi8HpHnVx/HdXt/hVMdYnVZ2w0PaJ9nwKewV1xV6kXrejeGGAiZG9U4YvKm7tWm0mqsVZQpUDFy/PcxiAWpyDIIL8HeeEZ5QsuZ5/iM05o5/ixPQT3Ilz3zUD/Qyv/JlovQD1XHEo483T1k9c5aYd/RrbMcREkXGGEM+7A1zOcmm1H563BQIgs6eqNoDF8I+kOKaHR2Nm5aXbXMTeAWrgY/w9o2IN/K02vxnzav0xTtXtS00g2vxRMSEeKGHdiFl475iCetXPmwqZ0zi0IACStNw72Euhh+rxcMEPnToynriUKxunvlNFve1ZM7BFugrpTnLbs8-----END CERTIFICATE REQUEST-----'

            }
            response = p.EnrollCertificate(enrollDictionary,certCategory)


event_loop()