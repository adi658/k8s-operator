import os 
import shutil  
import subprocess

# update secret
import shlex

print("----------------------------------------------------")
cmd = ''' cat /secret-patch-template.json | sed "s/NAMESPACE/default/" | sed "s/NAME/sectigo-secret/" | sed "s/TLSCERT/$(cat /sectigo_ssl.crt | base64 | tr -d '\n')/" | 	sed "s/TLSKEY/$(cat /sectigo_ssl.crt |  base64 | tr -d '\n')/" > /secret-patch.json '''
results = subprocess.run(
    cmd, shell=True, universal_newlines=True, check=True)
print(results.stdout)
print("----------------------------------------------------")
cmd = ''' curl -v --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" -k -v -XPATCH  -H "Accept: application/json, */*" -H "Content-Type: application/strategic-merge-patch+json" -d @/secret-patch.json https://kubernetes/api/v1/namespaces/default/secrets/sectigo-secret '''
results = subprocess.run(
    cmd, shell=True, universal_newlines=True, check=True)
print(results.stdout)
print("----------------------------------------------------")

# cmd = '''cat /secret-patch-template.json | sed "s/NAMESPACE/default/" | sed "s/NAME/sectigo-secret/" | sed "s/TLSCERT/$(cat /sectigo_ssl.crt | base64 | tr -d '\n')/" | 	sed "s/TLSKEY/$(cat /sectigo_ssl.crt |  base64 | tr -d '\n')/" > /secret-patch.json'''
# print("-------------CMD 1----------------")
# print(cmd)
# args = shlex.split(cmd)
# process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# stdout, stderr = process.communicate()
# print("-----------------------------")


# filename = "/etc/ssl/sectigo_ssl.crt"
# file = open(filename, "w") 
# cert = '''-----BEGIN CERTIFICATE-----
# MIIF0zCCBLugAwIBAgIRAMglaJ7Z0l19Ssmje8qJdYUwDQYJKoZIhvcNAQELBQAwgYMxCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAY
# BgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSkwJwYDVQQDEyBUZXN0IFJTQSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eTAeFw0yMDA2MDMwMDAwMDBaFw0yMTA2MDMyMzU5NTlaMIHXMQswCQYDVQQGEwJV
# UzEOMAwGA1UEERMFOTUwNTQxEzARBgNVBAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC1NhbnRhIENs
# YXJhMRMwEQYDVQQJEwpTdWl0ZSAxMjUwMSIwIAYDVQQJExkyNTMwIE1pc3Npb24gQ29sbGVnZSBC
# bHZkMRowGAYDVQQKExFUcmlhbnogQ29uc3VsdGluZzEeMBwGA1UECxMVVHJpYW56IENsb3VkIFNl
# cnZpY2VzMRgwFgYDVQQDEw90cmlhbnpjbG91ZC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCy3m17TplAx25Pgc97ZlVWwbGA8b9wJMU5zhGAKoRA6EvoTGO3iFV6ocAsbCZIG3SF
# vB0W1bt9IkOgAshwOqqCiQWNiySEaWMs9WaZv3VM+an9uqf0iCp7IKAFTC9OdKFdewK6/g+DcC/F
# vqRF0SOJtQ8GA08ePjKNNU/e+pyEUdCa6tphHv+UMa6ObmFPOm2CBg92+Trl6bAqmQdy8Af23n0g
# MwS/8zE9XRe/BZ6khQzxpOMct3jLUhGH+8E9fvVATAI8OqJ4YkvUvTgDowuVXBEq0XCpKQLnCQNR
# nOMiJbN5XjSJ/r8OuK/2yPvJhEwFZPIarPt38UU31gqRl4DNAgMBAAGjggHqMIIB5jAfBgNVHSME
# GDAWgBSGhh3LBiV9JwFXa+VqONDkRK+TMjAdBgNVHQ4EFgQU8GEwjOcR83Qd6RRwfjPE61zpmsAw
# DgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
# BwMCMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMEMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
# dGlnby5jb20vQ1BTMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL1Rl
# c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB7BggrBgEFBQcBAQRvMG0wRQYIKwYBBQUH
# MAKGOWh0dHA6Ly9jcnQuY29tb2RvY2EuY29tL1Rlc3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
# LmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMFwGA1UdEQRVMFOCD3Ry
# aWFuemNsb3VkLmNvbYIUYXBwMS50cmlhbnpjbG91ZC5jb22CFGFwcDIudHJpYW56Y2xvdWQuY29t
# ghRhcHAzLnRyaWFuemNsb3VkLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEATDfyeLxQRD1i+Gj9zfrN
# sj14J2lRjS9hkF/1S1WVH/RxvjAtMNIJxXu8OgpaSDct82PEpltZdjg41QGfK3MYHG0TZ9rlGaD/
# ZvxVCM+SYHsfqesLRkf744DVRcfa19XlRt5N9eMoXwE2ofUhjsz5WlRpGszN8/0ZWhLbPK84CR4C
# bdWu7jkMcFnC6cQnzp1QTpx8ws1F3klvxJ8BHxTj4iyT0Gu7r9kLv+joKuKwDt/Rqk/LnPH5V+sb
# f03A/J3PAWvBAyUtohtoH4Xwi0NI3FnPJF/xsTjNG8NcVASbb/VNB0bAvFKNo5Sjm9W5/Q5N2zfJ
# QuS66tlGqHqjHDEfdg==
# -----END CERTIFICATE-----'''

# file.write(cert)
# file.close()

# # f = open(filename, "r")
# # print(f.read()) 

# print("-----------------------------")
# print(os.environ["SECRET"])
# print("-----------------------------")





# # cat /deployment-patch-template.json | \
# # 	sed "s/TLSUPDATED/$(date)/" | \
# # 	sed "s/NAMESPACE/${NAMESPACE}/" | \
# # 	sed "s/NAME/${DEPLOYMENT}/" \
# # 	> /deployment-patch.json
  
# # cat deployment-patch.json
# f = open('secret-patch-template.json', "r")
# print(f.read()) 


# # dest = shutil.move(filename, "/etc/ssl/tls.crt")  


# # from base64 import b64encode
# # from subprocess import run

# # def b64encodestr(string):
# #     return b64encode(string.encode("utf-8")).decode()
    
# # def update_secrets(secret, key, val):
# #     b64val = b64encodestr(val)
# #     cmd = f"""kubectl patch secret {secret} -p='{{"data":{{"{key}": "{b64val}"}}}}'"""
# #     return run(cmd, shell=True)

# # update_secrets('sectigo-secret','crt','val')