import requests
import base64
import os 

def create_cert(domain, secretName):
  cert = '''-----BEGIN CERTIFICATE-----
  MIIF0zCCBLugAwIBAgIRAMglaJ7Z0l19Ssmje8qJdYUwDQYJKoZIhvcNAQELBQAwgYMxCzAJBgNV
  BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAY
  BgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSkwJwYDVQQDEyBUZXN0IFJTQSBDZXJ0aWZpY2F0aW9u
  IEF1dGhvcml0eTAeFw0yMDA2MDMwMDAwMDBaFw0yMTA2MDMyMzU5NTlaMIHXMQswCQYDVQQGEwJV
  UzEOMAwGA1UEERMFOTUwNTQxEzARBgNVBAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC1NhbnRhIENs
  YXJhMRMwEQYDVQQJEwpTdWl0ZSAxMjUwMSIwIAYDVQQJExkyNTMwIE1pc3Npb24gQ29sbGVnZSBC
  bHZkMRowGAYDVQQKExFUcmlhbnogQ29uc3VsdGluZzEeMBwGA1UECxMVVHJpYW56IENsb3VkIFNl
  cnZpY2VzMRgwFgYDVQQDEw90cmlhbnpjbG91ZC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
  ggEKAoIBAQCy3m17TplAx25Pgc97ZlVWwbGA8b9wJMU5zhGAKoRA6EvoTGO3iFV6ocAsbCZIG3SF
  vB0W1bt9IkOgAshwOqqCiQWNiySEaWMs9WaZv3VM+an9uqf0iCp7IKAFTC9OdKFdewK6/g+DcC/F
  vqRF0SOJtQ8GA08ePjKNNU/e+pyEUdCa6tphHv+UMa6ObmFPOm2CBg92+Trl6bAqmQdy8Af23n0g
  MwS/8zE9XRe/BZ6khQzxpOMct3jLUhGH+8E9fvVATAI8OqJ4YkvUvTgDowuVXBEq0XCpKQLnCQNR
  nOMiJbN5XjSJ/r8OuK/2yPvJhEwFZPIarPt38UU31gqRl4DNAgMBAAGjggHqMIIB5jAfBgNVHSME
  GDAWgBSGhh3LBiV9JwFXa+VqONDkRK+TMjAdBgNVHQ4EFgQU8GEwjOcR83Qd6RRwfjPE61zpmsAw
  DgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
  BwMCMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMEMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
  dGlnby5jb20vQ1BTMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL1Rl
  c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB7BggrBgEFBQcBAQRvMG0wRQYIKwYBBQUH
  MAKGOWh0dHA6Ly9jcnQuY29tb2RvY2EuY29tL1Rlc3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
  LmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMFwGA1UdEQRVMFOCD3Ry
  aWFuemNsb3VkLmNvbYIUYXBwMS50cmlhbnpjbG91ZC5jb22CFGFwcDIudHJpYW56Y2xvdWQuY29t
  ghRhcHAzLnRyaWFuemNsb3VkLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEATDfyeLxQRD1i+Gj9zfrN
  sj14J2lRjS9hkF/1S1WVH/RxvjAtMNIJxXu8OgpaSDct82PEpltZdjg41QGfK3MYHG0TZ9rlGaD/
  ZvxVCM+SYHsfqesLRkf744DVRcfa19XlRt5N9eMoXwE2ofUhjsz5WlRpGszN8/0ZWhLbPK84CR4C
  bdWu7jkMcFnC6cQnzp1QTpx8ws1F3klvxJ8BHxTj4iyT0Gu7r9kLv+joKuKwDt/Rqk/LnPH5V+sb
  f03A/J3PAWvBAyUtohtoH4Xwi0NI3FnPJF/xsTjNG8NcVASbb/VNB0bAvFKNo5Sjm9W5/Q5N2zfJ
  QuS66tlGqHqjHDEfdg==
  -----END CERTIFICATE-----'''

  message_bytes = cert.encode('ascii')
  base64_cert = base64.b64encode(message_bytes)
  encodedCert = str(base64_cert,'utf-8')

  print(cert)
  print("---------------")
  print(encodedCert)

  secretName_bytes = secretName.encode('ascii')
  base64_secretName = base64.b64encode(secretName_bytes)
  encodedSecretName = str(base64_secretName,'utf-8')

  domain_bytes = domain.encode('ascii')
  base64_domain = base64.b64encode(domain_bytes)
  encodedDomain = str(base64_domain,'utf-8')

  token = getToken()
  KUBERNETES_SERVICE_HOST=os.getenv("KUBERNETES_SERVICE_HOST")
  KUBERNETES_SERVICE_PORT=os.getenv("KUBERNETES_SERVICE_PORT")
  HOST = "https://"+KUBERNETES_SERVICE_HOST+":"+KUBERNETES_SERVICE_PORT

  print("TOKEN: ----------------")
  print(token)
  print(HOST)
  print("")

  url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets"
  # url = HOST+"/api/v1/namespaces/default/secrets"
  payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedCert+"\" }, \"type\": \"Opaque\" }"
  headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': token
    }

  response = requests.request("POST", url, headers=headers, data = payload, verify=False)
  print(response.text.encode('utf8'))

def delete_cert(domain, secretName):

  token = getToken()

  url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets/"+secretName
  # url = "https://kubernetes.default/api/v1/namespaces/default/secrets/"+secretName
  headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': token
    }
  response = requests.request("DELETE", url, headers=headers)
  print(response.text.encode('utf8'))  
