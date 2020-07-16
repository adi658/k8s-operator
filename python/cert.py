import requests
import base64
import os 

def create_cert(domain, secretName):

  cert = createCertString()
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

  # url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets"
  url ="https://kubernetes.default/api/v1/namespaces/default/secrets"
  print("======================================")
  print(url)
  print("======================================")
  payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedCert+"\" }, \"type\": \"Opaque\" }"
  headers = {
    "Authorization": "Bearer "+token,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
    }

  response = requests.request("POST", url, headers=headers, data = payload, verify=False)
  print(response.text.encode('utf8'))

def delete_cert(domain, secretName):

  token = getToken()

  # url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets/"+secretName
  url = "https://kubernetes.default/api/v1/namespaces/default/secrets/"+secretName
  headers = {
    "Authorization": "Bearer "+token,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
    }

  response = requests.request("DELETE", url, headers=headers, verify=False)
  print(response.text.encode('utf8'))  

def update_cert(domain, secretName):
  print(" ------------------------ Update detected 2------------------------")
  cert = updateCertString()
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

  # url = "http://3.211.68.242:8001/api/v1/namespaces/default/secrets"
  url = "https://kubernetes.default/api/v1/namespaces/default/secrets/"+secretName
  print("======================================")
  print(url)
  print("======================================")
  payload = "{ \"kind\": \"Secret\", \"apiVersion\": \"v1\", \"metadata\": { \"name\": \""+secretName+"\", \"namespace\": \"default\" }, \"data\": { \"tls.crt\": \""+encodedCert+"\" }, \"type\": \"Opaque\" }"
  headers = {
    "Authorization": "Bearer "+token,
    'Accept': 'application/json',
    'Connection': 'close',
    'Content-Type': 'application/json'
    }

  response = requests.request("PUT", url, headers=headers, data = payload, verify=False)
  print(response.text.encode('utf8'))

def getToken():
  token = ""
  with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as file:
      token = file.read().replace('\n', '')
  return token

def getCaCert():
  cacert = ""
  with open('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'r') as file:
      token = file.read().replace('\n', '')
  return cacert

def getHost():
  KUBERNETES_SERVICE_HOST=os.getenv("KUBERNETES_SERVICE_HOST")
  KUBERNETES_SERVICE_PORT=os.getenv("KUBERNETES_SERVICE_PORT")
  HOST = "https://"+KUBERNETES_SERVICE_HOST+":"+KUBERNETES_SERVICE_PORT
  return HOST

def createCertString():
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

  return cert

def updateCertString():
  cert = '''-----BEGIN CERTIFICATE-----
  MIIFvTCCBKWgAwIBAgIRAIjZhQxK5JyCO5W2uT8e02UwDQYJKoZIhvcNAQELBQAw
  gYMxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
  BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSkwJwYD
  VQQDEyBUZXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0yMDA2MjMw
  MDAwMDBaFw0yMTA2MjMyMzU5NTlaMIHXMQswCQYDVQQGEwJVUzEOMAwGA1UEERMF
  OTUwNTQxEzARBgNVBAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC1NhbnRhIENsYXJh
  MRMwEQYDVQQJEwpTdWl0ZSAxMjUwMSIwIAYDVQQJExkyNTMwIE1pc3Npb24gQ29s
  bGVnZSBCbHZkMRowGAYDVQQKExFUcmlhbnogQ29uc3VsdGluZzEeMBwGA1UECxMV
  VHJpYW56IENsb3VkIFNlcnZpY2VzMRgwFgYDVQQDEw90cmlhbnpjbG91ZC5jb20w
  ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2B/EZNDs35yHZaRjDLg2q
  4/r0uWi+OqZTPxCG8iLPSYJh0q7mqTmiKt8uVdNk6PYo0IP0YQdBP+wW1jAKdXTy
  uyOU47B5KxwYvvZGNqkqIQxU1Z3J/AfYOQ86lEqRIe5+e7OE5xZisLMnCObu+rwJ
  y6Ycyt1M+ulWB7/4hB3YW+Ia3dgmxasBgQGIC+v8lYhExl2TvtpBhYhOWWTfgQ31
  EMRoATW9mkxvuDc0hE7qk9KDvfwlmL8LlmbKMXCPjeMF5pfUWli4JfU2VzZ7PKUU
  8WJJeOXfLam7EBAvI+ffedipGBU/nOUTaCYBd3FxSBHhR9Hj9Yu+k2+5pvsGbKUx
  AgMBAAGjggHUMIIB0DAfBgNVHSMEGDAWgBSGhh3LBiV9JwFXa+VqONDkRK+TMjAd
  BgNVHQ4EFgQUw/zbz0LW78peRezc4f7RJGGUHmkwDgYDVR0PAQH/BAQDAgWgMAwG
  A1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEAGA1Ud
  IAQ5MDcwNQYMKwYBBAGyMQECAQMEMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
  dGlnby5jb20vQ1BTMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwuY29tb2Rv
  Y2EuY29tL1Rlc3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB7BggrBgEF
  BQcBAQRvMG0wRQYIKwYBBQUHMAKGOWh0dHA6Ly9jcnQuY29tb2RvY2EuY29tL1Rl
  c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNydDAkBggrBgEFBQcwAYYYaHR0
  cDovL29jc3AuY29tb2RvY2EuY29tMEYGA1UdEQQ/MD2CD3RyaWFuemNsb3VkLmNv
  bYIUYXBwMS50cmlhbnpjbG91ZC5jb22CFGFwcDIudHJpYW56Y2xvdWQuY29tMA0G
  CSqGSIb3DQEBCwUAA4IBAQA39zykKovri+uCrWrApoWaTRUc8MglUBh0n5ai9iBP
  pBNKBC+T6fbBl9aZ8gSXkCmWucsdBoSs/se6EeNzPjuqspciADjjp3OCkjJEX4IX
  QlPye9+iu8sB0uOIX3FenfmoLEtNw9AsPaFSng2SZFlYDnv73PFKmmRXJEXbvVKU
  4DC9qALilCZdmHi9qa17AfOk0VedCGE2e+Qdh5dGerquxaPyfBgEDWkvQHVChtR8
  +khlJxXyMA48DGgkSoUvxed87Wk9vqFD8CwgouoWP1Y+PCtIfv5h3G4BGJEWf2cM
  6nhRK9Zmrh2+p+hzeDIng+ZYfoOmwuLRgThr2Ka7LeCk
  -----END CERTIFICATE-----'''

  return cert 