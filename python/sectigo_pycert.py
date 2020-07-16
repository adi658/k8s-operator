#!/usr/bin/python
# -*- coding: utf-8 -*-
import os.path
import os
import sys

import requests
import json
import time
import logging
import inspect
import yaml
import OpenSSL


from os import path
from os.path import exists, join, isdir

# ------------------------------------------------------------- #
# Sectigo Certificate Manager Client - Pycert - APIFile         #
# Version: v1.0.0                                               #
# ------------------------------------------------------------- #

from os.path import exists, join, isdir
from datetime import datetime
from OpenSSL import crypto as c
from cryptography.hazmat.primitives import hashes

from OpenSSL.crypto import _lib, _ffi, X509

from logging.handlers import RotatingFileHandler

# Does not display the entire StackTrace on the Screen. Comment this to display the entire StackTrace.
# sys.tracebacklimit = 0

python_version = "3"
if sys.version_info[0] < 3:
    python_version = "2"

# Variables
error_resp = {}

cert_csr_handler = ''
cert_csr_name = ''
cert_crt_name = ''
cert_key_name = ''
cert_ids_name = ''

connectionParams = {}
outputDict = {}
sectigo_logger_stdout_flag = True

cert_resource_data_file = "sectigo_resource_data.txt"

log = logging.getLogger(__name__)
logger = ''

operation_parameters = {
    'SECT_CSR_DATA': [                  #DONE
        'CN', 'C', 'ST', 'L', 'O', 'OU', 'emailAddress', 'sectigo_csr_key_algo', 'sectigo_csr_key_size'
    ],

    'SECT_ENROLL_SSL_CERT': [           #DONE
        'sectigo_cm_org_id', 'sectigo_ssl_cert_type', 'sectigo_ssl_cert_validity', 
        'sectigo_ssl_cert_server_type'
    ],
    'SECT_ENROLL_CLIENT_CERT': [        #DONE
        'sectigo_cm_org_id', 'sectigo_client_cert_type', 'sectigo_client_cert_validity', 
        'sectigo_client_cert_first_name',  'sectigo_client_cert_last_name', 
        'sectigo_client_cert_email'
    ],
    'SECT_ENROLL_SSL_CERT_EXCL': [      #DONE
        'sectigo_ssl_cert_custom_fields', 'sectigo_ssl_cert_external_requester', 'sectigo_ssl_cert_comments', 
        'sectigo_ssl_cert_num_servers', 'sectigo_ssl_cert_subject_alt_names'
    ],
    'SECT_ENROLL_CLIENT_CERT_EXCL': [      #DONE
        'sectigo_client_cert_middle_name', 'sectigo_client_cert_custom_fields'
    ],

    'SECT_COLLECT_SSL_CERT': [          #DONE
        'sectigo_ssl_cert_ssl_id', 'sectigo_ssl_cert_format_type', 'sectigo_max_timeout','sectigo_loop_period'
    ],
    'SECT_COLLECT_CLIENT_CERT': [       #DONE
        'sectigo_client_cert_order_number', 'sectigo_max_timeout','sectigo_loop_period'
    ],

    'SECT_REVOKE_SSL_CERT': [           #DONE
        'sectigo_ssl_cert_ssl_id', 'sectigo_revoke_reason'
    ],
    'SECT_REVOKE_CLIENT_CERT': [        #DONE
        'sectigo_client_cert_order_number', 'sectigo_revoke_reason'
    ],

    'SECT_RENEW_SSL_CERT': [            #DONE
        'sectigo_ssl_cert_ssl_id'
    ],
    'SECT_RENEW_CLIENT_CERT': [         #DONE
        'sectigo_client_cert_order_number'
    ],

    'SECT_REPLACE_SSL_CERT': [          #DONE
        'sectigo_csr', 'sectigo_replace_reason', 'sectigo_ssl_cert_common_name', 'sectigo_ssl_cert_subject_alt_names',
        'sectigo_ssl_cert_ssl_id'
    ],
    'SECT_REPLACE_CLIENT_CERT': [       #DONE
        'sectigo_csr', 'sectigo_replace_reason', 'sectigo_client_cert_revoke_on_replace',  
        'sectigo_client_cert_order_number'
    ],
    'SECT_REQUEST_MANAGED_CERT_SSL': [  #DONE
        'sectigo_ssl_cert_file_path', 'sectigo_ssl_cert_file_name', 
        'sectigo_force', 'sectigo_cm_org_id', 'sectigo_ssl_cert_type', 'sectigo_ssl_cert_validity', 
        'sectigo_ssl_cert_server_type', 'sectigo_ssl_cert_format_type', 
        'sectigo_max_timeout', 'sectigo_loop_period', 'sectigo_expiry_window', 'sectigo_auto_renew'
    ],
    'SECT_REQUEST_MANAGED_CERT_CLIENT': [ #DONE   
        'sectigo_client_cert_file_path', 'sectigo_client_cert_file_name', 
        'sectigo_force', 'sectigo_cm_org_id', 'sectigo_client_cert_type', 'sectigo_client_cert_validity',
        'sectigo_client_cert_custom_fields', 'sectigo_client_cert_first_name', 'sectigo_client_cert_middle_name', 
        'sectigo_client_cert_last_name', 'sectigo_client_cert_email',
        'sectigo_max_timeout', 'sectigo_loop_period', 'sectigo_expiry_window', 'sectigo_auto_renew'
    ],
    'SECT_REPLACE_MANAGED_CERT_SSL': [    #DONE
        'sectigo_replace_reason', 'sectigo_ssl_cert_common_name',  
        'sectigo_ssl_cert_subject_alt_names', 'sectigo_ssl_cert_file_path', 'sectigo_ssl_cert_file_name', 
        'sectigo_ssl_cert_format_type', 'sectigo_max_timeout', 'sectigo_loop_period', 'sectigo_ssl_cert_ssl_id',
        'sectigo_generate_key_if_missing'
    ],
    'SECT_REPLACE_MANAGED_CERT_CLIENT': [  #DONE
        'sectigo_replace_reason', 'sectigo_client_cert_revoke_on_replace',  
        'sectigo_client_cert_file_path', 'sectigo_client_cert_file_name', 
        'sectigo_client_cert_order_number', 'sectigo_generate_key_if_missing', 
        'sectigo_max_timeout', 'sectigo_loop_period'
    ]

}

class SectigoException(Exception):

    def __init__(self, api_json, *args, **kwargs):
        """
        Sectigo Exception Constructor
        Provides details on an exception generated by the API client
        :param api_json: A JSON representation of the error. It consists of `description` and `code`.
        """
        super(SectigoException, self).__init__(*args)
        self._error_details = json.loads(api_json)

    def error_dictionary(self):
        """
        Provides a dictionary representing the JSON document
        :return:
        """
        return self._error_details

class PKCS7EX(c.PKCS7):

    def __init__(self, parent):
        self.parent = parent

    def get_certificates(self):
        """
        Returns all certificates for the PKCS7 structure, if present. Only
        objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
        certificates.
        :return: The certificates in the PKCS7, or :const:`None` if
            there are none.
        :rtype: :class:`tuple` of :class:`X509` or :const:`None`
        """
        certs = _ffi.NULL

        if self.parent.type_is_signed():
            certs = self.parent._pkcs7.d.sign.cert

        elif self.parent.type_is_signedAndEnveloped():
            certs = self.parent._pkcs7.d.signed_and_enveloped.cert

        pycerts = []

        for i in range(_lib.sk_X509_num(certs)):
            x509 = _ffi.gc(_lib.X509_dup(_lib.sk_X509_value(certs, i)),
                           _lib.X509_free)

            pycert = X509._from_raw_x509_ptr(x509)

            pycerts.append(pycert)

        if pycerts:
            return tuple(pycerts)

    def get_certificate(self):
        """
        Returns only the certificate included in the bundle
        :return: The certificate in teh PKCS7 or :const:`None` if there are none.
        :rtype: A :class:`X509` object representing the certificate inside the pkcs7 file or :const:`None`
        """
        certs = self.get_certificates()
        for cert in certs:
            cert_data = c.dump_certificate(c.FILETYPE_TEXT, cert)
            if b'CA:TRUE' in cert_data:
                continue
            else:
                return cert

def main(certCategory,configFile):
    """
    Main function that gets invoked by Salt commands 
    param, certCategory - argument passed by user - ssl/client
    param, configFile - argument passed by user - config file name to be used
    """
    
    #Params
    global params_dict
    params_dict = {} 
    enroll_params = {}
    collect_params = {}

    #Convert arguments to proper cases. 
    certCategory = certCategory.upper()
    certCategory_pillar_file = configFile.lower()

    #Check if "certCategory_pillar_file" - "config file" exists, if not display error
    if not exists(configFile):
        msg = "File: "+configFile+" does not exist. Please pass a valid config filename with full path. Exiting!"
        WriteLog(msg)
        logger.info(msg)
        exit(1)

    #Execute commands based on certCategory passed by user.
    if certCategory == "SSL" or certCategory == "CLIENT":
        
        #Read config file into Dictionary. 
        params_dict = read_config_data(configFile, certCategory)
        RequestManagedCertificate(params_dict, certCategory)

    else: 
        msg = getMessages("passValidCertCategory")
        WriteLog(msg)
        logger.info(msg)        
        exit(1)

def format_file_path(params_dict, certCategory):
    """
    Get the common file path and filename based on SSL/CLIENT 
    param, params_dict - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    """

    if certCategory == "SSL":
        params_dict["sectigo_ssl_cert_file_path"] = check_trailing_slash(params_dict["sectigo_ssl_cert_file_path"])
        params_dict["certFilePath"] = params_dict["sectigo_ssl_cert_file_path"]
        params_dict["certFileName"] = params_dict["sectigo_ssl_cert_file_name"]
    elif certCategory == "CLIENT":
        params_dict["sectigo_client_cert_file_path"] = check_trailing_slash(params_dict["sectigo_client_cert_file_path"])
        params_dict["certFilePath"] = params_dict["sectigo_client_cert_file_path"]
        params_dict["certFileName"] = params_dict["sectigo_client_cert_file_name"]

def format_params_dict_data(params_dict, certCategory):
    """
    Get the config data and format it as required by functions. 
    1) Check if sectigo_csr is set, or CSR params are defined. 
    2) If CSR params are set, form the certSubject

    param, params_dict  - config dict 
    param, certCategory    - ssl/client

    Return True,False - flag if everything is properly set
    """

    resp = False

    # Check if 'expiryWindow' is an integer and if it is at least 1
    try:
        if 'sectigo_expiry_window' in params_dict.keys(): 
            exp_window = int(params_dict["sectigo_expiry_window"])
            if exp_window < 1:
                log_error_resp("", "expiryWindow must be at least 1 day. Exiting!")

    except ValueError:
        log_error_resp("", "expiryWindow must be an integer. Exiting!")

    # Check if sectigo_csr is provided in config and the file exists in the path.
    does_cert_ids_file_exist = does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".ids")
    if 'sectigo_csr' in params_dict.keys(): 
        if exists(params_dict['sectigo_csr']) == False:
            msg = "CSR parameter provided by user. However the file is missing at "+params_dict['sectigo_csr']
            log_error_resp("",msg)

        else:
            msg = "External CSR parameter provided by user. Location: "+params_dict['sectigo_csr']
            logger.info(msg)
            WriteLog(msg)
            resp = True

    # If sectigo_csr not provided by user, check if all CSR values exist       
    else:
        if are_csr_params_valid(params_dict):
            params_dict["certSubject"] = "C="+params_dict['sectigo_csr_country']+"/ST="+params_dict['sectigo_csr_state']+"/L="+params_dict['sectigo_csr_location']+"/O="+params_dict['sectigo_csr_organization']+"/OU="+params_dict['sectigo_csr_organization_unit']+"/CN="+params_dict['sectigo_csr_domain']+"/emailAddress="+params_dict['sectigo_csr_email_address']
            resp = True
        else:
            msg = getMessages("CsrParamNotDefined")
            log_error_resp("",msg)
            # exit(1)
    
    return resp

def baseUrlFormat(baseurl,certCategory):
    """ 
    Create the baseurl based on certCategory 
    param baseurl - baseurl passed by user
    param certCategory - SSL / CLIENT
    Return baseurl - updated baseurl 
    # https://mycertmanager.com/api/ssl/v1/
    # https://mycertmanager.com/api/smime/v1/
    """

    baseurl = check_trailing_slash(baseurl)
    if certCategory == "SSL":
        baseurl = baseurl + "api/ssl/v1/"
    elif certCategory == "CLIENT":
        baseurl = baseurl + "api/smime/v1/"

    return baseurl

def mkdirRecursive(dirpath):
    """
    Create Path required for SaltStack - To store the output files
    param, dirpath - Directory path that has to be created. 
    """

    import os
    if os.path.isdir(dirpath): return

    h,t = os.path.split(dirpath) # head/tail
    if not os.path.isdir(h):
        mkdirRecursive(h)
        msg = getMessages("CreatingFilePath")
        logger.info(msg)

    dirname = join(h,t)
    if path.exists(dirname):
        WriteLog("")
    else:
        os.mkdir(dirname)

def log_error_resp(code, description):
    """
    Log an error message and print it to the console. In addition, add the
    error message to the response that will be returned when the currently
    running certificate operation is completed.

    param, code        - error code (if provided)
    param, description - error message
    """
    global error_resp

    if description == "":
        description = "No error description received from Sectigo REST API"
    if code == "":
        code = "N.A"

    WriteLog("Code: ("+str(code)+") | Description: "+str(description)+"\n")
    logger.debug("line " + str(inspect.stack()[1][2]) + ": " + str(description))
    error_resp["code"] = code
    error_resp["description"] = description

def getReturnVal(certCategory,operation):
    """
    Get the initial Return dictionary
    param, certCategory - argument passed by user - ssl/client
    param, operation - Enroll / Renew / Revoke etc 
    Return - returns the initial dictionary 
    """

    returnVal = {"status":"FAILURE", "message":"", "timestamp": "", "category":certCategory, "operation":operation}
    
    return returnVal

def getMessages(category):
    """
    Get the message

    param, category - Get the mesage based on keyword
    Return - returns the message based on keyword
    """

    msg = {
        "CallReplaceManagedAPI"             : "Call ReplaceManagedApi to Replace the Certificate. Ending Execution",
        "CertFileExists"                    : "Validity Check: The certificate is valid, no need to auto renew!",
        "passValidCertCategory"             : "Pass valid certificate types: ssl/client. Exiting!",
        "CertExistsButExpired"              : "ALERT !!! Certificate exists, but it has expired or is in the expiry window. ",
        "BackupFiles"                       : "-- Backing up all files --",
        "CsrParamNotDefined"                : "CSR Parameters not defined or are empty. Kindly set the CSR/Key values and try again",
        "NoExistingKeyCrtFound"             : "No existing key, csr certs found. Proceeding to generate new one!",
        "RetrievedExistingPrivKeyFromFile"  : "Retrieved an existing private key from file",
        "CSRGenerateSuccess"                : "Certificate CSR generated successfully",
        "CSRGenerateFail"                   : "Certificate CSR not generated successfully",
        "ProceedCertValidCheck"             : "Proceeding with Certificate validity check...",
        "CSRContentChanged"                 : "CSR content has changed",
        "EnrollCert"                        : "--------------------- ENROLLING CERT -----------------------",
        "AutoRenewSetToFalse"               : "Certificate sectigo_auto_renew is set to false so auto-renewal will not take place. Exiting!",
        "RenewCert"                         : "Certificate has to be Renewed",
        "Exiting"                           : "Exiting!",
        "SectigoForceFalseFilesExist"       : "Cert-related files already exist, however the .ids file is missing, and sectigo_force is false; In order to enroll a new certificate, you need to either delete the existing cert-related files, or set sectigo_force to true. If you enable sectigo_force, the existing files will get backed up, and new files will get generated.",
        "ChangeRevokeFlag"                  : "Kindly change the 'sectigo_(ssl/client)_cert_revoke' flag in config to False else it will keep revoking the certificate. Exiting!",
        "PreCheckSomethingWrong"            : "Something went wrong in enroll prechecks. Exiting!",
        "CSRProvidedKeyWontBeGenerated"     : "CSR parameter provided by USER. Key will not be generated by the system",
        "GetExistCSRFromFile"               : "Retrieved an existing CSR from file",
        "KeyCsrChangedReplaceCert"          : "KEY or CSR parameters changed! Proceeding to REPLACE the certificate...",
        "ReplaceSuccess"                    : "Replace certificate successful",
        "RevokeSetToTrue"                   : "Proceeding to Revoke the existing certificate...",
        "SomethingWrongPostCollect"         : "Some went wrong in Post Collect",
        "CreatingFilePath"                  : "Creating the required filestructure",
        "IDSFileMissing"                    : "Certificate IDS file missing.",
        "MissingKey"                        : "Missing Key. If you want this program to generate a key, set 'sectigo_generate_key_if_missing' to True. Ending Execution.",
        "DomainEmailNotMatching"            : "Email does not match in the existing CLIENT certificate. Could be a wrong certificate. Delete the existing CRT file and try again"
    }
    return msg[category]
    
def get_remaining_cert_validity(cert):
    """
    Get a number of remaining days before the certficate's expiry date.

    param, cert - certificate

    return -  number of remaining days before expiry
    """
    if python_version == "3":
        expires = datetime.strptime(str(cert.get_notAfter(), 'utf-8'), "%Y%m%d%H%M%SZ")
    else:
        expires = datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")

    logger.debug("Expires: {}".format(expires))
    logger.debug("UTC Now: {}".format(datetime.utcnow()))
    remaining = (expires - datetime.utcnow()).days
    logger.debug("Remaining: {}".format(remaining))

    return remaining

def getCurrentDateTime(param):
    """
    Get a current datetime.
    return - current datetime
    """
    date_time_prefix = int(time.time()) 
    date_time_prefix = str(date_time_prefix)

    if param == 1:
        date_time_prefix = datetime.now()
        date_time_prefix = date_time_prefix.isoformat()

    return date_time_prefix

def get_cert_id(funcDict, certCategory):
    """
    Get CertId from the IDS file
    param funcDict - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return - certId        
    """
    certId = 0
    try:
        if certCategory == "SSL":
            #Get SSLID
            if does_file_exist(funcDict["sectigo_ssl_cert_file_path"],funcDict["sectigo_ssl_cert_file_name"]+".ids"):
                ids_file_full_path = funcDict["sectigo_ssl_cert_file_path"]+funcDict["sectigo_ssl_cert_file_name"]+".ids"
                ids_text = open(ids_file_full_path, 'r').read()
                ids_dict = json.loads(ids_text)
                certId = ids_dict["sslId"]
        elif certCategory == "CLIENT":
            #Get ORDERNUMBER
            if does_file_exist(funcDict["sectigo_client_cert_file_path"],funcDict["sectigo_client_cert_file_name"]+".ids"):
                ids_file_full_path = funcDict["sectigo_client_cert_file_path"]+funcDict["sectigo_client_cert_file_name"]+".ids"
                ids_text = open(ids_file_full_path, 'r').read()
                ids_dict = json.loads(ids_text)
                certId = ids_dict["orderNumber"]
    except Exception as err:
        log_error_resp("", "Could not get CertId : {}".format(str(err)))
        raise

    return certId

def getRequestHeaders(params_dict):
    """
    Set connection and Get the username/password/customeruri
    param, params_dict - config dictionary passed by user
    Return - Returns the dictionary with these 3 values
    """

    global connectionParams

    requestHeader = {
        'login': params_dict["login"],
        'password': params_dict["password"],
        'customerUri': params_dict["customerUri"]
    }
    return requestHeader

def collect_x509_format_type_cert(cert_oper_params, certCategory):

    """
    Collect a certificate that has the same sslId as the one defined in the
    IDS file (if exists) and that is in the X509 format.

    param, cert_oper_params - parameters for certificate Enroll operation =
    """

    returnVal = getReturnVal(certCategory,'Enroll')
    returnVal["scm_response"] = {}
    returnVal["category"]   = certCategory
    returnVal["operation"]  = "Collect"
    returnVal["scm_response"]["body"] = "Error Occured In CollectX509"


    # Get the IDS certificate file full path name
    ids_file_full_path = join(cert_oper_params["certFilePath"], cert_oper_params["certFileName"] + ".ids")

    # Make sure that the IDS file exists
    if not exists(ids_file_full_path):
        log_error_resp("", "Cannot collect x509 certificate, IDs file doesn't exist")
        raise SectigoException(json.dumps(error_resp))

    if "sectigo_ssl_cert_ssl_id" not in cert_oper_params.keys():
        cert_oper_params["sectigo_ssl_cert_ssl_id"] = get_cert_id(cert_oper_params, certCategory)        

    collect_request_url = """{sectigo_cm_base_url}/collect/{sectigo_ssl_cert_ssl_id}/x509CO""".format(**cert_oper_params)
        
    # Define error codes returned by the Sectigo server that are valid for waiting during Collect
    valid_waiting_err_codes = [0, -1400]

    # Change the filename to x509 for collect for collect
    origFileName = cert_oper_params["certFileName"]
    cert_oper_params["certFileName"] = cert_oper_params["certFileName"]+"_x509"
    
    # Collect
    returnVal = collect_cert(cert_oper_params, collect_request_url, returnVal, valid_waiting_err_codes)
    post_collect_status = write_cert_to_file(cert_oper_params, returnVal, certCategory)

    # Change it back to original
    cert_oper_params["certFileName"] = origFileName

    # Success
    if ('description' not in error_resp and returnVal["status"] == "SUCCESS"):
        return

    # Some Error
    elif ('description' not in error_resp) and (returnVal["status"] != "SUCCESS"):
        log_error_resp("", "Unknown x509 certificate Collect error occurred.")
        raise SectigoException(json.dumps(error_resp))

    # Sectigo Error
    elif ('description' in error_resp):
        err_msg = "x509 certificate Collect error: error_resp={0}, response={1}, status_code={2}".format(
            error_resp, returnVal["scm_response"]["body"], returnVal["scm_response"]["status_code"])
        log_error_resp("", err_msg)
        raise SectigoException(json.dumps(error_resp))

    # Some other error
    else:
        log_error_resp("", "x509 certificate Collect error: error_resp={0}".format(error_resp))
        raise SectigoException(json.dumps(error_resp))

def read_config_data(configFile, certCategory):
    """
    Read data from SaltStack config file
    param, configFile      - config filepath with filename 
    param, certCategory    - ssl/client

    return - Dictionary with all config values set as per the certCategory
    """
    params_dict = {}
    params_dict_dict = {}

    # Read config file into dictionary
    with open(configFile, 'r') as stream:
        params_dict_dict = yaml.load(stream)    
    params_dict = params_dict_dict

    return params_dict

def check_cert_validity(cert_oper_params, certCategory):
    """
    Validate a given certificate validity and expiry date.

    param, cert_oper_params      - parameters for certificate Enroll operation =
    param, cert_file_name        - certificate file name

    return -  0 - valid certificate exists
              1 - valid certificate exists, but expired
             -1 - encountered an error while validating certificate
             -2 - Wrong certificate present
    """

    msg = getMessages("ProceedCertValidCheck")
    logger.info(msg)
    WriteLog(msg)

    remaining = 90000

    deleteTempCert = False
    certParseSuccess = False
    fullCertData = ""
    cert = ""
    forceCollectCert = False

    certDomain = ""
    csrText = ""
    if 'sectigo_csr' in cert_oper_params and exists(cert_oper_params["sectigo_csr"]):
        # Read domain from the csr 
        with open(cert_oper_params["sectigo_csr"], 'r') as file_handle:
            csrText = file_handle.read()
        certDomain = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csrText).get_subject().CN
    else:
        certDomain = cert_oper_params['sectigo_csr_domain']
    
    certErr = ""

    # Read cert file and get cert data
    checkValidityCertPath = join(cert_oper_params['certFilePath'],cert_oper_params['certFileName'] + ".crt")    
    if exists(checkValidityCertPath):
        with open(checkValidityCertPath, 'rb') as validation_file:
            fullCertData = validation_file.read()

        # Try and load the CERT - If it happens, its one of the X509 formats
        try:

            if certCategory == "SSL":
                certParseSuccess = True
                logger.debug("SSL certificate")
                cert = c.load_certificate(c.FILETYPE_PEM, fullCertData)
                cert = get_right_cert(fullCertData,certCategory,certDomain)

                if cert == -2:  # Domain not matched
                    msg = "Domain doesnt match. Downloading the X509CO certificate for same SSLID temporarily. Please note that the existing crt file will not be deleted/renamed."
                    WriteLog(msg)
                    logger.info(msg)

                    # Download x509CO and read that
                    collect_x509_format_type_cert(cert_oper_params, certCategory)
                    deleteTempCert = True
                    checkValidityCertPath = join(cert_oper_params['certFilePath'],cert_oper_params['certFileName'] + "_x509" + ".crt")
                    
                    # Read file and get file contents
                    with open(checkValidityCertPath, 'rb') as validation_file:
                        fullCertData = validation_file.read()
                        cert = c.load_certificate(c.FILETYPE_PEM, fullCertData)
                        cert = get_right_cert(fullCertData,certCategory,certDomain)

            elif certCategory == "CLIENT":
                logger.debug("Client certificate")

                # This function only returns the single client cert from chain without Intermediate/ROOT (check CA:TRUE in script)
                # In actual cert theres no CA:True, which it returns
                # So, no need to further split and parse it

                pkcs7 = PKCS7EX(c.load_pkcs7_data(c.FILETYPE_PEM, fullCertData))
                cert = pkcs7.get_certificate() 

                certEmail = cert_oper_params["sectigo_client_cert_email"]
                if certEmail != format(cert.get_subject().emailAddress):
                    return -2
            
        # IF error, that means, it could be bin or base64, then download the x509CO and read that cert...
        except Exception as err:
            certErr = format(err)
            msg = "Either Base64 or BIN format. Proceeding to download the X509CO cert {0:}".format(err)
            logger.info(msg)
            certParseSuccess = False

        # Out of TRY/CATCH block

        # For Base64 and BIN (from above except condition)
        if certParseSuccess == False:

            # Try if Base64, try block = base64, except block = bin 
            try:
                pkcs7 = PKCS7EX(c.load_pkcs7_data(c.FILETYPE_PEM, fullCertData))
                cert = pkcs7.get_certificate() # Returns single cert. Check description in client cert above

            # IF error, that means, it could be bin then download the x509CO and read that cert...
            except Exception as err:
                certErr = format(err)

                # Download x509CO and read that
                collect_x509_format_type_cert(cert_oper_params, certCategory)
                deleteTempCert = True
                checkValidityCertPath = join(cert_oper_params['certFilePath'],cert_oper_params['certFileName'] + "_x509" + ".crt")
                
                # Read file and get file contents
                with open(checkValidityCertPath, 'rb') as validation_file:
                    fullCertData = validation_file.read()
                    cert = c.load_certificate(c.FILETYPE_PEM, fullCertData)
                    cert = get_right_cert(fullCertData,certCategory,certDomain)

        # Finally once we have CERT, and if its not None or ""
        if cert is not None and cert != "":

            # Pass the right cert to get the validity
            remaining = get_remaining_cert_validity(cert)

            msg = "Remaining days " + str(remaining) + ", expiry window " + str(cert_oper_params["sectigo_expiry_window"])
            logger.info(msg)
            WriteLog(msg)

            if remaining < 1 or remaining <= int(cert_oper_params["sectigo_expiry_window"]):
                msg = getMessages("CertExistsButExpired")
                logger.info(msg)
                WriteLog(msg)
                return 1

            elif str(remaining).strip() == "":
                log_error_resp("", "Unable to read the certificate validity.")
                return -1

            else:
                msg = "Valid certificate exists and is valid up to " + format(remaining) + " days"
                logger.info(msg)
                WriteLog(msg)
                return 0

            # Delete the temporary certificate file, only if X509
            if deleteTempCert == True:
                os.remove(checkValidityCertPath)
        
        else: 
            log_error_resp("", "Error validating certificate: "+certErr)
            return -1

def get_right_cert(fullCertData,certCategory,certDomain):
    """
        Get the right cert from the bundle
        param fullCertData - full cert bundle
        param certCategory - argument passed by user - ssl/client
        param certDomain - Domain passed by user
        Return - cert - if domain matches 
                 -2   - if domain doesnt match
    """

    ct = 0
    splitText = "-----BEGIN CERTIFICATE-----"
    singleCertArr = []
    if python_version == "3":
        if type(fullCertData) is bytes:
            singleCertArr = str(fullCertData,'utf-8').split(splitText)
        else:
            singleCertArr = fullCertData.split(splitText)
    else:
        singleCertArr = fullCertData.split(splitText)

    for singleCert in singleCertArr:
        if singleCert != "":
            ct = ct +1 
            singleCert = splitText + singleCert
            singleCert =  c.load_certificate(c.FILETYPE_PEM, singleCert)

            if certDomain == format(singleCert.get_subject().commonName):
                # Return Correct Cert
                return singleCert

    # Correct Cert not found, so return -1    
    return -2
    
def rename_key_csr_if_externalcsr_exists(cert_oper_params,certCategory):
    """
    Rename key and csr if external csr exists
    param, cert_oper_params - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    """
    key_file_full_path = cert_oper_params["certFilePath"]+cert_oper_params["certFileName"]+".key"
    key_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'key',certCategory)
    csr_file_full_path = cert_oper_params["certFilePath"]+cert_oper_params["certFileName"]+".csr"
    csr_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'csr',certCategory)

    if exists(key_file_full_path):
        os.rename(key_file_full_path, key_file_full_path_new)
    if exists(csr_file_full_path):
        os.rename(csr_file_full_path, csr_file_full_path_new)

def rename_crt_ids_file(cert_oper_params,certCategory):
    """
    Rename certification files (CRT, CRS, IDS, KEY) such that current date/time
    gets added to their names.
    # Dont want to rename key and csr for 'sectigo_force'.. this function is only used in a couple of places
    """

    # Get certificate files full path names
    crt_file_full_path = join(cert_oper_params["certFilePath"], cert_oper_params["certFileName"]+".crt")
    ids_file_full_path = join(cert_oper_params["certFilePath"], cert_oper_params["certFileName"]+".ids")

    try:
        # Get the current date/time 
        date_time_prefix = getCurrentDateTime(0)

        # Get certificate files full path names
        crt_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'crt',certCategory)
        ids_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'ids',certCategory)

        if exists(crt_file_full_path):
            os.rename(crt_file_full_path, crt_file_full_path_new)

        if exists(ids_file_full_path):
            os.rename(ids_file_full_path, ids_file_full_path_new)

    except Exception as err:
        log_error_resp("", "Failed to rename certificate files: ".format(str(err)))
        raise

def rename_cert_files_all(cert_oper_params,certCategory):
    """
    In case of REVOKE, rename all files..

    param, cert_oper_params      - certificate REVOKE operation parameters

    """

    msg = getMessages("BackupFiles")
    logger.info(msg)
    WriteLog(msg)

    date_time_prefix = getCurrentDateTime(0)

    crt_file_full_path = cert_oper_params["certFilePath"]+cert_oper_params["certFileName"]+".crt"
    crt_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'crt',certCategory)
    csr_file_full_path = cert_oper_params["certFilePath"]+cert_oper_params["certFileName"]+".csr"
    csr_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'csr',certCategory)
    key_file_full_path = cert_oper_params["certFilePath"]+cert_oper_params["certFileName"]+".key"
    key_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'key',certCategory)    
    ids_file_full_path = cert_oper_params["certFilePath"]+cert_oper_params["certFileName"]+".ids"
    ids_file_full_path_new = createBackupFileFormat(cert_oper_params["certFilePath"],cert_oper_params["certFileName"],'ids',certCategory)    

    if exists(key_file_full_path):
        os.rename(key_file_full_path, key_file_full_path_new)

    if exists(csr_file_full_path):
        os.rename(csr_file_full_path, csr_file_full_path_new)

    if exists(crt_file_full_path):
        os.rename(crt_file_full_path, crt_file_full_path_new)

    if exists(ids_file_full_path):
        os.rename(ids_file_full_path, ids_file_full_path_new)

def is_valid_collect_waiting_code(resp_code, valid_code_array):
    """
    Check if the collect Sectigo error return code is a valid code for waiting.

    param, resp_code        - Response error code received from Sectigo server
    param, valid_code_array - Array of valid error codes,
                              'None' if all error codes are valid

    return - True,  Sectigo error code is a valid waiting code
             False, Otherwise
    """
    if valid_code_array is None:
        # All return codes are considered valid
        return True

    if resp_code in valid_code_array:
        return True

    return False

def createBackupFileFormat(filepath, filename, ext, certCategory):
    """
    create backup file format in case the files have to be backedup
    param filepath - filepath of the file to be backedup
    param filename - filename of the ifle to be backedup
    param ext - extention of the file
    param, certCategory - argument passed by user - ssl/client 
    Return filename of the backup file    
    """
    funcDict = {}
    try:
        if does_file_exist(filepath,filename+"."+ext):
            if certCategory == "SSL":
                funcDict["sectigo_ssl_cert_file_path"] = filepath
                funcDict["sectigo_ssl_cert_file_name"] = filename
            elif certCategory == "CLIENT":
                funcDict["sectigo_client_cert_file_path"] = filepath
                funcDict["sectigo_client_cert_file_name"] = filename
                
            certId = get_cert_id(funcDict,certCategory)

            date_time_prefix = getCurrentDateTime(0)
            filename = filepath+filename+"_"+str(certId)+"_backup_"+date_time_prefix+"."+ext

            return filename

    except Exception as err:
        log_error_resp("", "Could not get BackupFileFormat : {}".format(str(err)))
        exit(1)

def write_to_ids_file(param_dict,certCategory,response):
    """
    Write content sslid/ordernumber to ids filepath
    param, param_dict   - config data
    param, filepath     - path of the file to write the data
    param, content      - content that needs to be written
    """
    response = json.loads(response)
    cert_ids_file_full_path = param_dict["certFilePath"]+param_dict["certFileName"]+".ids"
    f = open(cert_ids_file_full_path, 'w')
    f.write(str(response))

def WriteLog(msg):
    """
    Function to print the messages to console bsaed on the 'sectigo_logger_stdout_flag' parameter
    param msg - message to be printed
    """
    global sectigo_logger_stdout_flag

    if sectigo_logger_stdout_flag == True:
        print(msg)
        print("")

def ConfigureLogger(params_dict):
    """
    Define the logger details
    param, params_dict - config dictionary passed by user
    """
    global logger 
    global sectigo_logger_stdout_flag

    # Initialize Logger and the configuration
    logger = logging.getLogger("entrypointlog")
    formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s: %(message)s')
    logger.setLevel(logging.DEBUG)

    # # Define Handlers for Logs - Stream Handler
    # stream_handler = logging.StreamHandler()
    # stream_handler.setLevel(logging.DEBUG)
    # stream_handler.setFormatter(formatter)

    # Create default log folder if not available
    sectigo_logger_file_dir = "/etc/ssl/"
    if not path.exists(sectigo_logger_file_dir):
        os.mkdir(sectigo_logger_file_dir)

    sectigo_logger_file_path = sectigo_logger_file_dir+"sectigo_pycert.log"
    sectigo_logger_max_file_size =  10000000 # 10 MB
    sectigo_logger_max_num_backups = 10
    print(params_dict)
    if 'sectigo_logger_file_path' in params_dict.keys():
        print("-------------- log 1")
        sectigo_logger_file_path = params_dict["sectigo_logger_file_path"]
    
    if 'sectigo_logger_max_file_size' in params_dict.keys():
        sectigo_logger_max_file_size = params_dict["sectigo_logger_max_file_size"]

    if 'sectigo_logger_max_num_backups' in params_dict.keys():
        sectigo_logger_max_num_backups = params_dict["sectigo_logger_max_num_backups"]

    if 'sectigo_logger_stdout_flag' in params_dict.keys():
        sectigo_logger_stdout_flag = params_dict["sectigo_logger_stdout_flag"]

    # Define Handlers for Logs - Logfile Handler
    logFilePath = sectigo_logger_file_path
    print("===============================")
    print(logFilePath)
    print("===============================")
    file_handler = RotatingFileHandler(filename=logFilePath, maxBytes=sectigo_logger_max_file_size, backupCount=sectigo_logger_max_num_backups)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Add the Handlers to Logger for various types of Logging 
    if not logger.handlers:
        logger.addHandler(file_handler)
        # logger.addHandler(stream_handler)

def createOutputJson(returnVal,certCategory,funcCategory,sub_operations):
    """
    Create the sub-operations section
    param returnVal - the scm_response of the sub operations 
    param certCategory - argument passed by user - ssl/client
    funcCategory - Operation - Enroll/Renew/Replace/etc
    sub_operations - The existing sub operations section to be appended
    Return outputDict - THe final output dictionary to be returned
    """
    global outputDict

    date_time_prefix = getCurrentDateTime(0)
    newReturnVal = {}
    outputDict["sub_operations"] = sub_operations
    try: 

        message = returnVal["message"]

        outputDict["status"] = returnVal["status"]
        outputDict["category"] = returnVal["category"]
        outputDict["timestamp"] = date_time_prefix
        outputDict["message"] = message
        outputDict["operation"] = funcCategory

        if 'certificate' in returnVal.keys():
            if returnVal["certificate"] != "":
                outputDict["certificate"] = returnVal["certificate"]

        if 'csr' in returnVal.keys():
            if returnVal["csr"] != "":
                outputDict["csr"] = returnVal["csr"]

        if 'private_key' in returnVal.keys():
            if returnVal["private_key"] != "":
                if python_version == "3":
                    if type(returnVal["private_key"]) is bytes:
                        returnVal["private_key"] = str(returnVal["private_key"],'utf-8')
                outputDict["private_key"] = returnVal["private_key"]

        if 'ssl_id' in returnVal.keys():
            outputDict["ssl_id"] = returnVal["ssl_id"]
        if 'orderNumber' in returnVal.keys():
            outputDict["orderNumber"] = returnVal["orderNumber"]

        newReturnVal["message"] = message

        # In case of some errors only, print the body into message. Else most of the times, it says So and so implies.. 
        # Otherwise it prints certificate in msg
        if 'scm_response' in returnVal.keys(): 
            if 'body' in returnVal["scm_response"]:
                if returnVal["scm_response"]["body"] != "" and returnVal["operation"] != "Collect" :
                    newReturnVal["message"] = returnVal["scm_response"]["body"]

        newReturnVal["status"] = returnVal["status"]
        newReturnVal["timestamp"] = returnVal["timestamp"]
        newReturnVal["operation"] = returnVal["operation"]
 
        outputDict["sub_operations"].append(newReturnVal)

    except Exception as err:
        msg = "Error in creating output message: {}".format(str(err))
        log_error_resp("", msg)
    
    return outputDict

def check_error(returnVal,params_dict):
    """
    CHeck if there is any error added to the error dictionary. If yes, display it
    param returnVal - sub opration return dictionary
    param, params_dict - config dictionary passed by user
    return - dictionary to be displayed on screen
    """
    if 'description' in error_resp:
        date_time_prefix = getCurrentDateTime(1)
        returnVal["message"] = error_resp["description"].replace("'","")
        returnVal["timestamp"] = date_time_prefix

        logger.info(returnVal)
        WriteLog(returnVal)

    return returnVal

###################################################  Validation Function - START

def check_if_managed(params_dict):
    """
    Check if managed operation - RequestManaged or ReplaceManaged. Setting the flag manually in these 2 functions
    param, params_dict - config dictionary passed by user
    Return True/False
    """
    flg = False 
    if 'managedCert' in params_dict.keys():
        if params_dict["managedCert"] == True:
            flg = True 
    
    return flg

def check_trailing_slash(filepath):
    """
    Checks trailing slashes in the filepath. If not present, adds it
    param filepath - filepath

    return - Filepath with a slash at the end
    """
    if filepath[-1:] != "/":
        filepath = filepath+"/"
    return filepath

def validate_cert_category(certCategory):
    """
    Check if certCategory is either SSL / CLIENT else display error
    param, certCategory - argument passed by user - ssl/client
    Return True/False
    """
    if certCategory == "SSL" or certCategory == "CLIENT":
        return True
    else: 
        msg = getMessages("passValidCertCategory")
        log_error_resp("",msg)
    return False

def get_param_name_list(operation):
    """
    Get a list of parameter names required for a given certificate operation.

    param, operation - certification operation for which parameter names are obtained

    return - list of parameters for a given certification operation
    """
    return operation_parameters[operation]

def does_file_exist(file_path, file_name):
    """
    Check if a given file exists on a given file path.

    param, file_path - full file path
    param, file_name - file name

    return -  True  - file exists
              False - otherwise
    """
    file_full_path = join(file_path, file_name)

    if isdir(file_path):

        if exists(file_full_path):
            logger.info("File path: " + str(file_full_path) + " exists... Reading it.")
            return True

        else:
            logger.info("File path: " + str(file_full_path) + " does not exist...")
            return False

    else:
        logger.info("File path: " + str(file_path) + " does not exist...")
        return False

def are_required_param_names_defined(operation, param_dict) :
    """
    check if required params for each of the operation are defined in the config data passed by user
    param operation - Enroll/Renew/Replace etc 
    param params_dict - config dictionary passed by user
    Return True/False
    """
    response = False

    # Get a list of requested parameter names from the 'configfile' file
    file_param_name_list = get_param_name_list(operation)

    # Get a list of parameter names (keys) from the input parameter dictionary
    dict_param_name_list = list(param_dict.keys())
    
    # Check if all required parameter names defined
    result = all(item in dict_param_name_list for item in file_param_name_list)
    if result:
        response = True
    else:
        # Let's find the missing parameter and report it
        for file_item in file_param_name_list:
            for input_item in dict_param_name_list:
                if file_item == input_item:
                    break
            else:
                log_error_resp("","Missing input parameter: {0}".format(str(file_item)))

    return response
    
def are_required_param_names_valid(operation, params_dict) :
    """
    check if required params for each of the operation are valid and not empty in the config data passed by user
    param operation - Enroll/Renew/Replace etc 
    param params_dict - config dictionary passed by user
    Return True/False
    """

    # Check if all required parameter names are not empty
    response = False
    # Get a list of requested parameter names from the 'configfile' file
    file_param_name_list = get_param_name_list(operation)

    for file_item in file_param_name_list:
        if params_dict[file_item] == "":
            log_error_resp("",file_item+" must not be empty.")
            break
        else:
            response = True

    return response

def are_requestManaged_cert_params_valid(cert_oper_params, certCategory):
    """
    check if required params for RequestManaged cert are defined in the config data passed by user
    param cert_oper_params - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return True/False
    """
    response = False
    requestManagedLabel = "SECT_REQUEST_MANAGED_CERT_"+certCategory
    requestManagedLabelExc = "SECT_ENROLL_"+certCategory+"_CERT_EXCL"
    excParamsDefinedFlag = ""

    if certCategory == "SSL":
        excParamsDefinedFlag = are_required_param_names_defined(requestManagedLabelExc,cert_oper_params)
    elif certCategory == "CLIENT":
        excParamsDefinedFlag = True

    # check if request managed related params are defined and not empty
    paramsDefinedFlag = are_required_param_names_defined(requestManagedLabel,cert_oper_params)
    if paramsDefinedFlag and excParamsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(requestManagedLabel,cert_oper_params)
        if paramsValidFlag:
            response = True

            # if all fine, check subj params if sectigo_csr not defined. 
            if 'sectigo_csr' not in cert_oper_params.keys():
                subjParamValidFlag = are_csr_params_valid(cert_oper_params)
                if subjParamValidFlag != True: 
                    response = False    # msg alread present in log_error_resp

    return response

def are_replaceManaged_cert_params_valid(cert_oper_params, certCategory):
    """
    check if required params for ReplaceManaged cert are defined in the config data passed by user
    param cert_oper_params - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return True/False
    """
    response = False
    replaceManagedLabel = "SECT_REPLACE_MANAGED_CERT_"+certCategory

    # check if request managed related params are defined and not empty
    paramsDefinedFlag = are_required_param_names_defined(replaceManagedLabel,cert_oper_params)
    if paramsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(replaceManagedLabel,cert_oper_params)
        if paramsValidFlag:
            response = True

            # if all fine, check subj params if sectigo_csr not defined. 
            if 'sectigo_csr' not in cert_oper_params.keys():
                subjParamValidFlag = are_csr_params_valid(cert_oper_params)
                if subjParamValidFlag != True:
                    response = False    # msg alread present in log_error_resp
    return response

def are_enroll_cert_params_valid(cert_oper_params, certCategory):
    """
    Check if parameters for the Enroll SSL/CLIENT certificate operation are valid.
    param, cert_oper_params - parameters for SSL/CLIENT certificate Enroll operation
    param, certCategory - argument passed by user - ssl/client

    return -  True  - parameters are valid
              False - otherwise
    """
    response = False
    enrollLabel = "SECT_ENROLL_"+certCategory+"_CERT"
    enrollLabelExc = "SECT_ENROLL_"+certCategory+"_CERT_EXCL"

    # check if enroll related params are defined and not empty
    paramsDefinedFlag = are_required_param_names_defined(enrollLabel,cert_oper_params)
    
    excParamsDefinedFlag = ""
    if certCategory == "SSL":
        excParamsDefinedFlag = are_required_param_names_defined(enrollLabelExc,cert_oper_params)
    elif certCategory == "CLIENT":
        excParamsDefinedFlag = are_required_param_names_defined(enrollLabelExc,cert_oper_params)
    if paramsDefinedFlag and excParamsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(enrollLabel,cert_oper_params)
        if paramsValidFlag:
            response = True

            # if all fine, check subj params if sectigo_csr not defined. 
            if 'sectigo_csr' not in cert_oper_params.keys():
                subjParamValidFlag = are_csr_params_valid(cert_oper_params)
                if subjParamValidFlag != True: 
                    response = False    # msg alread present in log_error_resp

    return response

###################################################  Validation Function - END

###################################################  KEY / CSR Generation Function - START

def get_subject_params(cert_oper_params):
    """
    Get a list of subject parameters used to generate content for the certificate CRS file.

    param, cert_oper_params - parameters for the current certificate operation

    return - a dictionary containing subject parameters
    """
    # Skip check if certSubject is null or empty
    
    cert_subject_params = {}
    if 'certSubject' in cert_oper_params:
        subject_content = cert_oper_params["certSubject"]

        subject_content = subject_content.replace('"', '')
        subject_content = subject_content.replace("'", "")
        subject_content_array = subject_content.split("/")

        for line in subject_content_array:
            item = [line_item.strip() for line_item in line.split('=')]
            cert_subject_params[item[0]] = item[1]
    else: 
        if are_csr_params_valid(cert_oper_params): 
            cert_subject_params = {
                "C" : params_dict['sectigo_csr_country'],
                "ST" : params_dict['sectigo_csr_state'],
                "L" : params_dict['sectigo_csr_location'],
                "O" : params_dict['sectigo_csr_organization'],
                "OU" : params_dict['sectigo_csr_organization_unit'],
                "CN" : params_dict['sectigo_csr_domain'],
                "emailAddress" : params_dict['sectigo_csr_email_address']
            }
    return cert_subject_params

def are_csr_params_valid(params_dict):
    """
    Check if all the CSR params are defined and not empty. 
    param, params_dict - config dictionary passed by user
    Return True/False
    """
    resp = False
    msg = getMessages("CsrParamNotDefined")

    if (('sectigo_csr_country' in params_dict.keys()) and ('sectigo_csr_state' in params_dict.keys()) and  
    ('sectigo_csr_location' in params_dict.keys()) and ('sectigo_csr_organization' in params_dict.keys()) and 
    ('sectigo_csr_organization_unit' in params_dict.keys()) and 
    ('sectigo_csr_email_address' in params_dict.keys()) and ('sectigo_csr_key_algo' in params_dict.keys()) and 
    ('sectigo_csr_key_size' in params_dict.keys()) and ('sectigo_csr_domain' in params_dict.keys()) ):
    
        if ((params_dict['sectigo_csr_country'] != "") and (params_dict['sectigo_csr_state'] != "") and 
        (params_dict['sectigo_csr_location'] != "") and (params_dict['sectigo_csr_organization'] != "") 
        and (params_dict['sectigo_csr_organization_unit'] != "") and (params_dict['sectigo_csr_email_address'] != "") 
        and (params_dict['sectigo_csr_key_algo'] != "") and (params_dict['sectigo_csr_key_size'] != "") and 
        (params_dict['sectigo_csr_domain'] != "") ):
            resp = True
        else:
            log_error_resp("",msg)
    else:
        log_error_resp("",msg)

    return resp
    
def generate_private_key(file_path, file_name, enroll_cert_params, certCategory):
    """
    Generate private key for a certificate request.

    param, file_path - certificate key file path
    param, file_name - certificate key file name
    param, enroll_cert_params - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client

    return - certificate key if it was successfully generated
             None, otherwise
    """
    # Proceed with new certificate key generation.
    msg = getMessages("NoExistingKeyCrtFound")
    logger.info(msg)
    WriteLog(msg)

    # IF key is not there, CSR cannot be old. Rename the CSR
    date_time_prefix = getCurrentDateTime(0)

    # Only for RequestManagedCertificate.
    if check_if_managed(enroll_cert_params):
        csr_file_full_path = enroll_cert_params["certFilePath"]+enroll_cert_params["certFileName"]+".csr"
        csr_file_full_path_new = createBackupFileFormat(enroll_cert_params["certFilePath"],enroll_cert_params["certFileName"],'csr',certCategory)

        if exists(csr_file_full_path):
            os.rename(csr_file_full_path, csr_file_full_path_new)

    cert_key = c.PKey()

    try:
        # Generate certification key
        cert_key.generate_key(c.TYPE_RSA, enroll_cert_params["sectigo_csr_key_size"])

        # Write to file only for RequestManagedCertificate. Else have it only in the cert_key variable
        if check_if_managed(enroll_cert_params):
            # Certificate key file full path
            cert_key_file_full_path = join(file_path, file_name)

            # Open the certificate key file and write the key into it
            if python_version == "3":
                open(cert_key_file_full_path,
                    "wt").write(str(c.dump_privatekey(c.FILETYPE_PEM, cert_key), 'utf-8'))
            else:
                open(cert_key_file_full_path,
                    "wb").write(c.dump_privatekey(c.FILETYPE_PEM, cert_key))

    except Exception as err:
        log_error_resp("", "Error in certificate private key generation: {}".format(err))
        return None
        # raise

    else:

        if check_if_managed(enroll_cert_params):
            if exists(cert_key_file_full_path):
                logger.info("Certificate key file " + str(file_name) + " generated successfully.")
                WriteLog("Certificate key file " + str(file_name) + " generated successfully.")
                return cert_key
            else:
                log_error_resp("", "Certificate key file " + str(file_name) + " not generated successfully.")
                return None
        else:
            if cert_key!="":
                return cert_key
            else:
                log_error_resp("", "Certificate key not generated successfully.")
                return None

def get_private_key_from_file(cert_oper_params):
    """
    Get a private key from the KEY file. 
    
    param, cert_oper_params - certificate Enroll operation parameters
    
    return - private key
    """

    # Get the full path name of the KEY file
    key_file_full_path = join(cert_oper_params['certFilePath'], cert_oper_params['certFileName']+".key")

    try:
        # Retrieve an existing private key from the KEY file                      
        with open(key_file_full_path, 'rb') as file:

            key_file_data = file.read()
            priv_key = c.load_privatekey(c.FILETYPE_PEM, key_file_data)

        msg = getMessages("RetrievedExistingPrivKeyFromFile")
        logger.info(msg)
        WriteLog(msg)

    except Exception as err:
        priv_key = None
        log_error_resp("", "Unable to retrieve private key from file: {}".format(str(err)))
        # raise

    return priv_key

def is_cert_csr_generated(cert_oper_params, file_path, file_name, cert_key, certCategory):
    """
    Generate CSR for a certificate request (operation)

    param, cert_oper_params  - certificate parameter dictionary that contains
                               parameters required for this operation
    param, file_path         - certificate CSR file path
    param, file_name         - certificate CSR file name
    param, cert_key          - certificate key
    param, certCategory      - argument passed by user - ssl/client

    return - True,  certificate CSR was successfully generated
             False, otherwise
    """
    global cert_csr

    # Only for RequestManagedCertificate.
    cert_csr_file_full_path = ""
    if check_if_managed(cert_oper_params):
        # Get full path name of the certificate CRS file
        cert_csr_file_full_path = join(file_path, file_name)

        # Check if the csr already exists
        if exists(cert_csr_file_full_path):

            logger.info("Certificate CSR file " + str(file_name) + " generated successfully.")
            WriteLog("Certificate CSR file " + str(file_name) + " generated successfully.")
            return True

    # Proceed with new certificate CSR generation
    if 'sectigo_csr_domain' in cert_oper_params:
        log_msg = "Proceeding with Certificate CSR generation: (CN Name: "+cert_oper_params["sectigo_csr_domain"]+")"
        logger.info(log_msg.strip())
        WriteLog(log_msg.strip())

    cert_subj_aliases = []

    cert_subject_params = get_subject_params(cert_oper_params)

    subject_alt_names = ""
    if certCategory == "SSL":
        subject_alt_names = cert_oper_params["sectigo_ssl_cert_subject_alt_names"]
    elif certCategory == "CLIENT":
        subject_alt_names = ""

    try:
        if subject_alt_names != "":
            for val in cert_subject_params:

                logger.debug("Module Key : " + val + ", Value : " + cert_subject_params[val])

            aliases = subject_alt_names.split(",")

            if aliases:
                for alias in aliases:
                    cert_subj_aliases.append("DNS:{}".format(alias))

            # Generate a CSR          
            cert_csr = c.X509Req()
            cert_csr.get_subject().CN = cert_subject_params["CN"]
            cert_csr.get_subject().C = cert_subject_params["C"]
            cert_csr.get_subject().ST = cert_subject_params["ST"]
            cert_csr.get_subject().L = cert_subject_params["L"]
            cert_csr.get_subject().O = cert_subject_params["O"]
            cert_csr.get_subject().OU = cert_subject_params["OU"]
            cert_csr.get_subject().emailAddress = cert_subject_params["emailAddress"]
            cert_csr.set_pubkey(cert_key)

            if python_version == "3":
                logger.info(",".join(cert_subj_aliases))

                cert_subj_aliases_bytes = str.encode(",".join(cert_subj_aliases))
                subject_alt_name_bytes = str.encode('subjectAltName')

                cert_csr.add_extensions([c.X509Extension(subject_alt_name_bytes,
                                                         False,
                                                         cert_subj_aliases_bytes)])
            else:
                cert_csr.add_extensions([c.X509Extension("subjectAltName",
                                                         False,
                                                         ",".join(cert_subj_aliases))])

            cert_csr.sign(cert_key, hashes.SHA256().name)

            # Only for RequestManagedCertificate.
            if check_if_managed(cert_oper_params):
                # Open the file
                open(cert_csr_file_full_path,
                    "wb+").write(c.dump_certificate_request(c.FILETYPE_PEM, cert_csr))

        else:
            # Generate a CSR
            cert_csr = c.X509Req()
            cert_csr.get_subject().CN = cert_subject_params["CN"]
            cert_csr.get_subject().C = cert_subject_params["C"]
            cert_csr.get_subject().ST = cert_subject_params["ST"]
            cert_csr.get_subject().L = cert_subject_params["L"]
            cert_csr.get_subject().O = cert_subject_params["O"]
            cert_csr.get_subject().OU = cert_subject_params["OU"]
            cert_csr.get_subject().emailAddress = cert_subject_params["emailAddress"]
            cert_csr.set_pubkey(cert_key)
            cert_csr.sign(cert_key, hashes.SHA256().name)

            # Only for RequestManagedCertificate.
            if check_if_managed(cert_oper_params):
                # Open the file
                open(cert_csr_file_full_path,
                    "wb+").write(c.dump_certificate_request(c.FILETYPE_PEM, cert_csr))

    except Exception as err:

        log_error_resp("", "Error in certificate CSR generation: {}".format(err))
        return False 
        # raise

    else:

        # Only for RequestManagedCertificate.
        if check_if_managed(cert_oper_params):

            if exists(cert_csr_file_full_path):
                msg = "Certificate CSR file " + str(file_name) + " generated successfully."
                logger.info(msg)
                WriteLog(msg)
                return True
            else:
                log_error_resp("", "Certificate CSR file " + str(file_name) + " not generated successfully.")
                return False
        else:

            # For Unmanaged, just check the variable
            if cert_csr != "":
                msg = getMessages("CSRGenerateSuccess")
                logger.info(msg)
                WriteLog(msg)
                return c.dump_certificate_request(c.FILETYPE_PEM, cert_csr)
            else:
                msg = getMessages("CSRGenerateFail")
                log_error_resp("", msg)
                return False

def prepare_csr_content_for_enroll_request(file_path, file_name, csr_content):
    """
    Get CRS content for Enroll certificate requests

    param, file_path - certificate file path
    param, file_name  - name of CSR certificate related file
    param, csr_content - csr content in casae of Direct API endpoints. The above 2 are null in case of direct api endpoints 
    return - CRS content from the file
    """

    # Get the full path CSR file name
    
    # FOr UnManaged and ManagedCert | For UnManaged -> only provide csr_content 
    if file_path != "" and file_name != "" and csr_content == "":

        csr_file_full_path = join(file_path, file_name)

        # Get the CSR file content            
        with open(csr_file_full_path, 'r') as file_handle:
            csr_content = file_handle.read()

    csr_content = csr_content.replace('\n', '')  # remove new line char
    csr_content = csr_content.replace('--- ', '')  # begin certificate
    csr_content = csr_content.replace(' ---', '')  # end certificate

    return csr_content

def is_first_time_apply(params_dict):
    """
    Checks if this is a first time apply.
    param, params_dict - config dict
    return             - True / False -> If IDS file exists, its not a first time apply, 
                            else it is first time apply 
    """

    flg = True 
    
    ids_file_exists = does_file_exist(params_dict["certFilePath"],params_dict["certFileName"]+".ids")
    if ids_file_exists:
        flg = False

    return flg    

def is_to_continue_with_enroll(cert_oper_params, certCategory):
    """
    Validate if necessary criteria is met to start the certificate Enroll operation.

    param, cert_oper_params      - certificate Enroll operation parameters

    return - True, necessary conditions are met
             False, otherwise
    """

    is_to_continue_response = ""

    # Check if certificate already exists locally, else generate a new certificate
    does_cert_crt_file_exist = does_file_exist(cert_oper_params["certFilePath"], cert_oper_params["certFileName"]+".crt")
    does_cert_key_file_exist = does_file_exist(cert_oper_params["certFilePath"], cert_oper_params["certFileName"]+".key")
    does_cert_csr_file_exist = does_file_exist(cert_oper_params["certFilePath"], cert_oper_params["certFileName"]+".csr")
    does_cert_ids_file_exist = does_file_exist(cert_oper_params["certFilePath"], cert_oper_params["certFileName"]+".ids")
    
    # If sectigo_force = True
    if cert_oper_params['sectigo_force'] == True:
        rename_cert_files_all(cert_oper_params,certCategory)
        is_to_continue_response = "EnrollCert"
    else:
        if does_cert_ids_file_exist == False:                                                           # IDS=F 
            if ('sectigo_csr' in cert_oper_params.keys() and exists(cert_oper_params['sectigo_csr'])):       # EXTCSR=T
                if (does_cert_key_file_exist == False and does_cert_csr_file_exist == False                     # KEY=F,CSR=F,CRT=F
                    and does_cert_crt_file_exist == False):
                    is_to_continue_response = "EnrollCert"                                                          # ENROLL using EXTCSR
                else: 
                    is_to_continue_response = "SectigoForceFalseFilesExist"                                     # some file present withoud IDS
            else:                                                                                           # EXTCSR=F
                if does_cert_key_file_exist == False:                                                            # KEY=F
                    if does_cert_csr_file_exist == False and does_cert_crt_file_exist == False:                     # CSR=F, CRT=F
                        is_to_continue_response = "EnrollCert"                                                          # ENROLL -> nothing present
                    else: 
                        is_to_continue_response = "SectigoForceFalseFilesExist"                                     # some file present withou IDS and KEY
                else:                                                                                           # KEY=T    
                    is_to_continue_response = "EnrollCert"                                                          # ENROLL -> For cases where CSR is present/absent with only Key and no CRT
                    if does_cert_crt_file_exist:                                                                    # CRT=T
                        is_to_continue_response = "SectigoForceFalseFilesExist"                                         # CRT present without IDS
                    else:                                                                                           # CRT=F
                        is_to_continue_response = "EnrollCert"                                                          # ENROLL using KEY
        else:                                                                                           # If IDS = TRUE 
            if does_cert_crt_file_exist:                                                                    # If CRT = TRUE

                # 0 -> Valid CRT | 1 -> Valid but Expired | -1 -> Some Error
                status = check_cert_validity(cert_oper_params, certCategory)                                    # Check Validity

                if status == -1:                                                                                # Error
                    if 'description' not in error_resp:
                        log_error_resp("", "Unable to validate certificate")

                elif status == -2:                                                                              # DOMAIN name/email in cert error
                    msg = getMessages("DomainEmailNotMatching")
                    log_error_resp("", msg)
                    
                elif status == 0:                                                                               # ALL OK, END # In case sectigo_csr, backup key and csr from path
                    is_to_continue_response = "CertFileExists"
                    if ('sectigo_csr' in cert_oper_params.keys()):                                                  # In case of Collect and sectigo_csr, backup key and csr from path
                        rename_key_csr_if_externalcsr_exists(cert_oper_params,certCategory)

                else:                                                                                           # EXISTS BUT EXPIRED. 
                    if cert_oper_params["sectigo_auto_renew"] is True:
                        is_to_continue_response = "RenewCert"
                        if ('sectigo_csr' in cert_oper_params.keys()):                                                  # In case of Collect and sectigo_csr, backup key and csr from path
                            rename_key_csr_if_externalcsr_exists(cert_oper_params,certCategory)
                    else:
                        is_to_continue_response = "ExpiredButRenewFlagNotSet" 
            else:                                                                                           # IF CRT = FALSE -> COLLECT 
                is_to_continue_response = "CollectCert"                                                         
                if ('sectigo_csr' in cert_oper_params.keys()):                                                  # In case of Collect and sectigo_csr, backup key and csr from path
                   rename_key_csr_if_externalcsr_exists(cert_oper_params,certCategory)

    return is_to_continue_response

###################################################  KEY / CSR Generation Function - END

################################################### COMMON FUNCTIONS - START (prechecks, enroll, collect, Revoke, Renew)

# PRE ENROLL CHECKS
def cert_pre_checks(params_dict, certCategory):
    """
    API used to do all prechecks and identify if we have to Enroll/Collect/Renew/Replace etc.

    param, params_dict - certificate parameter dictionary that contains
                            parameters required for this operation

    param, certCategory - SSL / CLIENT

    return - Next step to take 
    """
    global error_resp
    error_resp = {}

    functionResponse = ""
    sectigo_cert_revoke = False 
    
    # Set revoke cert param
    if certCategory == "SSL":
        if 'sectigo_ssl_cert_revoke' in params_dict.keys():
            sectigo_cert_revoke = params_dict["sectigo_ssl_cert_revoke"]
    elif certCategory == "CLIENT":
        if 'sectigo_ssl_cert_revoke' in params_dict.keys():
            sectigo_cert_revoke = params_dict["sectigo_client_cert_revoke"]
    
    if sectigo_cert_revoke:                                 # If REVOKE FLAG = TRUE
        first_time_apply = is_first_time_apply(params_dict)
        if first_time_apply:
            functionResponse = "FirstTimeRevokeFlagError"   # If this is a first time apply - Throw error as revoke cannot be TRUE  
        else:
            functionResponse = "RevokeCert"                 # If not first time apply, then REVOKE CERT
    else:                                                   # If REVOKE FLAG != TRUE, check renew, allok, certfileexists, and other errors
        try:
            is_to_continue_response = is_to_continue_with_enroll(params_dict, certCategory)
            if 'description' not in error_resp:
                functionResponse = is_to_continue_response
            else:
                logger.info(error_resp['description'])
                # raise SectigoException(json.dumps(error_resp))
        except Exception as err:
            log_error_resp("", "Enroll error occurred: {}".format(str(err)))
            raise

    return functionResponse

# ENROLL 1/2 - GET PAYLOADS
def get_enroll_payload(params_dict,certCategory):
    """
    Get the enroll payload based on SSL/CLIENT
    param, params_dict - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return payload dict
    """
    enroll_request_payload = ""
    if certCategory == "SSL":
        enroll_request_payload = {
            'orgId': params_dict["sectigo_cm_org_id"],
            'csr': '',
            'certType': params_dict["sectigo_ssl_cert_type"],
            'numberServers': params_dict["sectigo_ssl_cert_num_servers"],
            'serverType': params_dict["sectigo_ssl_cert_server_type"],
            'term': params_dict["sectigo_ssl_cert_validity"],
            'comments': params_dict["sectigo_ssl_cert_comments"],
            'externalRequester': params_dict["sectigo_ssl_cert_external_requester"],
            'subjAltNames': params_dict["sectigo_ssl_cert_subject_alt_names"],
            'customFields': params_dict["sectigo_ssl_cert_custom_fields"]
        }
    elif certCategory == "CLIENT":
        enroll_request_payload = {
            'orgId': params_dict["sectigo_cm_org_id"],
            'certType': params_dict["sectigo_client_cert_type"],
            'term': params_dict["sectigo_client_cert_validity"],
            'firstName': params_dict["sectigo_client_cert_first_name"],
            'middleName': params_dict["sectigo_client_cert_middle_name"],
            'lastName': params_dict["sectigo_client_cert_last_name"],
            'email': params_dict["sectigo_client_cert_email"],
            'customFields': params_dict["sectigo_client_cert_custom_fields"]
        }
    return enroll_request_payload

# ENROLL 2/2 - SEND PAYLOADS
def post_enroll_payload(params_dict, enroll_request_url, enroll_request_headers, enroll_request_payload):
    """
    Post the Enroll Payload to the SCM
    param, params_dict - config dictionary passed by user
    param, enroll_request_url - enroll request url
    param, enroll_request_headers - enroll request headers
    param, enroll_request_payload - enroll request payload
    Return enroll Response
    """
    try:
        msg = "EnrollCert"
        logger.debug(msg)
        WriteLog(msg)
        logger.info(enroll_request_url)
        logger.info("Posting payload: {0}".format(enroll_request_payload))
        # Enroll Payload Request Post
        enroll_response = requests.post(enroll_request_url,headers=enroll_request_headers,json=enroll_request_payload)
        logger.info("Enroll Response: "+str(enroll_response))
        
    except Exception as err:
        log_error_resp("", "Invalid Enroll response. Error: {}".format(err))
        # raise SectigoException(json.dumps(error_resp))
        return None

    return enroll_response

# COLLECT 1/2 - SEND PAYLOAD
def collect_cert(collect_cert_params, collect_request_url, returnVal, valid_codes=None):
    """
    Common function that processes a certificate Collect request.

    param, collect_cert_params - dictionary containing common certificate Collect
                                 parameters for all certificate type
    param, collect_request_url - Collect request URL that contains (in its path)
                                 specific certificate Collect parameters
    param, valid_codes         - array of valid Sectigo error response codes for waiting
                                 None if all codes are valid

    return - Requests response for the Collect operation
             None - if operation failed
    """

    sectigo_max_timeout = collect_cert_params["sectigo_max_timeout"]
    sectigo_loop_period = collect_cert_params["sectigo_loop_period"]

    collect_response = None

    try:
        collect_request_headers = getRequestHeaders(collect_cert_params)

        # POST COllect Request PayLoad
        collect_response = requests.get(collect_request_url,headers=collect_request_headers,allow_redirects=True)

        logger.debug("Collect Certificate Response Status Code: " + str(collect_response.status_code))
        logger.debug("Collect Certificate Response Content Type: " + str(collect_response.headers['content-type']))
        logger.debug("Collect Certificate Response Encoding: " + collect_response.encoding + "\n")

        timer = 0

        # Loop over till statusCode = 200, OR "", OR None => After that come out of WhileLoop
        while ((collect_response.status_code != 200) or (collect_response.status_code is None) or (collect_response.status_code == "")):

            # Either WAIT or TIMEOUT 
            if collect_response.status_code == 400:

                # TIMED-OUT
                if timer >= sectigo_max_timeout:
                    logger.info("-----------------------------------------")
                    if collect_response is not None:
                        dict_resp_content = json.loads(collect_response.text)
                        if (('code' in dict_resp_content) and ('description' in dict_resp_content)):
                            log_error_resp(collect_response.status_code,dict_resp_content['description'])
                        else:
                            log_error_resp(collect_response.status_code,"Invalid Collect response. Error: {}".format(err))
                    break

                # WAIT
                else:
                    # Sleep for 30 seconds so that the loop runs less number of times                                    
                    msg = "Collect certificate URL: " + collect_request_url
                    logger.debug("")
                    logger.debug(msg)

                    dict_resp_content = json.loads(collect_response.text)

                    # ERROR Occured in COLLECT or is WAITING.
                    if ('code' in dict_resp_content) and ('description' in dict_resp_content):
                        resp_code = dict_resp_content['code']
                        resp_desc = dict_resp_content['description']
                        # Check for the valid Sectigo response codes for waiting
                        if ((valid_codes is not None) and (is_valid_collect_waiting_code(int(resp_code), valid_codes) is False)):
                            log_error_resp(int(resp_code), resp_desc)
                            break

                        msg = "Collect certificate, Response code " + str(resp_code) + ", " + str(resp_desc)
                        logger.debug(msg)
                        WriteLog(msg)

                        msg = "Waiting... " + str(timer + sectigo_loop_period) + " seconds out of total " + str(sectigo_max_timeout) + " seconds(timeout)"
                        logger.info(msg+"\n")
                        WriteLog(msg)

                    else:
                        msg = "Collect certificate. Status code " + str(collect_response.status_code) + ", waiting... "
                        logger.debug(msg)
                        WriteLog(msg)

                    time.sleep(sectigo_loop_period)
                    timer = timer + sectigo_loop_period

                    collect_response = requests.get(collect_request_url,headers=collect_request_headers,allow_redirects=True)
                    continue
            else:
                log_error_resp(collect_response.status_code, "Error in Collect certificate")
                break

        # After WHILE END, 
        date_time_prefix = getCurrentDateTime(1)
        returnVal["timestamp"] = date_time_prefix

        # SUCCESS
        if (('description' not in error_resp) and (collect_response is not None) and (collect_response.status_code >= 200) and (collect_response.status_code < 300)):
            returnVal["scm_response"] = {}
            returnVal["scm_response"]["status_code"] = collect_response.status_code
            returnVal["scm_response"]["status"] = "SUCCESS"
            returnVal["scm_response"]["body"] = str(collect_response.text)
            returnVal["status"] = "SUCCESS"
            returnVal["message"] = "The received status code from SCM implies that the collect request has succeeded - StatusOK"

        # SOME ERROR
        elif ('description' not in error_resp) and (collect_response is None):
            msg = "An error has occurred during certificate collection: Null Response"
            returnVal["status"] = "FAILURE"
            returnVal["message"] = msg

        # TIMED-OUT
        elif ('description' in error_resp) and (collect_response is not None):
            collectData = json.loads(collect_response.text)

            returnVal["scm_response"] = {}
            returnVal["status"] = "FAILURE"
            returnVal["scm_response"]["status_code"] = collect_response.status_code
            timedOutMsg = ""
            if ('code' in collectData) and ('description' in collectData):
                if collectData["code"] == 0:
                    timedOutMsg = "TimedOut ("+str(collect_cert_params["sectigo_max_timeout"])+" seconds). "
        
                returnVal["message"] = "An error has occurred during certificate collection: "+timedOutMsg
                returnVal["scm_response"]["body"] = str(collect_response.text)
                returnVal["scm_response"]["status"] = "FAILURE"

        # SOME ERROR
        else:
            msg = "An error has occurred during certificate collection: {0}".format(error_resp)
            returnVal["status"] = "FAILURE"
            returnVal["message"] = msg

    except Exception as err:
        log_error_resp(collect_response.status_code, "Error in Collect certificate: {}".format(err))
        returnVal = check_error(returnVal,collect_cert_params)
        returnVal["status"] = "FAILURE"

    return returnVal

# COLLECT 2/2 - SAVE FILES
def write_cert_to_file(params_dict,collect_response,certCategory):
    """
    Post COllect steps to be performed. 
    param, params_dict - config dictionary passed by user
    param, collect_response - collect reponse - The is the returnval formed by us in collect_checks, not the response recieved from scm
    param, certCategory - argument passed by user - ssl/client
    Return True/False
    """
    # SUCCESS | This is only called through ManagedCert.
    if ('status' in collect_response.keys() and (collect_response["status"] == "SUCCESS")):

        #Write CRT to file
        cert_file_full_path = join(params_dict['certFilePath'], params_dict['certFileName']+".crt")

        if python_version == "3":
            with open(cert_file_full_path, 'w') as file_handle:
                file_handle.write(collect_response["scm_response"]["body"])
        else:
            with open(cert_file_full_path, 'wb') as file_handle:
                file_handle.write(collect_response["scm_response"]["body"])

        collect_response["message"] = "A certificate has been successfully collected."
        msg = "Sectigo certificate " + params_dict["certFileName"] + " downloaded at " + params_dict["certFilePath"] + " successfully"
        logger.info(msg)
        WriteLog(msg)

        #Write to Ouput file.. if yes, get certId from dict

        return True
    else: 
        collect_response["message"] = "A certificate was successfully enrolled, however, an error has occurred while collecting the certificate."
        WriteLog(collect_response["status"])
        logger.info(collect_response["status"])
        WriteLog(collect_response["message"])
        logger.info(collect_response["message"])

        return False

# REVOKE 
def revoke_cert(revoke_request_url, revoke_request_headers, revoke_request_payload):
    """
    Common function that processes a certificate Revoke request.

    param, revoke_request_url     - URL for the Revoke request
    param, revoke_request_headers - headers for the Revoke request
    param, revoke_request_payload - payload for the Revoke request

    return - Requests response for the Revoke operation
             None - if operation failed
    """
    revoke_response = None

    try:

        logger.debug("Revoke certificate URL : " + revoke_request_url)

        # Revoke Request Payload
        revoke_response = requests.post(revoke_request_url,headers=revoke_request_headers,json=revoke_request_payload)
        revoke_response.raise_for_status()

    except requests.exceptions.RequestException as err:

        if revoke_response is not None:
            dict_resp_content = json.loads(revoke_response.text)
            if ('code' in dict_resp_content) and ('description' in dict_resp_content):
                log_error_resp(dict_resp_content['code'],dict_resp_content['description'])
            else:
                log_error_resp(revoke_response.status_code,"Invalid Revoke response. Error: {}".format(err))
        else:
            log_error_resp("","Invalid Revoke response. Error: {}".format(err))

    except Exception as err:
        log_error_resp("", "Invalid Revoke response. Error: {}".format(err))
        
    return revoke_response

# RENEW 
def renew_cert(renew_cert_params,operation): 
    """
    Renew cert main function 
    param, renew_params     - Required parameters
    param, operation        - SSL/CLient (Can be renamed to cert_type)
    return - renew_response - Renew Reponse 
    """
    renew_request_url = ""
    renew_request_payload = ""

    if operation == "SSL":
        renew_request_url = renew_cert_params["sectigo_cm_base_url"]+"renewById/"+str(renew_cert_params["sectigo_ssl_cert_ssl_id"])
    elif operation == "CLIENT": 
        renew_request_url = renew_cert_params["sectigo_cm_base_url"]+"renew/order/"+str(renew_cert_params["sectigo_client_cert_order_number"])
        renew_request_url = renew_request_url.replace("v1","v2")

    renew_request_headers = getRequestHeaders(renew_cert_params)

    renew_response = ""
    logger.debug("Renew certificate URL : " + renew_request_url)

    try:
        logger.debug("Posting payload: {0}".format(renew_request_payload))

        # Renew Request Payload
        renew_response = requests.post(renew_request_url,headers=renew_request_headers,json=renew_request_payload)
        renew_response.raise_for_status()

    except requests.exceptions.RequestException as err:

        if renew_response is not None:
            dict_resp_content = json.loads(renew_response.text)

            if ('code' in dict_resp_content) and ('description' in dict_resp_content):
                log_error_resp(dict_resp_content['code'],dict_resp_content['description'])
            else:
                log_error_resp(renew_response.status_code,"Invalid Renew response. Error: {}".format(err))

        else:
            log_error_resp("", "Invalid Renew response. Error: {}".format(err))

    except Exception as err:
        log_error_resp("", "Invalid Renew response. Error: {}".format(err))

    return renew_response

# Replace Cert (Only for ReplaceManagedCertificate) | NOt API ENDPOINT
def Replace_Certificate_Managed(params_dict, certCategory):
    """
    Replace Cert Managed - Sub section of the ReplaceManagedCertificate endpoint. It does al the checks and makes the call to comon 
        replace function 
    param, params_dict - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return returnVal - The output dictionary to be displayed
    """

    # Param Definition
    global connectionParams
    replace_request_url = ""
    certId              = ""
    sanArr              = "'"
    cert_key            = None 
    returnVal           = getReturnVal(certCategory,'Replace')
    params_dict.update(connectionParams)
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)
    
    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    try:
        if certCategory == "SSL":
            certId = params_dict["sectigo_ssl_cert_ssl_id"]
            replace_request_url = params_dict["sectigo_cm_base_url"]+"replace/"+str(params_dict["sectigo_ssl_cert_ssl_id"])
        elif certCategory == "CLIENT": 
            certId = params_dict["sectigo_client_cert_order_number"]
            replace_request_url = params_dict["sectigo_cm_base_url"]+"replace/order/"+str(params_dict["sectigo_client_cert_order_number"])
            replace_request_url = replace_request_url.replace("v1","v2")

        # Rename CRT
        crt_file_full_path = join(params_dict["certFilePath"], params_dict["certFileName"] + ".crt")
        crt_file_full_path_new = createBackupFileFormat(params_dict["certFilePath"],params_dict["certFileName"],'crt',certCategory)
        if exists(crt_file_full_path):
            os.rename(crt_file_full_path, crt_file_full_path_new)

        # Rename CSR
        csr_file_full_path = join(params_dict["certFilePath"], params_dict["certFileName"] + ".csr")
        csr_file_full_path_new = createBackupFileFormat(params_dict["certFilePath"],params_dict["certFileName"],'csr',certCategory)
        if exists(csr_file_full_path):
            os.rename(csr_file_full_path, csr_file_full_path_new)

        # Build SANs
        if certCategory == "SSL":
            sanArr = params_dict["sectigo_ssl_cert_subject_alt_names"].split(",")
        elif certCategory == "CLIENT":
            sanArr = [] #params_dict["sectigo_client_cert_subject_alt_names"].split(",")

        # if sectigo_csr is defined 
        if 'sectigo_csr' in params_dict.keys():
            msg = getMessages("CSRProvidedKeyWontBeGenerated")
            WriteLog(msg)
            logger.info(msg)
            
            # Rename KEY as its of no use
            key_file_full_path = join(params_dict["certFilePath"], params_dict["certFileName"] + ".key")
            key_file_full_path_new = createBackupFileFormat(params_dict["certFilePath"],params_dict["certFileName"],'key',certCategory)    
            if exists(key_file_full_path):
                os.rename(key_file_full_path, key_file_full_path_new)

            # Get CSR and prepare it
            if os.path.exists(params_dict['sectigo_csr']) and os.path.isfile(params_dict['sectigo_csr']):
                dirname_filename = os.path.split(params_dict['sectigo_csr'])
                csr_content = prepare_csr_content_for_enroll_request(dirname_filename[0],dirname_filename[1],"")
            else:
                log_error_resp("", "CSR parameter value is not valid: {0}".format(params_dict['sectigo_csr']))
                returnVal = check_error(returnVal,params_dict)
                return returnVal
            
        else:    
            # If 'sectigo_csr' is not provided, Check if other CSR params are provided 
            if are_csr_params_valid(params_dict):
                does_cert_key_file_exist = does_file_exist(params_dict["certFilePath"], params_dict["certFileName"] + ".key")

                # If CSR PARAMS VALID = Yes, Check if key exist, 
                if does_cert_key_file_exist:  
                    # If KEY EXISTS = YES, retrieve it from file              
                    cert_key = get_private_key_from_file(params_dict)

                else:
                    # If KEY EXISTS = No, check if flag is set to generate new key
                    if (('sectigo_generate_key_if_missing' in params_dict.keys()) and params_dict["sectigo_generate_key_if_missing"] == True):
                        # If FLAG IS SET TO GENERATE NEW KEY, Generate a new private key
                        cert_key = generate_private_key(params_dict["certFilePath"], params_dict["certFileName"] + ".key", params_dict, certCategory)

                    else:
                        # If NO, Throw KEY MISSING error 
                        msg = getMessages("MissingKey")
                        log_error_resp("",msg)
                        returnVal = check_error(returnVal,params_dict)
                        return returnVal

                if cert_key is None:
                    returnVal = check_error(returnVal,params_dict)
                    return returnVal

                # Generate CSR and prepare it 
                csrGenFlag = is_cert_csr_generated(params_dict, params_dict["certFilePath"], params_dict["certFileName"]+".csr", cert_key, certCategory)
                if not csrGenFlag:
                    returnVal = check_error(returnVal,params_dict)
                    return returnVal

                csr_content = prepare_csr_content_for_enroll_request(params_dict["certFilePath"], params_dict["certFileName"]+".csr","")
                if csr_content == "":
                    returnVal = check_error(returnVal,params_dict)
                    return returnVal                        
            else:
                # sectigo_csr not defined and CSR params not defined. 
                msg = getMessages("CsrParamNotDefined")
                log_error_resp("",msg)
                returnVal = check_error(returnVal,params_dict)
                return returnVal

        ########################################################################################
        # RequestManagedCert - call replace_cert
        returnVal = replace_cert(params_dict, sanArr, certId, replace_request_url, returnVal, certCategory, csr_content, cert_key)
        
    except Exception as err:
        msg = "An error has occurred during certificate replacement: {}".format(str(err))
        log_error_resp("", msg)
        
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg

    WriteLog(returnVal)
    logger.info(returnVal)
    return returnVal

# Common replace_cert for for ReplaceManaged and Direct API Endpoint
def replace_cert(params_dict, sanArr, certId, replace_request_url, returnVal, certCategory, csr_content, cert_key):
    """
    Common replace_cert sub function that makes the call to the scm 
    param params_dict - config dictionary passed by user
    param sanArr - SAN dict
    param certId - cert id of the cert to be replaced
    param replace_request_url - replace scm url 
    param returnVal - The existing output dictionary to be displayed
    param, certCategory - argument passed by user - ssl/client
    param csr_content - the csr content
    param cert_key - the cert key
    Return returnVal - The output dictionary to be displayed
    """
    # Param Definition
    replace_request_payload = {}

    try:
        replace_request_headers = getRequestHeaders(params_dict)
        replace_request_headers['Content-Type'] = 'application/json'

        # Get Payload
        if certCategory == "SSL":
            returnVal["ssl_id"] = certId
            replace_request_payload = {
                "reason": params_dict["sectigo_replace_reason"],
                "subjectAlternativeNames": sanArr,
                "commonName": params_dict["sectigo_ssl_cert_common_name"]
            }
        elif certCategory == "CLIENT":
            returnVal["orderNumber"] = certId
            replace_request_payload = {
                "reason": params_dict["sectigo_replace_reason"],
                'revoke': params_dict["sectigo_client_cert_revoke_on_replace"]
            }            

        # Set the CSR value in the request payload passed to this function
        replace_request_payload["csr"] = csr_content

        # REPLACE PAYLOAD
        logger.info(replace_request_url)
        logger.info(replace_request_url)
        logger.info(replace_request_payload)
        replace_response = requests.post(replace_request_url,headers=replace_request_headers,json=replace_request_payload)

        returnVal["timestamp"] = getCurrentDateTime(1)

        # SUCCESS
        if (str(replace_response).find('204')) > 0:
            msg = getMessages("ReplaceSuccess")
            WriteLog(msg)
            logger.info(msg)
            
            returnVal["scm_response"] = {}
            returnVal["scm_response"]["status_code"] = replace_response.status_code
            returnVal["scm_response"]["status"] = "SUCCESS" 
            returnVal["scm_response"]["body"] = str(replace_response.text)
            returnVal["status"] = "SUCCESS"
            returnVal["message"] = "The received status code from SCM implies that the replace request has succeeded - StatusNoContent"

            if 'sectigo_csr' in params_dict.keys():
                returnVal["csr"] = params_dict["sectigo_csr"]
            else:
                # For RequestManagedCertificate.
                if check_if_managed(params_dict):
                    returnVal["csr"] = params_dict["certFilePath"]+params_dict["certFileName"]+".csr"
                    returnVal["private_key"] = params_dict["certFilePath"]+params_dict["certFileName"]+".key"
                else:
                    returnVal["csr"] = csr_content
                    returnVal["private_key"] = c.dump_privatekey(c.FILETYPE_PEM, cert_key)

        # Failure
        elif (replace_response is not None):

            returnVal["scm_response"] = {}
            returnVal["scm_response"]["body"] = str(replace_response.text)
            returnVal["scm_response"]["status_code"] = replace_response.status_code
            returnVal["scm_response"]["status"] = "FAILURE"
            returnVal["status"] = "FAILURE"
            returnVal["message"] = "An error has occurred during certificate replacement"

        # REPLACE ERROR
        else:
            msg = "An error has occurred during certificate replacement: {0}".format(error_resp)
            log_error_resp("", msg)
            returnVal["status"] = "FAILURE"
            returnVal["message"] = msg

    except Exception as err1:

        msg = "An error has occurred during certificate replacement: {}".format(str(err1))
        log_error_resp("", msg)
        
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg

    return returnVal

################################################### COMMON FUNCTIONS - END  ###################################################

################################################### ENDPOINTS - START (set-conn, requestManaged, enroll, collect, replace, revoke, renew)

# Set Conn Params 
def SetConnectionParameters(params_dict):
    """
    # GENERIC ENDPOINT to set Connection Params
    param, params_dict   - dictornary containing values
    return, params_dict  - dictornary containing connection parameter values
    """

    global connectionParams

    params_dict["login"] = params_dict['sectigo_cm_user']
    params_dict["password"] = params_dict['sectigo_cm_password']
    params_dict["customerUri"] = params_dict['sectigo_cm_uri']
    params_dict["sectigo_cm_base_url"] = params_dict["sectigo_cm_base_url"]

    connectionParams = params_dict

    return params_dict

# Request Managed Cert 
def RequestManagedCertificate(params_dict, certCategory):
    """
    RequestManagedCertificate Endpoint
    param, params_dict - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return outputDict - The output dictionary to be displayed
    """

    # Parameter Definition
    global outputDict
    global sectigo_logger_stdout_flag
    global connectionParams
    params_dict["managedCert"]   = True
    outputDict["sub_operations"] = []
    funcCategory                 = "RequestManagedCertificate"
    returnVal                    = getReturnVal(certCategory,funcCategory)
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)
    error_resp                   = {}

    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # Parameter validation
    if not are_requestManaged_cert_params_valid(params_dict, certCategory):
        returnVal = check_error(returnVal,params_dict)
        logger.info(returnVal)
        return returnVal

    # Get the cert path in a common variable depending on the certCategory |and| check the trailing slashes
    format_file_path(params_dict, certCategory)

    # Get the subject params in place based on 'sectigo_csr' present on not
    flg = format_params_dict_data(params_dict, certCategory)
    if not flg:
        returnVal = check_error(returnVal,params_dict)
        logger.info(returnVal)
        return returnVal

    #Create CERT_FILE_PATH if it does not exist
    mkdirRecursive(params_dict['certFilePath'])

    # Common Renew Flag as the code is common at multiple places below 1) after PostCollect 2) after RenewCertificate
    check_renew = "" 

    # PreChecks
    response = cert_pre_checks(params_dict,certCategory)
    logger.info("Request Managed Cert Pre Checks Response: "+response)
    
    # 1. EnrollCert
    if response == "EnrollCert":
        enroll_response = EnrollCertificate(params_dict,certCategory)
        if enroll_response != "":

            enrollData = enroll_response
            
            # Form main output data 
            outputDict = createOutputJson(enroll_response, certCategory, funcCategory, outputDict["sub_operations"])
            logger.info("---------------------------------------------------")
            logger.info("Output after Enroll")
            logger.info(outputDict)

            if ('status' in enrollData.keys() and (enrollData["status"] == "SUCCESS")):

                # Write to IDS file
                write_to_ids_file(params_dict,certCategory,json.dumps(enroll_response["scm_response"]["body"]))

                # 2. Collect Certificate after Enrolling
                collect_response = CollectCertificate(params_dict,certCategory)
                post_collect_status = write_cert_to_file(params_dict,collect_response,certCategory)
                
                # Send crt, csr, key to outputdict
                collect_response["csr"] = ""
                collect_response["certificate"] = ""

                if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".crt")):
                    collect_response["certificate"] = params_dict["certFilePath"]+params_dict["certFileName"]+".crt"
                if 'sectigo_csr' in params_dict.keys():
                    collect_response["csr"] = params_dict["sectigo_csr"]
                else: 
                    collect_response["private_key"] = ""
                    if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".csr")):
                        collect_response["csr"] = params_dict["certFilePath"]+params_dict["certFileName"]+".csr"
                    if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".key")):
                        collect_response["private_key"] = params_dict["certFilePath"]+params_dict["certFileName"]+".key"

                # Form main output data 
                outputDict = createOutputJson(collect_response, certCategory, funcCategory, outputDict["sub_operations"])
                logger.info("---------------------------------------------------")
                logger.info("Output after Enroll Collect")
                logger.info(outputDict)

    # 2. COLLECT API ENDPOINT | This is only for ManagedCert.
    elif response == "CollectCert":
        collect_response = CollectCertificate(params_dict, certCategory)
        post_collect_status = write_cert_to_file(params_dict,collect_response,certCategory)

        # Send crt, csr, key to outputdict
        collect_response["csr"] = ""
        collect_response["certificate"] = ""

        if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".crt")):
            collect_response["certificate"] = params_dict["certFilePath"]+params_dict["certFileName"]+".crt"
        if 'sectigo_csr' in params_dict.keys():
            collect_response["csr"] = params_dict["sectigo_csr"]
        else: 
            collect_response["private_key"] = ""
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".csr")):
                collect_response["csr"] = params_dict["certFilePath"]+params_dict["certFileName"]+".csr"
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".key")):
                collect_response["private_key"] = params_dict["certFilePath"]+params_dict["certFileName"]+".key"

        # Form main output data 
        outputDict = createOutputJson(collect_response, certCategory, funcCategory, outputDict["sub_operations"])
        logger.info("---------------------------------------------------")
        logger.info("Output after only Collect")
        logger.info(outputDict)

        # Only if CRT is missing in the first place, COLLECT it and then check validity. 
            # (Ex: if IDS=True,CRT=False we only collect, we dont check if its expired)
        # For cases like ENROLL and RENEW, since the CRT would be valid in almost all cases as it is just downloaded, 
            #do not check validity after ENROLL or RENEW

        if post_collect_status:
            
            status = check_cert_validity(params_dict, certCategory) # Check Validity

            if status == -1:    # Error
                if 'description' not in error_resp:
                    log_error_resp("", "Unable to validate certificate")
                raise SectigoException(json.dumps(error_resp))

            elif status == 0:   # ALL OK, END, In case sectigo_csr, backup key and csr from path
                check_renew = "CertFileExists"
                msg = getMessages(check_renew)

                # Form main output data 
                returnVal = getReturnVal(certCategory,check_renew)
                returnVal["scm_response"] = {}
                returnVal["certificate"] = outputDict["certificate"]
                returnVal["status"] = "SUCCESS"
                returnVal["message"] = msg
                returnVal["scm_response"]["body"] = msg
                returnVal["timestamp"] = getCurrentDateTime(0)
                returnVal["operation"] = "ValidityCheck"

                outputDict = createOutputJson(returnVal, certCategory, funcCategory, outputDict["sub_operations"])
                logger.info("---------------------------------------------------")
                logger.info("Output after "+check_renew)
                logger.info(outputDict)

            else:               # EXISTS BUT EXPIRED. In case of Collect and sectigo_csr, backup key and csr from path
                if params_dict["sectigo_auto_renew"] is True:
                    check_renew = "RenewCert"
                else:           # Renew Flag not set 
                    check_renew = "ExpiredButRenewFlagNotSet"

                    msg = getMessages("AutoRenewSetToFalse")
                    logger.debug(msg)
                    WriteLog(msg)

                    # Form main output data 
                    returnVal = getReturnVal(certCategory,check_renew)
                    returnVal["scm_response"] = {}
                    returnVal["status"] = "FAILURE"
                    returnVal["message"] = msg
                    returnVal["scm_response"]["body"] = msg
                    returnVal["timestamp"] = getCurrentDateTime(0)
                    outputDict = createOutputJson(returnVal, certCategory, funcCategory, outputDict["sub_operations"])
                    logger.info("---------------------------------------------------")
                    logger.info("Output after "+check_renew)
                    logger.info(outputDict)

        else: 
            msg = getMessages("SomethingWrongPostCollect")
            logger.debug(msg)
            WriteLog(msg)
            exit(1)

    # 3. REVOKE API ENDPOINT
    elif response == "RevokeCert":
        if certCategory == "SSL":
            params_dict["sectigo_ssl_cert_ssl_id"] = get_cert_id(params_dict, certCategory)                   
        elif certCategory == "CLIENT":
            params_dict["sectigo_client_cert_order_number"] = get_cert_id(params_dict, certCategory)                   

        revoke_response = RevokeCertificate(params_dict, certCategory)

        # Form main output data 
        outputDict = createOutputJson(revoke_response, certCategory, funcCategory, outputDict["sub_operations"])
        logger.info("---------------------------------------------------")
        logger.info("Output after Revoke")
        logger.info(outputDict)

        if 'status' in revoke_response and revoke_response['status'] == "SUCCESS": 
            #Success
            rename_cert_files_all(params_dict,certCategory)

    # 4. REPLACE API ENDPOINT (same fn for both certCategory)
    elif response == "ReplaceCert":
        msg = getMessages("CallReplaceManagedAPI")
        WriteLog(msg)
        logger.info("",msg)                 

    #5. AUTO-RENEW NOT SET! EXITING!
    elif response == "ExpiredButRenewFlagNotSet":
        msg = getMessages("AutoRenewSetToFalse")
        logger.debug(msg)
        WriteLog(msg)

        # Form main output data 
        returnVal = getReturnVal(certCategory,response)
        # returnVal["scm_response"] = {}
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg
        returnVal["operation"] = funcCategory
        # returnVal["scm_response"]["body"] = msg
        returnVal["timestamp"] = getCurrentDateTime(0)
        
        outputDict = returnVal         
        logger.info("---------------------------------------------------")
        logger.info("Output after "+check_renew)
        logger.info(outputDict)
        
    #6. RENEW API ENDPOINT
    elif response == "RenewCert":
        check_renew = "RenewCert"

    # 7. Valid CERT. Exit without changes!
    elif response == "CertFileExists":
        msg = getMessages(response)
        logger.info(msg)
        WriteLog(msg)

        # Form main output data 
        returnVal = getReturnVal(certCategory,response)
        returnVal["status"] = "SUCCESS"
        returnVal["message"] = msg
        returnVal["operation"] = funcCategory
        returnVal["timestamp"] = getCurrentDateTime(0) 

        # Send crt, csr, key to outputdict
        if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".crt")):
            returnVal["certificate"] = params_dict["certFilePath"]+params_dict["certFileName"]+".crt"
        if 'sectigo_csr' in params_dict.keys():
            returnVal["csr"] = params_dict["sectigo_csr"]
        else: 
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".csr")):
                returnVal["csr"] = params_dict["certFilePath"]+params_dict["certFileName"]+".csr"
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".key")):
                returnVal["private_key"] = params_dict["certFilePath"]+params_dict["certFileName"]+".key"

        outputDict = returnVal
        logger.info("---------------------------------------------------")
        logger.info("Output after "+response)
        logger.info(outputDict)
        
        if 'sectigo_csr' in params_dict.keys():
            # Rename Key file if exists as its of no use in case of External CSR
            key_file_full_path = params_dict["certFilePath"]+params_dict["certFileName"]+".key"
            key_file_full_path_new = createBackupFileFormat(params_dict["certFilePath"],params_dict["certFileName"],'key',certCategory)
            if exists(key_file_full_path):
                os.rename(key_file_full_path, key_file_full_path_new)

    # 8. REVOKE-FLAG-TRUE-ERROR FOR FIRST TIME APPLY
    elif response == "FirstTimeRevokeFlagError":
        msg = getMessages("ChangeRevokeFlag")
        WriteLog(msg)
        logger.info(msg)

        # Form main output data 
        returnVal = getReturnVal(certCategory,response)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg
        returnVal["timestamp"] = getCurrentDateTime(0) 
        returnVal["operation"] = funcCategory

        outputDict = returnVal
        logger.info("---------------------------------------------------")
        logger.info("Output after "+response)
        logger.info(outputDict)

    # 8. REVOKE-FLAG-TRUE-ERROR FOR FIRST TIME APPLY
    elif response == "SectigoForceFalseFilesExist":
        msg = getMessages(response)
        WriteLog(msg)
        logger.info(msg)

        # Form main output data 
        returnVal = getReturnVal(certCategory,response)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg
        returnVal["timestamp"] = getCurrentDateTime(0) 
        returnVal["operation"] = funcCategory

        outputDict = returnVal
        logger.info("---------------------------------------------------")
        logger.info("Output after "+response)
        logger.info(outputDict)

    else:
        msg = ""
        if 'description' in error_resp:
            msg =  error_resp["description"]
            logger.info(msg)
            WriteLog(msg)
        else:
            msg = getMessages("PreCheckSomethingWrong")
            WriteLog(msg)
            logger.info(msg)

        # Form main output data 
        returnVal = getReturnVal(certCategory,funcCategory)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg
        returnVal["timestamp"] = getCurrentDateTime(0) 
        returnVal["operation"] = funcCategory
        
        outputDict = returnVal
        logger.info("---------------------------------------------------")
        logger.info("Output after Some Error: ")
        logger.info(outputDict)

    if check_renew == "RenewCert":

        msg = getMessages("RenewCert")
        logger.debug(msg)
        WriteLog(msg)

        # New dict for renew
        renew_params = params_dict.copy()

        # Get Old SSLId / Ordernumber
        if certCategory == "SSL":
            renew_params["sectigo_ssl_cert_ssl_id"] = get_cert_id(renew_params, certCategory)
        elif certCategory == "CLIENT":
            renew_params["sectigo_client_cert_order_number"] = get_cert_id(renew_params, certCategory)

        # Renew 
        renew_response = RenewCertificate(renew_params, certCategory)

        outputDict = createOutputJson(renew_response, certCategory, funcCategory, outputDict["sub_operations"])
        logger.info("---------------------------------------------------")
        logger.info("Output after Renew")
        logger.info(outputDict)

        if ('status' in renew_response.keys() and (renew_response["status"] == "SUCCESS")):

            renew_response["message"] = "The certificate has been successfully auto renewed and collected."

            # Rename existing ids/crt files 
            rename_crt_ids_file(renew_params, certCategory)

            # Write new renewId to New IDS file and to the dictionary to collect
            write_to_ids_file(renew_params, certCategory, json.dumps(renew_response["scm_response"]["body"]))

            if certCategory == "SSL":
                renew_params["sectigo_ssl_cert_ssl_id"] = get_cert_id(renew_params, certCategory)
            elif certCategory == "CLIENT":
                renew_params["sectigo_client_cert_order_number"] = get_cert_id(renew_params, certCategory)
                        
            # 2. Collect Certificate after Renewing
            collect_response = CollectCertificate(renew_params,certCategory)
            post_collect_status = write_cert_to_file(renew_params,collect_response,certCategory)

            # Send crt, csr, key to outputdict
            collect_response["csr"] = ""
            collect_response["certificate"] = ""
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".crt")):
                collect_response["certificate"] = params_dict["certFilePath"]+params_dict["certFileName"]+".crt"
            if 'sectigo_csr' in params_dict.keys():
                collect_response["csr"] = params_dict["sectigo_csr"]
            else: 
                collect_response["private_key"] = ""
                if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".csr")):
                    collect_response["csr"] = params_dict["certFilePath"]+params_dict["certFileName"]+".csr"
                if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".key")):
                    collect_response["private_key"] = params_dict["certFilePath"]+params_dict["certFileName"]+".key"

            outputDict = createOutputJson(collect_response, certCategory, funcCategory, outputDict["sub_operations"])
            logger.info("---------------------------------------------------")
            logger.info("Output after Renew Collect")
            logger.info(outputDict)
    
    return outputDict

# Replace Managed Cert 
def ReplaceManagedCertificate(params_dict,certCategory):
    """
    ReplaceManagedCertificate Endpoint
    param, params_dict - config dictionary passed by user
    param, certCategory - argument passed by user - ssl/client
    Return outputDict - The output dictionary to be displayed
    """

    # Get Logger
    #ConfigureLogger(params_dict)

    # Param definition
    global sectigo_logger_stdout_flag
    global outputDict
    global connectionParams
    params_dict["managedCert"]   = True
    outputDict["sub_operations"] = []
    funcCategory                 = "ReplaceManagedCertificate"
    returnVal                    = getReturnVal(certCategory,funcCategory)
    # sectigo_logger_stdout_flag   = get_stdOut_status(params_dict) # Get STDOUT Status
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)
    error_resp                   = {}

    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # Parameter validity
    if not are_replaceManaged_cert_params_valid(params_dict, certCategory):
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # Get the cert path in a common variable depending on the certCategory |and| check the trailing slashes
    format_file_path(params_dict, certCategory)

    # Get the subject params in place based on 'sectigo_csr' present on not
    flg = format_params_dict_data(params_dict, certCategory)
    if not flg:
        returnVal = check_error(returnVal,params_dict)
        logger.info(returnVal)
        return returnVal
        
    # If IDS file exists, Proceed with Replace
    does_cert_ids_file_exist = does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".ids")
    if does_cert_ids_file_exist:
        certId = get_cert_id(params_dict, certCategory)
        if certCategory == "SSL":
            params_dict["sectigo_ssl_cert_ssl_id"] = certId
        elif certCategory == "CLIENT": 
            params_dict["sectigo_client_cert_order_number"] = certId

        replace_response = Replace_Certificate_Managed(params_dict, certCategory)
                
        # Form main output data 
        outputDict = createOutputJson(replace_response, certCategory, funcCategory, outputDict["sub_operations"])
        logger.info("---------------------------------------------------")
        logger.info("Output after Replace")
        logger.info(outputDict)

        if 'status' in replace_response.keys() and replace_response["status"] == "SUCCESS":
            replaceData = replace_response

            # 2. Collect Certificate after Replacing
            collect_response = CollectCertificate(params_dict,certCategory)
            post_collect_status = write_cert_to_file(params_dict, collect_response, certCategory)
            
            # Send crt, csr, key to outputdict
            collect_response["certificate"] = ""
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".crt")):
                collect_response["certificate"] = params_dict["certFilePath"]+params_dict["certFileName"]+".crt"

            # Form main output data 
            outputDict = createOutputJson(collect_response, certCategory, funcCategory, outputDict["sub_operations"])
            logger.info("---------------------------------------------------")
            logger.info("Output after Replace Collect")
            logger.info(outputDict)
        else:
            returnVal["status"] = "FAILURE"
            returnVal["message"] = replace_response["message"]
            returnVal["timestamp"] = getCurrentDateTime(0)
            returnVal["operation"] = funcCategory
            outputDict = returnVal
    else:
        # IDS file missing. Cant replace
        msg = getMessages("IDSFileMissing")
        log_error_resp("",msg)

        # Form main output data 
        returnVal = getReturnVal(certCategory,msg)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg
        returnVal["timestamp"] = getCurrentDateTime(0)
        returnVal["operation"] = funcCategory

        outputDict = returnVal

    return outputDict

# Enroll Cert 
def EnrollCertificate(params_dict,certCategory):
    """
    EnrollCertificate API ENDPOINT    
    param, params_dict      - Enroll certificate parameters
    param, certCategory     - SSL / CLIENT 

    return - Enroll response - Check for reponse["status"]=SUCCESS/FAILURE and reponse["message"]
    """
    
    # Params defined
    global sectigo_logger_stdout_flag
    global connectionParams
    enroll_request_payload     = {}
    error_resp                 = {}
    enroll_response            = None
    cert_key                   = None
    returnVal                  = getReturnVal(certCategory,'Enroll')
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)

    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # If managedCert, get the file formats proper
    if check_if_managed(params_dict):
        format_file_path(params_dict, certCategory)

    # Enroll Parameter Validation
    enrollParamValidFlag = are_enroll_cert_params_valid(params_dict, certCategory)
    if not enrollParamValidFlag:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # Check if sectigo_csr is set and not empty 
    if 'sectigo_csr' in params_dict.keys():
        if params_dict['sectigo_csr'] == "":
            returnVal["message"] = "sectigo_csr parameter cannot be null or empty: received csr={0}".format(params_dict['sectigo_csr'])

            if not check_if_managed(params_dict):
                logger.info(returnVal)
                WriteLog(returnVal)
            return returnVal
    else:
        # If sectigo_csr is not set, check if other csr params are valid
        if are_csr_params_valid(params_dict):
            do_parameter_validation = False
            params_dict["certSubject"] = "C="+params_dict['sectigo_csr_country']+"/ST="+params_dict['sectigo_csr_state']+"/L="+params_dict['sectigo_csr_location']+"/O="+params_dict['sectigo_csr_organization']+"/OU="+params_dict['sectigo_csr_organization_unit']+"/CN="+params_dict['sectigo_csr_domain']+"/emailAddress="+params_dict['sectigo_csr_email_address']
        else:
            returnVal = check_error(returnVal,params_dict)
            return returnVal

    # Proceed with new Sectigo certificate Enroll request
    enroll_request_url = join(params_dict["sectigo_cm_base_url"], str('enroll'))

    # Build Request Headers
    enroll_request_headers = getRequestHeaders(params_dict)

    # Get the Enroll Payload formed
    enroll_request_payload = get_enroll_payload(params_dict,certCategory)

    """
    only if csr parameter is provided and the file exists in that location, dont generate key..
    It means user has the csr and the key.. and the system need not generate a new one.
    In other cases, its a system generated CSR/KEY, so the system has to replace/renew/ 
    """

    # 1. GET existing KEY or create NEW KEY 

    # If sectigo_csr is set and not null, key wont be generated
    if 'sectigo_csr' in params_dict.keys() and params_dict['sectigo_csr'] != "":

        msg = getMessages("CSRProvidedKeyWontBeGenerated")
        WriteLog(msg)
        logger.info(msg)

        # For Enroll (1st time apply) - Rename existing files if they exist In case of RequestManagedCertificate, for others, there are no files.
        if check_if_managed(params_dict):
            rename_cert_files_all(params_dict,certCategory)

    # If sectigo_csr is not set
    else:

        # For RequestManagedCertificate. 
        if check_if_managed(params_dict):

            # If key is present
            if does_file_exist(params_dict["certFilePath"], params_dict["certFileName"] + ".key") == True:

                # Retrieve an existing private key from the KEY file 
                cert_key = get_private_key_from_file(params_dict)   
            else:

                # Key Absent. Generate a new private key
                cert_key = generate_private_key(params_dict["certFilePath"], params_dict["certFileName"] + ".key", params_dict, certCategory)
            
        # For Direct Endpoints, just generate the key without paths
        else:  

            cert_key = generate_private_key("", "", params_dict, certCategory)

        # Check if Key is None in case of any error
        if cert_key is None:

            returnVal = check_error(returnVal,params_dict)
            return returnVal

    # 2. GET existing CSR or create NEW CSR 
    
    # if 'sectigo_csr' is set
    if 'sectigo_csr' in params_dict.keys():

        # in managedCert,
        if check_if_managed(params_dict):

            # If 'sectigo_csr' is file, in managedcert, read it 
            if os.path.exists(params_dict['sectigo_csr']) and os.path.isfile(params_dict['sectigo_csr']):

                dirname_filename = os.path.split(params_dict['sectigo_csr'])
                enroll_request_payload['csr'] = prepare_csr_content_for_enroll_request(dirname_filename[0],dirname_filename[1],"")
            
            # If not file, throw error, as it cant be string in managedCert. It has to be file 
            else:

                log_error_resp("", "CSR parameter value is not valid: {0}".format(params_dict['sectigo_csr']))
                returnVal = check_error(returnVal,params_dict)
                return returnVal

         # In case of Direct Endpoints, check 'sectigo_csr', directly assign string to variable
        else:

            enroll_request_payload['csr'] = params_dict['sectigo_csr']

    # If 'sectigo_csr' not set, 
    else:

        checkCSRParams = 0 # Will stay 0 if csr file is there in path, 1 if managed, 2 if direct endpoints

        # in managedCert,
        if check_if_managed(params_dict):

            # If csr file exists in path, read it 
            if (does_file_exist(params_dict["certFilePath"], params_dict["certFileName"]+".csr") == True):

                checkCSRParams = 0
            # Check CSR params
            else:

                checkCSRParams = 1 # managed, generate file

         # In case of Direct Endpoints, check CSR Params to build CSR
        else: 

            checkCSRParams = 2      # unmanaged, dont generate file, only string

        # After all checks if this flag is > 0, in case of 'sectigo_csr' not present, generate CSR using CSR params
        # 1 - managed -> generate file
        # 2 - unmanaged -> generate only string

        # Check if all CSR params are defined properly
        if checkCSRParams > 0 and are_csr_params_valid(params_dict) == False:

            msg = "Either sectigo_csr or certSubject or CSR Parameters must be defined as input parameters"
            log_error_resp("", msg)
            returnVal["message"] = msg

            WriteLog(returnVal)
            logger.info(returnVal)
            return returnVal

        csr_content = ""
        if checkCSRParams == 0:

            msg = getMessages("GetExistCSRFromFile")
            WriteLog(msg)
            logger.info(msg)
            enroll_request_payload['csr'] = prepare_csr_content_for_enroll_request(params_dict["certFilePath"],params_dict["certFileName"]+".csr","")

        elif checkCSRParams == 1:

            if (is_cert_csr_generated(params_dict, params_dict["certFilePath"], params_dict["certFileName"]+".csr", cert_key, certCategory) is True):
                csr_content = prepare_csr_content_for_enroll_request(params_dict["certFilePath"],params_dict["certFileName"]+".csr","")
                enroll_request_payload['csr'] = csr_content
            else:

                # IF something goes wrong while generating CSR, raise error
                returnVal = check_error(returnVal,params_dict)
                return returnVal

        elif checkCSRParams == 2:

            # in case of unmanaged, below function returns csr string, other cases, it writes to file
            csr_content = is_cert_csr_generated(params_dict, "", "", cert_key, certCategory)
            if csr_content is not False:

                if python_version == "3":
                    csr_content = prepare_csr_content_for_enroll_request("","",str(csr_content,'utf-8'))
                else:
                    csr_content = prepare_csr_content_for_enroll_request("","",csr_content)

                enroll_request_payload['csr'] = csr_content
            else:

                # IF something goes wrong while generating CSR, raise error
                returnVal = check_error(returnVal,params_dict)
                return returnVal        

        # else ends here 

    # else ends here

    # IF everything is fine, post enroll payload
    enroll_response = post_enroll_payload(params_dict, enroll_request_url, enroll_request_headers, enroll_request_payload)

    returnVal["timestamp"] = getCurrentDateTime(1)

    # Success
    if (('description' not in error_resp) and (enroll_response is not None) and (enroll_response.status_code >= 200) and (enroll_response.status_code < 300)):
        enrollData = json.loads(enroll_response.text)

        # Get sslid or ordernumber from the Enroll Response
        certId = ""
        if certCategory == "SSL":
            certId = enrollData["sslId"]
            returnVal["ssl_id"] = certId
        elif certCategory == "CLIENT":
            certId = enrollData["orderNumber"]
            returnVal["orderNumber"] = certId

        # Form the return dictionary
        if 'sectigo_csr' in params_dict.keys():
            returnVal["csr"] = params_dict["sectigo_csr"]
        else:
            # For RequestManagedCertificate.
            if check_if_managed(params_dict):
                returnVal["csr"] = params_dict["certFilePath"]+params_dict["certFileName"]+".csr"
                returnVal["private_key"] = params_dict["certFilePath"]+params_dict["certFileName"]+".key"
            else:
                returnVal["csr"] = csr_content
                if python_version == "3":
                    returnVal["private_key"] = str(c.dump_privatekey(c.FILETYPE_PEM, cert_key),'utf-8')
                else:
                    returnVal["private_key"] = c.dump_privatekey(c.FILETYPE_PEM, cert_key)

        returnVal["scm_response"] = {}
        returnVal["scm_response"]["status_code"] = enroll_response.status_code
        returnVal["scm_response"]["body"] = str(enroll_response.text)
        returnVal["scm_response"]["status"] = "SUCCESS"
        returnVal["status"] = "SUCCESS"
        returnVal["message"] = "The received status code from SCM implies that the enroll request has succeeded - StatusOK"

    # Failure
    elif (enroll_response is not None):
        
        returnVal["scm_response"] = {}
        returnVal["scm_response"]["status_code"] = enroll_response.status_code
        returnVal["scm_response"]["body"] = str(enroll_response.text)
        returnVal["scm_response"]["status"] = "FAILURE"
        returnVal["status"] = "FAILURE"
        returnVal["message"] = "An error has occurred during certificate enrollment"

    # ENROLL ERROR
    else:
        msg = "An error has occurred during certificate enrollment: {0}".format(error_resp)
        log_error_resp("", msg)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = json.dumps(msg)
        
    msg = str(returnVal)
    logger.info("---------------------------------------------------")
    logger.info("Enroll Return Value")
    logger.info(msg)
    WriteLog(msg)
    return returnVal

# Collect Cert 
def CollectCertificate(params_dict, certCategory):
    """
    # GENERIC ENDPOINT  for COLLECT CERT
    param, params_dict          - dictornary containing values
    param, certCategory         - ssl / client
    return, returnVal           - Collect Response
    """

    # Params defined
    global sectigo_logger_stdout_flag
    global connectionParams
    global error_resp
    sslId                      = ""
    orderNumber                = ""
    collect_request_url        = ""
    error_resp                 = {}
    valid_waiting_err_codes    = []
    returnVal                  = getReturnVal(certCategory,'Collect')
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)

    
    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # Get SSLID or ORDERNUMBER on in case of MANAGED CERT
    if check_if_managed(params_dict):
        if certCategory == "SSL":
            if "sectigo_ssl_cert_ssl_id" not in params_dict.keys():
                params_dict["sectigo_ssl_cert_ssl_id"] = get_cert_id(params_dict, certCategory)        
        elif certCategory == "CLIENT":
            collectCertLabel = "SECT_COLLECT_CLIENT_CERT"
            if "sectigo_client_cert_order_number" not in params_dict.keys():
                params_dict["sectigo_client_cert_order_number"] = get_cert_id(params_dict, certCategory)

    collectCertLabel = "SECT_COLLECT_"+certCategory+"_CERT"
    validResponse = False

    # check if collect related params are defined and not empty
    paramsDefinedFlag = are_required_param_names_defined(collectCertLabel,params_dict)
    if paramsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(collectCertLabel,params_dict)
        if paramsValidFlag:
            validResponse = True
    if not validResponse:
        # log_error_resp("", "Collect parameter validation failed")
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    msg = "Proceeding to collect "+certCategory+" certificate..."
    logger.info(msg)
    WriteLog(msg)

    certId = ""
    try:
        if certCategory == "SSL":
            # Proceed with new Sectigo certificate Collect request
            collect_request_url = """{sectigo_cm_base_url}/collect/{sectigo_ssl_cert_ssl_id}/{sectigo_ssl_cert_format_type}""".format(**params_dict)

            # Error codes returned by the Sectigo server that are valid for waiting
            valid_waiting_err_codes = [0, -1400]
 
        elif certCategory == "CLIENT":
            # Proceed with new Sectigo certificate Collect request
            collect_request_url = """{sectigo_cm_base_url}/collect/{sectigo_client_cert_order_number}""".format(**params_dict)

            # Error codes returned by the Sectigo server that are valid for waiting
            valid_waiting_err_codes = [0, -183, -1400, -1]

        # COLLECT PAYLOAD
        returnVal = collect_cert(params_dict, collect_request_url, returnVal, valid_waiting_err_codes)
        if certCategory == "SSL":
            returnVal["ssl_id"] = params_dict["sectigo_ssl_cert_ssl_id"]
        elif certCategory == "CLIENT":
            returnVal["orderNumber"] = params_dict["sectigo_client_cert_order_number"] 
        
    except Exception as err:
        msg = "Collect error occurred: {}".format(str(err))
        log_error_resp("", msg)

        returnVal["status"] = "FAILURE"
        returnVal = check_error(returnVal,params_dict)

    logger.info("---------------------------------------------------")
    logger.info("Collect Return Value")
    logger.info(returnVal)
    WriteLog(returnVal)
    return returnVal

# Replace API ENDPOINT
def ReplaceCertificate(params_dict, certCategory):
    """
    # GENERIC ENDPOINT  for REPLACE CERT
    param, params_dict          - dictornary containing values
    param, certCategory         - ssl / client
    return, returnVal           - Collect Response
    """

    # Param Definition
    global sectigo_logger_stdout_flag
    global connectionParams
    certId                     = ""
    replace_request_url        = ""
    replaceLabel               = "SECT_REPLACE_"+certCategory+"_CERT"
    returnVal                  = getReturnVal(certCategory,'Replace')
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)
    error_resp                 = {}

    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    # Replace Parameter Validation
    validResponse = False
    paramsDefinedFlag = are_required_param_names_defined(replaceLabel,params_dict)
    if paramsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(replaceLabel,params_dict)
        if paramsValidFlag:
            validResponse = True
    if not validResponse:
        returnVal = check_error(returnVal,params_dict)
        logger.info(returnVal)
        return returnVal

    try:
        if certCategory == "SSL":
            certId = params_dict["sectigo_ssl_cert_ssl_id"]
            replace_request_url = params_dict["sectigo_cm_base_url"]+"replace/"+str(params_dict["sectigo_ssl_cert_ssl_id"])
        elif certCategory == "CLIENT": 
            certId = params_dict["sectigo_client_cert_order_number"]
            replace_request_url = params_dict["sectigo_cm_base_url"]+"replace/order/"+str(params_dict["sectigo_client_cert_order_number"])
            replace_request_url = replace_request_url.replace("v1","v2")

        # Build SANs
        sanArr = "'"
        if certCategory == "SSL":
            sanArr = params_dict["sectigo_ssl_cert_subject_alt_names"].split(",")
        elif certCategory == "CLIENT":
            sanArr = [] #params_dict["sectigo_client_cert_subject_alt_names"].split(",")            

        # Get CSR and prepare 
        csr_content = params_dict["sectigo_csr"]

        ########################################################################################

        # API ENDPOINT - call replace_cert
        returnVal = replace_cert(params_dict, sanArr, certId, replace_request_url, returnVal, certCategory, csr_content, "")
        if certCategory == "SSL":
            returnVal["ssl_id"] = params_dict["sectigo_ssl_cert_ssl_id"]
        elif certCategory == "CLIENT":
            returnVal["orderNumber"] = params_dict["sectigo_client_cert_order_number"] 

    except Exception as err2:
        msg = "An error has occurred during certificate replacement: {}".format(str(err2))
        log_error_resp("", msg)        
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg
        returnVal["timestamp"] = getCurrentDateTime(0)

    logger.info("---------------------------------------------------")
    logger.info("Replace Return Value")
    logger.info(returnVal)
    WriteLog(returnVal)
    return returnVal

# Revoke Cert 
def RevokeCertificate(params_dict, certCategory):
    """
    # GENERIC ENDPOINT  for REVOKE CERT
    param, params_dict       - dictornary containing values
    param, certCategory         - ssl / client
    return, functionResponse    - REVOKE Response
    """

    # Params defined
    global error_resp
    global connectionParams
    global sectigo_logger_stdout_flag
    error_resp                 = {}
    revoke_request_url         = ""
    validResponse              = False
    revokeLabel                = "SECT_REVOKE_"+certCategory+"_CERT"
    returnVal                  = getReturnVal(certCategory,'Revoke')
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)

    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    msg = getMessages("RevokeSetToTrue")
    WriteLog(msg)
    logger.info(msg)

    # check if collect related params are defined and not empty
    paramsDefinedFlag = are_required_param_names_defined(revokeLabel,params_dict)
    if paramsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(revokeLabel,params_dict)
        if paramsValidFlag:
            validResponse = True
    if not validResponse:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    #Get SSLID / ORDERNUMBER
    if certCategory == "SSL":
        returnVal["ssl_id"] = params_dict["sectigo_ssl_cert_ssl_id"]
        revoke_request_url = """{sectigo_cm_base_url}/revoke/{sectigo_ssl_cert_ssl_id}""".format(**params_dict)
    elif certCategory == "CLIENT":
        returnVal["orderNumber"] = params_dict["sectigo_client_cert_order_number"]
        revoke_request_url = """{sectigo_cm_base_url}/revoke/order/{sectigo_client_cert_order_number}""".format(**params_dict)

    try:
        revoke_request_headers = getRequestHeaders(params_dict)
        revoke_request_payload = {
            'reason': params_dict["sectigo_revoke_reason"]
        }

        # REVOKE PAYLOAD
        response = revoke_cert(revoke_request_url,revoke_request_headers,revoke_request_payload)
        
        returnVal["timestamp"] = getCurrentDateTime(1)

        # Success
        if (('description' not in error_resp) and (response is not None) and (response.status_code >= 200) and (response.status_code < 300)):

            returnVal["scm_response"] = {}
            returnVal["scm_response"]["body"] = str(response.text)
            returnVal["scm_response"]["status_code"] = response.status_code
            returnVal["scm_response"]["status"] = "SUCCESS"
            returnVal["status"] = "SUCCESS"
            returnVal["message"] = "The received status code from SCM implies that the revoke request has succeeded - StatusNoContent"

        # Response None
        elif ('description' not in error_resp) and (response is None):
            returnVal["status"] = "FAILURE"
            returnVal["message"] = "An error occured during certificate revocation. Response Null"

        # Some Sectigo Error
        elif ('description' in error_resp) and (response is not None):
            revokeData = json.loads(response.text)
            err_msg = "Revoke error: error_resp={0}, response={1}, status_code={2}".format(error_resp, response, response.status_code)
            log_error_resp("", err_msg)
            if ('code' in revokeData) and ('description' in revokeData):
                returnVal["scm_response"] = {}
                returnVal["status"] = "FAILURE"
                returnVal["message"] = "An error has occurred during certificate revocation: "
                returnVal["scm_response"]["status_code"] = response.status_code
                returnVal["scm_response"]["body"] = str(response.text)
                returnVal["scm_response"]["status"] = "FAILURE"

            else:
                returnVal["status"] = "FAILURE"
                returnVal["message"] = response.text

        # Some other error
        else:
            msg = "An error has occurred during certificate revocation: {0}".format(error_resp)
            returnVal["status"] = "FAILURE"
            returnVal["message"] = msg
            log_error_resp("", msg)

    except Exception as err:
        msg = "An error has occurred during certificate revocation: {}".format(str(err))
        msg = msg.replace("'","")
        log_error_resp("", msg)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg

    logger.info("---------------------------------------------------")
    logger.info("Revoke Return Value")
    logger.info(returnVal)
    WriteLog(returnVal)
    return returnVal

# Renew Cert 
def RenewCertificate(params_dict, certCategory):
    """
    # GENERIC ENDPOINT for RENEW CERT
    param, params_dict       - dictornary containing values
    param, certCategory         - ssl / client
    return, functionResponse    - RENEW Response
    """

    # Params defined
    global sectigo_logger_stdout_flag
    global connectionParams
    error_resp                 = {}
    renewLabel                 = "SECT_RENEW_"+certCategory+"_CERT"
    validResponse              = False
    returnVal                  = getReturnVal(certCategory,'Renew')
    returnVal["category"]      = certCategory
    returnVal["operation"]     = "Renew"
    params_dict.update(connectionParams)     # Get Param Connections
    params_dict["sectigo_cm_base_url"] = baseUrlFormat(params_dict["sectigo_cm_base_url"],certCategory)

    #CertCategory Checks
    certCategory = certCategory.upper()
    resp = validate_cert_category(certCategory)
    if not resp:
        returnVal = check_error(returnVal,params_dict)
        return returnVal
    
    # check if collect related params are defined and not empty
    paramsDefinedFlag = are_required_param_names_defined(renewLabel,params_dict)
    if paramsDefinedFlag:
        paramsValidFlag = are_required_param_names_valid(renewLabel,params_dict)
        if paramsValidFlag:
            validResponse = True
    if not validResponse:
        returnVal = check_error(returnVal,params_dict)
        return returnVal

    returnVal["timestamp"] = getCurrentDateTime(1)

    # RENEW PAYLOAD
    renew_response = renew_cert(params_dict,certCategory)

    # Success
    if (('description' not in error_resp) and (renew_response is not None) and (renew_response.status_code >= 200) and (renew_response.status_code < 300)):
        renewData = json.loads(renew_response.text)

        # Get sslid or ordernumber from the Renew Response
        certId = ""
        if certCategory == "SSL":
            returnVal["ssl_id"] = renewData["sslId"]
        elif certCategory == "CLIENT":
            returnVal["orderNumber"] = renewData["orderNumber"]

        returnVal["scm_response"] = {}
        returnVal["scm_response"]["body"] = str(renew_response.text)
        returnVal["scm_response"]["status"] = "SUCCESS"
        returnVal["scm_response"]["status_code"] = str(renew_response.status_code)
        returnVal["status"] = "SUCCESS"
        returnVal["message"] = "The received status code from SCM implies that the renew request has succeeded - StatusOK"

    # Failure
    elif (renew_response is not None):
        returnVal["scm_response"] = {}
        returnVal["scm_response"]["body"] = str(renew_response.text)
        returnVal["scm_response"]["status"] = "FAILURE"
        returnVal["scm_response"]["status_code"] = renew_response.status_code
        returnVal["status"] = "FAILURE"
        returnVal["message"] = "An error has occurred during certificate renewal"

    # RENEW ERROR
    else:
        msg = "An error has occurred during certificate renewal: {0}".format(error_resp)
        log_error_resp("", msg)
        returnVal["status"] = "FAILURE"
        returnVal["message"] = msg

    logger.info("---------------------------------------------------")
    logger.info("Renew Return Value")
    logger.info(returnVal)
    WriteLog(returnVal)
    return returnVal

################################################### ENDPOINTS - END ###################################################  