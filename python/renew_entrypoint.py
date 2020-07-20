#!/usr/local/bin/python
from datetime import datetime
print("Cron job has run at {0} with environment variable ".format(str(datetime.now())))


param_dict = {}
response = '{"id":"12345"}'
param_dict["certFilePath"] = '/root/'
param_dict["certFileName"] = 'aaa'
# w = s.write_to_ids_file(param_dict,'ssl',response)
print(param_dict)
cert_ids_file_full_path = param_dict["certFilePath"]+param_dict["certFileName"]+".ids"

f = open(cert_ids_file_full_path, 'w')
f.write(str(response))
