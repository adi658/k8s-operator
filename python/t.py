#!/usr/bin/env python
# import sectigo_pycert as s 

param_dict = {}
response = '{"id":"12345"}'
param_dict["certFilePath"] = '/root/'
param_dict["certFileName"] = 'aaa'
# w = s.write_to_ids_file(param_dict,'ssl',response)
print(param_dict)
cert_ids_file_full_path = param_dict["certFilePath"]+param_dict["certFileName"]+".ids"

f = open(cert_ids_file_full_path, 'w')
f.write(str(response))
