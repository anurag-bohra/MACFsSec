# MACFsSec
Scan Mac filesystem for known MAC executable and bundles and get data regarding the signing info, Virustotal Score, etc. with elastic integration

For scanning watchdog library is used. It actively monitors the paths specified and can also work incase of non-existent directory. Two separate handlers have been enabled. One for the extensions specified and the other default one for mach-o binaries. The code signing info of files matched are done using codesign utility. Additional check has been added for revoked certificates - **CSSMERR_TP_CERT_REVOKED**

Database feature has also been added so as to avoid repeated lookup of files in VT and to store the data regarding the File events occurred.

**FILES**

**settings.yaml:** This file consists settings and switches regarding the elastic, virustotal, database and scan parameters. Input the following fields:
'''
paths: ['/home']  #empty means base directory - '/'. Avoid using base dir as it will increase the load in the script and might require increasing the node limit.
enableVT: True
virustotalAPI: "<API_KEY>"
enableElastic: True
elasticIP: "localhost"
elasticPort: "9200"
databaseFile: "files.db"
extensions: ['app', 'dmg', 'pkg', 'kext']
'''

**Requirements:**
 - Python 3.7+

**Library Requirements**
1. watchdog
2. macholib
3. elasticsearch
4. requests
5. pyyaml

To Execute simply run **python3 main.py**. This can also be executed in background.
