import sys
import ssl
import socket
import json
from datetime import datetime
from traceback import print_tb
extra_ca=[]
class Certificate(object):

    def __init__(self):
        self.valid = False
        self.error = ''

    def load(self, data):
        for k, v in data.items():
            setattr(self, k, v)
        self.datetime = datetime.strptime(self.notAfter, '%b %d %H:%M:%S %Y %Z')
        self.valid = True


def get_cert(host):
    certificate = Certificate()
    context = ssl.create_default_context()
    for ca in extra_ca:
        context.load_verify_locations(ca)
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    try:
        conn.connect((host, 443))
        certificate.load(conn.getpeercert())
    except ssl.CertificateError as e:
        certificate.error = "{0}: UNTRUSTED {1}".format(host, e)
    except socket.gaierror as e:
        certificate.error = "{0}: ERROR1 {1}".format(host, e)
    except socket.error as e:
        certificate.error = "{0}: ERROR2 {1}".format(host, e)
    
    return certificate
import requests


domain = "google.com"





lis = []
unlis=[]
not_valid_cer=[]
xss_header_check=[]
# read all subdomains
file = open("subdomain.txt")
# read all content
content = file.read()
# split by new lines
subdomains = content.splitlines()
# a list of discovered subdomains
discovered_subdomains = []
for subdomain in subdomains:
    # construct the url
    url = f"https://{subdomain}.{domain}"
    try:
        response = requests.get(url)
    except requests.ConnectionError:
        unlis.append(url)
    else:
        print("[+] Discovered subdomain:", url)
        urll=f"{subdomain}.{domain}"
        certificate = get_cert(urll)
        if certificate.valid:
            lis.append({urll,response.status_code})
        else:
            not_valid_cer.append(urll)
print("*"*100+"List Of SubDomains with Valid Certificate"+"*"*100)
for i in lis:
    print(i)
with open('valid_subdomains.txt', 'w') as f:
    for line in lis:
        f.write(f"{line}\n")
print("*"*100+"List Of Not Working Subdomain"+"*"*100)
for i in unlis:
    print(i)
with open('notworking_subdomains.txt', 'w') as f:
    for line in unlis:
        f.write(f"{line}\n")
print("*"*100+"List Of Domains with Not Valid Certificate"+"*"*100)
for i in not_valid_cer:
    print(i)
with open('unvalid_certificate.txt', 'w') as f:
    for line in not_valid_cer:
        f.write(f"{line}\n")

import pyfiglet
import sys
import socket
from datetime import datetime



target = socket.gethostbyname(domain)

print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)
port_list=[]
unport_list=[]

try:
     
    for port in range(1,251):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
         
        result = s.connect_ex((target,port))
        if result==0:
            port_list.append(port)
        else:
            unport_list.append(port)
        s.close()
except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()
print("*"*100+"List Of Ports which are Working"+"*"*100)
for i in port_list:
    print("PORT is {} OPEN",i)
with open('valid_ports.txt', 'w') as f:
    for line in port_list:
        f.write(f"{line}\n")
print("*"*100+"List Of Ports which are not Working"+"*"*100)
for i in unport_list:
    print("PORT is {} Closed",i)
with open('unvalid_ports.txt', 'w') as f:
    for line in unport_list:
        f.write(f"{line}\n")

from operator import contains
import requests
temp="https://"+domain
xss=[]
r=requests.get(temp)
print(r.headers['x-xss-protection'])
if r.headers['X-XSS-Protection']=='1; mode=block' or r.headers['x-xss-protection']=='1' or r.headers['X-XSS-Protection']==1 or r.headers['x-xss-protection']==1 :
    xss.append("X-XSS-Protection : Enabled")
    print('1')
else:
    xss.append("X-XSS-Protection : Disabled")
    print('2')
with open('xss_header.txt', 'w') as f:
    for line in xss:
        f.write(f"{line}\n")
