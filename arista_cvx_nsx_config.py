import ssl
import OpenSSL
import socket
import hashlib
import getpass
from cryptography.hazmat.primitives import serialization
import oscrypto
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import urllib3
import time
import sys, getopt
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#retrive SSL Thumbprint from Arista CVX 
def get_cvx_thumbprint(addr):
    print("Read SSL Thumbprint from CVX server at IP Address -> "+cvx_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((addr,443))
    except:
        reponse = False
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        cvx_thumbprint = str(hashlib.sha256(der_cert_bin).hexdigest())
        return cvx_thumbprint

    wrappedSocket.close()
    
def get_nsx_thumbprint(addr):
        pubkey = os.popen("openssl s_client -connect "+addr+":443 | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl base64").read()
        pubkey = pubkey.rstrip("\n")
        return pubkey

#Configure NSX to have CVX as an enforcement point. Only one enformcent point allowed per site 
def delete_cvx_in_nxs():
    print("Deleting existing CVX as enforcement point...will fail if not present")
    url = "https://"+nsx_ip+"/policy/api/v1/infra/sites/default/enforcement-points/cvx-ep"

    payload = {
        "display_name": "cvx-deployment-map",
        "id": "cvx-default-dmap",
        "enforcement_point_path": "/infra/sites/default/enforcement-points/cvx-ep"
    }
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("DELETE", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        print ('--> Deleted successfully')
    else:
        print ('--> Failed')

def register_cvx_in_nsx(cvx_thumbprint):
    time.sleep(10)
    print("Creating CVX Entry as enforcement point in NSX-T manager")
    url = "https://"+nsx_ip+"/policy/api/v1/infra/sites/default/enforcement-points/cvx-ep"
    payload = {
            "auto_enforce": "false",
            "connection_info": {
                "enforcement_point_address": cvx_ip,
                "resource_type": "CvxConnectionInfo",
                "username": cvx_user,
                "password": cvx_password,
                "thumbprint": cvx_thumbprint
            }
        }
    headers = {
            'Content-Type': 'application/json'
    }
    response = requests.request("PATCH", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        print ('--> Change made successfully')
    else:
        print ('--> Failed')

#Read CVX Enforcement point setting from NSX 
def get_cvx_from_nsx():
    print("Read enforement point from NSX")
    url = "https://"+nsx_ip+"/policy/api/v1/infra/sites/default/enforcement-points/cvx-ep"
    payload = ""
    headers = { }
    response = requests.request("GET", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=payload, verify=False)
    if response.status_code == 200:
        print ('--> Read successful')
    else:
        print ('--> Failed')

#Create notification ID 
def create_notification_id():
    print("Creating notification ID from NSX-T Manager")
    url = "https://"+nsx_ip+"/api/v1/notification-watchers"
    payload = {
        "server": cvx_ip,
        "method": "POST",
        "uri": "/pcs/v1/nsgroup/notification",
        "use_https": True,
        "certificate_sha256_thumbprint": cvx_thumbprint,
        "authentication_scheme": {
        "scheme_name": "BASIC_AUTH",
        "username": cvx_user,
        "password": cvx_password
        }
    }
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        print ('--> Change made successfully')
    else:
        print ('--> Failed')


def get_notification_id_from_nsx():
    print("Extracting notification ID from NSX-T Manager")
    url = "https://"+nsx_ip+"/api/v1/notification-watchers"
    print(url)
    payload = {}
    headers = {}
    try:
        response = requests.request("GET", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=json.dumps(payload), verify=False)
        print(response)
        json_object = json.loads(response.text)
        notification_id = (json_object['results'][0]['id'])
        print (notification_id)
        return notification_id
    except:
        print("--> Error :(") 


def delete_notification_id_from_nsx():
    print("Delete existing notification ID from NSX-T Manager")
    id = get_notification_id_from_nsx()
    url = "https://"+nsx_ip+"/api/v1/notification-watchers/"+str(id)
    print(url)
    payload = {}
    headers = {}    
    response = requests.request("DELETE", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=payload, verify=False)
    print (response)
    if response.status_code == 200:
        print ('--> Deleted successfully')
    else:
        print ('--> Failed')


#create deployment map
def delete_deployment_map():
    print("Deleting existing deployment map for cvx-default-dmap")
    url = "https://"+nsx_ip+"/policy/api/v1/infra/domains/default/domain-deployment-maps/cvx-default-dmap"

    payload = json.dumps({
        "display_name": "cvx-deployment-map",
        "id": "cvx-default-dmap",
        "enforcement_point_path": "/infra/sites/default/enforcement-points/cvx-ep"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("DELETE", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        print ('--> Change made successfully')
    else:
        print ('--> Failed')

def create_deployment_map():
    print("Creating deployment map for cvx-default-dmap")
    url = "https://"+nsx_ip+"/policy/api/v1/infra/domains/default/domain-deployment-maps/cvx-default-dmap"
    headers = {
            'Content-Type': 'application/json'
    }
    payload = {
    "display_name": "cvx-deployment-map",
    "id": "cvx-default-dmap",
    "enforcement_point_path": "/infra/sites/default/enforcement-points/cvx-ep"
    }

    response = requests.request("PATCH", url, headers=headers, auth = HTTPBasicAuth(nsxt_user, nsxt_password), data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        print ('--> Change made successfully')
    else:
        print ('--> Failed')




def main(argv):
    try:
        opts, args = getopt.getopt(argv,"ha:d:")
    except getopt.GetoptError:
        print ('arista_cvx_nsx_config.py -a (add) -d (del)')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-a':
            register_cvx_in_nsx(cvx_thumbprint)
            create_notification_id()
            time.sleep(10)
            cvx_notification_id = get_notification_id_from_nsx()
            create_deployment_map()
            print("management api http-commands")
            print("no shutdown")
            print("exit")
            print("cvx")
            print("no shutdown")
            print("source-interface management 1")
            print("service pcs")
            print("no shutdown")
            print("controller "+nsx_ip)
            print("username "+nsxt_user)
            print("password "+nsxt_password)
            print("enforcement-point cvx-ep")
            print("pinned-public-key sha256//"+nsx_thumbprint)
            print("notification-id "+cvx_notification_id)
            print("end")
            print("write mem")      
            sys.exit()
        elif opt == '-d':
            delete_notification_id_from_nsx()
            delete_deployment_map()
            delete_cvx_in_nxs()


if __name__ == "__main__":
    cvx_ip = input("IP Address of CVX: ")  
    nsx_ip = input("IP Address of NSX-T: ") 
    nsxt_user = input("NSX-T Admin Username: ")
    nsxt_password = getpass.getpass("Enter NSX-T Admin Password: ")
    cvx_user = input("CVX Admin Username: ")
    cvx_password = getpass.getpass("Enter CVX Password: ")
    cvx_thumbprint = get_cvx_thumbprint(cvx_ip)
    nsx_thumbprint = get_nsx_thumbprint(nsx_ip)
    main(sys.argv[1:])

















