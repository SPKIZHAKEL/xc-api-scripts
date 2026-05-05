import requests
import json
import csv


API_TOKEN = "{TOKEN}"
TENANT = "{TENANT}"   
BASE_URL = f"{BASE URL}"


HEADERS = {
    "Authorization": f"APIToken {API_TOKEN}",
    "Content-Type": "application/json"
}

def get_namespaces():
    url = f"{BASE_URL}/api/web/namespaces"
    resp=requests.get(url,headers=HEADERS)
    if resp.status_code!=200:
        print("Error fetching namespaces")
        return []
    data=resp.json();
    print(data);
    namespace_list=[]
    for item in data["items"]:
        namespace_list.append(item["name"])
    print(namespace_list)
    return namespace_list


namespaces=get_namespaces();

#sanitizing the input
def role_filter_validation():
    while True:
        role_filter = input("Enter namespace role filter (press Enter for all OR enter a valid exisiting namespace): ").strip().lower()
        if role_filter in namespaces or role_filter=="":
            return role_filter
        else:
            print("Invalid input namespace does not exist")


role_filter=role_filter_validation();

def get_cert_details():
 missing_cert_names=[]
 url = f"{BASE_URL}/api/config/namespaces/{role_filter}/certificates?report_fields"
 resp = requests.get(url, headers=HEADERS)
 data = resp.json();
 response=data["items"]
 for index, item in enumerate(response):
        
        if not item['get_spec']['certificate_chain']:
            print(f"Relative index: {index+1}")
            print(f"Certificate Name: {item['name']}")
            print("**********************")
            missing_cert_names.append(item['name'])

 print("\n\n")
 print(f"total number of certs missing intermediates:{len(missing_cert_names)}")
       
    
 if resp.status_code != 200:
    print("Error fetching certs:", resp.text)
    return []

 return response;

get_cert_details();
