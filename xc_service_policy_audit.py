import requests
import json
import csv


API_TOKEN = "<API TOKEN>"
TENANT = "<TENANT>"   
BASE_URL = f"<BASE_URL>"

HEADERS = {
    "Authorization": f"APIToken {API_TOKEN}",
    "Content-Type": "application/json"
}

service_policy_names=[]
service_policy_combined=[]
load_balancer_names=[]
namespace_service_policy_names=[]
lb_policy_map = {}
unique_csv_headers=set()


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


namespace_filter=role_filter_validation();
OUTPUT_FILE = f"f5xc_service_{namespace_filter}_policies.csv"
SORTED_OUTPUT_FILE=f"f5xc_service_sorted_{namespace_filter}_policies.csv"


def get_lb_service_policies(namespace):
    url = f"{BASE_URL}/api/config/namespaces/{namespace}/http_loadbalancers?report_fields"
    resp = requests.get(url, headers=HEADERS)
    data = resp.json();
    response=data["items"]
    print("load balancer service policies")
    for index, item in enumerate(response):
        print(index)
        service_policy_names=[]
        load_balancer_names.append(item['name']);
        if 'active_service_policies' in item.get("get_spec",{}):
            for policy in item['get_spec']['active_service_policies']['policies']:
                service_policy_names.append(policy['name'])
                print("***********")
                print(service_policy_names)
            service_policy_combined.append(service_policy_names);
        
      
    
    if resp.status_code != 200:
        print("Error fetching roles:", resp.text)
        return []

    return load_balancer_names,service_policy_combined;



def service_policy_expanded(namespace,load_balancer_names,service_policy_names):
    url = f"{BASE_URL}/api/config/namespaces/{namespace}/service_policys?report_fields"
    resp = requests.get(url, headers=HEADERS)
    data = resp.json();   
    response=data['items']
    print("service policies on namespace")
    namespace_service_policy_names=[]
    for index, item in enumerate(response):
        temp=item['get_spec']
        if "rule_list" in temp or "allow_list" in temp or "deny_list" in temp:

            print(index)
            namespace_service_policy_names.append(item['name'])
            
            print("--------------------------")
            lb_policy_map[item['name']]=temp;
            print("**************************")

    
    global lb_policy_map_copy;

    index=0;
    with open(OUTPUT_FILE, "w", newline="") as f:
        unique_csv_headers=[
    "load_balancer_name",
    "service_policy_name",
    "algo",
    "allow_list",
    "any_server",
    "deny_list",
    "port_matcher",
    "rule_list",
    "rules",
    "server_name",
    "server_name_matcher",
    "simple_rules"
        ]
        preferred = ["load_balancer_name","service_policy_name"]
        ordered_keys = preferred + sorted(k for k in unique_csv_headers if k not in preferred)
        writer = csv.DictWriter(f, fieldnames=ordered_keys)
        writer.writeheader()
        for service_policy_list in service_policy_names:
            print("LOAD BALANCER NAME")
            print(load_balancer_names[index])
            
            for service_policy in service_policy_list:
                if service_policy in lb_policy_map:
                    print("----------correct stuff-------------")
                    print("key")
                    
                    print("value")
                    lb_policy_map[service_policy].update({"load_balancer_name":load_balancer_names[index]})
                    lb_policy_map[service_policy].update({"service_policy_name":service_policy})
                    writer.writerow(lb_policy_map[service_policy])
                    
                    print("----------correct stuff end---------")
                    
            index=index+1;
        

        # return unique_csv_headers
        preferred = ["load_balancer_name","service_policy_name"]
        ordered_keys = preferred + sorted(k for k in unique_csv_headers if k not in preferred)


def main():
    print(f"\nFetching data for namespace: {namespace_filter}\n")

    load_balancer_names,service_policy_names = get_lb_service_policies(namespace_filter)
    print("***************************")
    print("UNPACKED TUPLE")
    print(load_balancer_names)
    print(service_policy_names)
    print("***************************")
    service_policy_expanded(namespace_filter,load_balancer_names,service_policy_names);
    
  
if __name__ == "__main__":
    main()




