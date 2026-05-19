import pandas as pd
import subprocess
import re
import requests


NS1="ns1.f5clouddns.com" #or replace with current nameserver seen on nslookup
NS2="ns2.f5clouddns.com"

API_TOKEN = "<API_token_value>"
TENANT = "<tenant name>"   # e.g. "mycompany"
ZONE_NAME = "<zone name>"

# Base URL
BASE_URL = f"https://<TENANT>.console.ves.volterra.io"

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



def role_filter_validation(namespaces):
    while True:
        role_filter = input("Enter namespace role filter (press Enter for all OR enter a valid exisiting namespace): ").strip().lower()
        if role_filter in namespaces or role_filter=="":
            return role_filter
        else:
            print("Invalid input namespace does not exist")




def run_dig(nameserver, fqdn, record_type):
    """
    Run dig and return RDATA values from the ANSWER section only.
    """
    try:
        result = subprocess.run(
            [
                "dig",
                f"@{nameserver}",
                fqdn,
                record_type,
                "+noall",
                "+answer"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout.strip()
        if not output:
            return []

        rdata_values = []

        for line in output.splitlines():
            # Expected format:
            # name ttl class type rdata...
            parts = line.split()
            if len(parts) >= 5:
                rdata = " ".join(parts[4:])
                rdata_values.append(rdata)

        return rdata_values

    except Exception as e:
        print(f"dig error {fqdn} {record_type} @{nameserver}: {e}")
        return []

def normalize(value):
    """
    Normalize DNS RDATA for reliable comparison.
    """
    if pd.isna(value):
        return ""

    value = str(value).strip().lower()
    value = value.strip('"').rstrip(".")

    # Remove MX priority if present
    value = re.sub(r"^\d+\s+", "", value)

    return value

def match_result(answer_values, expected_value):
    expected = normalize(expected_value)

    for answer in answer_values:
        if expected == normalize(answer):
            return "SUCCESS"

    return "FAILURE"

def main(input_excel):
    namespaces=get_namespaces();
    namespace_filter=role_filter_validation(namespaces);
    df = pd.read_excel(input_excel)
    df.columns = df.columns.str.strip()

    ns1_results = []
    ns2_results = []

    for _, row in df.iterrows():
        fqdn = str(row["SUBDOMAIN"]).strip()
        record_type = str(row["RECORD TYPE"]).strip()
        expected_value = row["VALUE"]

        answers_ns1 = run_dig(NS1, fqdn, record_type)
        answers_ns2 = run_dig(NS2, fqdn, record_type)

        ns1_results.append(match_result(answers_ns1, expected_value))
        ns2_results.append(match_result(answers_ns2, expected_value))

    df["RESULT_NS1"] = ns1_results
    df["RESULT_NS2"] = ns2_results

    df.to_excel(f"output_{namespace_filter}.xlsx", index=False)

if __name__ == "__main__":
    main("dns_records_f5_input.xlsx")
