#! /usr/bin/python3
import requests
import json
from pprint import pprint

documents = [
    "actions",
    "ratelimits",
    "securitypolicies",
    "contentfilterrules",
    "contentfilterprofiles",
    "aclprofiles",
    "globalfilters",
    "flowcontrol",
    "virtualtags",
    "custom",
]

branch = "prod"
host = "34.65.106.27"
port = "30000"
url = f"http://{host}:{port}"

def update():
    for doc in documents:
        print (f"pushing {doc}")
        json=open(f"{doc}.json", "r+b").read()
        response = requests.delete(f"{url}/api/v3/configs/{branch}/d/{doc}/")
        response = requests.post(f"{url}/api/v3/configs/{branch}/d/{doc}/",
            data = json, headers = {"content-type": "application/json"})
        if response.status_code > 399:
            pprint (response.json())

if __name__ == "__main__":
    update()
