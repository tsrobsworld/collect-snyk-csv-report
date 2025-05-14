import json
import requests
from requests.exceptions import HTTPError
import time

from utils.helper import get_snyk_token

SNYK_TOKEN = get_snyk_token()

restHeaders = {'Content-Type': 'application/vnd.api+json', 'Authorization': f'token {SNYK_TOKEN}'}
restExportHeaders = {'Content-Type': 'application/json', 'Authorization': f'token {SNYK_TOKEN}'}
v1Headers = {'Content-Type': 'application/json; charset=utf-8', 'Authorization': f'token {SNYK_TOKEN}'}
rest_version = '2024-10-15'

# Paginate through Snyk's API endpoints with retry and backoff
def pagination_snyk_rest_endpoint(url, method, region, headers=None, body=None, return_body=False):
    match method.upper():
        case 'POST':
            try:
                response = requests.post(url, headers=headers, json=body)
                response.raise_for_status()  # Raise an error for bad responses
                # Return the body if include_body is true, otherwise return the status code
                return response.json() if return_body else response.status_code
            except requests.exceptions.RequestException as e:
                return f"An error occurred during POST request: {e}"

        case 'GET':
            try:
                results = []
                response = requests.get(url, headers=headers)
                response.raise_for_status()  # Raise an error for bad responses
                data = response.json()
                
                # Collect data from the first page
                results.extend(data['data'])
                
                # Check for the 'next' link
                next_url = data.get('links', {}).get('next')
                
                if not next_url:
                    # If no 'next' link, return the collected results immediately
                    return data
                
                # If there is a 'next' link, continue pagination
                while next_url:
                    next_url = f'https://{region}' + next_url
                    response = requests.get(next_url, headers=headers)
                    response.raise_for_status()
                    data = response.json()
                    results.extend(data['data'])
                    next_url = data.get('links', {}).get('next')
                
                return results
            except requests.exceptions.RequestException as e:
                return f"An error occurred during GET request: {e}"

        case 'DELETE':
            try:
                response = requests.delete(url, headers=headers)
                response.raise_for_status()  # Raise an error for bad responses
                return response.status_code
            except requests.exceptions.RequestException as e:
                return f"An error occurred during DELETE request: {e}"


def initiate_snyk_export_csv(group_id, introduced_from, introduced_to, region):
    url = f'https://{region}/rest/groups/{group_id}/export?version=2024-10-15'
    body = {"data":{"type":"resource","attributes":{"formats":["csv"],"columns":["ISSUE_SEVERITY_RANK","ISSUE_SEVERITY","SCORE","PROBLEM_TITLE","CVE","CWE","PROJECT_NAME","PROJECT_URL","EXPLOIT_MATURITY","FIRST_INTRODUCED","PRODUCT_NAME","ISSUE_URL","ISSUE_TYPE"],"dataset":"issues","destination":{"file_name":"test_export","type":"snyk"},"filters":{"introduced":{"from":introduced_from,"to":introduced_to}}}}}
    try:
        response = requests.post(url, headers=restExportHeaders, json=body)
        response.raise_for_status()
        return response.json()
    except HTTPError as exc:
        print("Snyk Export endpoint failed.")
        print(exc)
    
    return response

def get_snyk_export_status(group_id, export_id, region):
    url = f'https://{region}/rest/groups/{group_id}/jobs/export/{export_id}?version=2024-10-15'
    print(url)
    response = pagination_snyk_rest_endpoint(url, 'GET', region, restExportHeaders)
    return response

def get_snyk_export_csv(group_id, export_id, region):
    url = f'https://{region}/rest/groups/{group_id}/export/{export_id}?version=2024-10-15'
    response = pagination_snyk_rest_endpoint(url, 'GET', region, restExportHeaders)
    return response['data']['attributes']['results'][0]['url']
