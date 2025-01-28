import os
import argparse
import requests
from requests.auth import HTTPBasicAuth

# Load credentials from the .veracode/credentials file
def load_credentials():
    credentials_file = os.path.expanduser("~/.veracode/credentials")
    try:
        with open(credentials_file, "r") as file:
            lines = file.readlines()
            credentials = {}
            for line in lines:
                if "veracode_api_key_id" in line:
                    credentials["api_key_id"] = line.split("=")[1].strip()
                elif "veracode_api_key_secret" in line:
                    credentials["api_key_secret"] = line.split("=")[1].strip()
            return credentials
    except FileNotFoundError:
        print("Error: Veracode credentials file not found.")
        exit(1)

# Veracode API base URL
VERACODE_BASE_URL = "https://api.veracode.com"

# Get application by name
def get_application_by_name(application_name, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications"
    params = {"name": application_name}
    response = requests.get(url, params=params, auth=auth)
    if response.status_code == 200:
        apps = response.json().get("_embedded", {}).get("applications", [])
        for app in apps:
            if app["profile"]["name"] == application_name:
                return app
    print(f"Error: Application '{application_name}' not found.")
    return None

# Get sandboxes for an application
def get_sandbox_by_name(application_id, sandbox_name, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications/{application_id}/sandboxes"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        sandboxes = response.json().get("_embedded", {}).get("sandboxes", [])
        for sandbox in sandboxes:
            if sandbox["name"] == sandbox_name:
                return sandbox
    print(f"Error: Sandbox '{sandbox_name}' not found.")
    return None

# Get scans for a sandbox
def get_scans_for_sandbox(application_id, sandbox_id, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications/{application_id}/sandboxes/{sandbox_id}/scans"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        return response.json().get("_embedded", {}).get("scans", [])
    print(f"Error: No scans found for sandbox '{sandbox_id}'.")
    return []

# Check if a scan is promoted
def is_scan_promoted(application_id, scan_id, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications/{application_id}/scans/{scan_id}"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        scan_details = response.json()
        return scan_details.get("lifecycle_stage") == "promoted"
    elif response.status_code == 404:
        print(f"Error: Scan with ID '{scan_id}' not found.")
    else:
        print(f"Error: Unable to retrieve scan details. HTTP {response.status_code}: {response.text}")
    return False

def main():
    parser = argparse.ArgumentParser(description="Check if a Veracode scan is promoted.")
    parser.add_argument("--scan-name", required=True, help="The name of the scan (e.g., '12345-AVT-1Q2025-SCA').")
    args = parser.parse_args()

    scan_name = args.scan_name
    application_name = f"{scan_name.split('-')[0]}-SCA-AVT"  # Derive application name from scan name

    # Load credentials and set up authentication
    credentials = load_credentials()
    auth = HTTPBasicAuth(credentials["api_key_id"], credentials["api_key_secret"])

    print(f"Derived Application Name: {application_name}")

    # Step 1: Check if the application exists
    application = get_application_by_name(application_name, auth)
    if not application:
        return

    # Step 2: Check if the sandbox exists
    sandbox = get_sandbox_by_name(application["guid"], scan_name, auth)
    if not sandbox:
        return

    # Step 3: Check if a scan exists in the sandbox
    scans = get_scans_for_sandbox(application["guid"], sandbox["guid"], auth)
    if not scans:
        return

    # Step 4: Check if the latest scan is promoted
    latest_scan = scans[0]  # Assuming scans are sorted by most recent
    is_promoted = is_scan_promoted(application["guid"], latest_scan["scan_id"], auth)
    if is_promoted:
        print(f"The scan '{scan_name}' is PROMOTED.")
    else:
        print(f"The scan '{scan_name}' is NOT PROMOTED.")

if __name__ == "__main__":
    main()
