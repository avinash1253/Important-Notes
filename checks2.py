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
    return None

# Get scans for a sandbox
def get_scans_for_sandbox(application_id, sandbox_id, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications/{application_id}/sandboxes/{sandbox_id}/scans"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        return response.json().get("_embedded", {}).get("scans", [])
    return []

# Get scan details by scan ID
def get_scan_details(application_id, sandbox_id, scan_id, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications/{application_id}/sandboxes/{sandbox_id}/scans/{scan_id}"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        return response.json()
    return None

# Check findings for a scan
def get_findings(application_id, scan_id, auth):
    url = f"{VERACODE_BASE_URL}/appsec/v1/applications/{application_id}/scans/{scan_id}/findings"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        return response.json().get("_embedded", {}).get("findings", [])
    return []

def main():
    parser = argparse.ArgumentParser(description="Veracode Scan Validator using REST APIs")
    parser.add_argument("--scan-name", required=True, help="The name of the scan (e.g., '12345-AVT-1Q2025-SCA').")
    args = parser.parse_args()

    scan_name = args.scan_name
    application_name = f"{scan_name.split('-')[0]}-SCA-AVT"  # Derive application name from scan name

    # Load credentials and set up authentication
    credentials = load_credentials()
    auth = HTTPBasicAuth(credentials["api_key_id"], credentials["api_key_secret"])

    print(f"Derived Application Name: {application_name}")
    print("\nPerforming checks...\n")

    # Step 1: Check if the application exists
    application = get_application_by_name(application_name, auth)
    if not application:
        print("Application Check: FAILED")
        print(f"Application '{application_name}' does not exist.")
        return
    print("Application Check: PASSED")

    # Step 2: Check if the sandbox exists
    sandbox = get_sandbox_by_name(application["guid"], scan_name, auth)
    if not sandbox:
        print("Sandbox Check: FAILED")
        print(f"No sandbox found with name '{scan_name}'.")
        return
    print("Sandbox Check: PASSED")

    # Step 3: Check if a scan exists and is completed
    scans = get_scans_for_sandbox(application["guid"], sandbox["guid"], auth)
    completed_scans = [scan for scan in scans if scan["status"] == "COMPLETE"]
    if not completed_scans:
        print("Scan Check: FAILED")
        print(f"No completed scan found in sandbox '{scan_name}'.")
        return
    print("Scan Check: PASSED")

    # Step 4: Get the latest scan details
    latest_scan = completed_scans[0]
    scan_details = get_scan_details(application["guid"], sandbox["guid"], latest_scan["scan_id"], auth)

    # Step 5: Check policy
    policy_name = scan_details.get("policy_name", "Unknown")
    if policy_name == "AT&T Gateway Default":
        print("Policy Check: PASSED")
    else:
        print(f"Policy Check: FAILED (Policy: {policy_name})")

    # Step 6: Check for findings
    findings = get_findings(application["guid"], latest_scan["scan_id"], auth)
    critical = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    print(f"Findings: Critical={critical}, High={high}, Medium={medium}")

    # Step 7: Check if SCA is linked
    sca_details = scan_details.get("sca_details")
    if sca_details:
        print("SCA Linked Check: PASSED")
    else:
        print("SCA Linked Check: FAILED")

if __name__ == "__main__":
    main()
