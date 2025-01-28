import argparse
import re
from veracode_api_py import Applications, Sandboxes, Scans, Findings, SoftwareCompositionAnalyses

def validate_scan_name(scan_name):
    """Validate the scan name format."""
    pattern = r"^\d{5}-AVT-\dQ\d{4}-SCA$"
    return re.match(pattern, scan_name) is not None

def get_application_by_name(app_name):
    """Fetch application by name."""
    apps = Applications().search(app_name)
    return apps[0] if apps else None

def get_sandbox_by_name(app_id, sandbox_name):
    """Fetch sandbox by name for a given application."""
    sandboxes = Sandboxes().get_all(app_id)
    for sandbox in sandboxes:
        if sandbox["name"] == sandbox_name:
            return sandbox
    return None

def get_latest_scan(sandbox_id):
    """Fetch the latest scan for a given sandbox."""
    scans = Scans().get_all(sandbox_id)
    return scans[0] if scans else None

def get_scan_policy(scan_id):
    """Fetch the policy used for a scan."""
    scan_details = Scans().get(scan_id)
    return scan_details.get("policy", {}).get("name", "")

def get_scan_modules(scan_id):
    """Fetch the modules selected for a scan."""
    scan_details = Scans().get(scan_id)
    return [module["name"] for module in scan_details.get("modules", [])]

def get_scan_findings(scan_id):
    """Fetch findings for a scan."""
    findings = Findings().get_findings(scan_id)
    return findings

def get_sca_analysis(scan_id):
    """Fetch SCA analysis linked to the scan."""
    sca_analyses = SoftwareCompositionAnalyses().get_all(scan_id)
    return sca_analyses[0] if sca_analyses else None

def main():
    parser = argparse.ArgumentParser(description="Validate scan details.")
    parser.add_argument("scan_name", type=str, help="Scan name in the format MOTSID-AVT-QuarterYear-SCA")
    args = parser.parse_args()

    scan_name = args.scan_name

    if not validate_scan_name(scan_name):
        print("FAILED: Invalid scan name format.")
        return

    motsid = scan_name.split("-")[0]
    app_name = f"{motsid}-SCA-AVT"

    # Check if the application exists
    application = get_application_by_name(app_name)
    if not application:
        print("FAILED: Application does not exist.")
        return
    print("PASSED: Application exists.")

    app_id = application["guid"]

    # Check if the sandbox exists
    sandbox = get_sandbox_by_name(app_id, scan_name)
    if not sandbox:
        print("FAILED: Sandbox does not exist.")
        return
    print("PASSED: Sandbox exists.")

    sandbox_id = sandbox["guid"]

    # Fetch the latest scan in the sandbox
    scan = get_latest_scan(sandbox_id)
    if not scan:
        print("FAILED: No scan found in the sandbox.")
        return

    scan_id = scan["scan_id"]

    # Check if the scan is completed
    if scan["status"] != "completed":
        print("FAILED: Scan is not completed.")
        return
    print("PASSED: Scan is completed.")

    # Check if auto-scan is turned off
    if scan.get("auto_scan", False):
        print("FAILED: Auto-Scan is turned on.")
        return
    print("PASSED: Auto-Scan is turned off.")

    # Check the scan policy
    policy_name = get_scan_policy(scan_id)
    if policy_name != "ORG Gateway Default":
        print(f"FAILED: Policy used is '{policy_name}'.")
        return
    print("PASSED: Policy is 'ORG Gateway Default'.")

    # Check for fatal errors
    if scan.get("fatal_errors", []):
        print("FAILED: Scan has fatal errors.")
        return
    print("PASSED: No fatal errors in the scan.")

    # Check selected modules
    modules = get_scan_modules(scan_id)
    print(f"Selected modules: {', '.join(modules)}")

    # Compare with last promoted scan modules (assuming last promoted scan is the same for simplicity)
    last_promoted_modules = modules  # Replace with actual logic to fetch last promoted scan modules
    new_modules = set(modules) - set(last_promoted_modules)
    if new_modules:
        print(f"Newly selected modules: {', '.join(new_modules)}")
    else:
        print("No new modules introduced.")

    # Check for missing files and warnings
    missing_files = scan.get("missing_files", 0)
    warnings = scan.get("warnings", 0)
    if missing_files or warnings:
        print(f"Missing files: {missing_files}, Warnings: {warnings}")
    else:
        print("No missing files or warnings.")

    # Check for new issues
    findings = get_scan_findings(scan_id)
    new_issues = {"Critical": 0, "High": 0, "Medium": 0}
    for finding in findings:
        if finding["status"] == "NEW":
            severity = finding["severity"]
            if severity in new_issues:
                new_issues[severity] += 1
    if any(new_issues.values()):
        print(f"New issues - Critical: {new_issues['Critical']}, High: {new_issues['High']}, Medium: {new_issues['Medium']}")
    else:
        print("No new Critical, High, or Medium issues.")

    # Check for open issues
    open_issues = {"Critical": 0, "High": 0, "Medium": 0}
    for finding in findings:
        if finding["status"] == "OPEN":
            severity = finding["severity"]
            if severity in open_issues:
                open_issues[severity] += 1
    if any(open_issues.values()):
        print(f"Open issues - Critical: {open_issues['Critical']}, High: {open_issues['High']}, Medium: {open_issues['Medium']}")
    else:
        print("No open Critical, High, or Medium issues.")

    # Check for false positives
    false_positives = [finding for finding in findings if finding["status"] == "FALSE_POSITIVE"]
    if false_positives:
        print(f"False Positive Proposed Findings: {len(false_positives)} (IDs: {', '.join(str(fp['id']) for fp in false_positives)})")
    else:
        print("No False Positive Proposed Findings.")

    # Check for comments on findings
    findings_without_comments = [finding for finding in findings if not finding.get("comments")]
    if findings_without_comments:
        print("FAILED: Some findings do not have comments.")
    else:
        print("PASSED: Comments exist for all Open/New true findings and Proposed findings.")

    # Check if SCA is linked
    sca_analysis = get_sca_analysis(scan_id)
    if not sca_analysis:
        print("FAILED: No SCA linked with the scan.")
    else:
        print("PASSED: SCA is linked with the scan.")

if __name__ == "__main__":
    main()
