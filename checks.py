import argparse
from veracode_api_py import VeracodeAPI as vapi

def extract_application_name(scan_name):
    """
    Derive the application name from the scan name.
    Example: For scan name "12345-AVT-1Q2025-SCA", application name is "12345-SCA-AVT".
    """
    prefix = scan_name.split("-")[0]
    application_name = f"{prefix}-SCA-AVT"
    return application_name

def check_application(application_name):
    """
    Check if the application exists.
    """
    apps = vapi().get_apps()
    for app in apps:
        if app.get("profile").get("name") == application_name:
            return app
    return None

def check_sandbox(application_id, scan_name):
    """
    Check if a sandbox exists with the given scan name.
    """
    sandboxes = vapi().get_sandboxes(application_id)
    for sandbox in sandboxes:
        if sandbox.get("name") == scan_name:
            return sandbox
    return None

def check_scan(application_id, sandbox_id):
    """
    Check if there is a scan in the sandbox and whether it is completed.
    """
    builds = vapi().get_builds(application_id, sandbox_id=sandbox_id)
    for build in builds:
        if build.get("results_ready"):
            return build
    return None

def check_policy(scan):
    """
    Check the policy of the scan.
    """
    policy_name = scan.get("policy_name")
    if policy_name == "AT&T Gateway Default":
        return "PASSED", policy_name
    return "FAILED", policy_name

def check_fatal_errors(scan):
    """
    Check for fatal errors in the scan.
    """
    if scan.get("fatal_errors"):
        return True, scan.get("fatal_errors")
    return False, None

def check_selected_modules(scan):
    """
    Get the list of selected modules and their details.
    """
    modules = scan.get("modules", [])
    return modules

def compare_with_last_promoted(application_id, sandbox_id, current_modules):
    """
    Compare current selected modules with the last promoted scan.
    """
    last_promoted = vapi().get_promoted_build(application_id, sandbox_id=sandbox_id)
    if not last_promoted:
        return [], current_modules
    last_modules = [mod["name"] for mod in last_promoted.get("modules", [])]
    current_modules_names = [mod["name"] for mod in current_modules]
    new_modules = list(set(current_modules_names) - set(last_modules))
    return new_modules, current_modules_names

def check_missing_files_and_warnings(modules):
    """
    Count missing files and warnings in the selected modules.
    """
    missing_files = sum(mod.get("missing_files", 0) for mod in modules)
    warnings = sum(mod.get("warnings", 0) for mod in modules)
    return missing_files, warnings

def check_new_findings(scan_id):
    """
    Check for new findings of Critical, High, and Medium severity.
    """
    findings = vapi().get_findings(scan_id, scan_type="new")
    counts = {"Critical": 0, "High": 0, "Medium": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts

def check_open_findings(scan_id):
    """
    Check for open findings of Critical, High, and Medium severity.
    """
    findings = vapi().get_findings(scan_id, scan_type="open")
    counts = {"Critical": 0, "High": 0, "Medium": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts

def check_false_positives(scan_id):
    """
    Check for false positive proposed findings.
    """
    findings = vapi().get_findings(scan_id)
    false_positives = [f for f in findings if f.get("status") == "False Positive Proposed"]
    ids = [f["id"] for f in false_positives]
    return len(false_positives), ids

def check_sca_link(scan):
    """
    Check if there is an SCA linked with the scan.
    """
    sca_details = scan.get("sca_details", None)
    return sca_details is not None

def main():
    parser = argparse.ArgumentParser(description="Veracode Scan Validator")
    parser.add_argument("--scan-name", required=True, help="The name of the scan (e.g., '12345-AVT-1Q2025-SCA').")
    args = parser.parse_args()

    scan_name = args.scan_name
    application_name = extract_application_name(scan_name)
    print(f"Derived Application Name: {application_name}")
    print("\nPerforming checks...\n")

    # Step 1: Check if the application exists
    application = check_application(application_name)
    if not application:
        print("Application Check: FAILED")
        print(f"Application '{application_name}' does not exist.")
        return
    print("Application Check: PASSED")

    # Step 2: Check if the sandbox exists
    sandbox = check_sandbox(application["guid"], scan_name)
    if not sandbox:
        print("Sandbox Check: FAILED")
        print(f"No sandbox found with name '{scan_name}'.")
        return
    print("Sandbox Check: PASSED")

    # Step 3: Check if a scan exists and is completed
    scan = check_scan(application["guid"], sandbox["sandbox_id"])
    if not scan:
        print("Scan Check: FAILED")
        print(f"No completed scan found in sandbox '{scan_name}'.")
        return
    print("Scan Check: PASSED")

    # Step 4: Check policy
    policy_status, policy_name = check_policy(scan)
    print(f"Policy Check: {policy_status} (Policy: {policy_name})")

    # Step 5: Check for fatal errors
    fatal_errors, error_details = check_fatal_errors(scan)
    if fatal_errors:
        print("Fatal Errors Check: FAILED")
        print(f"Fatal Errors: {error_details}")
    else:
        print("Fatal Errors Check: PASSED")

    # Step 6: Check selected modules
    modules = check_selected_modules(scan)
    print(f"Selected Modules: {[mod['name'] for mod in modules]}")

    # Step 7: Compare with last promoted scan
    new_modules, _ = compare_with_last_promoted(application["guid"], sandbox["sandbox_id"], modules)
    if new_modules:
        print(f"New Modules Introduced: {new_modules}")
    else:
        print("Module Comparison: No new modules introduced.")

    # Step 8: Check missing files and warnings
    missing_files, warnings = check_missing_files_and_warnings(modules)
    print(f"Missing Files: {missing_files}, Warnings: {warnings}")

    # Step 9: Check for new findings
    new_findings = check_new_findings(scan["build_id"])
    print(f"New Findings: {new_findings}")

    # Step 10: Check for open findings
    open_findings = check_open_findings(scan["build_id"])
    print(f"Open Findings: {open_findings}")

    # Step 11: Check for false positive proposed findings
    fp_count, fp_ids = check_false_positives(scan["build_id"])
    if fp_count > 0:
        print(f"False Positive Proposed Findings: {fp_count} (IDs: {fp_ids})")
    else:
        print("False Positive Check: PASSED")

    # Step 12: Check if SCA is linked
    sca_linked = check_sca_link(scan)
    if sca_linked:
        print("SCA Linked Check: PASSED")
    else:
        print("SCA Linked Check: FAILED")

if __name__ == "__main__":
    main()
