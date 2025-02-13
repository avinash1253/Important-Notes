from lxml import etree

# Load and parse the XML file
xml_file = "veracode_report.xml"  # Update with actual file path
tree = etree.parse(xml_file)
root = tree.getroot()

# Namespace Dictionary (Veracode XML uses namespaces)
ns = {"ns": "https://www.veracode.com/schema/reports/export/1.0"}

### 1️⃣ Extract Scan Submitter Name ###
submitter_name = root.xpath("//ns:detailedreport/@submitter", namespaces=ns)[0]
print(f"Scan Submitter Name: {submitter_name}")

### 2️⃣ Extract Total Flaws ###
total_flaws = int(root.xpath("//ns:detailedreport/@total_flaws", namespaces=ns)[0])
print(f"Total Flaws: {total_flaws}")

### 3️⃣ Count Open Flaws by Severity ###
open_severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

# Extract all flaws
flaws = root.xpath("//ns:staticflaws/ns:flaw[@remediation_status='Open']", namespaces=ns)

# Count open flaws by severity level
for flaw in flaws:
    severity = int(flaw.get("severity"))
    if severity == 5:
        open_severity_counts["Critical"] += 1
    elif severity == 4:
        open_severity_counts["High"] += 1
    elif severity == 3:
        open_severity_counts["Medium"] += 1
    elif severity == 2:
        open_severity_counts["Low"] += 1

print(f"Flaws Still Open: C={open_severity_counts['Critical']}, H={open_severity_counts['High']}, M={open_severity_counts['Medium']}, L={open_severity_counts['Low']}")

### 4️⃣ Extract Policy Name ###
policy_name = root.xpath("//ns:detailedreport/@policy_name", namespaces=ns)[0]
print(f"Policy Name: {policy_name}")

### 5️⃣ Check If Scan is Promoted ###
is_promoted = root.xpath("//ns:detailedreport/@is_latest_build", namespaces=ns)[0]
promoted_status = "Yes" if is_promoted.lower() == "true" else "No"
print(f"Is Scan Promoted?: {promoted_status}")
