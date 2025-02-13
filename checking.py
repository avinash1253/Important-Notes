from lxml import etree

# Load and parse the XML file
xml_file = "veracode_report.xml"  # Update with your actual file path
tree = etree.parse(xml_file)
root = tree.getroot()

# Namespace Dictionary (Veracode XML uses namespaces)
ns = {"ns": "https://www.veracode.com/schema/reports/export/1.0"}

# Extract Basic Report Information
app_name = root.xpath("//ns:detailedreport/@app_name", namespaces=ns)[0]
app_id = root.xpath("//ns:detailedreport/@app_id", namespaces=ns)[0]
total_flaws = root.xpath("//ns:detailedreport/@total_flaws", namespaces=ns)[0]
flaws_not_mitigated = root.xpath("//ns:detailedreport/@flaws_not_mitigated", namespaces=ns)[0]

print(f"Application Name: {app_name}")
print(f"Application ID: {app_id}")
print(f"Total Flaws: {total_flaws}")
print(f"Flaws Not Mitigated: {flaws_not_mitigated}")

# Extract Flaw Details
flaws = root.xpath("//ns:staticflaws/ns:flaw", namespaces=ns)

print("\nFlaw Details:")
for flaw in flaws:
    severity = flaw.get("severity")
    category = flaw.get("categoryname")
    cwe_id = flaw.get("cweid")
    description = flaw.get("description")
    remediation_status = flaw.get("remediation_status")
    
    print(f"  - Severity: {severity}")
    print(f"    Category: {category}")
    print(f"    CWE ID: {cwe_id}")
    print(f"    Description: {description}")
    print(f"    Remediation Status: {remediation_status}\n")
