import uvicorn
import webbrowser
import asyncio
import platform
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import mysql.connector
from netAssetDisc_mysql import (
    get_active_interface_info, get_network_range_from_ip, nmap_scan,
    get_snmp_info, identify_device_type, get_mac_vendor,
    discover_upnp_devices, parse_device_description, save_scan_to_db, DB_CONFIG
)
from sysAssetDisc_mysql import detect_and_store_system
from vulnerabilityDisc import batch_scan_ips
from clamAV_Scanner import scan_all_app_paths
import ipaddress

app = FastAPI()

def render_template(title, body):
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='UTF-8'>
  <title>{title}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      background: #f7f7f7;
      color: #333;
    }}
    header {{
      background: #ff6b6b;
      padding: 1rem;
      text-align: center;
      font-size: 1.5rem;
      font-weight: bold;
      color: #fff;
    }}
    .container {{
      display: flex;
    }}
    nav {{
      width: 200px;
      background: #f0f0f0;
      padding: 1rem;
      height: 100vh;
    }}
    nav a {{
      display: block;
      background: #ff4d4d;
      color: #fff;
      text-decoration: none;
      padding: 10px;
      border-radius: 4px;
      margin-bottom: 10px;
      text-align: center;
    }}
    nav a:hover {{
      background: #e60000;
    }}
    main {{
      flex: 1;
      padding: 2rem;
    }}
    .button {{
      display: inline-block;
      padding: 10px 20px;
      background: #4CAF50;
      color: white;
      text-decoration: none;
      border-radius: 5px;
    }}
    .button:hover {{
      background: #45a049;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }}
    th, td {{
      border: 1px solid #ccc;
      padding: 8px;
      text-align: left;
    }}
    th {{
      background: #eee;
    }}
    pre {{
      background: #f0f0f0;
      padding: 1rem;
      border-radius: 5px;
    }}
  </style>
</head>
<body>
  <header>Net Scanner</header>
  <div class="container">
    <nav>
      <a href="/">Dashboard</a>
      <a href="/network-info">WiFi/LAN information</a>
      <a href="/devices">Devices in network</a>
      <a href='/vulnerabilities'>Vulnerabilities</a>
      <a href="/remote-form">Softwares installed</a>
      <a href="/cloud-assets">Cloud Assets</a>
      <a href="/cloud-history">Cloud History</a>
    </nav>
    <main>
      {body}
    </main>
  </div>
</body>
</html>""")

@app.get("/", response_class=HTMLResponse)
def dashboard():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM networks ORDER BY scan_time DESC LIMIT 1")
    network = cur.fetchone()

    if not network:
        return render_template("Dashboard", "<p>No scan data available</p>")

    cur.execute("SELECT * FROM devices WHERE network_id = %s", (network['id'],))
    devices = cur.fetchall()
    conn.close()

    table = "<h2>Most Recent Network Scan</h2>"
    table += "<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>MAC</th><th>Type</th></tr>"

    for d in devices:
        table += f"<tr><td>{d['ip']}</td><td>{d['hostname']}</td><td>{d['os']}</td><td>{d['ports']}</td><td>{d['mac']}</td><td>{d['device_type']}</td></tr>"

    table += "</table>"
    table += """
      <br>
      <form method="get" action="/scan">
        <label><input type="checkbox" name="vuln" value="yes" checked> Also perform vulnerability scan</label><br><br>
        <input class="button" type="submit" value="Start a new scan">
      </form>
    """

    return render_template("Dashboard", table)

@app.get("/network-info", response_class=HTMLResponse)
def network_info():
    info = get_active_interface_info()
    table = "<h2>WiFi/LAN Information</h2><table>"
    for key, value in info.items():
        if isinstance(value, dict):
            table += f"<tr><td>{key}</td><td><ul>"
            for k, v in value.items():
                table += f"<li><strong>{k}</strong>: {v}</li>"
            table += "</ul></td></tr>"
        else:
            table += f"<tr><td>{key}</td><td>{value}</td></tr>"

    table += "</table>"
    return render_template("WiFi/LAN Information", table)

@app.get("/devices", response_class=HTMLResponse)
def show_devices():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM networks ORDER BY scan_time DESC")
    networks = cur.fetchall()
    body = "<h2>Devices in Network</h2>"
    for net in networks:
        body += f"<h3>{net['ip_range']} (Scanned: {net['scan_time']})</h3>"
        cur.execute("SELECT * FROM devices WHERE network_id = %s", (net['id'],))
        devices = cur.fetchall()
        body += "<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>MAC</th><th>Type</th></tr>"
        for d in devices:
            body += f"<tr><td>{d['ip']}</td><td>{d['hostname']}</td><td>{d['os']}</td><td>{d['ports']}</td><td>{d['mac']}</td><td>{d['device_type']}</td></tr>"
        body += "</table>"
    conn.close()
    return render_template("Devices", body)

@app.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM vulnerabilities ORDER BY severity DESC")
    vulnerabilities = cur.fetchall()
    conn.close()

    table = "<h2>Vulnerabilities</h2>"
    table += "<table><tr><th>Device IP</th><th>Port</th><th>Vulnerability</th><th>Description</th><th>Severity</th></tr>"

    for v in vulnerabilities:
        table += f"<tr><td>{v['ip']}</td><td>{v['port']}</td><td>{v['vulnerability_id']}</td><td>{v['vulnerability_description']}</td><td>{v['severity']}</td></tr>"

    table += "</table>"
    return render_template("Vulnerabilities.", table)

@app.get("/remote-form", response_class=HTMLResponse)
def remote_form():
    return render_template("Softwares installed.", """
      <h2>Get Installed Softwares</h2>
      <form method='post' action='/remote-scan'>
        <label>IP Address:</label><br><input name='ip' required /><br><br>
        <label>Username:</label><br><input name='username' required /><br><br>
        <label>Password:</label><br><input type='password' name='password' required /><br><br>
        <label><input type='checkbox' name='clamav' value='yes'> Also perform ClamAV malware scan</label><br><br>
        <input class='button' type='submit' value='Fetch Software Info'><br>
      </form>
    """)

@app.post("/remote-scan", response_class=HTMLResponse)
def remote_scan(
    request: Request,
    ip: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    clamav: str = Form(None)
):
    os_type, sys_info, apps = detect_and_store_system(ip, username, password)

    # Get system_id from DB to log ClamAV results
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT id FROM systems WHERE ip = %s", (ip,))
    row = cur.fetchone()
    conn.close()
    system_id = row[0] if row else None

    # If checkbox was checked, run ClamAV on install paths
    if clamav == "yes" and system_id:
        scan_all_app_paths(system_id, apps, os_type, ip, username, password)

    # Render installed software list
    app_table = "<table><tr><th>Name</th><th>Version</th><th>Publisher</th></tr>"
    for app in apps:
        app_table += f"<tr><td>{app.get('DisplayName')}</td><td>{app.get('DisplayVersion')}</td><td>{app.get('Publisher')}</td></tr>"
    app_table += "</table>"

    return render_template("Software Info", f"<h2>System: {ip}</h2><pre>{sys_info}</pre>{app_table}")


@app.get("/cloud-history", response_class=HTMLResponse)
def cloud_history():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM cloud_scan_history ORDER BY scan_time DESC")
    scans = cur.fetchall()
    conn.close()

    html = "<h2>Cloud Scan History</h2>"
    if not scans:
        html += "<p>No cloud scans have been performed yet.</p>"
    else:
        html += "<table><tr><th>Scan ID</th><th>Provider</th><th>Scan Time</th><th>Action</th></tr>"
        for scan in scans:
            html += f"""
            <tr>
                <td>{scan['id']}</td>
                <td>{scan['provider'].upper()}</td>
                <td>{scan['scan_time']}</td>
                <td><a class="button" href="/cloud-history/{scan['provider']}/{scan['id']}">View Details</a></td>
            </tr>"""
        html += "</table>"

    return render_template("Cloud Scan History", html)

@app.get("/cloud-history/{provider}/{scan_id}", response_class=HTMLResponse)
def cloud_scan_details(provider: str, scan_id: int):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor(dictionary=True)
    title = f"{provider.upper()} Scan #{scan_id} Details"
    html = f"<h2>{title}</h2>"

    tables = {
        "aws": {
            "EC2 Instances": "aws_ec2",
            "S3 Buckets": "aws_s3",
            "ECS Clusters": "aws_ecs"
        },
        "azure": {
            "Virtual Machines": "azure_vms",
            "Storage Accounts": "azure_storage_accounts",
            "AKS Clusters": "azure_aks_clusters"
        },
        "gcp": {
            "Virtual Machines": "gcp_vms",
            "Storage Buckets": "gcp_buckets",
            "GKE Clusters": "gcp_gke_clusters"
        }
    }

    if provider not in tables:
        return render_template("Invalid Provider", "<p>Unsupported cloud provider.</p>")

    for section, table in tables[provider].items():
        cur.execute(f"SELECT * FROM {table} WHERE scan_id = %s", (scan_id,))
        rows = cur.fetchall()
        html += f"<h3>{section}</h3>"
        if not rows:
            html += "<p>No data available.</p>"
            continue
        html += "<table><tr>"
        for key in rows[0].keys():
            html += f"<th>{key}</th>"
        html += "</tr>"
        for row in rows:
            html += "<tr>" + "".join(f"<td>{str(val)}</td>" for val in row.values()) + "</tr>"
        html += "</table><br>"

    conn.close()
    return render_template(title, html)

@app.get("/scan", response_class=HTMLResponse)
async def scan(vuln: str = None):
    query = "?vuln=yes" if vuln == "yes" else ""
    return render_template("Scanning", f"<h2>Scanning started...</h2><meta http-equiv='refresh' content='1;URL=/scan/start{query}'>")

@app.api_route("/scan/start", methods=["GET", "POST"])
async def start_scan(vuln: str = None):
    vuln_scan = vuln == "yes"
    interface_info = get_active_interface_info()
    if not interface_info:
        return render_template("No Network", "<p>No active network interface found.</p>")
    network_range = get_network_range_from_ip(interface_info.get("IP Address"))
    if not network_range:
        return render_template("Error", "<p>Unable to determine network range.</p>")

    nmap_results = nmap_scan(network_range)
    devices_to_store = []

    for ip in ipaddress.IPv4Network(network_range).hosts():
        ip_str = str(ip)
        if ip_str in nmap_results:
            snmp_data = await get_snmp_info(ip_str)
            desc = snmp_data.get("Description") if snmp_data else None
            os_detect = nmap_results[ip_str]["os"]
            mac_address = nmap_results[ip_str]["mac"]
            vendor = nmap_results[ip_str]["vendor"]
            manufacturer = get_mac_vendor(mac_address)
            device_type = identify_device_type(desc, os_detect, nmap_results[ip_str]['ports'], vendor)

            devices_to_store.append({
                'ip': ip_str,
                'hostname': nmap_results[ip_str]['hostname'],
                'os': os_detect,
                'ports': ', '.join(nmap_results[ip_str]['ports']),
                'mac': mac_address,
                'vendor': vendor,
                'manufacturer': manufacturer,
                'snmp_name': snmp_data.get('Name') if snmp_data else None,
                'snmp_desc': desc,
                'device_type': device_type
            })

    print("Scanning for UPnP/SSDP devices...")
    upnp_devices = discover_upnp_devices()
    print(f"SSDP found {len(upnp_devices)} device(s)")

    for ip, url in upnp_devices:
        details = parse_device_description(url)
        if details:
            ip = details['location'].split('/')[2].split(':')[0]
            matching = next((d for d in devices_to_store if d['ip'] == ip), None)
            if matching:
                matching['manufacturer'] = details['manufacturer']
                matching['hostname'] = details['friendly_name']
            else:
                devices_to_store.append({
                    'ip': ip,
                    'hostname': details['friendly_name'],
                    'os': 'Unknown',
                    'ports': '',
                    'mac': '',
                    'vendor': '',
                    'manufacturer': details['manufacturer'],
                    'snmp_name': details['friendly_name'],
                    'snmp_desc': details['model_name'],
                    'device_type': details['device_type']
                })

    save_scan_to_db(interface_info, network_range, devices_to_store)
    ips = [d['ip'] for d in devices_to_store]
    if vuln_scan:
        batch_scan_ips(ips)

    return RedirectResponse(url="/", status_code=303)

from aws_scan import get_aws_resources
from azure_scan import get_azure_resources
from gcp_scan import get_gcp_resources

@app.get("/cloud-assets", response_class=HTMLResponse)
def cloud_assets_form():
    return render_template("Cloud Assets", """<style>
input[type="text"],
input[type="password"],
select {
  width: 100%;
  padding: 6px 10px;
  margin-bottom: 12px;
  font-size: 14px;
  box-sizing: border-box;
  border: 1px solid #aaa;
  border-radius: 4px;
  height: 34px;
}
</style>

<h2>Cloud Assets Discovery</h2>
<form method="post" action="/cloud-assets" style="max-width: 400px;">
  <label><strong>Select Cloud Provider:</strong></label><br>
  <select name="provider" required>
    <option value="aws">AWS</option>
    <option value="azure">Azure</option>
    <option value="gcp">GCP</option>
  </select>

  <div id="aws-fields">
    <label>AWS Access Key:</label><br>
    <input type="text" name="aws_access_key" /><br>
    <label>AWS Secret Key:</label><br>
    <input type="text" name="aws_secret_key" /><br>
    <label>Region:</label><br>
    <input type="text" name="aws_region" value="us-east-1" /><br>
  </div>

  <div id="azure-fields" style="display:none;">
    <label>Tenant ID:</label><br>
    <input type="text" name="azure_tenant_id" /><br>
    <label>Client ID:</label><br>
    <input type="text" name="azure_client_id" /><br>
    <label>Client Secret:</label><br>
    <input type="text" name="azure_client_secret" /><br>
    <label>Subscription ID:</label><br>
    <input type="text" name="azure_subscription_id" /><br>
  </div>

  <div id="gcp-fields" style="display:none;">
    <label>GCP Project ID:</label><br>
    <input type="text" name="gcp_project_id" /><br>
    <label>Credentials JSON Path:</label><br>
    <input type="text" name="gcp_credentials_path" /><br>
  </div>

  <input class="button" type="submit" value="Discover" style="padding:8px 16px;">
</form>

<script>
const providerSelect = document.querySelector('select[name="provider"]');
const awsFields = document.getElementById("aws-fields");
const azureFields = document.getElementById("azure-fields");
const gcpFields = document.getElementById("gcp-fields");

function updateVisibility() {
  const val = providerSelect.value;
  awsFields.style.display = val === "aws" ? "block" : "none";
  azureFields.style.display = val === "azure" ? "block" : "none";
  gcpFields.style.display = val === "gcp" ? "block" : "none";
}

providerSelect.addEventListener("change", updateVisibility);
window.addEventListener("DOMContentLoaded", updateVisibility);
</script>

""")

@app.post("/cloud-assets", response_class=HTMLResponse)
async def cloud_assets(
    request: Request,
    provider: str = Form(...),
    aws_access_key: str = Form(None),
    aws_secret_key: str = Form(None),
    aws_region: str = Form(None),
    azure_tenant_id: str = Form(None),
    azure_client_id: str = Form(None),
    azure_client_secret: str = Form(None),
    azure_subscription_id: str = Form(None),
    gcp_project_id: str = Form(None),
    gcp_credentials_path: str = Form(None)
):
    try:
        if provider == "aws":
            result = get_aws_resources(aws_access_key, aws_secret_key, aws_region)
        elif provider == "azure":
            result = get_azure_resources(azure_tenant_id, azure_client_id, azure_client_secret, azure_subscription_id)
        elif provider == "gcp":
            result = get_gcp_resources(gcp_project_id, gcp_credentials_path)
        else:
            return render_template("Cloud Assets", "<p>Invalid provider selected.</p>")

        if result.get("error"):
            return render_template("Cloud Assets", f"<p>Error: {result['error']}</p>")

        # Render result
        html = "<h2>Discovered Assets</h2>"
        for key, items in result.items():
            if key == "error":
                continue
            html += f"<h3>{key.replace('_', ' ').title()}</h3>"
            if not items:
                html += "<p>No assets found.</p>"
                continue
            html += "<table><tr>" + "".join(f"<th>{k}</th>" for k in items[0].keys()) + "</tr>"
            for item in items:
                html += "<tr>" + "".join(f"<td>{v}</td>" for v in item.values()) + "</tr>"
            html += "</table><br>"

        return render_template("Cloud Assets", html)

    except Exception as e:
        return render_template("Cloud Assets", f"<p>Error: {str(e)}</p>")

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    webbrowser.open("http://127.0.0.1:8000")
    uvicorn.run("web_app:app", host="127.0.0.1", port=8000)
