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

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    webbrowser.open("http://127.0.0.1:8000")
    uvicorn.run("web_app:app", host="127.0.0.1", port=8000)
