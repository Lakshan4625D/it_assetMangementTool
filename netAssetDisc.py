import asyncio
import platform
import socket
import subprocess
import re
import ipaddress
import psutil
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity, get_cmd
)
import nmap
import requests

def get_active_interface_info():
    system = platform.system()
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addrs in interfaces.items():
        if iface == 'lo' or not stats[iface].isup:
            continue

        ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), None)
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)

        if ipv4 and mac:
            info = {
                'Active Interface': iface,
                'IP Address': ipv4,
                'MAC Address': mac,
                'Interface Status': 'UP',
                'Connection Type': 'Wired/Wi-Fi'
            }

            wifi_details = get_wifi_details_by_os(system, iface)
            if wifi_details:
                info['Connection Type'] = 'Wi-Fi'
                info['Wi-Fi Details'] = wifi_details

            return info

    return None

def get_wifi_details_by_os(system, iface):
    try:
        if system == 'Windows':
            output = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, encoding='utf-8')
            if iface not in output:
                return None
            return {
                'SSID': re.search(r'SSID *: (.+)', output).group(1),
                'Signal': re.search(r'Signal *: (\d+)%', output).group(1) + '%',
                'Radio Type': re.search(r'Radio type *: (.+)', output).group(1),
                'Channel': re.search(r'Channel *: (\d+)', output).group(1),
                'Authentication': re.search(r'Authentication *: (.+)', output).group(1)
            }
        elif system == 'Linux':
            output = subprocess.check_output(["nmcli", "-t", "-f", "active,ssid,signal,chan,security", "dev", "wifi"], text=True)
            for line in output.splitlines():
                if line.startswith("yes"):
                    _, ssid, signal, channel, auth = line.split(":")
                    return {
                        'SSID': ssid,
                        'Signal': signal + '%',
                        'Radio Type': 'Unknown',
                        'Channel': channel,
                        'Authentication': auth
                    }
        elif system == 'Darwin':
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            output = subprocess.check_output([airport_path, "-I"], text=True)
            return {
                'SSID': re.search(r'\s*SSID: (.+)', output).group(1),
                'Signal': str(int(re.search(r'agrCtlRSSI: (-?\d+)', output).group(1)) + 100) + '%',
                'Radio Type': re.search(r'PHY Mode: (.+)', output).group(1),
                'Channel': re.search(r'channel: (\d+)', output).group(1),
                'Authentication': 'Unknown'
            }
    except Exception:
        return None

def get_network_range_from_ip(ip_address):
    try:
        ip_obj = ipaddress.IPv4Address(ip_address)
        network = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)
        return str(network)
    except Exception:
        return None

async def get_snmp_info(ip, community='public'):
    oid_sysdescr = '1.3.6.1.2.1.1.1.0'
    oid_sysname = '1.3.6.1.2.1.1.5.0'
    info = {}

    snmpEngine = SnmpEngine()
    for oid, label in [(oid_sysdescr, "Description"), (oid_sysname, "Name")]:
        iterator = get_cmd(
            snmpEngine,
            CommunityData(community, mpModel=0),
            await UdpTransportTarget.create((str(ip), 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        errorIndication, errorStatus, errorIndex, varBinds = await iterator
        if errorIndication or errorStatus:
            info[label] = None
        else:
            for varBind in varBinds:
                info[label] = str(varBind[1])
    snmpEngine.close_dispatcher()
    return info if info.get("Description") else None

def nmap_scan(network_range):
    nm = nmap.PortScanner()
    print(f"Scanning network {network_range} with Nmap...\n")
    try:
        nm.scan(hosts=network_range, arguments='-O -T4')
    except Exception as e:
        print("Nmap scan failed:", e)
        return {}

    results = {}
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            data = {
                "hostname": nm[host].hostname() or "Unknown",
                "os": nm[host]['osmatch'][0]['name'] if nm[host].get('osmatch') else "Unknown",
                "os_accuracy": nm[host]['osmatch'][0]['accuracy'] if nm[host].get('osmatch') else None,
                "ports": [],
                "mac": nm[host]['addresses'].get('mac', 'Unknown'),
                "vendor": nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown')
            }
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    pinfo = nm[host]['tcp'][port]
                    data["ports"].append(f"{port}/{pinfo['state']} ({pinfo['name']})")
            results[host] = data
    return results

def identify_device_type(snmp_desc, nmap_os, ports, vendor):
    joined_info = f"{snmp_desc or ''} {nmap_os or ''} {vendor or ''}".lower()
    ports = [p.split('/')[0] for p in ports]  # extract port numbers only

    def match_any(keywords):
        return any(k in joined_info for k in keywords)

    def vendor_match(vendors):
        return vendor and any(v in vendor.lower() for v in vendors)

    # Router / Gateway
    if (match_any(['router', 'gateway', 'edge', 'firewall', 'broadband', 'cpe']) or 
        any(p in ports for p in ['53', '1900', '500', '4500', '1701', '80', '443', '8080', '8443'])) and \
       vendor_match(['arcadyan', 'cisco', 'd-link', 'tp-link', 'netgear', 'asus', 'zte', 'huawei']):
        return "Router"

    # Switch
    if match_any(['switch', 'catalyst', 'layer 2', 'layer 3', 'dell', 'juniper']) or \
       vendor_match(['cisco', 'juniper', 'dell', 'hp', 'netgear']):
        return "Switch"

    # Printer
    if match_any(['printer', 'hp', 'canon', 'epson', 'xerox']) or any(p in ports for p in ['515', '631', '9100', '9101']):
        return "Printer"
    
    # PC / Workstation
    if match_any(['windows', 'linux', 'ubuntu', 'mac', 'microsoft', 'desktop']) or \
       any(p in ports for p in ['22', '135', '139', '445', '3389']):
        return "PC"

    # IP Camera
    if match_any(['camera', 'hikvision', 'dahua', 'ip camera', 'axis']) or any(p in ports for p in ['554', '8080', '37777', '5000', '5001']):
        return "IP Camera"

    # Access Point
    if match_any(['access point', 'ap', 'aruba', 'unifi', 'wireless controller']) or \
       any(p in ports for p in ['80', '443', '161', '22']):
        return "Access Point"

    # VoIP Phone
    if match_any(['voip', 'sip', 'phone', 'polycom']) or any(p in ports for p in ['5060', '5061', '5062']):
        return "VoIP Phone"

    # NAS (Network Storage)
    if match_any(['nas', 'storage', 'synology', 'diskstation', 'qnap']) or any(p in ports for p in ['2049', '5000', '5001', '445', '139']):
        return "NAS (Network Storage)"

    # Firewall
    if match_any(['firewall', 'palo alto', 'fortigate', 'checkpoint', 'juniper']):
        return "Firewall"

    # Smart TV
    if match_any(['smart tv', 'samsung', 'lg', 'roku', 'android tv']) or any(p in ports for p in ['8008', '8009', '8443', '1935', '6970']):
        return "Smart TV"

    # IoT Device
    if match_any(['iot', 'smart plug', 'esp8266', 'tuya', 'espressif', 'zigbee']):
        return "IoT Device"

    # Game Console
    if match_any(['xbox', 'playstation', 'nintendo', 'game console']) or any(p in ports for p in ['3074', '3478', '3479', '3480']):
        return "Game Console"

    # Media Server
    if match_any(['plex', 'emby', 'jellyfin', 'media server']) or any(p in ports for p in ['32400', '8096', '9000']):
        return "Media Server"

    # Virtual Machine / Hypervisor
    if match_any(['vmware', 'virtualbox', 'qemu', 'kvm', 'virtual machine', 'hyper-v']) or \
       (vendor and 'vm' in vendor.lower()):
        return "Virtual Machine"

    return "Unknown"

def is_randomized_mac(mac):
    try:
        # Ensure it's colon-separated and has exactly 6 parts
        parts = mac.split(':')
        if len(parts) != 6:
            return False
        first_byte = int(parts[0], 16)
        return (first_byte & 0x02) == 0x02  # Check the locally administered bit
    except (ValueError, AttributeError):
        return False  # Invalid MAC format like 'unknown' or malformed strings

def get_mac_vendor(mac_address):
    # Handle missing or invalid MACs
    if not mac_address or mac_address.lower() == "unknown":
        return "MAC Address Unknown"

    if is_randomized_mac(mac_address):
        return "Locally Administered / Randomized MAC (Cannot determine vendor)"
    
    # Format the MAC properly for the API (removes colons, hyphens, dots)
    mac_clean = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')
    url = f"https://api.macvendors.com/{mac_clean}"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MACVendorLookup/1.0)"
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 429:
            return "Rate limit exceeded. Try again later."
        else:
            return f"API Error: {response.status_code}"
    except requests.RequestException as e:
        return f"Request failed: {e}"
    
async def scan_network_combined():
    interface_info = get_active_interface_info()
    if interface_info:
        print("Active Interface :", interface_info.get('Active Interface', 'Unknown'))
        print("IP Address       :", interface_info.get('IP Address', 'Unknown'))
        print("Connection Type  :", interface_info.get('Connection Type', 'Unknown'))
        print("MAC Address      :", interface_info.get('MAC Address', 'Unknown'))
        print("Interface Status :", interface_info.get('Interface Status', 'Unknown'))
        wifi_details = interface_info.get('Wi-Fi Details', {})
        if wifi_details:
            print("Wi-Fi Details:")
            for k, v in wifi_details.items():
                print(f"  {k}: {v}")
        print("\n")
        network_range = get_network_range_from_ip(interface_info.get('IP Address'))
        if not network_range:
            print("Could not determine network range from IP address.")
            return
    else:
        print("No active network interface detected.")
        return

    nmap_results = nmap_scan(network_range)
    print("Now collecting SNMP info...\n")
    found_devices = 0
    for ip in ipaddress.IPv4Network(network_range).hosts():
        ip_str = str(ip)
        if ip_str in nmap_results:
            snmp_data = await get_snmp_info(ip_str)
            desc = snmp_data.get('Description') if snmp_data else None
            os_detect = nmap_results[ip_str]['os']
            mac_address = nmap_results[ip_str]['mac']
            vendor = nmap_results[ip_str]['vendor']

            print("=" * 50)
            print(f"IP Address     : {ip_str}")
            print(f"State          : up")
            print(f"Hostname       : {nmap_results[ip_str]['hostname']}")
            print(f"Detected OS    : {os_detect}")
            print(f"Open Ports     : {', '.join(nmap_results[ip_str]['ports']) or 'None'}")
            print(f"MAC Address    : {mac_address}")
            print(f"Vendor(s)      : {vendor}")
            print(f"Manufacturer   : {get_mac_vendor(mac_address)}")
            if snmp_data:
                print(f"SNMP Name      : {snmp_data.get('Name')}")
                print(f"SNMP Desc      : {desc}")
            else:
                print("SNMP Info      : Not available or device does not support SNMP.")
            device_type = identify_device_type(desc, os_detect, nmap_results[ip_str]['ports'], vendor)
            print(f"Device Type     : {device_type}")
            if device_type in ["Router", "Switch"]:
                print(f"Router/Switch detected at {ip_str}")
                found_devices += 1
            print("=" * 50 + "\n")

    if found_devices == 0:
        print("No routers or switches found in the network range.")
    else:
        print("No.of Routers or Switches =", found_devices)


if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(scan_network_combined())
