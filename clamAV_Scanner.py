import subprocess
import mysql.connector
import paramiko
import winrm
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from sysAssetDisc_mysql import DB_CONFIG

MAX_THREADS = 4
SCAN_TIMEOUT = 300  # seconds

def run_clamav_remote(path, os_type, ip, username, password):
    try:
        if os_type.lower() == "windows":
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password), transport='ntlm')
            cmd = f'clamscan --infected --no-summary -r "{path}"'
            result = session.run_cmd(cmd)
            return result.std_out.decode()
        else:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=10)
            cmd = fr'"C:\ClamAV\clamscan.exe" --infected --no-summary -r "{path}"'
            stdin, stdout, stderr = client.exec_command(cmd)
            errors = stderr.read().decode()
            output = stdout.read().decode()
            print("📤 STDOUT:\n", output)
            print("❌ STDERR:\n", errors)
            client.close()
            return output
    except Exception as e:
        return f"[ERROR] {path}: {e}"

def parse_clamav_output(output):
    detections = []
    for line in output.strip().splitlines():
        if line.strip().endswith("FOUND"):
            try:
                path, sig = line.rsplit(":", 1)
                detections.append((path.strip(), sig.replace("FOUND", "").strip()))
            except ValueError:
                continue
    return detections

def save_clamav_results(system_id, app_name, path, detections):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for file_path, signature in detections:
        cur.execute("""
            INSERT INTO malware_detections (system_id, application_name, file_path, signature, scan_time)
            VALUES (%s, %s, %s, %s, %s)
        """, (system_id, app_name, file_path, signature, now))

    conn.commit()
    conn.close()

def scan_all_app_paths(system_id, apps, os_type, ip, username, password):
    def scan_and_store(app):
        name = app.get("DisplayName", "")
        path = app.get("InstallLocation") or app.get("DisplayIcon")
        if path and len(path) > 3:
            print(f"🔍 Scanning: {name} at {path}")
            output = run_clamav_remote(path, os_type, ip, username, password)
            detections = parse_clamav_output(output)
            print(f"[RAW OUTPUT]\n{output}")
            if detections:
                print(f"⚠️ Infected files found in {name}")
                save_clamav_results(system_id, name, path, detections)
            else:
                print(f"✅ Clean: {name}")
        return

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_and_store, app) for app in apps]
        for f in as_completed(futures):
            _ = f.result()
