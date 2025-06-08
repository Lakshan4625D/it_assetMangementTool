import getpass
import winrm
import paramiko
import json


def try_winrm(ip, username, password):
    try:
        session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password), transport='ntlm')
        result = session.run_cmd('ver')
        if result.status_code == 0:
            return True
    except:
        return False
    return False


def run_winrm_command(ip, username, password):
    session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password), transport='ntlm')
    result = session.run_cmd('systeminfo')
    print("\n[Windows] System Info:\n", result.std_out.decode())
    if result.std_err:
        print("STDERR:\n", result.std_err.decode())


def get_installed_software_win(ip, username, password):
    session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password), transport='ntlm')
    ps_script = r'''
    $paths = @(
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
      "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $software = foreach ($path in $paths) {
      Get-ItemProperty $path | Select-Object DisplayName, DisplayVersion, Publisher
    }
    $software | Where-Object { $_.DisplayName -ne $null } | ConvertTo-Json
    '''
    result = session.run_ps(ps_script)
    try:
        decoded = result.std_out.decode()
        data = json.loads(decoded)
        print(json.dumps(data, indent=2))
    except:
        print("Failed to parse software list.\nRaw output:\n", decoded)


def run_ssh_command(ip, username, password, cmd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()
        client.close()
        return out.strip(), err.strip()
    except Exception as e:
        return None, str(e)


def detect_remote_os_ssh(ip, username, password):
    out, err = run_ssh_command(ip, username, password, "uname -s")
    if out:
        if "Linux" in out:
            return "Linux"
        elif "Darwin" in out:
            return "macOS"
        else:
            return "Unknown"
    return None


def get_linux_info(ip, username, password):
    cmds = [
        "uname -a",
        "cat /etc/os-release",
        "lsb_release -a"
    ]
    for cmd in cmds:
        out, err = run_ssh_command(ip, username, password, cmd)
        if out:
            print(f"\n[Linux/macOS] Output from `{cmd}`:\n{out}")
            break


def get_installed_software_unix(ip, username, password):
    pkg_cmds = [
        ("dpkg -l", "Debian/Ubuntu"),
        ("rpm -qa", "RedHat/CentOS"),
        ("brew list --versions", "macOS/Homebrew")
    ]
    for cmd, label in pkg_cmds:
        out, err = run_ssh_command(ip, username, password, cmd)
        if out:
            print(f"\n[{label}] Installed Packages:\n{out}")
            break


def detect_remote_os_and_fetch(ip, username, password):
    print("\n🔍 Attempting to detect remote OS...")

    if try_winrm(ip, username, password):
        print(f"\n✅ Detected Windows OS at {ip}")
        run_winrm_command(ip, username, password)
        if input("Fetch installed software? (y/n): ").lower() == 'y':
            get_installed_software_win(ip, username, password)
    else:
        os_type = detect_remote_os_ssh(ip, username, password)
        if os_type:
            print(f"\n✅ Detected {os_type} OS at {ip}")
            get_linux_info(ip, username, password)
            if input("Fetch installed software? (y/n): ").lower() == 'y':
                get_installed_software_unix(ip, username, password)
        else:
            print("❌ Could not detect remote OS or connect via SSH.")


if __name__ == "__main__":
    while True:
        ask = input("\nDo you want to connect to a remote system? (y/n): ").lower()
        if ask != 'y':
            break

        ip = input("Enter target IP: ").strip()
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        detect_remote_os_and_fetch(ip, username, password)
