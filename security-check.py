import psutil
import time
import threading
import os
import subprocess
import socket
import re
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

LOG_FILE = "D:/your-patch/patch/realtimePort.txt"

# Mascheramento leggero solo se l'utente è "io" o "posta"
def mask_console(text):
    text = text.replace("DOP-D3N832c", "DESKTOP-D4RCA1L")
    text = text.replace("\\stia", "\\pota")
    text = text.replace("\\nic", "\\no")
    text = re.sub(r'\b(mona)\b', 'no', text)  # Maschera solo "io" come parola intera
    return text
    

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write("Port Monitoring Log\n")

known_ports = {}
log_lock = threading.Lock()

def log_event(message, color=Fore.CYAN):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    print(color + mask_console(log_entry.strip()))

def get_signature_status(exe_path):
    try:
        cmd = [
            "powershell", "-Command",
            f"(Get-AuthenticodeSignature '{exe_path}').Status"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip() or "Unknown"
    except Exception as e:
        return f"Error: {e}"

def get_remote_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Hostname not available"

def inspect_process(pid):
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        username = proc.username()
        signature_status = get_signature_status(exe_path)

        suspicious_files = [
            m.path for m in proc.memory_maps()
            if any(x in m.path for x in ("Temp", "AppData"))
        ]

        details = {
            "Path": exe_path,
            "User": username,
            "Digital Signature": signature_status,
            "Suspicious Files": ', '.join(suspicious_files) if suspicious_files else 'None'
        }
        return details

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"Error": f"Unable to inspect process: {e}"}

def monitor_ports():
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                laddr = conn.laddr.port if conn.laddr else None
                pid = conn.pid
                status = conn.status

                if laddr and pid and laddr not in known_ports:
                    try:
                        proc = psutil.Process(pid)
                        pname = proc.name()
                        known_ports[laddr] = pid

                        full_user = proc.username()
                        if "\\" in full_user:
                            host_name, user_name = full_user.split("\\", 1)
                        else:
                            host_name, user_name = "UnknownHost", full_user

                        if conn.raddr:
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            remote_host = get_remote_hostname(remote_ip)
                        else:
                            remote_ip = "Not available"
                            remote_port = "Not available"
                            remote_host = "Not available"

                        log_event(f"Port {laddr}", Fore.BLUE)
                        log_event(f"   Process: '{pname}' (PID: {pid})", Fore.YELLOW)
                        log_event(f"   Status: {status}", Fore.MAGENTA)
                        log_event(f"   Remote IP: {remote_ip}:{remote_port}", Fore.LIGHTRED_EX)
                        log_event(f"   Remote server: {remote_host}", Fore.GREEN)
                        log_event(f"   Authorized by user: {user_name}", Fore.LIGHTCYAN_EX)
                        log_event(f"   On host: {host_name}", Fore.LIGHTBLUE_EX)

                        extra_info = inspect_process(pid)
                        for key, value in extra_info.items():
                            color = Fore.LIGHTYELLOW_EX if key in ["Path", "User", "Digital Signature"] else Fore.LIGHTGREEN_EX
                            print(color + mask_console(f"   {key}: {value}"))

                    except psutil.NoSuchProcess:
                        log_event(f"Port {laddr} opened by unknown process (PID: {pid}) - Status: {status}", Fore.RED)

        except Exception as e:
            log_event(f"Error during monitoring: {str(e)}", Fore.RED)
        time.sleep(2)

def stop_process_by_port(port):
    pid = known_ports.get(port)
    if pid:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            log_event(f"Terminated process '{proc.name()}' (PID: {pid}) on port {port}", Fore.RED)
        except Exception as e:
            log_event(f"Error terminating port {port}: {str(e)}", Fore.RED)
    else:
        log_event(f"No known process on port {port}", Fore.RED)

monitor_thread = threading.Thread(target=monitor_ports, daemon=True)
monitor_thread.start()

while True:
    time.sleep(10)
