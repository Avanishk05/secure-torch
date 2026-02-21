# Signature Verification

secure-torch supports two verification modes. Choose based on your environment.

## Mode 1 — Online (Sigstore / Rekor)

Uses the [Sigstore](https://sigstore.dev) transparency log. Requires internet access to Rekor.

**Sign your model:**

```bash
# Install cosign
pip install sigstore

# Sign
python -m sigstore sign model.pt
# Produces: model.pt.sigstore
```

**Verify on load:**

```python
import secure_torch as torch

model = torch.load(
    "model.pt",
    require_signature=True,
    bundle_path="model.pt.sigstore",
)
```

## Mode 2 — Offline (Ed25519 / RSA pubkey)

No Rekor access required. Suitable for air-gapped environments and enterprises that block external transparency logs.

**Generate a keypair:**

```bash
# Ed25519 (recommended)
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

**Sign your model:**

```bash
openssl pkeyutl -sign -inkey private.pem -in model.pt -out model.pt.sig
```

**Verify on load:**

```python
import secure_torch as torch

model = torch.load(
    "model.pt",
    require_signature=True,
    pubkey_path="public.pem",
    bundle_path="model.pt.sig",
)
```

## Auto-detection

secure-torch auto-detects sidecar files. If `model.pt.sigstore` or `model.pt.sig` exists next to `model.pt`, it will be used automatically — no need to specify `bundle_path`.

## Fail-closed semantics

```python
# This RAISES SignatureRequiredError if no bundle found
model = torch.load("model.pt", require_signature=True)

# This LOADS and returns a report even without a signature
model, report = torch.load("model.pt", audit_only=True)
print(report.provenance.verified)  # False
```

## ProvenanceRecord

```python
model, report = torch.load("model.pt", audit_only=True)
prov = report.provenance

prov.verified      # bool
prov.signer        # "pubkey:public.pem" or Sigstore identity
prov.mode          # "pubkey" or "sigstore"
prov.bundle_path   # path to bundle/sig file
prov.error         # error message if verification failed
```
