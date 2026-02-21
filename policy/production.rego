package secure_torch.policy

# ── Production policy example ─────────────────────────────────────────────
# Deny models with sensitive personal information
deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information — blocked by policy"
}

# Deny GPL-licensed training datasets in production
deny[msg] {
    ds := input.aiProfile.trainingDatasets[_]
    startswith(ds.license, "GPL")
    input.environment == "production"
    msg := sprintf("GPL dataset '%v' blocked in production (license: %v)", [ds.name, ds.license])
}

# Require suppliedBy field in production
deny[msg] {
    input.environment == "production"
    not input.suppliedBy
    msg := "Model SBOM missing required suppliedBy field for production deployment"
}

# Block models from untrusted domains
deny[msg] {
    input.environment == "production"
    not startswith(input.suppliedBy, "Organization: huggingface.co")
    not startswith(input.suppliedBy, "Organization: openai.com")
    not startswith(input.suppliedBy, "Organization: meta.com")
    msg := sprintf("Model supplier '%v' is not in the trusted publisher list", [input.suppliedBy])
}
