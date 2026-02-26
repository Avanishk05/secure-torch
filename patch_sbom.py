import os

file_path = "docs/hardcoded_constants.md"

with open(file_path, "r", encoding="utf-8") as f:
    text = f.read()

old_str = "| `SCORE_SBOM_MISSING` | 20 | No accompanying SBOM found |"
new_str = "| `SCORE_SBOM_MISSING` | 20 | Provided SBOM path failed to parse or was missing |"
text = text.replace(old_str, new_str)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(text)

print("success")
