import json
import re
import requests
from pathlib import Path

# =========================
# CONFIG
# =========================

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma3:12b"

MODEL_CONTEXT_WINDOW = 131072
RESERVED_OUTPUT_TOKENS = 1200
SAFETY_MARGIN = 500

PROMPT_FILE = Path("text/prompt")
ROLE_FILE = Path("text/role")
JSON_DIR = Path("json")

# =========================
# TOKEN COUNT VIA OLLAMA
# =========================

def count_tokens(text: str) -> int:
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": text,
                "stream": False,
                "options": {"num_predict": 0}
            },
            timeout=120
        )
        r.raise_for_status()
        return r.json()["prompt_eval_count"]
    except Exception as e:
        print("❌ Ollama token count failed:", e)
        exit(1)

# =========================
# LOAD PROMPTS
# =========================

if not PROMPT_FILE.exists() or not ROLE_FILE.exists():
    print("❌ Missing text/prompt or text/role")
    exit(1)

system_prompt = ROLE_FILE.read_text(encoding="utf-8")
prompt_template = PROMPT_FILE.read_text(encoding="utf-8")

static_prompt = prompt_template.replace("{full_json_str}", "")

print("Counting static tokens...\n")

system_tokens = count_tokens(system_prompt)
static_tokens = count_tokens(static_prompt)

max_input_tokens = (
    MODEL_CONTEXT_WINDOW
    - RESERVED_OUTPUT_TOKENS
    - SAFETY_MARGIN
)

available_for_json = max_input_tokens - system_tokens - static_tokens

# =========================
# GROUP FILES BY CVE ID
# =========================

print("Scanning CVE pairs...\n")

pattern = re.compile(r"CVE-\d{4}-\d+", re.I)
pairs = {}

if not JSON_DIR.exists():
    print("❌ json directory not found")
    exit()

for file in JSON_DIR.iterdir():
    if not file.is_file():
        continue

    match = pattern.search(file.name)
    if not match:
        continue

    cve_id = match.group(0).upper()
    pairs.setdefault(cve_id, {})

    suffix = file.suffix.lower()

    if suffix == ".nvd":
        pairs[cve_id]["nvd"] = file
    elif suffix == ".mitre":
        pairs[cve_id]["mitre"] = file

valid_pairs = {}

for cve_id, files in pairs.items():
    if "nvd" in files and "mitre" in files:
        valid_pairs[cve_id] = files
    else:
        print(f"⚠ incomplete pair: {cve_id}")

if not valid_pairs:
    print("\n❌ No valid CVE pairs found.")
    print(f"Pairs detected: {len(pairs)}")
    exit()

print(f"Pairs found: {len(valid_pairs)}\n")

# =========================
# FIND LARGEST CVE PAIR
# =========================

largest_pair_json = None
largest_size = 0
largest_id = None

for cve_id, files in valid_pairs.items():
    try:
        nvd_data = json.loads(files["nvd"].read_text(encoding="utf-8"))
        mitre_data = json.loads(files["mitre"].read_text(encoding="utf-8"))
    except Exception as e:
        print(f"⚠ skipping {cve_id} (invalid JSON)")
        continue

    merged = {
        "nvd": nvd_data,
        "mitre": mitre_data
    }

    merged_str = json.dumps(merged, separators=(",", ":"))
    size = len(merged_str)

    if size > largest_size:
        largest_size = size
        largest_pair_json = merged_str
        largest_id = cve_id

if not largest_pair_json:
    print("❌ Could not build any merged CVE JSON.")
    exit()

print(f"Largest CVE pair: {largest_id}")
print(f"Combined JSON size: {largest_size:,} characters\n")

# =========================
# TOKENIZE WORST CASE ONCE
# =========================

full_prompt = prompt_template.replace("{full_json_str}", largest_pair_json)

total_prompt_tokens = count_tokens(system_prompt + full_prompt)

headroom = max_input_tokens - total_prompt_tokens

max_cves_per_request = max_input_tokens // total_prompt_tokens

# =========================
# RESULTS
# =========================

print("============================")
print(" WORST-CASE TOKEN ANALYSIS")
print("============================")
print(f"Model: {MODEL}")
print(f"Context window: {MODEL_CONTEXT_WINDOW}")
print(f"Max usable input: {max_input_tokens}")
print()
print(f"System tokens: {system_tokens}")
print(f"Static prompt tokens: {static_tokens}")
print(f"Worst CVE tokens: {total_prompt_tokens}")
print(f"Remaining headroom: {headroom}")
print()
print(f"Max worst-case CVEs per request: {max_cves_per_request}")
print("============================\n")