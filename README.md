# Local LLM CVE Classifier (Healthcare & MITRE)

This tool uses a locally running Large Language Model (via **Ollama**) to analyze CVE (Common Vulnerabilities and Exposures) JSON data. It automatically classifies vulnerabilities based on **Healthcare Relevance** and maps them to the **MITRE ATT&CK** framework.

## Key Features

* **100% Local & Private:** No data leaves your machine. Uses Ollama API.
* **Specialized Classification:**
* **Healthcare Relevance:** Distinguishes between generic IT software and core medical systems (EHR, PACS, Medical Devices).
* **MITRE ATT&CK:** Maps vulnerabilities to tactics like *Initial Access*, *Privilege Escalation*, or *Impact* using a priority kill-chain logic.
* **Flexible Input:** Process entire directories of JSONs or single specific files.
* **Robust Error Handling:** Automatic retries for API failures and malformed JSON responses.
* **Customizable Settings:** Fully customizable classification settings.

---

## Prerequisites

### 1. Hardware

* **GPU:** Recommended NVIDIA RTX 5070 (12GB) or higher.
* **RAM:** 32GB system RAM recommended.
* **Disk:** Enough space for the LLM weights (~8-10GB for 12B models).

### 2. Software

* **Python 3.8+**
* **[Ollama](https://ollama.com/)** installed and running.

### 3. Python Dependencies

You can install dependencies manually or via a requirements file.

**Option A: Using requirements.txt (Recommended)**
Create a file named `requirements.txt` with the following content:

```text
requests>=2.31.0
tqdm>=4.66.0

```

Then run:

```bash
pip install -r requirements.txt

```

**Option B: Manual Install**

```bash
pip install requests tqdm

```

---

## Setup & Configuration

### 1. Configure Ollama Environment (Critical)

For optimal performance with large contexts (20k tokens), you **must** set these environment variables before starting the Ollama server. These settings enable Flash Attention, optimize memory usage (KV Cache quantization), and ensure the context window is large enough.

**PowerShell (Windows):**

```powershell
$env:OLLAMA_CONTEXT_LENGTH=20480
$env:OLLAMA_FLASH_ATTENTION="1"
$env:OLLAMA_NUM_PARALLEL="2"
$env:OLLAMA_KV_CACHE_TYPE="q4_0"

```

**Bash (Linux/Mac):**

```bash
export OLLAMA_CONTEXT_LENGTH=20480
export OLLAMA_FLASH_ATTENTION="1"
export OLLAMA_NUM_PARALLEL="2"
export OLLAMA_KV_CACHE_TYPE="q4_0"

```

### 2. Pull the Model

Ensure you have the model installed. We recommend `gemma3:12b` for the best balance of speed and reasoning.

```bash
ollama pull gemma3:12b

```

### 3. Directory Structure

Ensure your project looks like this:

```text
.
├── llm_start.py            # Main entry script
├── llm_classifier.py       # API interaction & logic
├── config.json             # (Optional) Default configuration
├── json/                   # Folder containing input .nvd/.mitre/.json files
├── output/                 # Folder where results will be saved
├── cvss/                   # Folder containing the CVSS extractor
└── text/
    └── prompt              # The text prompt file with classification rules

```

---

## Usage

### 1. Start Ollama

After setting the environment variables (see Setup step 1), start the server:

```bash
ollama serve

```

### 2. Run the Classifier

#### **Option A: Process a whole directory (Default)**

Scans the `--json-dir` (default: `json/`) and processes all found CVEs.

```bash
python llm_start.py

```

#### **Option B: Process a single file**

Analyze a specific CVE. If you point to a `.nvd` file, the script automatically looks for its matching `.mitre` partner in the same folder.

```bash
python llm_start.py --file ./json/CVE-2024-1234.nvd

```

#### **Option C: Custom Performance Settings**

If you have a high-end GPU, you can increase workers. If you have a lower-end GPU, reduce them.

```bash
# For 24GB+ VRAM (RTX 3090/4090)
python llm_start.py --workers 3 --model gemma3:12b

# For 12GB VRAM (RTX 5070)
python llm_start.py --workers 2 --model gemma3:12b

```

---

## CLI Arguments

| Argument | Default | Description |
| --- | --- | --- |
| `--file` | None | Path to a single file to process (Mutually exclusive with `--json-dir`). |
| `--json-dir` | `json` | Directory containing input JSON files. |
| `--out-dir` | `output` | Directory where result JSONs are saved. |
| `--workers` | `2` | Number of parallel threads. **Set to 1** if you experience Out Of Memory (OOM) errors. |
| `--model` | `gemma3:12b` | The Ollama model tag to use. |
| `--attempts` | `3` | Max retries for AI generation or JSON parsing failures. |
| `--timeout` | `120` | HTTP timeout (seconds) for the AI response. |
| `--prompt-file` | `text/prompt` | Path to the text file containing the system prompt. |

---

## How It Works

### 1. Context Window & Pruning

The script sets `num_ctx` to **20,480 tokens** to handle large CVE descriptions.

* **Smart Pruning:** If a CVE JSON is too large, the script automatically strips out the `configurations` list (CPE data) and limits the number of `references` to save space without losing context.
* **Truncation:** If the file is still massive, it safely truncates the text to prevent API crashes.

### 2. Classification Logic

The AI is guided by a strict prompt (`text/prompt`) to determine:

1. **Healthcare Relevance:** Is this a core medical system? (e.g., *Is it an MRI scanner or just a PC running Excel?*)
2. **Category:** Maps to 5 distinct categories (EHR, Dept Systems, Medical Devices, PACS, Interoperability).
3. **MITRE ATT&CK:** Selects the **single most relevant** tactic based on a "Kill Chain Priority" rule (Initial Access > Execution > Impact).

### 3. Output Format

For each CVE, a JSON is generated in `output/`:

```json
{
  "CVE_ID": "CVE-2016-6530",
  "HealthcareRelevant": true,
  "MedicalRelevanceConfidence": 100,
  "RelevanceReasoning": "The product, CDR Dicom, is a specialized clinical tool used in dental imaging and falls under the category of medical devices and clinical systems. It contains keywords like 'dicom' and 'clinical'.",
  "Vendors": [
    "dentsply_sirona"
  ],
  "Products": [
    "cdr_dicom"
  ],
  "Category": 3,
  "CategoryName": "Medical Devices and IoMT",
  "CategoryConfidence": 100,
  "CategoryReasoning": "The product is a medical imaging device (DICOM) and falls under the scope of hardware or embedded software responsible for patient care and data acquisition.",
  "ComponentType": "Software",
  "ComponentConfidence": 80,
  "ComponentReasoning": "While it's a medical device, the vulnerability is in the software component managing the device's functionality.",
  "AttackPhase": "Initial Access",
  "AttackPhaseConfidence": 100,
  "AttackPhaseReasoning": "The vulnerability involves default credentials, allowing an unauthenticated attacker to gain initial access to the system.",
  "AttackPhaseProbabilityMatrix": {
    "1": 100,
    "2": 0,
    "3": 0,
    "4": 0,
    "5": 0,
    "6": 0,
    "7": 0,
    "8": 0,
    "9": 0,
    "10": 0,
    "11": 0,
    "12": 0,
    "13": 0,
    "14": 0
  },
  "CVSS_score": 9.8,
  "CVSS_version": "3.0",
  "execution_time_seconds": 14.34,
  "attempts": 1
}

```

---

## Troubleshooting

**Q: The AI returns "JSON parsing failed".**
A: The script automatically retries 3 times. If it persists, the model might be too small to follow complex JSON instructions reliably. Upgrade to a larger model or a "cleaner" model like `gemma3:12b`.

**Q: Why does my GPU usage spike to 100%?**
A: This is normal during the "pre-fill" phase when the model reads the large JSON input. It usually settles around 80-90% during generation depending on your setup.