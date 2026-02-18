import os
import json
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from tqdm import tqdm

from llm_classifier import CVEClassifier

def load_config(config_path: str) -> dict:
    """Loads a JSON configuration file if it exists."""
    if not os.path.exists(config_path):
        if config_path != "config.json":
            logging.warning(f"Config file not found: {config_path}")
        return {}
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to parse config file: {e}")
        return {}

def group_cve_files(json_dir: str) -> dict:
    groups = defaultdict(dict)

    if not os.path.exists(json_dir):
        logging.error(f"Input directory '{json_dir}' does not exist.")
        return groups

    for f in os.listdir(json_dir):
        if not (f.endswith(".json") or f.endswith(".nvd") or f.endswith(".mitre")):
            continue

        base, ext = os.path.splitext(f)
        ext = ext.lower()

        if ext in [".nvd", ".mitre"]:
            groups[base][ext[1:]] = f
            
    return groups

def get_single_file_group(file_path: str) -> dict:
    """
    Creates a group for a single file. 
    It attempts to find the sibling file (pair .nvd/.mitre) automatically.
    """
    groups = defaultdict(dict)
    
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return groups

    dirname = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    base, ext = os.path.splitext(filename)
    ext = ext.lower()

    if ext not in [".nvd", ".mitre", ".json"]:
        logging.error(f"Unsupported file extension: {ext}")
        return groups

    if ext == ".json":
        groups[base]["mitre"] = filename
        return groups

    type_key = ext[1:]
    groups[base][type_key] = filename

    partner_ext = ".mitre" if type_key == "nvd" else ".nvd"
    partner_file = base + partner_ext
    
    if os.path.exists(os.path.join(dirname, partner_file)):
        groups[base][partner_ext[1:]] = partner_file

    return groups


def process_file_group(base: str, file_map: dict, base_dir: str, args: argparse.Namespace, classifier: CVEClassifier, prompt_template: str):
    combined = {}

    for t in ["nvd", "mitre"]:
        fname = file_map.get(t)
        if not fname:
            continue        
        path = os.path.join(base_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                combined[t] = json.load(f)
        except Exception as e:
            logging.warning("Failed reading %s: %s", fname, e)

    if not combined:
        return None

    return classifier.classify(combined, prompt_template, base)

def main():
    conf_parser = argparse.ArgumentParser(add_help=False)
    conf_parser.add_argument("--config", type=str, default="config.json", help="Path to JSON config file")
    args, remaining_argv = conf_parser.parse_known_args()

    file_defaults = load_config(args.config)

    parser = argparse.ArgumentParser(
        description="Process CVEs and classify them via Ollama AI.",
        parents=[conf_parser]
    )
    
    parser.set_defaults(**file_defaults)

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--json-dir", type=str, default="json", help="Directory containing input JSON files")
    input_group.add_argument("--file", type=str, help="Path to a single .nvd, .mitre, or .json file to process")

    parser.add_argument("--out-dir", type=str, default="output", help="Directory to save output JSON files")
    parser.add_argument("--ollama-url", type=str, default="http://127.0.0.1:11434/v1/chat/completions", help="Ollama API URL")
    parser.add_argument("--model", type=str, default="gemma3:12b", help="Model name to use in Ollama")
    parser.add_argument("--workers", type=int, default=2, help="Maximum concurrent workers")
    parser.add_argument("--attempts", type=int, default=3, help="Max attempts for API requests and JSON parsing")
    parser.add_argument("--timeout", type=int, default=120, help="Request timeout in seconds")
    parser.add_argument("--retry-delay", type=int, default=2, help="Delay between retries in seconds")
    parser.add_argument("--log-file", type=str, default="cve_processing_errors.log", help="General error log file")
    parser.add_argument("--failed-log", type=str, default="failed_cves.txt", help="File to output a list of failed CVE IDs")
    parser.add_argument("--prompt-file", type=str, default="text/prompt", help="Path to the text file containing the prompt")

    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(args.log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

    try:
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            prompt_template = f.read()
    except Exception as e:
        logging.error("Failed to read prompt file at %s: %s", args.prompt_file, e)
        return

    classifier = CVEClassifier(
        model=args.model,
        url=args.ollama_url,
        attempts=args.attempts,
        retry_delay=args.retry_delay,
        timeout=args.timeout
    )

    if args.file:
        groups = get_single_file_group(args.file)
        base_dir = os.path.dirname(os.path.abspath(args.file))
    else:
        groups = group_cve_files(args.json_dir)
        base_dir = args.json_dir
    
    if not groups:
        print(f"No valid input found.")
        return

    failed_cves = []
    
    print(f"Starting processing with {args.workers} workers...")
    print(f"Input Mode: {'Single File' if args.file else 'Directory'}")
    print(f"Model: {args.model} | Output: {args.out_dir} | Max Attempts: {args.attempts}")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_file_group, base, fmap, base_dir, args, classifier, prompt_template): base
            for base, fmap in groups.items()
        }

        for future in tqdm(as_completed(futures), total=len(futures), desc="Classifying"):
            try:
                r = future.result()
                
                if not r:
                    continue

                if r.get("error"):
                    failed_cves.append(r["CVE_ID"])
                    continue

                cve_id = r["CVE_ID"]
                out_path = os.path.join(args.out_dir, f"{cve_id}.json")

                try:
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(r, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno()) 
                except Exception as e:
                    logging.warning("Failed writing %s: %s", out_path, e)
            except Exception as e:
                logging.error(f"Critical error in worker thread: {e}")

    if failed_cves:
        with open(args.failed_log, "w", encoding="utf-8") as f:
            for cve in failed_cves:
                f.write(f"{cve}\n")
        print(f"\nDone. Saved successfully processed CVEs. {len(failed_cves)} CVEs failed (listed in {args.failed_log}). Check {args.log_file} for stack traces.")
    else:
        print("\nDone. All CVEs saved successfully with 0 failures.")

if __name__ == "__main__":
    main()