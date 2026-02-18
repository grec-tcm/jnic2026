import json
import requests
import time
import re
import logging
from typing import Any, Dict, Optional

def safe_json_loads(s: str) -> dict:
    """Attempts to extract and parse JSON. Raises ValueError on failure."""
    if not s: 
        raise ValueError("Received empty string from AI.")
    try:
        match = re.search(r'(\{.*\})', s, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        return json.loads(s)
    except Exception as e:
        raise ValueError(f"JSON parse failed: {e}. Raw snippet: {s[:200]}")

def _query(payload: dict, url: str, attempts: int, delay: int, timeout: int) -> Optional[str]:
    """Internal function to handle HTTP POST requests with attempts."""
    session = requests.Session()
    for attempt in range(1, attempts + 1):
        try:
            r = session.post(url, json=payload, timeout=timeout)

            if r.status_code != 200:
                raise RuntimeError(f"Bad status {r.status_code}")

            data = r.json()
            content = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )

            if content:
                return content.strip()

        except Exception as e:
            logging.warning("AI network/API failure %d/%d: %s", attempt, attempts, e)

        time.sleep(delay)

    return None

class CVEClassifier:
    def __init__(self, 
                 model: str, 
                 url: str, 
                 attempts: int, 
                 retry_delay: int, 
                 timeout: int, 
                 role_file: str = "text/role",
                 template_file: str = "text/output_template.json"):
        self.model = model
        self.url = url
        self.attempts = attempts
        self.retry_delay = retry_delay
        self.timeout = timeout
        
        try:
            with open(role_file, 'r', encoding='utf-8') as f:
                self.system_prompt = f.read().strip()
        except FileNotFoundError:
            logging.error(f"Role file not found: {role_file}")
            raise

        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                self.output_map = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Failed to load template file {template_file}: {e}")
            raise

    def classify(self, cve_data: Dict[str, Any], prompt_template: str, cve_id_fallback: str) -> Dict[str, Any]:
        start_time = time.time()
        
        cve_id = (
            cve_data.get("mitre", {})
            .get("cveMetadata", {})
            .get("cveId") 
            or cve_id_fallback
        )

        full_json_str = json.dumps(cve_data, indent=2)
        prompt = prompt_template.replace("{full_json_str}", full_json_str)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "temperature": 0,
            "format": "json",
            "options": {"num_ctx": 20480, "num_gpu": 99}
        }

        data = None
        attempts_used = 0

        for attempt in range(1, self.attempts + 1):
            attempts_used = attempt
            raw = _query(payload, self.url, self.attempts, self.retry_delay, self.timeout)
            
            if not raw:
                continue
                
            try:
                data = safe_json_loads(raw)
                break
            except ValueError:
                time.sleep(self.retry_delay)

        execution_time = round(time.time() - start_time, 2)

        result = {"CVE_ID": cve_id} 
        
        if not data:
            result.update({"error": True, "attempts": attempts_used, "execution_time_seconds": execution_time})
            return result

        for final_key, ai_key in self.output_map.items():
            if final_key == "CVE_ID":
                continue 
                
            default_val = [] if any(x in final_key for x in ["Vendors", "Products"]) else None
            result[final_key] = data.get(ai_key, default_val)

        result["execution_time_seconds"] = execution_time
        result["attempts"] = attempts_used
        
        return result