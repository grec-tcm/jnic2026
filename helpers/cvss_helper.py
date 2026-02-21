import argparse
import json
from pathlib import Path

def get_nvd_cvss_score(data: dict) -> tuple[float, str] | tuple[None, None]:
    """
    Extracts the highest available CVSS base score and its version from NVD JSON data.
    Priority: v4.0 -> v3.1 -> v3.0 -> v2.0.
    """
    try:
        vulnerability_info = data.get("vulnerabilities", [])[0]
        metrics = vulnerability_info.get("cve", {}).get("metrics", {})

        version_priority = {
            "cvssMetricV40": "4.0",
            "cvssMetricV31": "3.1",
            "cvssMetricV30": "3.0",
            "cvssMetricV2": "2.0"
        }

        for key, version_str in version_priority.items():
            if key in metrics:
                metric_list = metrics[key]
                if metric_list:
                    score = metric_list[0].get("cvssData", {}).get("baseScore")
                    if score is not None:
                        return score, version_str
    except (IndexError, AttributeError, TypeError):
        return None, None
    return None, None

def get_mitre_cvss_score(data: dict) -> tuple[float, str] | tuple[None, None]:
    """
    Extracts the highest available CVSS base score and its version from MITRE JSON data.
    Priority: v4.0 -> v3.1 -> v3.0 -> v2.0.
    """
    try:
        metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
        if not metrics:
            return None, None

        version_priority = {
            "cvssV4_0": "4.0",
            "cvssV3_1": "3.1",
            "cvssV3_0": "3.0",
            "cvssV2_0": "2.0"
        }

        for key, version_str in version_priority.items():
            for metric in metrics:
                if key in metric:
                    score = metric.get(key, {}).get("baseScore")
                    if score is not None:
                        return score, version_str
    except (IndexError, AttributeError, TypeError):
        return None, None
    return None, None

def main():
    parser = argparse.ArgumentParser(description="Update output JSON files with CVSS scores from NVD/MITRE data.")
    parser.add_argument("json_dir", type=str, help="Directory containing the source .nvd and .mitre files.")
    parser.add_argument("output_dir", type=str, help="Directory containing the target JSON files to update.")
    args = parser.parse_args()

    json_dir = Path(args.json_dir)
    output_dir = Path(args.output_dir)

    # Validate directories
    if not json_dir.is_dir():
        print(f"Error: Source directory '{json_dir}' not found.")
        return
    if not output_dir.is_dir():
        print(f"Error: Output directory '{output_dir}' not found.")
        return

    updated_count = 0
    missing_count = 0

    # Iterate over all JSON files in the output directory
    for output_file in output_dir.glob("*.json"):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                output_data = json.load(f)
            
            cve_id = output_data.get("CVE_ID")
            if not cve_id:
                print(f"[!] No 'CVE_ID' found in {output_file.name}. Skipping.")
                continue

            score, version, source = None, None, None
            nvd_file = json_dir / f"{cve_id}.nvd"
            mitre_file = json_dir / f"{cve_id}.mitre"

            # 1. Check NVD first (Primary Priority)
            if nvd_file.is_file():
                with open(nvd_file, "r", encoding="utf-8") as f:
                    nvd_data = json.load(f)
                score, version = get_nvd_cvss_score(nvd_data)
                if score is not None:
                    source = "nvd"

            # 2. Check MITRE if NVD didn't yield a score
            if score is None and mitre_file.is_file():
                with open(mitre_file, "r", encoding="utf-8") as f:
                    mitre_data = json.load(f)
                score, version = get_mitre_cvss_score(mitre_data)
                if score is not None:
                    source = "mitre"

            # 3. Update and save the file if a score was found
            if score is not None:
                output_data["CVSS_score"] = score
                output_data["CVSS_version"] = f"{version}.{source}"
                
                # Write back to the exact same file
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(output_data, f, indent=2)
                
                print(f"[+] Updated {cve_id:<18} -> Score: {score:<4} | Version: {output_data['CVSS_version']}")
                updated_count += 1
            else:
                print(f"[-] No CVSS score found for {cve_id} in '{json_dir}'.")
                missing_count += 1

        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Error processing {output_file.name}: {e}")

    # Print Summary
    print("\n" + "="*50)
    print(" " * 18 + "UPDATE SUMMARY")
    print("="*50)
    print(f"Files updated successfully : {updated_count}")
    print(f"Files missing CVSS data    : {missing_count}")
    print("="*50)

if __name__ == "__main__":
    main()