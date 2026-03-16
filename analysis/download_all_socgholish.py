#!/usr/bin/env python3
"""
Download ALL SocGholish ecosystem samples from MalwareBazaar.
Combines: SocGholish tag, FakeUpdates tag, FakeUpdate tag,
FakeBrowserUpdate tag, TA569 tag, NDSW tag, and SocGholish signature.
Skips anything already downloaded.
"""

import os
import sys
import json
import time
import subprocess
import requests
from collections import Counter

API_URL = "https://mb-api.abuse.ch/api/v1/"
API_KEY = "0409476090a89040cb74a18d65c3bedb0156723083662a5f"
HEADERS = {"Auth-Key": API_KEY}
SAMPLES_DIR = "/root/socgholish_analysis/samples"
ZIP_PASSWORD = "infected"


def fetch_all_socgholish():
    """Gather all unique SocGholish samples from multiple sources."""
    all_samples = {}

    # Tags directly related to SocGholish
    tags = ["SocGholish", "FakeUpdates", "FAKEUPDATES", "FakeUpdate",
            "FakeBrowserUpdate", "ta569", "TA569", "NDSW"]

    for tag in tags:
        try:
            r = requests.post(API_URL, data={"query": "get_taginfo", "tag": tag, "limit": 1000},
                              headers=HEADERS, timeout=60)
            d = r.json()
            if d.get("query_status") == "ok":
                for s in d.get("data", []):
                    h = s["sha256_hash"]
                    if h not in all_samples:
                        all_samples[h] = s
                print(f"  Tag '{tag}': found samples (total unique so far: {len(all_samples)})")
        except Exception as e:
            print(f"  Tag '{tag}': error - {e}")

    # Also grab by signature
    try:
        r = requests.post(API_URL, data={"query": "get_siginfo", "signature": "SocGholish", "limit": 1000},
                          headers=HEADERS, timeout=60)
        d = r.json()
        if d.get("query_status") == "ok":
            for s in d.get("data", []):
                h = s["sha256_hash"]
                if h not in all_samples:
                    all_samples[h] = s
            print(f"  Signature 'SocGholish': found samples (total unique: {len(all_samples)})")
    except Exception as e:
        print(f"  Signature 'SocGholish': error - {e}")

    return all_samples


def download_and_extract(sha256, output_dir):
    zip_path = os.path.join(output_dir, sha256 + ".zip")
    try:
        r = requests.post(API_URL, data={"query": "get_file", "sha256_hash": sha256},
                          headers=HEADERS, timeout=120)
        if r.status_code == 200 and len(r.content) > 100:
            with open(zip_path, 'wb') as f:
                f.write(r.content)
            result = subprocess.run(
                ["7z", "x", f"-p{ZIP_PASSWORD}", "-aoa", f"-o{output_dir}", zip_path],
                capture_output=True, timeout=30
            )
            if result.returncode == 0:
                os.remove(zip_path)
                return True
            else:
                os.rename(zip_path, os.path.join(output_dir, sha256))
                return True
        else:
            return False
    except Exception as e:
        print(f"    Error: {e}")
        if os.path.exists(zip_path):
            os.remove(zip_path)
        return False


def main():
    os.makedirs(SAMPLES_DIR, exist_ok=True)

    print("[*] Gathering all SocGholish ecosystem samples from MalwareBazaar...\n")
    all_samples = fetch_all_socgholish()

    print(f"\n[+] Total unique SocGholish samples available: {len(all_samples)}")

    types = Counter(s.get("file_type", "unknown") for s in all_samples.values())
    print("\n[*] File type distribution:")
    for t, c in types.most_common():
        print(f"    {t}: {c}")

    # Check existing
    existing = set()
    if os.path.isdir(SAMPLES_DIR):
        for f in os.listdir(SAMPLES_DIR):
            existing.add(f)
            # Also add without extension for hash-based matching
            if '.' in f:
                existing.add(f.rsplit('.', 1)[0])

    # Filter to only new samples
    to_download = []
    for h, s in all_samples.items():
        fname = s.get("file_name", "")
        if h not in existing and fname not in existing:
            to_download.append((h, s))

    print(f"\n[*] Already have: ~{len(existing)} files")
    print(f"[*] New to download: {len(to_download)}")

    if not to_download:
        print("[+] Nothing new to download!")
        all_files = [f for f in os.listdir(SAMPLES_DIR) if not f.endswith('.json')]
        print(f"[+] Total files in samples directory: {len(all_files)}")
        return

    success = 0
    failed = 0

    print(f"\n[*] Downloading {len(to_download)} new samples...\n")

    for i, (sha256, sample) in enumerate(to_download):
        fname = sample.get("file_name", "unknown")
        ftype = sample.get("file_type", "unknown")

        print(f"  [{i+1}/{len(to_download)}] {fname} ({ftype}) ", end="", flush=True)

        if download_and_extract(sha256, SAMPLES_DIR):
            success += 1
            print("OK")
        else:
            failed += 1
            print("FAILED")

        time.sleep(1)

    print(f"\n{'='*50}")
    print(f"  Download Summary")
    print(f"{'='*50}")
    print(f"  New samples found:  {len(to_download)}")
    print(f"  Downloaded:         {success}")
    print(f"  Failed:             {failed}")
    print(f"{'='*50}")

    all_files = [f for f in os.listdir(SAMPLES_DIR) if not f.endswith('.json')]
    print(f"\n[+] Total files in samples directory: {len(all_files)}")


if __name__ == "__main__":
    main()
