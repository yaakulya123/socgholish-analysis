#!/usr/bin/env python3
"""
SocGholish Sample Downloader from MalwareBazaar
Downloads verified SocGholish malware samples for analysis.
"""

import os
import sys
import json
import time
import zipfile
import requests
from datetime import datetime

MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
SAMPLES_DIR = "/root/socgholish_analysis/samples"
RESULTS_DIR = "/root/socgholish_analysis/results"
ZIP_PASSWORD = b"infected"  # MalwareBazaar standard password


def query_malware_bazaar(tag="SocGholish", limit=100):
    """Query MalwareBazaar for SocGholish samples."""
    print(f"[*] Querying MalwareBazaar for tag: {tag}")

    data = {
        "query": "get_taginfo",
        "tag": tag,
        "limit": limit,
    }

    try:
        response = requests.post(MALWARE_BAZAAR_API, data=data, timeout=60)
        result = response.json()

        if result.get("query_status") == "ok":
            samples = result.get("data", [])
            print(f"[+] Found {len(samples)} samples")
            return samples
        elif result.get("query_status") == "tag_not_found":
            print(f"[!] Tag '{tag}' not found. Trying signature search...")
            return query_by_signature(tag, limit)
        else:
            print(f"[!] Query status: {result.get('query_status')}")
            return []
    except Exception as e:
        print(f"[!] Error querying API: {e}")
        return []


def query_by_signature(signature="SocGholish", limit=100):
    """Query by signature name."""
    data = {
        "query": "get_siginfo",
        "signature": signature,
        "limit": limit,
    }

    try:
        response = requests.post(MALWARE_BAZAAR_API, data=data, timeout=60)
        result = response.json()

        if result.get("query_status") == "ok":
            samples = result.get("data", [])
            print(f"[+] Found {len(samples)} samples by signature")
            return samples
        else:
            print(f"[!] Signature query status: {result.get('query_status')}")
            return []
    except Exception as e:
        print(f"[!] Error: {e}")
        return []


def query_recent_samples(file_type=None, limit=100):
    """Query recent samples, optionally filtered by type."""
    data = {
        "query": "get_recent",
        "selector": "100",
    }

    try:
        response = requests.post(MALWARE_BAZAAR_API, data=data, timeout=60)
        result = response.json()

        if result.get("query_status") == "ok":
            return result.get("data", [])
        return []
    except Exception as e:
        print(f"[!] Error: {e}")
        return []


def download_sample(sha256_hash, output_dir):
    """Download a single sample from MalwareBazaar."""
    output_path = os.path.join(output_dir, sha256_hash)

    data = {
        "query": "get_file",
        "sha256_hash": sha256_hash,
    }

    try:
        response = requests.post(MALWARE_BAZAAR_API, data=data, timeout=120)

        if response.status_code == 200 and response.headers.get('Content-Type') == 'application/zip':
            zip_path = output_path + ".zip"
            with open(zip_path, 'wb') as f:
                f.write(response.content)

            # Extract with password "infected"
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(output_dir, pwd=ZIP_PASSWORD)
                os.remove(zip_path)
                print(f"  [+] Downloaded and extracted: {sha256_hash[:16]}...")
                return True
            except Exception as e:
                print(f"  [!] Extraction error: {e}")
                # Keep the zip if extraction fails
                return False
        else:
            print(f"  [!] Download failed for {sha256_hash[:16]}... (status: {response.status_code})")
            return False
    except Exception as e:
        print(f"  [!] Error downloading {sha256_hash[:16]}...: {e}")
        return False


def download_all_samples(samples, output_dir, max_samples=None):
    """Download all samples from the list."""
    os.makedirs(output_dir, exist_ok=True)

    if max_samples:
        samples = samples[:max_samples]

    total = len(samples)
    success = 0
    failed = 0
    skipped = 0

    # Save sample metadata
    metadata_file = os.path.join(output_dir, "sample_metadata.json")
    with open(metadata_file, 'w') as f:
        json.dump(samples, f, indent=2, default=str)
    print(f"[+] Saved metadata for {total} samples to {metadata_file}")

    print(f"\n[*] Downloading {total} samples...")

    for i, sample in enumerate(samples):
        sha256 = sample.get('sha256_hash', '')
        filename = sample.get('file_name', 'unknown')
        file_type = sample.get('file_type', 'unknown')

        print(f"  [{i+1}/{total}] {filename} ({file_type})")

        # Check if already downloaded
        existing_files = [f for f in os.listdir(output_dir) if sha256[:16] in f]
        if existing_files:
            print(f"    [~] Already exists, skipping")
            skipped += 1
            continue

        if download_sample(sha256, output_dir):
            success += 1
        else:
            failed += 1

        # Rate limiting
        time.sleep(1)

    print(f"\n[+] Download complete:")
    print(f"    Success: {success}")
    print(f"    Failed:  {failed}")
    print(f"    Skipped: {skipped}")
    print(f"    Total:   {total}")

    return success


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Download SocGholish samples from MalwareBazaar')
    parser.add_argument('-t', '--tag', default='SocGholish', help='MalwareBazaar tag to search')
    parser.add_argument('-l', '--limit', type=int, default=100, help='Maximum samples to query')
    parser.add_argument('-m', '--max-download', type=int, help='Maximum samples to download')
    parser.add_argument('-o', '--output', default=SAMPLES_DIR, help='Output directory')
    parser.add_argument('--list-only', action='store_true', help='List samples without downloading')
    parser.add_argument('--signature', action='store_true', help='Search by signature instead of tag')

    args = parser.parse_args()

    # Query samples
    if args.signature:
        samples = query_by_signature(args.tag, args.limit)
    else:
        samples = query_malware_bazaar(args.tag, args.limit)

    if not samples:
        # Try alternative tags
        alt_tags = ['socgholish', 'FakeUpdates', 'fakeupdates', 'SocGholish']
        for tag in alt_tags:
            if tag != args.tag:
                print(f"[*] Trying alternative tag: {tag}")
                samples = query_malware_bazaar(tag, args.limit)
                if samples:
                    break

        if not samples:
            # Try signature search
            print("[*] Trying signature-based search...")
            samples = query_by_signature("SocGholish", args.limit)

    if not samples:
        print("[!] No samples found. Check your search criteria.")
        sys.exit(1)

    # Display sample info
    print(f"\n[*] Sample Summary:")
    file_types = {}
    for s in samples:
        ft = s.get('file_type', 'unknown')
        file_types[ft] = file_types.get(ft, 0) + 1
    for ft, count in sorted(file_types.items(), key=lambda x: -x[1]):
        print(f"    {ft}: {count}")

    if args.list_only:
        print(f"\n[*] Listing {len(samples)} samples:")
        for s in samples:
            print(f"  {s.get('sha256_hash', 'N/A')[:32]}... | {s.get('file_name', 'N/A')} | {s.get('file_type', 'N/A')}")
        sys.exit(0)

    # Download
    download_all_samples(samples, args.output, args.max_download)


if __name__ == '__main__':
    main()
