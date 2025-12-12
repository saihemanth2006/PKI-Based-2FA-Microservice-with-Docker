#!/usr/bin/env python3
"""
Request encrypted seed from instructor API
Saves encrypted seed to encrypted_seed.txt (NOT committed to Git)
"""

import json
import requests
from typing import Optional

def request_seed(
    student_id: str,
    github_repo_url: str,
    public_key_path: str = "student_public.pem",
    api_url: str = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
) -> Optional[str]:
    """
    Request encrypted seed from instructor API
    
    Args:
        student_id: Your student ID
        github_repo_url: Your GitHub repository URL
        public_key_path: Path to student public key PEM file
        api_url: Instructor API endpoint URL
    
    Returns:
        Encrypted seed as base64 string or None if failed
    """
    
    print(f"[*] Requesting encrypted seed from instructor API...")
    print(f"[*] Student ID: {student_id}")
    print(f"[*] Repository: {github_repo_url}")
    
    # Step 1: Read student public key from PEM file
    print(f"[*] Reading public key from {public_key_path}...")
    try:
        with open(public_key_path, 'r') as f:
            public_key = f.read()
        print(f"[OK] Public key loaded ({len(public_key)} bytes)")
    except FileNotFoundError:
        print(f"[ERROR] Public key file not found: {public_key_path}")
        return None
    
    # Step 2: Prepare HTTP POST request payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key
    }
    
    print(f"[*] Payload prepared:")
    print(f"    - student_id: {student_id}")
    print(f"    - github_repo_url: {github_repo_url}")
    print(f"    - public_key: {len(public_key)} bytes")
    
    # Step 3: Send POST request to instructor API
    print(f"[*] Sending POST request to {api_url}...")
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(api_url, json=payload, headers=headers, timeout=30)
        print(f"[*] Response status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None
    
    # Step 4: Parse JSON response
    try:
        response_data = response.json()
        print(f"[*] Response received")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON response: {e}")
        print(f"[DEBUG] Response text: {response.text[:200]}")
        return None
    
    # Check for API errors
    if response.status_code != 200:
        error_msg = response_data.get("error", response_data.get("message", "Unknown error"))
        print(f"[ERROR] API error ({response.status_code}): {error_msg}")
        return None
    
    if response_data.get("status") != "success":
        print(f"[ERROR] API returned non-success status: {response_data.get('status')}")
        return None
    
    # Extract encrypted seed
    encrypted_seed = response_data.get("encrypted_seed")
    if not encrypted_seed:
        print(f"[ERROR] No encrypted_seed in response")
        return None
    
    print(f"[OK] Encrypted seed received ({len(encrypted_seed)} bytes)")
    
    # Step 5: Save encrypted seed to file
    output_file = "encrypted_seed.txt"
    print(f"[*] Saving encrypted seed to {output_file}...")
    try:
        with open(output_file, 'w') as f:
            f.write(encrypted_seed)
        print(f"[OK] Encrypted seed saved successfully")
        print(f"[!] NOTE: This file is NOT committed to Git (add to .gitignore)")
        return encrypted_seed
    except IOError as e:
        print(f"[ERROR] Failed to save encrypted seed: {e}")
        return None


if __name__ == "__main__":
    # Configuration
    STUDENT_ID = "23A91A1235"
    GITHUB_REPO_URL = "https://github.com/saihemanth2006/PKI-Based-2FA-Microservice-with-Docker"
    
    print("=" * 70)
    print("Instructor Seed Request Script")
    print("=" * 70)
    
    # Request encrypted seed
    encrypted_seed = request_seed(
        student_id=STUDENT_ID,
        github_repo_url=GITHUB_REPO_URL
    )
    
    if encrypted_seed:
        print("\n" + "=" * 70)
        print("SUCCESS: Encrypted seed obtained!")
        print("=" * 70)
        print(f"Encrypted seed preview: {encrypted_seed[:50]}...")
    else:
        print("\n" + "=" * 70)
        print("FAILED: Could not obtain encrypted seed")
        print("=" * 70)
