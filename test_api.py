#!/usr/bin/env python3
"""
Test script for FastAPI endpoints
Tests all three API endpoints locally
"""

import time
import requests
import json

BASE_URL = "http://localhost:8080"


def test_health():
    """Test health check endpoint"""
    print("\n" + "=" * 70)
    print("Test 1: Health Check (GET /)")
    print("=" * 70)
    
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_decrypt_seed():
    """Test POST /decrypt-seed endpoint"""
    print("\n" + "=" * 70)
    print("Test 2: Decrypt Seed (POST /decrypt-seed)")
    print("=" * 70)
    
    # Read encrypted seed
    try:
        with open("encrypted_seed.txt", 'r') as f:
            encrypted_seed = f.read().strip()
        print(f"[*] Encrypted seed loaded ({len(encrypted_seed)} bytes)")
    except Exception as e:
        print(f"[ERROR] Failed to read encrypted seed: {e}")
        return False
    
    # Send request
    try:
        payload = {"encrypted_seed": encrypted_seed}
        response = requests.post(f"{BASE_URL}/decrypt-seed", json=payload)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("[OK] Seed decrypted and stored successfully")
            return True
        else:
            print(f"[ERROR] Decryption failed: {response.json()}")
            return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_generate_2fa():
    """Test GET /generate-2fa endpoint"""
    print("\n" + "=" * 70)
    print("Test 3: Generate 2FA Code (GET /generate-2fa)")
    print("=" * 70)
    
    try:
        response = requests.get(f"{BASE_URL}/generate-2fa")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if response.status_code == 200:
            code = data.get('code')
            valid_for = data.get('valid_for')
            print(f"[OK] Generated 2FA code: {code}")
            print(f"[OK] Valid for: {valid_for} seconds")
            return code
        else:
            print(f"[ERROR] Failed to generate code: {data}")
            return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def test_verify_2fa_valid(code):
    """Test POST /verify-2fa with valid code"""
    print("\n" + "=" * 70)
    print("Test 4: Verify Valid 2FA Code (POST /verify-2fa)")
    print("=" * 70)
    
    try:
        payload = {"code": code}
        response = requests.post(f"{BASE_URL}/verify-2fa", json=payload)
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if response.status_code == 200:
            is_valid = data.get('valid')
            print(f"[OK] Code verification: {'VALID' if is_valid else 'INVALID'}")
            return is_valid
        else:
            print(f"[ERROR] Verification failed: {data}")
            return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_verify_2fa_invalid():
    """Test POST /verify-2fa with invalid code"""
    print("\n" + "=" * 70)
    print("Test 5: Verify Invalid 2FA Code (POST /verify-2fa)")
    print("=" * 70)
    
    try:
        payload = {"code": "000000"}
        response = requests.post(f"{BASE_URL}/verify-2fa", json=payload)
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if response.status_code == 200:
            is_valid = data.get('valid')
            print(f"[OK] Code verification: {'VALID' if is_valid else 'INVALID (expected)'}")
            return not is_valid  # Should be invalid
        else:
            print(f"[ERROR] Verification failed: {data}")
            return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_verify_2fa_missing_code():
    """Test POST /verify-2fa with missing code"""
    print("\n" + "=" * 70)
    print("Test 6: Verify with Missing Code (POST /verify-2fa)")
    print("=" * 70)
    
    try:
        payload = {"code": ""}
        response = requests.post(f"{BASE_URL}/verify-2fa", json=payload)
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if response.status_code == 400:
            print("[OK] Correctly rejected empty code with HTTP 400")
            return True
        else:
            print(f"[ERROR] Expected HTTP 400, got {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("FastAPI Endpoint Testing Suite")
    print("=" * 70)
    print("\n[*] Waiting for API server to start...")
    
    # Wait for server to be ready
    for i in range(10):
        try:
            response = requests.get(f"{BASE_URL}/")
            if response.status_code == 200:
                print("[OK] API server is ready")
                break
        except:
            time.sleep(1)
    else:
        print("[ERROR] API server not accessible. Make sure it's running on port 8080")
        return
    
    # Run tests
    results = []
    
    # Test 1: Health check
    results.append(("Health Check", test_health()))
    
    # Test 2: Decrypt seed
    results.append(("Decrypt Seed", test_decrypt_seed()))
    
    # Test 3: Generate 2FA code
    code = test_generate_2fa()
    results.append(("Generate 2FA", code is not None))
    
    if code:
        # Test 4: Verify valid code
        results.append(("Verify Valid Code", test_verify_2fa_valid(code)))
        
        # Test 5: Verify invalid code
        results.append(("Verify Invalid Code", test_verify_2fa_invalid()))
        
        # Test 6: Verify missing code
        results.append(("Verify Missing Code", test_verify_2fa_missing_code()))
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print("=" * 70)


if __name__ == "__main__":
    main()
