#!/usr/bin/env python3
"""
Cryptographic operations for PKI-Based 2FA Microservice
Implements RSA/OAEP decryption and TOTP generation
"""

import base64
import re
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


def decrypt_seed(encrypted_seed_b64: str, private_key: rsa.RSAPrivateKey) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP
    
    Algorithm: RSA/OAEP with SHA-256 and MGF1
    
    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object
    
    Returns:
        Decrypted hex seed (64-character string)
    
    Raises:
        ValueError: If decryption fails or seed format is invalid
    """
    
    # Step 1: Base64 decode the encrypted seed string
    try:
        encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Failed to decode base64: {e}")
    
    # Step 2: RSA/OAEP decrypt with SHA-256
    try:
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")
    
    # Step 3: Decode bytes to UTF-8 string
    try:
        hex_seed = decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise ValueError(f"Failed to decode decrypted bytes: {e}")
    
    # Step 4: Validate - must be 64-character hex string
    if len(hex_seed) != 64:
        raise ValueError(f"Invalid seed length: expected 64, got {len(hex_seed)}")
    
    if not re.match(r'^[0-9a-fA-F]{64}$', hex_seed):
        raise ValueError("Seed contains non-hexadecimal characters")
    
    # Normalize to lowercase
    hex_seed = hex_seed.lower()
    
    # Step 5: Return hex seed
    return hex_seed


def load_private_key(pem_path: str) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file
    
    Args:
        pem_path: Path to PEM-encoded private key file
    
    Returns:
        RSA private key object
    
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key format is invalid
    """
    try:
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
        
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend()
        )
        
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Key is not an RSA private key")
        
        return private_key
    except FileNotFoundError:
        raise FileNotFoundError(f"Private key file not found: {pem_path}")
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}")


def hex_to_base32(hex_string: str) -> str:
    """
    Convert 64-character hex string to base32 encoding for TOTP
    
    TOTP libraries expect base32-encoded secrets, but our seed is hex.
    This function converts the hex seed to base32 format.
    
    Args:
        hex_string: 64-character hexadecimal string
    
    Returns:
        Base32-encoded string (uppercase, no padding)
    
    Raises:
        ValueError: If hex string is invalid
    """
    if len(hex_string) != 64:
        raise ValueError(f"Invalid hex seed length: expected 64, got {len(hex_string)}")
    
    if not re.match(r'^[0-9a-fA-F]{64}$', hex_string):
        raise ValueError("Invalid hex string format")
    
    # Convert hex to bytes
    seed_bytes = bytes.fromhex(hex_string)
    
    # Convert bytes to base32
    base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
    
    # Remove padding (TOTP libraries handle this)
    return base32_seed.rstrip('=')


def verify_decryption_setup() -> Tuple[bool, str]:
    """
    Verify that all required files exist for decryption
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    import os
    
    required_files = {
        'student_private.pem': 'Student private key',
        'encrypted_seed.txt': 'Encrypted seed from instructor API'
    }
    
    missing_files = []
    for file_path, description in required_files.items():
        if not os.path.exists(file_path):
            missing_files.append(f"{description} ({file_path})")
    
    if missing_files:
        return False, "Missing files: " + ", ".join(missing_files)
    
    return True, "All required files present"


if __name__ == "__main__":
    """
    Test the decryption function locally
    """
    import os
    
    print("=" * 70)
    print("Testing Seed Decryption")
    print("=" * 70)
    
    # Verify setup
    success, message = verify_decryption_setup()
    print(f"\n[*] Setup verification: {message}")
    
    if not success:
        print("[ERROR] Cannot proceed without required files")
        exit(1)
    
    # Load private key
    print("\n[*] Loading private key...")
    try:
        private_key = load_private_key("student_private.pem")
        key_size = private_key.key_size
        print(f"[OK] Private key loaded ({key_size} bits)")
    except Exception as e:
        print(f"[ERROR] Failed to load private key: {e}")
        exit(1)
    
    # Read encrypted seed
    print("\n[*] Reading encrypted seed...")
    try:
        with open("encrypted_seed.txt", 'r') as f:
            encrypted_seed_b64 = f.read().strip()
        print(f"[OK] Encrypted seed loaded ({len(encrypted_seed_b64)} bytes)")
    except Exception as e:
        print(f"[ERROR] Failed to read encrypted seed: {e}")
        exit(1)
    
    # Decrypt seed
    print("\n[*] Decrypting seed...")
    try:
        hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
        print(f"[OK] Seed decrypted successfully")
        print(f"[*] Hex seed (64 chars): {hex_seed}")
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        exit(1)
    
    # Convert to base32 for TOTP
    print("\n[*] Converting to base32 for TOTP...")
    try:
        base32_seed = hex_to_base32(hex_seed)
        print(f"[OK] Base32 seed: {base32_seed}")
    except Exception as e:
        print(f"[ERROR] Conversion failed: {e}")
        exit(1)
    
    print("\n" + "=" * 70)
    print("SUCCESS: Seed decryption working correctly")
    print("=" * 70)
