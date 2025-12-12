#!/usr/bin/env python3
"""
Step 13: Generate Commit Proof

Sign the commit hash with student private key using RSA-PSS-SHA256
Encrypt the signature with instructor public key using RSA/OAEP-SHA256
Base64 encode the encrypted signature
"""

import subprocess
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_private_key(pem_path: str):
    """Load RSA private key from PEM file"""
    with open(pem_path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )


def load_public_key(pem_path: str):
    """Load RSA public key from PEM file"""
    with open(pem_path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )


def sign_message(message: str, private_key) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256
    
    Implementation:
    1. Encode commit hash as ASCII/UTF-8 bytes
       - CRITICAL: Sign the ASCII string, NOT binary hex!
       - Use message.encode('utf-8')
    
    2. Sign using RSA-PSS with SHA-256
       - Padding: PSS
       - MGF: MGF1 with SHA-256
       - Hash Algorithm: SHA-256
       - Salt Length: Maximum
    
    3. Return signature bytes
    """
    message_bytes = message.encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with public key
    
    Implementation:
    1. Encrypt signature bytes using RSA/OAEP with SHA-256
       - Padding: OAEP
       - MGF: MGF1 with SHA-256
       - Hash Algorithm: SHA-256
       - Label: None
    
    2. Return encrypted ciphertext bytes
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def main():
    print("=" * 80)
    print("STEP 13: GENERATE COMMIT PROOF")
    print("=" * 80)
    
    # Step 1: Get current commit hash
    print("\n[1] Getting commit hash...")
    result = subprocess.run(
        ['git', 'log', '-1', '--format=%H'],
        capture_output=True,
        text=True,
        cwd='.'
    )
    commit_hash = result.stdout.strip()
    print(f"    Commit Hash: {commit_hash}")
    
    # Step 2: Load student private key
    print("\n[2] Loading student private key...")
    student_private_key = load_private_key('student_private.pem')
    print("    [OK] Student private key loaded (RSA-4096)")
    
    # Step 3: Sign commit hash with student private key
    print("\n[3] Signing commit hash with RSA-PSS-SHA256...")
    signature = sign_message(commit_hash, student_private_key)
    print(f"    [OK] Signature generated ({len(signature)} bytes)")
    
    # Step 4: Load instructor public key
    print("\n[4] Loading instructor public key...")
    instructor_public_key = load_public_key('instructor_public.pem')
    print("    [OK] Instructor public key loaded (RSA-4096)")
    
    # Step 5: Encrypt signature with instructor public key
    print("\n[5] Encrypting signature with RSA/OAEP-SHA256...")
    encrypted_signature = encrypt_with_public_key(signature, instructor_public_key)
    print(f"    [OK] Signature encrypted ({len(encrypted_signature)} bytes)")
    
    # Step 6: Base64 encode encrypted signature
    print("\n[6] Base64 encoding encrypted signature...")
    encoded_signature = base64.b64encode(encrypted_signature).decode('utf-8')
    print("    [OK] Encoding complete")
    
    # Output results
    print("\n" + "=" * 80)
    print("COMMIT PROOF GENERATED")
    print("=" * 80)
    print(f"\nCommit Hash:\n{commit_hash}\n")
    print(f"Encrypted Signature (Base64):\n{encoded_signature}\n")
    print("=" * 80)
    
    # Save to file for submission
    with open('commit_proof.txt', 'w') as f:
        f.write(f"Commit Hash: {commit_hash}\n")
        f.write(f"Encrypted Signature: {encoded_signature}\n")
    
    print("\n[OK] Proof saved to commit_proof.txt")
    print("=" * 80)


if __name__ == '__main__':
    main()
