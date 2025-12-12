#!/usr/bin/env python3
"""
Generate RSA 4096-bit key pair for student identity
Key size: 4096 bits
Public exponent: 65537
Format: PEM
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair
    
    Args:
        key_size: Size of RSA key in bits (default: 4096)
    
    Returns:
        Tuple of (private_key, public_key) objects
    """
    # Generate private key with 4096 bits and public exponent 65537
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Extract public key from private key
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_keys_to_pem(private_key, public_key, private_path: str, public_path: str):
    """
    Save RSA keys to PEM format files
    
    Args:
        private_key: RSA private key object
        public_key: RSA public key object
        private_path: Path to save private key
        public_path: Path to save public key
    """
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write to files
    with open(private_path, 'wb') as f:
        f.write(private_pem)
    print(f"[OK] Private key saved to {private_path}")
    
    with open(public_path, 'wb') as f:
        f.write(public_pem)
    print(f"[OK] Public key saved to {public_path}")


if __name__ == "__main__":
    print("Generating RSA 4096-bit key pair...")
    private_key, public_key = generate_rsa_keypair(key_size=4096)
    print("[OK] Key pair generated successfully")
    
    save_keys_to_pem(
        private_key,
        public_key,
        "student_private.pem",
        "student_public.pem"
    )
    
    print("\n[OK] Key generation complete!")
    print("Files created:")
    print("  - student_private.pem (4096-bit private key)")
    print("  - student_public.pem (4096-bit public key)")
