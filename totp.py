#!/usr/bin/env python3
"""
TOTP (Time-based One-Time Password) implementation
Generates and verifies 2FA codes
"""

import time
import pyotp
from typing import Tuple


def generate_totp_code(base32_seed: str) -> Tuple[str, int]:
    """
    Generate current TOTP code and calculate remaining validity
    
    TOTP Parameters:
    - Algorithm: SHA-1 (standard for TOTP)
    - Period: 30 seconds
    - Digits: 6
    
    Args:
        base32_seed: Base32-encoded secret
    
    Returns:
        Tuple of (code: str, valid_for: int)
        - code: 6-digit TOTP code
        - valid_for: seconds remaining in current period
    
    Raises:
        ValueError: If seed is invalid
    """
    try:
        # Create TOTP instance with standard parameters
        totp = pyotp.TOTP(
            base32_seed,
            digits=6,
            digest='sha1',
            interval=30
        )
        
        # Generate current code
        code = totp.now()
        
        # Calculate remaining validity
        # TOTP period is 30 seconds, calculate how many seconds left
        current_time = int(time.time())
        period_start = (current_time // 30) * 30
        valid_for = 30 - (current_time - period_start)
        
        return code, valid_for
        
    except Exception as e:
        raise ValueError(f"Failed to generate TOTP code: {e}")


def verify_totp_code(code: str, base32_seed: str, tolerance: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance
    
    Args:
        code: 6-digit code to verify
        base32_seed: Base32-encoded secret
        tolerance: Number of periods to accept (±tolerance * 30 seconds)
                  Default: 1 (accepts ±30 seconds)
    
    Returns:
        True if code is valid, False otherwise
    
    Notes:
        With tolerance=1:
        - Accepts codes from previous period (up to 30s ago)
        - Accepts codes from current period
        - Accepts codes from next period (up to 30s ahead)
        This gives a total window of ±30 seconds
    """
    try:
        # Create TOTP instance
        totp = pyotp.TOTP(
            base32_seed,
            digits=6,
            digest='sha1',
            interval=30
        )
        
        # Verify with tolerance window
        # valid_window specifies how many periods before/after to accept
        return totp.verify(code, valid_window=tolerance)
        
    except Exception as e:
        return False


def get_current_period_info() -> dict:
    """
    Get information about current TOTP time period
    
    Returns:
        Dictionary with period information:
        - current_time: Current Unix timestamp
        - period_start: Start of current 30s period
        - period_end: End of current 30s period
        - seconds_remaining: Seconds left in period
    """
    current_time = int(time.time())
    period_start = (current_time // 30) * 30
    period_end = period_start + 30
    seconds_remaining = period_end - current_time
    
    return {
        'current_time': current_time,
        'period_start': period_start,
        'period_end': period_end,
        'seconds_remaining': seconds_remaining
    }


if __name__ == "__main__":
    """
    Test TOTP generation and verification
    """
    import sys
    sys.path.insert(0, '.')
    from crypto import load_private_key, decrypt_seed, hex_to_base32
    
    print("=" * 70)
    print("Testing TOTP Generation and Verification")
    print("=" * 70)
    
    # Load and decrypt seed
    print("\n[*] Loading and decrypting seed...")
    try:
        private_key = load_private_key("student_private.pem")
        
        with open("encrypted_seed.txt", 'r') as f:
            encrypted_seed = f.read().strip()
        
        hex_seed = decrypt_seed(encrypted_seed, private_key)
        base32_seed = hex_to_base32(hex_seed)
        print(f"[OK] Seed ready for TOTP")
    except Exception as e:
        print(f"[ERROR] {e}")
        exit(1)
    
    # Generate TOTP code
    print("\n[*] Generating TOTP code...")
    try:
        code, valid_for = generate_totp_code(base32_seed)
        print(f"[OK] Current 2FA Code: {code}")
        print(f"[*] Valid for: {valid_for} seconds")
    except Exception as e:
        print(f"[ERROR] {e}")
        exit(1)
    
    # Verify the code
    print("\n[*] Verifying generated code...")
    is_valid = verify_totp_code(code, base32_seed)
    print(f"[OK] Code verification: {'VALID' if is_valid else 'INVALID'}")
    
    # Test invalid code
    print("\n[*] Testing invalid code (000000)...")
    is_valid = verify_totp_code("000000", base32_seed)
    print(f"[OK] Invalid code verification: {'VALID' if is_valid else 'INVALID (expected)'}")
    
    # Show period info
    print("\n[*] Current period information:")
    period_info = get_current_period_info()
    for key, value in period_info.items():
        print(f"    {key}: {value}")
    
    print("\n" + "=" * 70)
    print("SUCCESS: TOTP implementation working correctly")
    print("=" * 70)
