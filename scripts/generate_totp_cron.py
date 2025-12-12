#!/usr/bin/env python3
"""
Cron job script for TOTP code generation
Runs every minute to generate and log current 2FA code
"""

import sys
import os
from datetime import datetime

# Add current directory to path
sys.path.insert(0, '/app')

from crypto import hex_to_base32
from totp import generate_totp_code


def main():
    """Generate TOTP code and log to file"""
    seed_file = '/data/seed.txt'
    output_file = '/cron/last_code.txt'
    
    try:
        # Check if seed file exists
        if not os.path.exists(seed_file):
            error_msg = f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - ERROR: Seed file not found"
            print(error_msg, file=sys.stderr)
            with open(output_file, 'w') as f:
                f.write(error_msg + '\n')
            return 1
        
        # Read hex seed
        with open(seed_file, 'r') as f:
            hex_seed = f.read().strip()
        
        # Convert to base32 and generate TOTP code
        base32_seed = hex_to_base32(hex_seed)
        code, valid_for = generate_totp_code(base32_seed)
        
        # Format timestamp in UTC
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        # Log to file
        log_message = f"{timestamp} - 2FA Code: {code}"
        with open(output_file, 'w') as f:
            f.write(log_message + '\n')
        
        # Also print to stdout for cron logs
        print(log_message)
        
        return 0
        
    except Exception as e:
        error_msg = f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {str(e)}"
        print(error_msg, file=sys.stderr)
        try:
            with open(output_file, 'w') as f:
                f.write(error_msg + '\n')
        except:
            pass
        return 1


if __name__ == '__main__':
    sys.exit(main())
