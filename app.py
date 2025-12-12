#!/usr/bin/env python3
"""
PKI-Based 2FA Microservice API
FastAPI application with three endpoints for seed decryption and TOTP operations
"""

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from crypto import load_private_key, decrypt_seed, hex_to_base32
from totp import generate_totp_code, verify_totp_code


# Configuration
# Use local data directory for development, /data for Docker
SEED_FILE_PATH = os.environ.get("SEED_FILE_PATH", "data/seed.txt")
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "student_private.pem")

# Initialize FastAPI app
app = FastAPI(
    title="PKI-Based 2FA Microservice",
    description="Secure authentication microservice using RSA/OAEP and TOTP",
    version="1.0.0"
)


# ===========================
# Request/Response Models
# ===========================

class DecryptSeedRequest(BaseModel):
    """Request model for POST /decrypt-seed"""
    encrypted_seed: str


class DecryptSeedResponse(BaseModel):
    """Response model for POST /decrypt-seed"""
    status: str


class Generate2FAResponse(BaseModel):
    """Response model for GET /generate-2fa"""
    code: str
    valid_for: int


class Verify2FARequest(BaseModel):
    """Request model for POST /verify-2fa"""
    code: str


class Verify2FAResponse(BaseModel):
    """Response model for POST /verify-2fa"""
    valid: bool


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str


# ===========================
# Helper Functions
# ===========================

def ensure_data_directory():
    """Ensure /data directory exists"""
    data_dir = Path(SEED_FILE_PATH).parent
    data_dir.mkdir(parents=True, exist_ok=True)


def read_seed_from_file() -> Optional[str]:
    """
    Read hex seed from persistent storage
    
    Returns:
        Hex seed string or None if file doesn't exist
    """
    if not os.path.exists(SEED_FILE_PATH):
        return None
    
    try:
        with open(SEED_FILE_PATH, 'r') as f:
            seed = f.read().strip()
        return seed if seed else None
    except Exception:
        return None


def write_seed_to_file(hex_seed: str):
    """
    Write hex seed to persistent storage
    
    Args:
        hex_seed: 64-character hex string
    """
    ensure_data_directory()
    with open(SEED_FILE_PATH, 'w') as f:
        f.write(hex_seed)


# ===========================
# API Endpoints
# ===========================

@app.get("/", tags=["Health"])
def root():
    """Health check endpoint"""
    return {
        "service": "PKI-Based 2FA Microservice",
        "status": "running",
        "endpoints": [
            "POST /decrypt-seed",
            "GET /generate-2fa",
            "POST /verify-2fa"
        ]
    }


@app.post(
    "/decrypt-seed",
    response_model=DecryptSeedResponse,
    responses={
        200: {"model": DecryptSeedResponse},
        500: {"model": ErrorResponse}
    },
    tags=["Seed Management"]
)
def decrypt_seed_endpoint(request: DecryptSeedRequest):
    """
    Endpoint 1: Decrypt encrypted seed and store persistently
    
    Decrypts the base64-encoded encrypted seed using student's private key
    (RSA/OAEP-SHA256) and saves it to /data/seed.txt for persistent storage.
    
    Args:
        request: Contains encrypted_seed (base64-encoded)
    
    Returns:
        {"status": "ok"} on success
        {"error": "Decryption failed"} on failure (HTTP 500)
    """
    try:
        # Step 1: Load student private key from file
        private_key = load_private_key(PRIVATE_KEY_PATH)
        
        # Step 2-3: Decrypt using RSA/OAEP-SHA256 (handled in decrypt_seed)
        hex_seed = decrypt_seed(request.encrypted_seed, private_key)
        
        # Step 4: Validation is done inside decrypt_seed function
        # (checks 64-character hex format)
        
        # Step 5: Save to /data/seed.txt
        write_seed_to_file(hex_seed)
        
        # Step 6: Return success
        return DecryptSeedResponse(status="ok")
        
    except Exception as e:
        # Return 500 on any decryption error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed"
        )


@app.get(
    "/generate-2fa",
    response_model=Generate2FAResponse,
    responses={
        200: {"model": Generate2FAResponse},
        500: {"model": ErrorResponse}
    },
    tags=["2FA Operations"]
)
def generate_2fa_endpoint():
    """
    Endpoint 2: Generate current TOTP code
    
    Reads the decrypted seed from persistent storage, generates the current
    TOTP code, and calculates remaining validity seconds.
    
    Returns:
        {"code": "123456", "valid_for": 30} on success
        {"error": "Seed not decrypted yet"} if seed unavailable (HTTP 500)
    """
    try:
        # Step 1: Check if /data/seed.txt exists
        hex_seed = read_seed_from_file()
        
        if hex_seed is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Seed not decrypted yet"
            )
        
        # Step 2: Read hex seed from file (already done above)
        
        # Step 3-4: Generate TOTP code and calculate remaining seconds
        base32_seed = hex_to_base32(hex_seed)
        code, valid_for = generate_totp_code(base32_seed)
        
        # Step 5: Return code and valid_for
        return Generate2FAResponse(code=code, valid_for=valid_for)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Seed not decrypted yet"
        )


@app.post(
    "/verify-2fa",
    response_model=Verify2FAResponse,
    responses={
        200: {"model": Verify2FAResponse},
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    },
    tags=["2FA Operations"]
)
def verify_2fa_endpoint(request: Verify2FARequest):
    """
    Endpoint 3: Verify TOTP code
    
    Verifies the provided 6-digit TOTP code against the stored seed
    with ±1 period tolerance (±30 seconds) to handle clock skew.
    
    Args:
        request: Contains code (6-digit string)
    
    Returns:
        {"valid": true/false} on success
        {"error": "Missing code"} if code not provided (HTTP 400)
        {"error": "Seed not decrypted yet"} if seed unavailable (HTTP 500)
    """
    try:
        # Step 1: Validate code is provided
        if not request.code or not request.code.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing code"
            )
        
        # Step 2: Check if /data/seed.txt exists
        hex_seed = read_seed_from_file()
        
        if hex_seed is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Seed not decrypted yet"
            )
        
        # Step 3: Read hex seed from file (already done above)
        
        # Step 4: Verify TOTP code with ±1 period tolerance
        base32_seed = hex_to_base32(hex_seed)
        is_valid = verify_totp_code(request.code.strip(), base32_seed, tolerance=1)
        
        # Step 5: Return validation result
        return Verify2FAResponse(valid=is_valid)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Seed not decrypted yet"
        )


# ===========================
# Application Entry Point
# ===========================

if __name__ == "__main__":
    import uvicorn
    
    # Run the API server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
