import os
import json
import hashlib
from typing import List, Tuple # Import these
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel # Import BaseModel
import logging

# Assuming your compiled rust lib is importable as rust_ffi
import rust_tss as rust_tss

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Configuration & PID Handling ---
try:
    # Use the integer PID directly as passed to Rust
    PID = int(os.environ["PARTY_ID"])
    N = int(os.environ["TOTAL"])      # total signers
    T = int(os.environ["THRESHOLD"])  # min signers
    if PID == 0: # Basic validation based on Rust constraints
         raise ValueError("PARTY_ID cannot be zero")
except KeyError as e:
    logger.error(f"Missing environment variable: {e}")
    exit(1)
except ValueError as e:
     logger.error(f"Invalid environment variable (PARTY_ID must be > 0, N, T must be integers): {e}")
     exit(1)

logger.info(f"Party ID (u16): {PID}")
logger.info(f"DKG Config: T={T}, N={N}")

app = FastAPI()


# --- Helper function for error handling ---
def handle_rust_error(e: Exception, context: str):
     logger.error(f"Error during {context}: {e}")
     # Check if it's a PyO3 mapped exception or a base Python one
     if isinstance(e, (RuntimeError, ValueError, ConnectionError, OSError, SystemError)): # SystemError might map from some panics
         raise HTTPException(status_code=500, detail=f"Internal Server Error: {context}: {e}")
     else: # Catchall for unexpected errors
          raise HTTPException(status_code=500, detail=f"Internal Server Error: {context}: Unexpected error type {type(e)}")


# --- Pydantic Models for Request Bodies ---
# Use u16 (int in Python) for participant IDs
class DkgRound2Body(BaseModel):
    pkgs_hex: List[Tuple[str, str]] # List of (pid_u16, pkg_hex)

class DkgRound3Body(BaseModel):
    r1_pkgs_hex: List[Tuple[str, str]] # List of (pid_u16, pkg_hex)
    r2_pkgs_hex: List[Tuple[str, str]] # List of (pid_u16, pkg_hex)

# Optional: Model for init endpoint if you add it
class InitBody(BaseModel):
    key_package_hex: str
    public_key_package_hex: str
    
# --- Models for Signing ---
class SigningRound2Body(BaseModel):
    message_hex: str
    commitments: List[Tuple[str, str]]



# ------- Check Key Existence Endpoint --------
@app.get("/dkg/status")
async def dkg_status():
    global PID_HEX
    logger.info(f"[{PID}] Received request for /dkg/status")
    try:
        # Call Rust FFI with integer PID
        is_exists,verify_key_hex,pubkp,id_hex = rust_tss.init(PID)
        PID_HEX = id_hex
        if is_exists:
            # logger.info(f"[{PID}] Keys exist. Verifying Key: {verify_key_hex}")
            return {"id": PID, "is_exist":is_exists,"verify_key_hex": verify_key_hex,"pubkp_hex": pubkp,"id_hex":id_hex}
        else:
            logger.info(f"[{PID}] Keys do not exist.")
            return {"id": PID, "is_exist":is_exists,"verify_key_hex": verify_key_hex,"pubkp_hex": pubkp,"id_hex":id_hex}
    except Exception as e:
         handle_rust_error(e, "DKG Status Check")


# ------- Round-1 Endpoint --------
@app.post("/dkg/round1")
async def dkg_round1_endpoint():
    global PID_HEX

    logger.info(f"[{PID}] Received request for /dkg/round1")
    try:
        # Call Rust FFI with integer PID
        # Rust dkg_round1 now returns single string: bcast_pkg_hex
        _PID_HEX,bcast_pkg_hex = rust_tss.dkg_round1(PID, N, T)
        PID_HEX = _PID_HEX
        logger.info(f"[{PID}] DKG Round 1 successful.")
        # Return structure contains integer PID
        return {"id_hex": PID_HEX, "pkg_hex": bcast_pkg_hex}
    except Exception as e:
        handle_rust_error(e, "DKG Round 1")


# ------- Round-2 Endpoint --------
@app.post("/dkg/round2")
async def dkg_round2_endpoint(body: DkgRound2Body):
    logger.info(f"[{PID}] Received request for /dkg/round2 with {len(body.pkgs_hex)} packages.")
    if not body.pkgs_hex:
         raise HTTPException(status_code=400, detail="Missing 'pkgs_hex' in request body")
    try:
        # Pass integer PIDs and packages directly to Rust
        # Rust returns JSON string: '[ [pid_u16, pkg2_hex], ... ]'
        pkgs2_json_str = rust_tss.dkg_round2(PID_HEX, body.pkgs_hex)
        # logger.info(f"TESTING!!!!!! [{PID}] DKG Round 2 successful. Packages: {pkgs2_json_str}")
        logger.info(f"[{PID}] DKG Round 2 successful.")
        # Return JSON string containing list of [pid_u16, pkg2_hex]
        # Client/Orchestrator needs to json.loads() this string
        return {"id_hex": PID_HEX, "pkgs2_json": pkgs2_json_str}
    except Exception as e:
        handle_rust_error(e, "DKG Round 2")


# ------- Round-3 Endpoint --------
@app.post("/dkg/round3")
async def dkg_round3_endpoint(body: DkgRound3Body):
    logger.info(f"[{PID}] Received request for /dkg/round3.")
    if not body.r1_pkgs_hex or not body.r2_pkgs_hex:
         raise HTTPException(status_code=400, detail="Missing 'r1_pkgs_hex' or 'r2_pkgs_hex' in request body")
    try:
        # Pass integer PIDs and packages directly to Rust
        # Rust returns (kp_hex, pubkp_hex, verify_key_hex)
        _pubkp_hex,_verify_key_hex  = rust_tss.dkg_round3(
            PID_HEX,
            body.r1_pkgs_hex,
            body.r2_pkgs_hex
        )
        # Persistence is handled by Rust/sled. No file writing here.
        logger.info(f"[{PID}] DKG Round 3 successful. Keys persisted in Rust/sled.")
        logger.info(f"[{PID}] Group public key pkg hash Verifying Key (x-only hex): {_verify_key_hex}")
        # Return the final group verifying key (needed for address generation)
        return {"id": PID, "verify_key_hex": _verify_key_hex,"pubkp_hex": _pubkp_hex}
    except Exception as e:
        handle_rust_error(e, "DKG Round 3")

# ------- For signing --------

@app.post("/sign/round1")
async def signing_round1():
    try:
        logger.info(f"[{PID}] Received request for /sign/round1")
        commitments_hex = rust_tss.sign_round1(PID_HEX)
        logger.info(f"[{PID}] Frost signing Round 1 successful.")
        # Return structure contains PID
        return {"id": PID_HEX, "commitment": commitments_hex}
    except Exception as e:
        handle_rust_error(e, "Signing Round 1")

@app.post("/sign/round2")
async def signing_round2(body: SigningRound2Body):
    try:
        is_valid = dummy_verify(body.message_hex)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid message hex, potentially malformed transaction, decline to sign.")
        logger.info(f"[{PID}] Received request for /sign/round2")
        sig_share_hex = rust_tss.sign_round2(PID_HEX, body.message_hex, body.commitments)
        logger.info(f"[{PID}] Frost signing Round 2 successful.")
        return {"id": PID_HEX, "sig_share": sig_share_hex}
    except Exception as e:
        handle_rust_error(e, "Signing Round 2")
        
        
def dummy_verify(message_hex: str):
    # Dummy verification function
    # In a real-world scenario, you would implement the actual verification logic here
    return True

