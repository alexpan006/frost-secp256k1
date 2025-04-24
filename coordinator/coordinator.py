import asyncio
import httpx
import json
import logging
from typing import List, Tuple
import os
from bitcoinlib.keys import Key
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Read signer URLs from environment variable
signer_urls_str = os.getenv("SIGNER_URLS")
if not signer_urls_str:
    logger.error("Environment variable SIGNER_URLS is not set.")
    raise ValueError("SIGNER_URLS is required.")

SIGNERS = signer_urls_str.split(",")




async def check_dkg_status(client: httpx.AsyncClient) -> Tuple[bool, str]:
    """
    Checks if all signers have existing keys.
    Returns True if all signers have keys, False otherwise.
    """
    status_tasks = [client.get(f"{signer}/dkg/status") for signer in SIGNERS]
    try:
        responses = await asyncio.gather(*status_tasks)
        statuses = [resp.json() for resp in responses]
        for status in statuses:
            if not status["is_exist"]:
                logger.info(f"Signer {status['id']} does not have keys. DKG is needed.")
                return (False,"")
        logger.info("All signers have existing keys. No DKG needed.")
        return (True,statuses[0]["verify_key_hex"])
    except Exception as e:
        logger.error(f"Failed to check DKG status: {e}")
        raise






async def run_dkg():
    """
    Orchestrates the DKG process across multiple signer nodes.
    Returns the group verifying key upon completion.
    """
    async with httpx.AsyncClient() as client:
        
        is_exist, verify_key_hex = await check_dkg_status(client)
        if is_exist:
            logger.info("All signers have keys. No DKG needed.")
            return verify_key_hex
        logger.info("Starting DKG process...")

        
        # --- Round 1: Collect broadcast packages from all signers ---
        logger.info("Starting DKG Round 1...")
        round1_tasks = [client.post(f"{signer}/dkg/round1") for signer in SIGNERS]
        try:
            round1_responses = await asyncio.gather(*round1_tasks)
            round1_data = [resp.json() for resp in round1_responses]
        except Exception as e:
            logger.error(f"Round 1 failed: {e}")
            raise

        # Extract id and pkg_hex from each response
        r1_pkgs: List[Tuple[str, str]] = [(data["id_hex"], data["pkg_hex"]) for data in round1_data]
        logger.info(f"Round 1 completed. Collected packages: {r1_pkgs}")





        # --- Round 2: Distribute Round 1 packages and collect Round 2 packages ---
        logger.info("Starting DKG Round 2...")
        round2_tasks = []
        for signer, self_id in zip(SIGNERS, [data["id_hex"] for data in round1_data]):
            # logger.info(f"Signer =  {signer}, for Round 2")
            # Exclude the signer's own package
            pkgs_for_signer = [pkg for pkg in r1_pkgs if pkg[0] != self_id]
            body = {"pkgs_hex": pkgs_for_signer}
            round2_tasks.append(client.post(f"{signer}/dkg/round2", json=body))

        try:
            round2_responses = await asyncio.gather(*round2_tasks)
            round2_data = [resp.json() for resp in round2_responses]
        except Exception as e:
            logger.error(f"Round 2 failed: {e}")
            raise

        # Extract id and pkgs2_json from each response
        r2_pkgs_json = [(data["id_hex"],data["pkgs2_json"]) for data in round2_data]
        # logger.info(f"Round 2 completed. Collected packages: {r2_pkgs_json}")

        # Parse the JSON strings to get the actual Round 2 packages
        r2_pkgs: List[Tuple[int, Tuple[int, str]]] = []
        for sender_id, pkgs_json in r2_pkgs_json:
            pkgs = json.loads(pkgs_json)  # List of [target_id, pkg_hex]
            for pkg in pkgs:
                target_id, pkg_hex = pkg
                r2_pkgs.append((sender_id, (target_id, pkg_hex)))
        logger.info(f"Parsed Round 2 packages: {r2_pkgs}")
        
        
        
        
        # --- Round 3: Distribute Round 1 and Round 2 packages and finalize DKG ---
        logger.info("Starting DKG Round 3...")
        round3_tasks = []
        for signer, self_id in zip(SIGNERS, [data["id_hex"] for data in round1_data]):
            # All Round 1 packages are sent to every signer
            # r1_pkgs_for_signer = r1_pkgs
            # r1_pkgs_for_signer = r1_pkgs
            # logger.info(f"Signer =  {r1_pkgs_for_signer}, for Round 3")
            r1_pkgs_for_signer = [
                (sender_id, pkg) for sender_id, pkg in r1_pkgs if sender_id != self_id
            ]
            # Filter Round 2 packages intended for this signer
            r2_pkgs_for_signer = [
                (sender_id, pkg[1]) for sender_id, pkg in r2_pkgs if pkg[0] == self_id
            ]
            body = {
                "r1_pkgs_hex": r1_pkgs_for_signer,
                "r2_pkgs_hex": r2_pkgs_for_signer
            }
            # logger.info(f"Sending Round 3 packages to {signer}: {body}")
            
            # logger.info(f"Sending Round 3 packages to {signer}: {body}")
            round3_tasks.append(client.post(f"{signer}/dkg/round3", json=body))

        try:
            round3_responses = await asyncio.gather(*round3_tasks)
            round3_data = [resp.json() for resp in round3_responses]
        except Exception as e:
            logger.error(f"Round 3 failed: {e}")
            raise

        # Extract group verifying key (should be the same for all signers)
        verify_key_hex = round3_data[0]["verify_key_hex"]
        logger.info(f"DKG completed. Group Verifying Key: {verify_key_hex}")

        return verify_key_hex

if __name__ == "__main__":
    try:
        group_vk_hex = asyncio.run(run_dkg())
        # Create a Key object for Taproot (x-only public key)
        key = Key(import_key=bytes.fromhex(group_vk_hex), compressed=True, network='testnet')

        # Derive the Taproot (P2TR) address
        address = key.address(script_type ='p2tr')

        print(f"Taproot Address: {address}")
        print(f"Group Verifying Key: {group_vk_hex}")
    except Exception as e:
        logger.error(f"DKG process failed: {e}")
        raise