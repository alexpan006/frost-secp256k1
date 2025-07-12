import asyncio
import httpx
import json
import logging
from typing import List, Tuple
import os
import requests
from bitcoinlib.keys import Key,Address
import rust_tss as rust_tss
from bitcoinlib.services.services import Service 
from bitcoinlib.transactions import Transaction
# Configure logging
class CustomFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = self.formatter_time_with_ms(ct, record)
        else:
            s = logging.Formatter.formatTime(self, record, datefmt)
        return s

    def formatter_time_with_ms(self, ct, record):
        return f"{ct.tm_year}-{ct.tm_mon:02}-{ct.tm_mday:02} {ct.tm_hour:02}:{ct.tm_min:02}:{ct.tm_sec:02}.{int(record.msecs):03}"

formatter = CustomFormatter(
    fmt='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False  # Avoid double logging if root logger also set
# Read signer URLs from environment variable
signer_urls_str = os.getenv("SIGNER_URLS")
if not signer_urls_str:
    logger.error("Environment variable SIGNER_URLS is not set.")
    raise ValueError("SIGNER_URLS is required.")

SIGNERS = signer_urls_str.split(",")




async def check_dkg_status(client: httpx.AsyncClient) -> Tuple[bool, str,str]:
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
                return (False,"","")
        logger.info("All signers have existing keys. No DKG needed.")
        return (True,statuses[0]["verify_key_hex"],statuses[0]["pubkp_hex"])
    except Exception as e:
        logger.error(f"Failed to check DKG status: {e}")
        raise






async def run_dkg():
    """
    Orchestrates the DKG process across multiple signer nodes.
    Returns the group verifying key upon completion.
    """
    async with httpx.AsyncClient() as client:
        
        is_exist, verify_key_hex,pubkp = await check_dkg_status(client)
        if is_exist:
            logger.info("All signers have keys. No DKG needed.")
            return verify_key_hex,pubkp
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
        logger.info(f"Round 1 completed.")
        # --- Round 2: Distribute Round 1 packages and collect Round 2 packages ---
        logger.info("Starting DKG Round 2...")
        round2_tasks = []
        for signer, self_id in zip(SIGNERS, [data["id_hex"] for data in round1_data]):
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

        # Parse the JSON strings to get the actual Round 2 packages
        r2_pkgs: List[Tuple[int, Tuple[int, str]]] = []
        for sender_id, pkgs_json in r2_pkgs_json:
            pkgs = json.loads(pkgs_json)  # List of [target_id, pkg_hex]
            for pkg in pkgs:
                target_id, pkg_hex = pkg
                r2_pkgs.append((sender_id, (target_id, pkg_hex)))
        # logger.info(f"Parsed Round 2 packages: {r2_pkgs}")
        logger.info(f"Round 2 Completed")
        
        
        
        # --- Round 3: Distribute Round 1 and Round 2 packages and finalize DKG ---
        logger.info("Starting DKG Round 3...")
        round3_tasks = []
        for signer, self_id in zip(SIGNERS, [data["id_hex"] for data in round1_data]):
            # All Round 1 packages are sent to every signer
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
            round3_tasks.append(client.post(f"{signer}/dkg/round3", json=body))
        try:
            round3_responses = await asyncio.gather(*round3_tasks)
            round3_data = [resp.json() for resp in round3_responses]
        except Exception as e:
            logger.error(f"Round 3 failed: {e}")
            raise

        # Extract group verifying key (should be the same for all signers)
        verify_key_hex = round3_data[0]["verify_key_hex"]
        pubkp_hex = round3_data[0]["pubkp_hex"]
        logger.info(f"DKG completed. Group Verifying Key: {verify_key_hex}. Public Key Pkg: {pubkp_hex}")

        return verify_key_hex,pubkp_hex


async def coordinate_frost_sign(message: str, pubkp_hex: str):

    logger.info(f"From the FUnction: Message to sign: {message}")
    async with httpx.AsyncClient() as client:
        # --- Round 1: Get commitments from each signer
        logger.info("Starting Frost Sign Round 1, sending out to signers...")
        round1_tasks = [client.post(f"{signer}/sign/round1") for signer in SIGNERS]
        round1_responses = await asyncio.gather(*round1_tasks)
        round1_commitments = [
            (resp.json()["id"], resp.json()["commitment"]) for resp in round1_responses
        ]
        logger.info("Frost Sign Round 1 complete...")
        # --- Round 2: Send commitments + message to each signer
        logger.info("Starting Frost Sign Round 2, sending out to signers...")
        round2_tasks = []
        for signer, (sid, _) in zip(SIGNERS, round1_commitments):
            body = {
                "message_hex": message,
                "commitments": round1_commitments  # All commitments
            }
            round2_tasks.append(client.post(f"{signer}/sign/round2", json=body))

        round2_responses = await asyncio.gather(*round2_tasks)
        sig_shares = [
            (resp.json()["id"], resp.json()["sig_share"]) for resp in round2_responses
        ]
        logger.info("Starting Signature Aggregation...")
        # --- Coordinator aggregates signature
        aggregated_sig = rust_tss.aggregate_signature(message, sig_shares, round1_commitments, pubkp_hex)
        logger.info(f"Aggregated Schnorr Signature: {aggregated_sig}")
        return aggregated_sig

def broadcast_tx(tx_hex: str, network: str = "testnet") -> str:
    """
    Broadcast the signed transaction using Bitcoinlib.
    """
    service = Service(network=network)
    txid = service.sendrawtransaction(tx_hex)
    logger.info(f"Broadcasted transaction. TXID: {txid}")
    return txid

def broadcast_tx_mempool(tx_hex: str):
    url = "https://mempool.space/testnet/api/tx"
    headers = {"Content-Type": "text/plain"}
    response = requests.post(url, data=tx_hex, headers=headers)
    
    if response.status_code != 200:
        raise Exception(f"Broadcast failed: {response.text}")
    
    txid = response.text.strip()
    return txid

def fetch_fee_rate(network='testnet', priority='medium') -> int:
    """
    Fetch estimated fee rate (sats/vbyte) using bitcoinlib's estimatefee.
    
    Args:
        network (str): 'mainnet' | 'testnet' etc
        priority (str): 'low' | 'medium' | 'high'
        
    Returns:
        int: fee rate in sats/vbyte
    """
    service = Service(network=network)
    fee_per_kb = service.estimatefee(priority=priority)

    if not isinstance(fee_per_kb, int):
        raise ValueError(f"Invalid fee estimation response: {fee_per_kb}")
    
    # estimatefee returns fee per kilobyte → divide by 1000 to get per-byte
    fee_per_byte = fee_per_kb // 1000  

    if fee_per_byte == 0:
        # fallback to reasonable default
        fee_per_byte = 5
    
    print(f"Estimated fee rate ({priority}): {fee_per_byte} sats/vbyte")
    return fee_per_byte
def decode_signed_tx(signed_tx_hex: str):
    """
    Decode and inspect a signed Bitcoin transaction hex.
    
    Args:
        signed_tx_hex (str): The hex-encoded signed transaction.
    
    Returns:
        dict: Parsed details like inputs, outputs, amounts.
    """
    tx = Transaction.import_raw(signed_tx_hex)
    
    decoded = {
        "version": tx.version,
        "locktime": tx.locktime,
        "inputs": [],
        "outputs": [],
        "txid": tx.txid,
    }

    # Parse inputs
    for inp in tx.inputs:
        decoded["inputs"].append({
            "prev_txid": inp.txid,
            "vout": inp.txindex,
            "script_sig": inp.script,
            "sequence": inp.sequence,
        })

    # Parse outputs
    for outp in tx.outputs:
        decoded["outputs"].append({
            "value_satoshi": outp.value,
            "address": outp.address,
            "script_pubkey": outp.script,
        })
    
    return decoded

async def propose_tx_and_sign(
    utxo_txid: str,
    utxo_vout: int,
    utxo_value: int,
    prev_spk_hex:str,
    to_address: str,
    send_value: int,
    change_address: str,
    network: str,
    pubkp_hex: str,
):
    """
    Prepares a transaction dynamically (with fee estimation), gets FROST signature, and finalizes it.

    Args:
        utxo_txid: The TXID of the UTXO to spend.
        utxo_vout: The vout (output index) of the UTXO.
        utxo_value: The value of the UTXO (in sats).
        to_address: Recipient address.
        send_value: Amount to send (in sats).
        change_address: Change address to send leftover funds to.
        network: 'mainnet' | 'testnet'
        pubkp_hex: Group public key package hex (for FROST aggregation).

    Returns:
        signed_tx_hex (str)
    """

    logger.info("Fetching fee rate...")
    fee_rate = 2
    if fee_rate == 0:
        fee_rate = 5  # Fallback minimum fee rate
    logger.info(f"Estimated fee rate: {fee_rate} sats/vbyte")


    logger.info("Preparing unsigned transaction and sighash...")
    tx_hex, sighash_hex = rust_tss.prepare_unsigned_tx_and_sighash(
        utxo_txid,
        utxo_vout,
        utxo_value,
        prev_spk_hex,
        to_address,
        send_value,
        fee_rate,
        change_address,
        network
    )

    logger.info("Starting FROST signing over sighash...")
    logger.info(f"Transaction Hex: {tx_hex}")
    logger.info(f"Sighash Hex: {sighash_hex}")
    sig_hex = await coordinate_frost_sign(sighash_hex, pubkp_hex)

    logger.info("Finalizing the signed transaction...")
    signed_tx_hex = rust_tss.finalize_signed_tx_from_hex(tx_hex, sig_hex)

    return signed_tx_hex




if __name__ == "__main__":
    try:
        group_vk_hex,pubkp_hex = asyncio.run(run_dkg())
        taproot_address = rust_tss.derive_taproot_address(group_vk_hex, "testnet")
        logger.info(f"Taproot Address:{taproot_address}")
        
        
        
        # ===================== IMPORTANT USAGE NOTES =====================
        # 1. The DKG process must be completed first. This will generate the group Taproot address.
        #    This address represents the joint control of the bridge and should be used for all subsequent operations.
        #
        # 2. Before you can create and sign a transaction from the bridge account, you must ensure that the Taproot address
        #    has received sufficient funds. This is a prerequisite for demonstrating the signing and spending process.
        #
        # 3. The transaction creation and signing (see the commented-out section below) is NOT a common operation for bridge setup.
        #    It is included here for demonstration purposes only. Please refer to the thesis for more details on when and why
        #    you might need to perform such an operation.
        #
        # 4. To proceed:
        #    - Send funds to the generated Taproot address.
        #    - Set the transaction parameters (utxo_txid, utxo_vout, utxo_value, prev_spk_hex, to_address, send_value, change_address, network)
        #      according to the actual UTXO you control.
        #    - Uncomment and run the transaction proposal and signing code as needed.
        # ================================================================
        
        # --------- Create a Bitcoin trx (fill in your own UTXO and addresses) ---------
        # utxo_txid = "<YOUR_UTXO_TXID_HERE>"
        # utxo_vout = <YOUR_UTXO_VOUT_HERE>
        # utxo_value = <YOUR_UTXO_VALUE_IN_SATS>
        # prev_spk_hex = "<YOUR_PREV_SCRIPT_PUBKEY_HEX>"
        # to_address = "<RECIPIENT_ADDRESS>"
        # send_value = <AMOUNT_TO_SEND_IN_SATS>
        # change_address = "<YOUR_CHANGE_ADDRESS>"
        # network = "<NETWORK_NAME>"  # e.g., "testnet" or "mainnet"
        # logger.info(f"Preparing to propose transaction with UTXO {utxo_txid}:{utxo_vout} of value {utxo_value} sats")
        # signed_tx_hex = asyncio.run(
        #     propose_tx_and_sign(
        #         utxo_txid,
        #         utxo_vout,
        #         utxo_value,
        #         prev_spk_hex,
        #         to_address,
        #         send_value,
        #         change_address,
        #         network,
        #         pubkp_hex
        #     )
        # )
        # logger.info(f"Signed Transaction Hex:{signed_tx_hex}")
        # txid = broadcast_tx_mempool(signed_tx_hex)
        # logger.info(f"Broadcasted TXID:{txid}")
        
    except Exception as e:
        logger.error(f"DKG process failed: {e}")
        raise