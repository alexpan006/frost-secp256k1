# Threshold Signature Scheme (TSS) for Bitcoin Taproot using FROST

This project implements a distributed threshold signature scheme (TSS) for Bitcoin Taproot transactions using the FROST protocol. It is designed for research, testing, and demonstration of secure multi-party signing, and is orchestrated using Docker Compose for easy scaling and simulation.

---

## System Overview

The system consists of:
- **Signer Nodes:** Each runs in its own Docker container, exposes a FastAPI HTTP API, and uses a Rust library (via PyO3) for cryptographic operations. Each signer persists its state in a local sled database and participates in distributed key generation (DKG) and signing rounds.
- **Coordinator Node:** Orchestrates the DKG and signing process by communicating with all signers via HTTP. It collects and distributes protocol messages, aggregates signature shares, and can construct and broadcast Bitcoin transactions.
- **Rust Cryptography Library:** Implements the FROST protocol for threshold Schnorr signatures, as well as Bitcoin Taproot transaction construction and signing. Exposed to Python via PyO3.

---

## Protocol Workflow

### Distributed Key Generation (DKG)
- The coordinator initiates a 3-round DKG protocol among all signers.
- Each round involves exchanging protocol messages (packages) between signers, with the coordinator relaying messages.
- At the end of DKG, each signer holds a share of the private key, and the group public key is established.

### Signing (FROST)
- Signing is a 2-round protocol:
  - **Round 1:** Each signer generates and broadcasts a signing commitment (nonce).
  - **Round 2:** Each signer receives all commitments and the message to sign, then produces a signature share.
- The coordinator collects signature shares and aggregates them into a final Schnorr signature.

### Bitcoin Transaction Handling
- The system can construct, sign, and broadcast Bitcoin Taproot transactions using the threshold signature.
- The process:
  1. The coordinator creates an unsigned Bitcoin transaction and computes the Taproot sighash (the message to be signed).
  2. The sighash is distributed to all signers, who use the FROST protocol to generate signature shares.
  3. The coordinator aggregates the signature shares into a single Schnorr signature.
  4. The aggregated signature is inserted into the transaction’s witness field, finalizing the signed transaction.
  5. The fully signed transaction can then be broadcast to the Bitcoin network.
- **Note:** This approach is similar in spirit to PSBT (Partially Signed Bitcoin Transaction), but uses a custom workflow optimized for threshold signing and does not use the PSBT format.

---

## Deployment & Simulation

### Prerequisites
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- Python 3.8+ (for local scripts or API interaction)

### Build and Start the Network

```sh
docker-compose build
docker-compose up
```

This will launch all signer and coordinator containers. Each signer will initialize its state and expose its API.

### Running a Simulation

1. **Trigger DKG:**  
   Use an HTTP client (e.g., `curl`, Postman, or a Python script) to call the coordinator’s DKG endpoint, or let the coordinator start DKG automatically if implemented.

2. **Simulate a Signing Session:**  
   - Prepare a message or transaction to sign.
   - Use an HTTP request to the coordinator to start the signing protocol.
   - The coordinator will coordinate the FROST signing protocol, collect signature shares, aggregate them, and finalize the signature.

3. **Broadcast a Transaction (Optional):**  
   - If signing a Bitcoin transaction, the coordinator can broadcast the signed transaction to the Bitcoin network (testnet or mainnet).

4. **Observe Logs and Results:**  
   - Logs from all containers will be visible in your terminal or via `docker-compose logs`.
   - You can inspect the output, signatures, and transaction status.

---

## Key Features

- **Scalable:** Easily increase the number of signers by editing the Docker Compose file.
- **Modular:** Clear separation of orchestration (Python), cryptography (Rust), and deployment (Docker).
- **Secure:** Each signer holds only its own key share; the private key is never reconstructed in one place.

---

## Important Usage Notes

- **DKG First:**  
  Always complete the DKG process first. This will generate the group Taproot address, which represents the joint control of the bridge.

- **Funding Required:**  
  Before you can create and sign a transaction from the bridge account, you must send funds to the generated Taproot address. This is necessary for demonstrating the signing and spending process.

- **Transaction Demonstration:**  
  The transaction creation and signing code is provided for demonstration purposes only. This is not a standard operation for bridge setup. For more details on the protocol and when such operations are needed, please refer to the thesis.

- **How to Proceed:**  
  1. Complete DKG to obtain the Taproot address.
  2. Send funds to this address.
  3. Set the transaction parameters (UTXO details, recipient, amounts, etc.) according to your actual UTXO.
  4. Uncomment and run the transaction proposal and signing code in `coordinator.py` as needed.

---

## Notes

- This system is for research and testing. Do not use in production without a thorough security review.
- For large-scale simulations (e.g., 100+ signers), consider scripting the generation of the `docker-compose.yml` file.

---

## License

[MIT](LICENSE) or as specified in this repository.
