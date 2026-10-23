from web3 import Web3
import json
import rlp
from eth_utils import keccak, decode_hex, encode_hex
import os
from dotenv import load_dotenv

load_dotenv()
INFURA_API_KEY = os.getenv("INFURA_API_KEY")
INFURA_URL = f"https://mainnet.infura.io/v3/{INFURA_API_KEY}"

w3 = Web3(Web3.HTTPProvider(INFURA_URL))

def fetch_trie_kv_pairs(num_accounts=50, output_file=None, block_number='latest'):
    """
    Fetch accounts and construct their exact State Trie Key-Value pairs.
    """
    if not w3.is_connected():
        print("Failed to connect to Infura")
        return None
    
    # Get block info
    block = w3.eth.get_block(block_number)
    
    print(f"Connected to Ethereum mainnet")
    print(f"Block: {block['number']}")
    print("=" * 60)
    
    # Collect addresses from recent blocks
    addresses = set()
    for i in range(50):
        if len(addresses) >= num_accounts:
            break
        try:
            blk = w3.eth.get_block(block['number'] - i, full_transactions=True)
            for tx in blk.transactions:
                addresses.add(tx['from'])
                if tx['to']:
                    addresses.add(tx['to'])
        except Exception:
            continue
    
    print(f"\nCollected {len(addresses)} addresses")
    print("Fetching account states and calculating KV pairs...\n")
    
    # Dictionary to hold the final { "0xKey": "0xValue" } pairs
    trie_kv_data = {}
    
    for idx, address in enumerate(list(addresses)[:num_accounts]):
        try:
            # Fetch the account proof to get the exact state at this block
            proof = w3.eth.get_proof(
                Web3.to_checksum_address(address),
                [],  # No storage proofs needed
                block_number
            )
            
            # --- CALCULATE THE EXACT KEY ---
            # In the Secure Trie, the path (key) is the Keccak256 hash of the address
            address_bytes = decode_hex(address)
            trie_key = keccak(address_bytes)
            
            # --- CALCULATE THE EXACT VALUE ---
            # The leaf value is the RLP encoded list of [nonce, balance, storageRoot, codeHash]
            # Note: Web3 returns hashes as HexBytes, we must cast them to raw bytes for RLP
            account_state = [
                proof.nonce,
                proof.balance,
                bytes(proof.storageHash),
                bytes(proof.codeHash)
            ]
            trie_value = rlp.encode(account_state)
            
            # Convert both to hex strings for JSON serialization
            hex_key = encode_hex(trie_key)
            hex_value = encode_hex(trie_value)
            
            trie_kv_data[hex_key] = hex_value
            
            print(f"[{idx+1}/{num_accounts}] Processed Address: {address}")
            print(f"  Key:   {hex_key}")
            print(f"  Value: {hex_value[:20]}...{hex_value[-10:]}\n")
            
        except Exception as e:
            print(f"  Error processing {address}: {e}\n")
            continue
    
    # Save to JSON
    if output_file is not None:
        with open(output_file, 'w') as f:
            json.dump(trie_kv_data, f, indent=4)
    
    # print("=" * 60)
    # print(f"COMPLETE! Saved {len(trie_kv_data)} key-value pairs to {output_file}")
    # print("=" * 60)
    
    return trie_kv_data

if __name__ == '__main__':
    fetch_trie_kv_pairs(num_accounts=1024)