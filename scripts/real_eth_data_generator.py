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

def fetch_real_state_trie(num_accounts=50, block_number='latest'):
    """
    Fetch ACTUAL state trie nodes using eth_getProof.
    This is the real trie structure, not reconstructed data.
    """
    
    if not w3.is_connected():
        print("Failed to connect to Infura")
        return None
    
    # Get block info
    block = w3.eth.get_block(block_number)
    state_root = block['stateRoot'].hex()
    
    print(f"Connected to Ethereum mainnet")
    print(f"Block: {block['number']}")
    print(f"State Root: {state_root}")
    print("=" * 60)
    
    # Collect addresses
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
        except:
            continue
    
    print(f"\nCollected {len(addresses)} addresses")
    print("Fetching REAL trie nodes...\n")
    
    # Storage for real trie
    trie_data = {
        'state_root': state_root,
        'block_number': block['number'],
        'nodes': {},
        'accounts': []
    }
    
    for idx, address in enumerate(list(addresses)[:num_accounts]):
        try:
            # ===== THIS ACCESSES THE REAL TRIE =====
            proof = w3.eth.get_proof(
                Web3.to_checksum_address(address),
                [],  # No storage proofs
                block_number
            )
            
            print(f"[{idx+1}/{num_accounts}] {address}")
            print(f"  Proof depth: {len(proof.accountProof)} nodes")
            
            account = {
                'address': address,
                'address_hash': '0x' + keccak(decode_hex(address)).hex(),
                'balance': proof.balance,
                'nonce': proof.nonce,
                'proof_nodes': []
            }
            
            # Process each REAL trie node
            for depth, node_bytes in enumerate(proof.accountProof):
                node_hex = encode_hex(node_bytes)
                
                # Calculate node hash
                if len(node_bytes) >= 32:
                    node_hash = '0x' + keccak(node_bytes).hex()
                else:
                    node_hash = node_hex
                
                # Decode structure
                decoded = rlp.decode(node_bytes)
                if len(decoded) == 17:
                    node_type = 'branch'
                elif len(decoded) == 2:
                    prefix = decoded[0][0] if len(decoded[0]) > 0 else 0
                    node_type = 'leaf' if (prefix & 0x20) else 'extension'
                else:
                    node_type = 'unknown'
                
                # Store node
                if node_hash not in trie_data['nodes']:
                    trie_data['nodes'][node_hash] = {
                        'hash': node_hash,
                        'rlp': node_hex,
                        'type': node_type,
                        'size': len(node_bytes)
                    }
                
                account['proof_nodes'].append({
                    'depth': depth,
                    'hash': node_hash,
                    'type': node_type
                })
                
                print(f"    Node {depth}: {node_type} ({len(node_bytes)} bytes)")
            
            trie_data['accounts'].append(account)
            print()
            
        except Exception as e:
            print(f"  Error: {e}\n")
            continue
    
    # Summary
    print("=" * 60)
    print(f"COMPLETE!")
    print(f"Accounts: {len(trie_data['accounts'])}")
    print(f"Unique Nodes: {len(trie_data['nodes'])}")
    print("=" * 60)
    
    # Save
    with open('ethereum_real_state_trie.json', 'w') as f:
        json.dump(trie_data, f, indent=2)
    
    print("\nSaved to: ethereum_real_state_trie.json")
    
    return trie_data

if __name__ == '__main__':
    trie_data = fetch_real_state_trie(num_accounts=50)
    
    if trie_data and trie_data['accounts']:
        print("\n" + "=" * 60)
        print("EXAMPLE: First Account's Real Trie Path")
        print("=" * 60)
        
        example = trie_data['accounts'][0]
        print(f"\nAddress: {example['address']}")
        print(f"Balance: {example['balance']} wei")
        print(f"\nReal Trie Path:")
        print(f"  State Root: {trie_data['state_root']}")
        
        for node in example['proof_nodes']:
            node_data = trie_data['nodes'][node['hash']]
            print(f"  → {node['type']} node: {node['hash'][:20]}...")
        
        print("\nThese are REAL nodes from Ethereum's state trie!")