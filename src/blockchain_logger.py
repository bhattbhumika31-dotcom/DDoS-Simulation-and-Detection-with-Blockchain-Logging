import time
import hashlib
import json

class BlockchainLogger:
    """
    Simulates a secure ledger for logging traffic events.
    The chain is stored in memory for the duration of the Flask application run.
    """
    def __init__(self):
        self.chain = []
        self._create_genesis_block()

    def _calculate_hash(self, block):
        """Calculates the SHA-256 hash of a block's contents."""
    
        block_string = json.dumps(block, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def _create_genesis_block(self):
        """Creates the first block (index 0) in the chain."""
        genesis_block = {
            'index': 0,
            'timestamp': time.time(),
            'data': 'Genesis Block',
            'previous_hash': '0',
            'nonce': 0,
            'hash': '0000'
        }

        genesis_block['hash'] = self._calculate_hash(genesis_block)
        self.chain.append(genesis_block)
        print("Blockchain initialized with Genesis Block.")

    def create_block(self, ip, status, is_flagged, is_actual_attack):
        """
        Creates a new block and adds it to the chain.
        - is_flagged: Did the detection module detect an attack?
        - is_actual_attack: Is this traffic actually malicious (Ground Truth)?
        """
        last_block = self.chain[-1]
        
        classification = 'TP' if is_flagged and is_actual_attack else \
                         'FP' if is_flagged and not is_actual_attack else \
                         'FN' if not is_flagged and is_actual_attack else \
                         'TN'
        
        block = {
            'index': last_block['index'] + 1,
            'timestamp': time.time(),
            'ip_address': ip,
            'detection_status': status,
            'is_flagged': is_flagged,
            'is_actual_attack': is_actual_attack,
            'classification': classification, 
            'previous_hash': last_block['hash'],
            'nonce': 0
        }
   
        block['hash'] = self._calculate_hash(block)
        self.chain.append(block)
        return block

    def is_chain_valid(self):
        """
        Checks if the blockchain is valid by verifying:
        1. Every block's stored previous_hash matches the actual hash of the preceding block.
        2. Every block's hash is correct based on its contents.


        Returns: (bool, str) - (Is Valid, Validation Message)
        """
        if len(self.chain) == 0:
            return False, "Chain is empty."

        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block['previous_hash'] != previous_block['hash']:
                return False, f"Integrity Failure: Block {current_block['index']}'s previous hash does not match Block {previous_block['index']}'s hash."

            temp_block = current_block.copy()
            current_hash = temp_block.pop('hash')
            
            if self._calculate_hash(temp_block) != current_hash:
                return False, f"Integrity Failure: Block {current_block['index']}'s hash is invalid (content tampered)."

        return True, f"Chain integrity verified. Total blocks: {len(self.chain) - 1}."

    def get_chain_length(self):
        """Returns the total number of blocks in the chain."""
        return len(self.chain)

    def get_recent_logs(self, count=25):
        """Returns the most recent 'count' blocks, excluding the genesis block."""
        logs = self.chain[1:] 
        return logs[-count:]

    def get_full_chain(self):
        """Returns the entire chain, used by the evaluation module (excluding genesis)."""
        return self.chain[1:]