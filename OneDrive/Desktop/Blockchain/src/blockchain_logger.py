# Manasi Sharma - Blockchain Logging Module

import hashlib
import json
import time
import os

class BlockchainLogger:
    """
    Implements a simple blockchain-style log for traffic data.
    Each log entry (block) contains a hash of the previous block,
    ensuring tamper-proof logging of network activity and detection results.
    """
    def __init__(self, log_filepath='logs/blockchain_log.json'):
        self.log_filepath = log_filepath
        # Cache the chain in memory for faster access, updated on every append/load
        self.chain = []
        self._load_chain()

    def _load_chain(self):
        """Loads the blockchain log from the JSON file."""
        if os.path.exists(self.log_filepath) and os.path.getsize(self.log_filepath) > 0:
            try:
                with open(self.log_filepath, 'r') as f:
                    self.chain = json.load(f)
                print(f"Logger: Loaded chain with {len(self.chain)} blocks.")
            except json.JSONDecodeError:
                print("Logger: WARNING! Log file is corrupted. Initializing new chain.")
                self.initialize_log()
            except Exception as e:
                print(f"Logger: Error loading log file: {e}. Initializing new chain.")
                self.initialize_log()
        else:
            self.initialize_log()

    def _save_chain(self):
        """Saves the current chain to the JSON file."""
        with open(self.log_filepath, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def initialize_log(self):
        """Creates the genesis block if the log file is empty or missing."""
        self.chain = []
        self.create_block(
            ip="0.0.0.0",
            detection_status="genesis",
            is_attack=False,
            # Genesis block has a fixed previous hash of 0
            prev_hash="0" * 64 
        )
        print("Logger: Created genesis block.")

    def calculate_hash(self, block):
        """Calculates the SHA-256 hash for a given block content."""
        # Convert dictionary to a string, ensuring consistent key order for consistent hashing
        block_string = json.dumps(block, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def create_block(self, ip, detection_status, is_attack):
        """
        Creates a new log entry (block), links it to the chain, and saves it.
        
        :param ip: The source IP address of the traffic.
        :param detection_status: The result from the DetectionModule ('normal', 'attack', or 'detected').
        :param is_attack: Boolean flag indicating if the traffic was part of a known attack simulation (for evaluation).
        """
        # Get the hash of the last block in the chain
        prev_block = self.chain[-1] if self.chain else None
        prev_hash = prev_block['hash'] if prev_block else "0" * 64

        # Create the new block structure (log entry)
        new_block_data = {
            "index": len(self.chain) + 1,
            "timestamp": int(time.time()),
            "ip": ip,
            "detection_status": detection_status,
            "is_attack": is_attack,
            "prev_hash": prev_hash,
            # Add placeholders for data integrity check
            "nonce": 0 
        }

        # Calculate the hash for the new block
        current_hash = self.calculate_hash(new_block_data)
        new_block_data["hash"] = current_hash

        # Append to chain and save to disk
        self.chain.append(new_block_data)
        self._save_chain()
        
        return new_block_data

    def validate_chain(self):
        """Iterates through the chain and verifies all hash links."""
        if not self.chain or len(self.chain) <= 1:
            return True, "Chain is empty or only contains the genesis block."

        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            prev_block = self.chain[i-1]

            # 1. Verify the previous hash link
            if current_block['prev_hash'] != prev_block['hash']:
                return False, f"Validation Failed: Block {current_block['index']} hash link broken."

            # 2. Verify the current block's own hash integrity
            # Create a temporary block copy without the 'hash' field to recalculate
            temp_block = current_block.copy()
            temp_block.pop('hash')
            recalculated_hash = self.calculate_hash(temp_block)
            
            if current_block['hash'] != recalculated_hash:
                return False, f"Validation Failed: Block {current_block['index']} data integrity compromised."

        return True, "Chain is fully verified and secure."

    def get_recent_logs(self, count):
        """Returns the last 'count' number of log entries."""
        return self.chain[-count:]
        
    def get_chain_length(self):
        """Returns the total number of blocks in the chain."""
        return len(self.chain)

# Example usage (for testing this module in isolation)
if __name__ == '__main__':
    logger = BlockchainLogger(log_filepath='test_log.json')
    
    # Create two normal logs
    logger.create_block("192.168.1.10", "normal", False)
    logger.create_block("192.168.1.11", "normal", False)
    
    # Create an attack log
    logger.create_block("10.0.0.5", "detected", True)
    
    # Test validation
    valid, msg = logger.validate_chain()
    print(f"\nChain Valid: {valid}, Message: {msg}")
    
    # Tamper with the log file (simulated external attack)
    try:
        with open('test_log.json', 'r') as f:
            temp_chain = json.load(f)
        
        # Change the IP of the second block (tampering)
        if len(temp_chain) > 2:
            print("\nSIMULATING TAMPERING...")
            temp_chain[2]['ip'] = "99.99.99.99"
            with open('test_log.json', 'w') as f:
                json.dump(temp_chain, f, indent=4)
        
        logger_tampered = BlockchainLogger(log_filepath='test_log.json')
        tampered_valid, tampered_msg = logger_tampered.validate_chain()
        print(f"Tampered Chain Valid: {tampered_valid}, Message: {tampered_msg}")
        
    except Exception as e:
        print(f"Tampering simulation failed: {e}")
        
    # Clean up test file
    if os.path.exists('test_log.json'):
        os.remove('test_log.json')
