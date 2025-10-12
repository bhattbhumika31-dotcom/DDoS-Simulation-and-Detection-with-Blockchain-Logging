import hashlib
import json
import time
import os

class BlockchainLogger:
    def __init__(self, log_filepath='logs/blockchain_log.json'):
        self.log_filepath = log_filepath
        self.chain = []
        self._load_chain()

    def _load_chain(self):
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
        with open(self.log_filepath, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def initialize_log(self):
        self.chain = []
        self.create_block(
            ip="0.0.0.0",
            detection_status="genesis",
            is_attack=False,
            prev_hash="0" * 64
        )
        print("Logger: Created genesis block.")

    def calculate_hash(self, block):
        block_string = json.dumps(block, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def create_block(self, ip, detection_status, is_attack):
        prev_block = self.chain[-1] if self.chain else None
        prev_hash = prev_block['hash'] if prev_block else "0" * 64

        new_block_data = {
            "index": len(self.chain) + 1,
            "timestamp": int(time.time()),
            "ip": ip,
            "detection_status": detection_status,
            "is_attack": is_attack,
            "prev_hash": prev_hash,
            "nonce": 0
        }

        current_hash = self.calculate_hash(new_block_data)
        new_block_data["hash"] = current_hash

        self.chain.append(new_block_data)
        self._save_chain()
        
        return new_block_data

    def validate_chain(self):
        if not self.chain or len(self.chain) <= 1:
            return True, "Chain is empty or only contains the genesis block."

        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            prev_block = self.chain[i-1]

            if current_block['prev_hash'] != prev_block['hash']:
                return False, f"Validation Failed: Block {current_block['index']} hash link broken."

            temp_block = current_block.copy()
            temp_block.pop('hash')
            recalculated_hash = self.calculate_hash(temp_block)
            
            if current_block['hash'] != recalculated_hash:
                return False, f"Validation Failed: Block {current_block['index']} data integrity compromised."

        return True, "Chain is fully verified and secure."

    def get_recent_logs(self, count):
        return self.chain[-count:]
        
    def get_chain_length(self):
        return len(self.chain)

if __name__ == '__main__':
    logger = BlockchainLogger(log_filepath='test_log.json')
    
    logger.create_block("192.168.1.10", "normal", False)
    logger.create_block("192.168.1.11", "normal", False)
    
    logger.create_block("10.0.0.5", "detected", True)
    
    valid, msg = logger.validate_chain()
    print(f"\nChain Valid: {valid}, Message: {msg}")
    
    try:
        with open('test_log.json', 'r') as f:
            temp_chain = json.load(f)
        
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
        
    if os.path.exists('test_log.json'):
        os.remove('test_log.json')
