# Evaluation Module - Calculates DDoS Detection Metrics using Pandas

import pandas as pd
import json
import os

class EvaluationModule:
    """
    Analyzes the blockchain log (created by Manasi Sharma) to calculate detection metrics
    (True Positives, False Positives, Accuracy) using the 'is_attack' field 
    as the ground truth from the simulation (Saachi Aggarwal).
    
    This module provides the data points for Bhumika's dashboard metrics panel.
    """
    def __init__(self, log_filepath='logs/blockchain_log.json'):
        self.log_filepath = log_filepath
        # Ensure the logs directory exists before attempting to load/read
        os.makedirs(os.path.dirname(self.log_filepath), exist_ok=True)
        print("Evaluation: Initialized.")

    def _load_log_data(self):
        """Loads the log file into a pandas DataFrame, skipping the genesis block."""
        
        # Check if file exists and has content
        if not os.path.exists(self.log_filepath) or os.path.getsize(self.log_filepath) == 0:
            return None

        try:
            with open(self.log_filepath, 'r') as f:
                # The log file is a JSON array of blocks
                data = json.load(f)
            
            # Skip the genesis block (index 1) which has no traffic data
            df = pd.DataFrame([block for block in data if block['index'] > 1])
            return df
            
        except json.JSONDecodeError:
            print("Evaluation Error: Log file is corrupted or empty. Cannot load data.")
            return None
        except Exception as e:
            print(f"Evaluation Error: Could not load or parse log file: {e}")
            return None

    def calculate_metrics(self):
        """
        Calculates all key performance indicators: TP, FP, FN, TN, and Accuracy.
        
        The logic relies on two fields in the log:
        - Ground Truth (Actual): 'is_attack' (True/False, set by the simulator)
        - Prediction (Detected): 'detection_status' ('detected'/'normal', set by the detection module)
        """
        df = self._load_log_data()

        if df is None or df.empty:
            return {
                'true_positives': 0,
                'false_positives': 0,
                'false_negatives': 0,
                'true_negatives': 0,
                'total_requests': 0,
                'accuracy': 0.0,
                'status': 'No traffic data available for evaluation.'
            }

        # --- Calculate the Confusion Matrix Components ---

        # 1. True Positives (TP): Actual Attack (True) AND Detected ('detected')
        # The system correctly identified an attack.
        tp = len(df[(df['is_attack'] == True) & (df['detection_status'] == 'detected')])

        # 2. False Positives (FP): Actual Normal (False) BUT Detected ('detected')
        # The system raised a false alarm (Type I Error).
        fp = len(df[(df['is_attack'] == False) & (df['detection_status'] == 'detected')])

        # 3. False Negatives (FN): Actual Attack (True) BUT NOT Detected ('normal')
        # The system missed an attack (Type II Error).
        fn = len(df[(df['is_attack'] == True) & (df['detection_status'] == 'normal')])
        
        # 4. True Negatives (TN): Actual Normal (False) AND NOT Detected ('normal')
        # The system correctly identified normal traffic.
        tn = len(df[(df['is_attack'] == False) & (df['detection_status'] == 'normal')])

        total = len(df)
        
        # Calculate Accuracy: (Correct Predictions) / (Total Requests)
        accuracy = (tp + tn) / total if total > 0 else 0.0

        return {
            'true_positives': int(tp),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_negatives': int(tn),
            'total_requests': int(total),
            # Return accuracy as a value between 0.0 and 1.0
            'accuracy': accuracy,
            'status': 'Metrics calculated successfully.'
        }

# Example usage (for testing this module in isolation)
if __name__ == '__main__':
    # NOTE: This requires pandas, which must be installed (pip install pandas)
    print("Running Evaluation Module standalone test...")
    
    # Create a mock log file for testing
    mock_data = [
        # Genesis block (ignored)
        {"index": 1, "detection_status": "genesis", "is_attack": False, "hash": "0"}, 
        # TP: Actual Attack (True), Detected ('detected')
        {"index": 2, "detection_status": "detected", "is_attack": True, "hash": "a"}, 
        {"index": 3, "detection_status": "detected", "is_attack": True, "hash": "b"}, 
        # FP: Actual Normal (False), Detected ('detected')
        {"index": 4, "detection_status": "detected", "is_attack": False, "hash": "c"}, 
        # FN: Actual Attack (True), NOT Detected ('normal')
        {"index": 5, "detection_status": "normal", "is_attack": True, "hash": "d"}, 
        # TN: Actual Normal (False), NOT Detected ('normal')
        {"index": 6, "detection_status": "normal", "is_attack": False, "hash": "e"}, 
        {"index": 7, "detection_status": "normal", "is_attack": False, "hash": "f"}, 
    ]
    test_filepath = 'logs/test_eval_log.json'
    os.makedirs(os.path.dirname(test_filepath), exist_ok=True)
    with open(test_filepath, 'w') as f:
        json.dump(mock_data, f, indent=4)

    evaluator = EvaluationModule(log_filepath=test_filepath)
    metrics = evaluator.calculate_metrics()
    
    print("\n--- Evaluation Metrics Test Results ---")
    print(f"Total Blocks Analyzed (Excluding Genesis): {metrics['total_requests']}") # Should be 6
    print(f"True Positives (Correctly caught attack): {metrics['true_positives']}") # Expected: 2
    print(f"False Positives (False Alarm): {metrics['false_positives']}")      # Expected: 1
    print(f"False Negatives (Missed Attack): {metrics['false_negatives']}")    # Expected: 1
    print(f"True Negatives (Correctly identified normal): {metrics['true_negatives']}") # Expected: 2
    print(f"Accuracy: {metrics['accuracy']:.2f}") # Expected: (2+2)/6 = 0.67
    
    # Clean up test file
    if os.path.exists(test_filepath):
        os.remove(test_filepath)
