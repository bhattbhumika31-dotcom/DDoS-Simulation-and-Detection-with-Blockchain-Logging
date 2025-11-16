class EvaluationModule:
    def __init__(self):
        print("Evaluation: Initialized.")

    def calculate_metrics(self, traffic_logs):
        if not traffic_logs:
            return {
                'true_positives': 0,
                'false_positives': 0,
                'false_negatives': 0,
                'true_negatives': 0,
                'total_requests': 0,
                'accuracy': 0.0,
                'status': 'No traffic data available for evaluation.'
            }

        tp = 0
        fp = 0
        fn = 0
        tn = 0

        for log in traffic_logs:
            is_actual_attack = log.get('is_actual_attack', False)
            is_flagged = log.get('is_flagged', False) 

            if is_actual_attack and is_flagged:
                tp += 1
            elif not is_actual_attack and is_flagged:
                fp += 1
            elif is_actual_attack and not is_flagged:
                fn += 1
            elif not is_actual_attack and not is_flagged:
                tn += 1

        total = len(traffic_logs)
        accuracy = (tp + tn) / total if total > 0 else 0.0

        return {
            'true_positives': tp,
            'false_positives': fp,
            'false_negatives': fn,
            'true_negatives': tn,
            'total_requests': total,
            'accuracy': accuracy,
            'status': 'Metrics calculated successfully.'
        }
