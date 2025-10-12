import pandas as pd

LOGFILE = "detection_log_data.jsonl"
def load_log_data():
    try:
        data = pd.read_json(LOGFILE, lines=True)
        return data
    except ValueError:
        print(" Log file is empty or not found! ")
        return pd.DataFrame(columns=["ip", "count", "phase", "detected", "timestamp"])

def evaluate_detection(data):
    if data.empty:
        print("No data available for evaluation.")
        return
    data["phase"] = data["phase"].str.lower()
    tp = fp = fn = tn = 0
    for index, row in data.iterrows():
        detected = row["detected"]
        label = row["phase"]
        print(f"Row {index}: Detected = {detected}, Phase = {label}")

    if detected and label == "attack":
            tp += 1
    elif detected and label == "normal":
            fp += 1
    elif not detected and label == "attack":
            fn += 1
    elif not detected and label == "normal":
            tn += 1
    if (tp + fp) != 0:
        precision = tp / (tp + fp)
    else:
        precision = 0
 
    if (tp + fn) != 0:
        recall = tp / (tp + fn)
    else:
        recall = 0

    if (precision + recall) != 0:
        f1 = (2 * precision * recall) / (precision + recall)
    else:
        f1 = 0

    total = tp + fp + fn + tn
    if total != 0:
       accuracy = (tp + tn) / total
    else:
       accuracy = 0

    print("\n Evaluation Summary")
    print(f"True Positives (TP): {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print(f"True Negatives (TN): {tn}")
    print("-" * 40)
    print(f" Precision: {precision:.2f}")
    print(f" Recall: {recall:.2f}")
    print(f" F1 Score: {f1:.2f}")
    print(f" Accuracy: {accuracy:.2f}")

if __name__ == "__main__":
    log_data = load_log_data()
    evaluate_detection(log_data)
