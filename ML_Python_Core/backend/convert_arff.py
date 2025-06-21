import pandas as pd
import os
from scipy.io import arff

def convert_arff_to_csv(arff_path, csv_path):
    try:
        # Load ARFF file
        data, meta = arff.loadarff(arff_path)
        
        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Convert bytes to strings for categorical columns
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].str.decode('utf-8')
        
        # Save as CSV
        df.to_csv(csv_path, index=False)
        print(f"Successfully converted {arff_path} to {csv_path}")
        return True
    except Exception as e:
        print(f"Error converting {arff_path}: {str(e)}")
        return False

def main():
    # Create csv directory if it doesn't exist
    csv_dir = os.path.join("cyb datasets", "Phising Datset", "csv")
    os.makedirs(csv_dir, exist_ok=True)
    
    # Convert each ARFF file
    arff_files = [
        ".old.arff",
        "Training Dataset.arff"
    ]
    
    for arff_file in arff_files:
        # Adjust path to go up two directories
        arff_path = os.path.join("..", "..", "cyb datasets", "Phising Datset", arff_file)
        csv_file = os.path.splitext(arff_file)[0] + ".csv"
        csv_path = os.path.join(csv_dir, csv_file)
        
        if os.path.exists(arff_path):
            convert_arff_to_csv(arff_path, csv_path)
        else:
            print(f"File not found: {arff_path}")

if __name__ == "__main__":
    main() 