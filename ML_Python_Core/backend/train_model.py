import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import pickle
from pathlib import Path
from sklearn.utils.class_weight import compute_class_weight
from guardian_ai import HighPrecisionThreatDetector, GuardianAI
import os
from scipy.io import arff

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_dataset_path(filename, subfolder):
    # Returns the correct path for a CSV file in the given subfolder
    return os.path.join(os.path.dirname(__file__), f"../cyb datasets/{subfolder}/{filename}")

def load_phishing_dataset():
    try:
        csv_path = get_dataset_path('phishing_dataset.csv', 'Phising Datset')
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            if 'Result' in df.columns:
                df = df.rename(columns={'Result': 'ThreatType'})
            return df
        else:
            logger.warning('Phishing dataset not found.')
            return None
    except Exception as e:
        logger.error(f'Error loading phishing dataset: {e}')
        return None

def load_cicids_dataset():
    try:
        csv_path = get_dataset_path('CICIDS2017_sample.csv', 'CICIDS2017')
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            # Always rename all possible label columns to 'ThreatType'
            for col in [' Label', 'Label', 'label', 'Result']:
                if col in df.columns:
                    df = df.rename(columns={col: 'ThreatType'})
            # If still missing, try to create from any available label column
            if 'ThreatType' not in df.columns:
                for col in df.columns:
                    if 'label' in col.lower():
                        df['ThreatType'] = df[col]
                        break
            # Fallback: if still missing, fill with 'Benign'
            if 'ThreatType' not in df.columns:
                df['ThreatType'] = 'Benign'
            # Ensure ThreatType is string
            df['ThreatType'] = df['ThreatType'].astype(str)
            return df
        else:
            logger.warning('CICIDS2017 dataset not found.')
            return None
    except Exception as e:
        logger.error(f'Error loading CICIDS2017 dataset: {e}')
        return None

def load_ember_dataset():
    try:
        csv_path = get_dataset_path('ember2018_sample.csv', 'EMBER')
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            if 'label' in df.columns:
                df = df.rename(columns={'label': 'ThreatType'})
            return df
        else:
            logger.warning('EMBER dataset not found.')
            return None
    except Exception as e:
        logger.error(f'Error loading EMBER dataset: {e}')
        return None

def load_violent_threats_dataset():
    """Loads the violent threats dataset"""
    try:
        csv_path = get_dataset_path('Violent_Threats_Dataset.csv', 'ViolentThreats')
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            # Ensure ThreatType column exists and is named correctly
            if 'ThreatType' in df.columns:
                return df[['text', 'ThreatType']]
            else:
                logger.warning('Violent threats dataset missing "ThreatType" column.')
                return None
        else:
            logger.warning('Violent threats dataset not found.')
            return None
    except Exception as e:
        logger.error(f'Error loading violent threats dataset: {e}')
        return None

def combine_datasets():
    """Combine all datasets with strict label alignment and diagnostics"""
    phishing = load_phishing_dataset()
    cicids = load_cicids_dataset()
    ember = load_ember_dataset()
    violent_threats = load_violent_threats_dataset()
    
    all_dfs = [df for df in [phishing, cicids, ember, violent_threats] if df is not None]
    if not all_dfs:
        raise ValueError('No datasets loaded!')
    
    # Create a unified 'text' column if it doesn't exist
    for i, df in enumerate(all_dfs):
        if 'text' not in df.columns:
            string_cols = [col for col in df.columns if df[col].dtype == object and col.lower() != 'threattype']
            if string_cols:
                all_dfs[i]['text'] = df[string_cols].fillna('').astype(str).agg(' '.join, axis=1)
            else:
                # If no string columns, create a placeholder
                all_dfs[i]['text'] = ''
        
        # Ensure 'ThreatType' column exists and is string type
        if 'ThreatType' in df.columns:
            all_dfs[i]['ThreatType'] = df['ThreatType'].astype(str)
        else:
            all_dfs[i]['ThreatType'] = 'Benign' # Default if missing
        
        # Keep only the essential columns to ensure clean concatenation
        all_dfs[i] = all_dfs[i][['text', 'ThreatType']]

    # Drop all label columns except 'ThreatType'
    label_cols = ['Result', 'Label', 'label', ' Label']
    for i, df in enumerate(all_dfs):
        for col in label_cols:
            if col in df.columns:
                all_dfs[i] = df.drop(columns=[col])
    combined = pd.concat(all_dfs, ignore_index=True)
    for col in label_cols:
        if col in combined.columns:
            combined = combined.drop(columns=[col])
    # Only keep rows with non-null ThreatType
    combined = combined.dropna(subset=['ThreatType'])
    # Print class distribution
    print('Class distribution after combining:')
    print(combined['ThreatType'].value_counts())
    # Now split into X and y
    X = combined.drop(columns=['ThreatType'])
    y = combined['ThreatType'].astype(str).values
    # Only use numeric columns for features
    print('Feature column data types:')
    print(X.dtypes)
    X = X.loc[:, X.apply(lambda col: np.issubdtype(col.dtype, np.number))]
    # Diagnostic: Check for non-numeric values in features
    for col in X.columns:
        if not np.issubdtype(X[col].dtype, np.number):
            print(f'Non-numeric column: {col}, dtype: {X[col].dtype}, unique values: {X[col].unique()[:10]}')
        else:
            if X[col].apply(lambda v: isinstance(v, str)).any():
                print(f'Column {col} contains string values! Example: {X[col][X[col].apply(lambda v: isinstance(v, str))].unique()[:10]}')
    logger.info(f"Combined {len(all_dfs)} datasets with total {len(X)} samples")
    # After combining datasets, check for NaN values
    if X.isnull().any().any():
        print('NaN values found in the following columns:')
        print(X.isnull().sum()[X.isnull().sum() > 0])
        print('Total NaN values:', X.isnull().sum().sum())
        X = X.fillna(0)
        print('NaN values replaced with 0.')
    print('Label column unique values and types:')
    print(pd.Series(y).apply(type).value_counts())
    print(pd.Series(y).unique()[:20])
    return X, y

def train_model():
    """Train and save the model"""
    try:
        # Initialize GuardianAI
        guardian = GuardianAI()
        
        # Train the model
        metrics = guardian.train()
        logger.info(f"Model training complete. Metrics: {metrics}")
        
        # Save the model
        model_path = os.path.join(os.path.dirname(__file__), 'trained_model.pkl')
        guardian.detector.save_model(model_path)
        logger.info(f"Model saved to {model_path}")
        
    except Exception as e:
        logger.error(f"Error in training: {e}")
        raise

if __name__ == "__main__":
    train_model() 