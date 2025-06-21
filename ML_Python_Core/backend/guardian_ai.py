import pandas as pd
import numpy as np
import pickle
import logging
import warnings
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import secrets
import json
import os
import arff
import joblib
import time

# ML Libraries
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import VotingClassifier
from imblearn.over_sampling import SMOTE

# Deep Learning & NLP
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from sentence_transformers import SentenceTransformer

# Security Libraries
from cryptography.fernet import Fernet
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - GuardianAI - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('guardian_ai.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ThreatAnalysisResult:
    """Comprehensive threat analysis result"""
    original_text: str
    threat_type: str
    specific_threat_name: str
    confidence: float
    risk_level: str
    model_predictions: Dict[str, float]
    feature_importance: Dict[str, float]
    timestamp: datetime
    processing_time: float

class DatasetProcessor:
    """Handles loading and preprocessing of various cybersecurity datasets"""
    def __init__(self):
        self.logger = logging.getLogger('GuardianAI')
        self.datasets = {
            'phishing': {
                'path': '../cyb datasets/Phising Datset/phishing_dataset.csv',
                'label_column': 'Result'
            },
            'cicids': {
                'path': '../cyb datasets/CICIDS2017/CICIDS2017_sample.csv',
                'label_column': ' Label' # Note the leading space
            },
            'ember': {
                'path': '../cyb datasets/EMBER/ember2018_sample.csv',
                'label_column': 'label'
            },
            'violent_threats': {
                'path': '../cyb datasets/ViolentThreats/Violent_Threats_Dataset.csv',
                'label_column': 'ThreatType'
            },
            'benign_conversational': {
                'path': '../cyb datasets/BenignConversational/Benign_Conversational.csv',
                'label_column': 'ThreatType'
            }
        }

    def load_dataset(self, dataset_name: str) -> Optional[pd.DataFrame]:
        if dataset_name not in self.datasets:
            raise ValueError(f"Unknown dataset: {dataset_name}")
        
        dataset_info = self.datasets[dataset_name]
        try:
            csv_path = os.path.join(os.path.dirname(__file__), dataset_info['path'])
            if not os.path.exists(csv_path):
                self.logger.warning(f"Dataset not found: {csv_path}")
                return None
            
            df = pd.read_csv(csv_path)
            
            # --- Robust Column Handling ---
            
            # 1. Find and Unify the label column
            label_col_to_rename = None
            # Check for primary label, then common alternatives
            possible_labels = [dataset_info.get('label_column'), 'ThreatType', 'Label', 'label', 'Result', ' Label']
            # Filter out None from the list
            possible_labels = [label for label in possible_labels if label]
            
            for col in possible_labels:
                if col in df.columns:
                    label_col_to_rename = col
                    break
            
            if not label_col_to_rename:
                self.logger.error(f"No suitable label column found in {dataset_name}. Searched for {possible_labels}. Skipping.")
                return None

            df = df.rename(columns={label_col_to_rename: 'ThreatType'})
            
            # 2. Clean the ThreatType column immediately
            df['ThreatType'] = df['ThreatType'].astype(str).str.strip()

            # --- Add a mapping for numeric labels based on dataset ---
            if dataset_name == 'phishing' or dataset_name == 'ember':
                # Assuming 0 is Benign and 1 is Malicious/Phishing
                label_map = {'0': 'Benign', '1': 'Malware'}
                df['ThreatType'] = df['ThreatType'].replace(label_map)
            # Add other specific mappings if needed for other datasets
            
            # 3. Create a unified 'text' column
            if 'text' not in df.columns:
                feature_cols = [col for col in df.columns if col != 'ThreatType']
                if not feature_cols:
                    self.logger.error(f"Dataset {dataset_name} has no feature columns to create 'text'. Skipping.")
                    return None
                df['text'] = df[feature_cols].astype(str).agg(' '.join, axis=1)

            # 4. Final check and return
            df = df.dropna(subset=['ThreatType', 'text'])
            return df[['text', 'ThreatType']]

        except Exception as e:
            self.logger.error(f"Error loading {dataset_name} dataset: {e}", exc_info=True)
            return None

    def combine_datasets(self) -> pd.DataFrame:
        all_dfs = []
        for dataset_name in self.datasets:
            df = self.load_dataset(dataset_name)
            if df is not None:
                all_dfs.append(df)
                self.logger.info(f"Loaded {len(df)} samples from {dataset_name}")
            else:
                self.logger.warning(f"Failed to load {dataset_name}")
        if not all_dfs:
            raise ValueError("No datasets were successfully loaded")
        
        combined_df = pd.concat(all_dfs, ignore_index=True)
        # The cleaning is now done in load_dataset, but an extra strip doesn't hurt.
        combined_df['ThreatType'] = combined_df['ThreatType'].str.strip()
        combined_df = combined_df.dropna(subset=['ThreatType', 'text'])
        
        self.logger.info(f"Combined {len(combined_df)} total samples from {len(all_dfs)} datasets")
        # Check class balance
        class_counts = combined_df['ThreatType'].value_counts()
        self.logger.info(f"Class distribution after combining: {class_counts.to_dict()}")
        return combined_df

class HighPrecisionThreatDetector:
    """High-precision threat detection using an advanced sentence embedding model"""
    
    def __init__(self, model_path: str = None):
        self.is_trained = False
        # Load the powerful sentence transformer model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize class_names as an empty list
        self.class_names = []
        
        if model_path and os.path.exists(model_path):
            # The new model file only contains the trained classifier
            self.model = joblib.load(model_path)
                self.is_trained = True
            
            # --- The Definitive Fix ---
            # The model's internal list is the only source of truth.
            if hasattr(self.model, 'classes_'):
                self.class_names = self.model.classes_
                logging.info(f"Successfully loaded {len(self.class_names)} class names directly from the trained model.")
            else:
                logging.error("CRITICAL: Trained model is missing the .classes_ attribute. Predictions will fail.")
            
        else:
            # Initialize for training
            self.model = None
            self.is_trained = False
            
        self.threat_category_mapping = {
            'Malware': ['Backdoor', 'Ransomware', 'Spyware', 'Trojan', 'Worm', 'Dropper'],
            'Phishing': ['Keylogger'],
            'DDoS': ['DDoS'],
            'Intrusion': ['Brute Force', 'Exploit', 'PortScan'],
            'Violent Threat': ['Violent Threat'],
            'Benign': ['Benign']
        }
        
    def prepare_features(self, data: dict):
        """
        Prepare features for prediction using sentence embeddings.
        Accepts a dict containing the text to be analyzed.
        """
        if 'text' in data and isinstance(data['text'], str):
            # Generate a dense vector (embedding) for the input text
            return self.embedding_model.encode([data['text']], show_progress_bar=False)
        else:
            raise ValueError("Input data must be a dictionary with a 'text' key containing a string.")
        
    def predict_threat(self, features: np.ndarray, original_text: str = "") -> ThreatAnalysisResult:
        start_time = time.time()
        
        # Get model predictions
        predictions = self.model.predict_proba(features)[0]
        
        # Create a dictionary of threat probabilities
        model_predictions = {self.class_names[i]: float(predictions[i]) for i in range(len(predictions))}
        
        # Get the highest probability prediction
        predicted_index = np.argmax(predictions)
        confidence = float(predictions[predicted_index])
        specific_threat_name = self.class_names[predicted_index]
        
        # Determine the general threat type
        threat_type = "Benign"
        for general_type, specific_list in self.threat_category_mapping.items():
            if specific_threat_name in specific_list:
                threat_type = general_type
                break
        
        # --- Upgraded Risk Level Logic ---
        risk_level = "LOW" # Default risk level
        
        # Rule 1: Threat-based override (highest priority)
        if threat_type == 'Violent Threat' and confidence > 0.5:
            risk_level = 'CRITICAL'
        elif threat_type == 'Violent Threat':
            # It's identified as violent, but confidence is too low.
            # Call it medium risk, as it's better to be cautious.
            risk_level = 'MEDIUM'
        elif threat_type in ['Malware', 'Phishing', 'Intrusion']:
            # Rule 2: Confidence-based assessment for other serious threats
            if confidence > 0.75:
                risk_level = "HIGH"
            elif confidence > 0.4:
                risk_level = "MEDIUM"
        else:
                risk_level = "LOW"
        else:
            # Rule 3: General confidence-based assessment
            if confidence > 0.9:
                risk_level = "HIGH"
            elif confidence > 0.6:
                risk_level = "MEDIUM"

        end_time = time.time()
        
        result = ThreatAnalysisResult(
            original_text=original_text,
            threat_type=threat_type,
            specific_threat_name=specific_threat_name,
            confidence=confidence,
            risk_level=risk_level,
            model_predictions=model_predictions,
            feature_importance={},
            timestamp=datetime.now().isoformat(),
            processing_time=end_time - start_time
        )
        
        return result

    def save_model(self, model_path: str) -> None:
        """Saves only the trained classifier model."""
        if self.model:
            joblib.dump(self.model, model_path)
            logging.info(f"Classifier model saved successfully to {model_path}")
        else:
            logging.error("No model to save.")

    def train_model(self, X_texts: List[str], labels: List[str]) -> Dict[str, float]:
        """
        Train the classifier on sentence embeddings.
        X_texts should be a list of raw text strings.
        """
        self.class_names = sorted(list(set(labels)))
        logging.info(f"Training model on {len(X_texts)} samples with {len(self.class_names)} classes.")
        
        # Generate embeddings for all training texts
        logging.info("Generating sentence embeddings for training data... (This may take a while)")
        X_embeddings = self.embedding_model.encode(X_texts, show_progress_bar=True)
        
        # Apply SMOTE to balance the dataset
        logging.info("Applying SMOTE to balance class distribution...")
        smote = SMOTE(k_neighbors=5, random_state=42)
        try:
            X_resampled, y_resampled = smote.fit_resample(X_embeddings, labels)
            logging.info(f"Applied SMOTE. New class distribution: {pd.Series(y_resampled).value_counts().to_dict()}")
        except ValueError as e:
            logging.warning(f"SMOTE failed: {e}. Using original data. Consider adding more samples to small classes.")
            X_resampled, y_resampled = X_embeddings, labels

        # Initialize and train the classifier
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        logging.info("Starting model training...")
        self.model.fit(X_resampled, y_resampled)
        
        # Evaluate with cross-validation
        logging.info("Performing stratified 5-fold cross-validation...")
        cv_scores = cross_val_score(self.model, X_resampled, y_resampled, cv=5, scoring='accuracy')
        logging.info(f"Stratified 5-fold CV accuracy: {cv_scores.mean():.4f}")
        
        # Final evaluation on a held-out test set
        X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled)
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }
        
        self.is_trained = True
        return metrics

class GuardianAI:
    """The main AI class orchestrating training and analysis."""
    def __init__(self):
        self.logger = logging.getLogger('GuardianAI')
        self.data_processor = DatasetProcessor()
        model_path = os.path.join(os.path.dirname(__file__), 'trained_model.pkl')
        self.detector = HighPrecisionThreatDetector(model_path=model_path)
        
    def train(self) -> Dict[str, float]:
        """Trains the model using sentence embeddings."""
        self.logger.info("Starting model training process...")
        
        # 1. Load and combine datasets
        df = self.data_processor.combine_datasets()
        X_train_texts = df['text'].tolist()
        y_train_labels = df['ThreatType'].tolist()
        
        # 2. Train the detector
        metrics = self.detector.train_model(X_train_texts, y_train_labels)
        
        # 3. Save the trained model
        model_path = os.path.join(os.path.dirname(__file__), 'trained_model.pkl')
        self.detector.save_model(model_path)
        
        self.logger.info(f"Model training complete. Final metrics: {metrics}")
            return metrics
    
    def analyze_threat_secure(self, text: str, client_ip: str = None) -> ThreatAnalysisResult:
        """Secure threat analysis with OWASP protections"""
        # Rate limiting
        if client_ip and self._is_rate_limited(client_ip):
            raise ValueError("Rate limit exceeded")
        
        # Input validation
        if not isinstance(text, str) or len(text) > 50000:
            raise ValueError("Invalid input: text too long or invalid type")
        
        # XSS and injection detection
        if self._detect_malicious_input(text):
            logger.warning(f"Malicious input detected from {client_ip}")
            raise ValueError("Potentially malicious input detected")
        
        # Perform analysis
        analysis = self.detector.predict_threat(text)
        
        # Log analysis (encrypted)
        self._log_analysis_secure(analysis, client_ip)
        
        return analysis
    
    def _is_rate_limited(self, ip: str, max_requests: int = 100, window: int = 3600) -> bool:
        """Check if IP is rate limited"""
        current_time = datetime.now().timestamp()
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        
        # Clean old requests
        self.rate_limits[ip] = [
            req_time for req_time in self.rate_limits[ip]
            if current_time - req_time < window
        ]
        
        # Check limit
        if len(self.rate_limits[ip]) >= max_requests:
            return True
        
        # Add current request
        self.rate_limits[ip].append(current_time)
        return False
    
    def _detect_malicious_input(self, text: str) -> bool:
        """Detect malicious input patterns"""
        malicious_patterns = [
            r'<script.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'union\s+select',
            r'drop\s+table',
            r'exec\s*\(',
            r'system\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        text_lower = text.lower()
        for pattern in malicious_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _log_analysis_secure(self, analysis: ThreatAnalysisResult, client_ip: str = None):
        """Securely log analysis results"""
        log_data = {
            'timestamp': analysis.timestamp,
            'threat_type': analysis.threat_type,
            'confidence': analysis.confidence,
            'risk_level': analysis.risk_level,
            'client_ip_hash': hashlib.sha256(client_ip.encode()).hexdigest() if client_ip else None,
            'text_hash': hashlib.sha256(analysis.original_text.encode()).hexdigest()
        }
        
        # Encrypt sensitive data
        encrypted_log = self.cipher_suite.encrypt(json.dumps(log_data).encode())
        self.analysis_history.append(encrypted_log)
    
    def generate_security_report(self) -> Dict[str, Union[int, float, List[str]]]:
        """Generate comprehensive security report"""
        if not self.analysis_history:
            return {"message": "No analysis history available"}
        
        # Decrypt and analyze logs
        decrypted_logs = []
        for encrypted_log in self.analysis_history[-1000:]:  # Last 1000 analyses
            try:
                decrypted_data = json.loads(self.cipher_suite.decrypt(encrypted_log).decode())
                decrypted_logs.append(decrypted_data)
            except:
                continue
        
        if not decrypted_logs:
            return {"message": "No valid analysis history available"}
        
        # Generate statistics
        threat_types = [log['threat_type'] for log in decrypted_logs]
        risk_levels = [log['risk_level'] for log in decrypted_logs]
        
        return {
            'total_analyses': len(decrypted_logs),
            'threat_distribution': pd.Series(threat_types).value_counts().to_dict(),
            'risk_distribution': pd.Series(risk_levels).value_counts().to_dict(),
            'average_confidence': np.mean([log['confidence'] for log in decrypted_logs]),
            'unique_ips': len(set(log['client_ip_hash'] for log in decrypted_logs if log['client_ip_hash']))
        } 