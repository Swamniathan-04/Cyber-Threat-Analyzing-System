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
                'label_column': 'Result',
                'text_column': 'text'
            },
            'cicids': {
                'path': '../cyb datasets/CICIDS2017/CICIDS2017_sample.csv',
                'label_column': ' Label',
                'text_column': 'text'
            },
            'ember': {
                'path': '../cyb datasets/EMBER/ember2018_sample.csv',
                'label_column': 'label',
                'text_column': 'text'
            }
        }

    def load_dataset(self, dataset_name: str) -> Optional[pd.DataFrame]:
        if dataset_name not in self.datasets:
            raise ValueError(f"Unknown dataset: {dataset_name}")
        dataset_info = self.datasets[dataset_name]
        try:
            csv_path = os.path.join(os.path.dirname(__file__), dataset_info['path'])
            if os.path.exists(csv_path):
                df = pd.read_csv(csv_path)
                # Unify label column
                if dataset_info['label_column'] in df.columns:
                    df = df.rename(columns={dataset_info['label_column']: 'ThreatType'})
                # If no 'text' column, create one from all string columns
                if 'text' not in df.columns:
                    text_col = None
                    for col in df.columns:
                        if df[col].dtype == object and col.lower() != 'threattype':
                            text_col = col
                            break
                    if text_col:
                        df['text'] = df[text_col].astype(str)
                    else:
                        df['text'] = df.apply(lambda row: ' '.join([str(x) for x in row.values]), axis=1)
                # Ensure both columns exist
                if 'ThreatType' not in df.columns or 'text' not in df.columns:
                    self.logger.error(f"Dataset {dataset_name} missing required columns after processing.")
                    return None
                # Drop rows with missing values in key columns
                df = df.dropna(subset=['ThreatType', 'text'])
                return df[['text', 'ThreatType']]
            else:
                self.logger.warning(f"Dataset not found: {csv_path}")
                return None
        except Exception as e:
            self.logger.error(f"Error loading {dataset_name} dataset: {e}")
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
        # Align columns (should be just ['text', 'ThreatType'])
        for i, df in enumerate(all_dfs):
            for col in ['text', 'ThreatType']:
                if col not in df.columns:
                    all_dfs[i][col] = '' if col == 'text' else 'Benign'
        combined_df = pd.concat(all_dfs, ignore_index=True)
        combined_df = combined_df.dropna(subset=['ThreatType', 'text'])
        self.logger.info(f"Combined {len(combined_df)} total samples from {len(all_dfs)} datasets")
        # Check class balance
        class_counts = combined_df['ThreatType'].value_counts()
        self.logger.info(f"Class distribution after combining: {class_counts.to_dict()}")
        return combined_df

class HighPrecisionThreatDetector:
    """High-precision threat detection using TF-IDF, embeddings, SVM, and Random Forest"""
    
    def __init__(self, model_path: str = None):
        self.is_trained = False
        if model_path:
            loaded = joblib.load(model_path)
            if isinstance(loaded, dict):
                self.model = loaded.get('model')
                self.vectorizer = loaded.get('vectorizer')
                self.feature_names = loaded.get('feature_names', [])
                self.class_names = loaded.get('class_names', [
                    'Benign', 'Malware', 'Phishing', 'DDoS', 'Intrusion',
                    'Backdoor', 'Brute Force', 'Exploit', 'Keylogger',
                    'PortScan', 'Ransomware', 'Spyware', 'Trojan', 'Worm'
                ])
                self.is_trained = True
            else:
                self.model = loaded
                self.vectorizer = None
                self.feature_names = getattr(self.model, 'feature_names_in_', [])
                self.class_names = [
                    'Benign', 'Malware', 'Phishing', 'DDoS', 'Intrusion',
                    'Backdoor', 'Brute Force', 'Exploit', 'Keylogger',
                    'PortScan', 'Ransomware', 'Spyware', 'Trojan', 'Worm'
                ]
                self.is_trained = True
        else:
            # Initialize for training
            self.model = None
            self.vectorizer = None
            self.feature_names = []
            self.class_names = [
                'Benign', 'Malware', 'Phishing', 'DDoS', 'Intrusion',
                'Backdoor', 'Brute Force', 'Exploit', 'Keylogger',
                'PortScan', 'Ransomware', 'Spyware', 'Trojan', 'Worm'
            ]
            self.is_trained = False
        self.threat_category_mapping = {
            'Malware': ['Backdoor', 'Ransomware', 'Spyware', 'Trojan', 'Worm'],
            'Phishing': ['Keylogger'],
            'DDoS': ['DDoS'],
            'Intrusion': ['Brute Force', 'Exploit', 'PortScan']
        }
        
    def prepare_features(self, data):
        """
        Prepare features for prediction using TF-IDF and embeddings.
        Accepts a DataFrame or dict of features.
        """
        if isinstance(data, dict):
            if 'text' in data:
                if self.vectorizer:
                    return self.vectorizer.transform([data['text']]).toarray()
                else:
                    raise ValueError("Vectorizer not loaded. Cannot process raw text.")
            data = pd.DataFrame([data])
        elif isinstance(data, list) and isinstance(data[0], dict):
            data = pd.DataFrame(data)
        
        # Use the feature names from the model
        if hasattr(self, 'feature_names') and self.feature_names:
            features = data[self.feature_names].values
        else:
            # Fallback: use all numeric columns
            features = data.select_dtypes(include=['number']).values
        return features
        
    def predict_threat(self, features: np.ndarray, original_text: str = "") -> ThreatAnalysisResult:
        start_time = time.time()
        
        # Get model predictions
        predictions = self.model.predict_proba(features)
        if predictions.size == 0:
            raise ValueError("Model returned empty predictions")
            
        threat_idx = np.argmax(predictions[0])
        if threat_idx >= len(self.class_names):
            threat_idx = 0  # Default to 'Benign' if index is out of range
            
        confidence = float(predictions[0][threat_idx])
        
        # Get specific threat name
        specific_threat = self.class_names[threat_idx]
        
        # Map to general category
        threat_category = 'Benign'
        for category, threats in self.threat_category_mapping.items():
            if specific_threat in threats:
                threat_category = category
                break
        
        # Determine risk level
        if confidence >= 0.8:
            risk_level = 'CRITICAL'
        elif confidence >= 0.6:
            risk_level = 'HIGH'
        elif confidence >= 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        # Get feature importance
        if hasattr(self.model, 'feature_importances_'):
            feature_importance = dict(zip(self.feature_names, 
                                        self.model.feature_importances_))
        else:
            feature_importance = {}
            
        # Get model predictions for all classes
        model_predictions = {
            'main_model': dict(zip(self.class_names, predictions[0]))
        }
        
        processing_time = time.time() - start_time
        
        return ThreatAnalysisResult(
            original_text=original_text,
            threat_type=threat_category,
            specific_threat_name=specific_threat,
            confidence=confidence,
            risk_level=risk_level,
            model_predictions=model_predictions,
            feature_importance=feature_importance,
            timestamp=datetime.now().isoformat(),
            processing_time=processing_time
        )

    def save_model(self, model_path: str) -> None:
        """Save the trained model and vectorizer to disk."""
        if not hasattr(self, 'model') or self.model is None:
            raise ValueError("No trained model to save")
        dir_name = os.path.dirname(model_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        # Save the model and vectorizer
        with open(model_path, 'wb') as f:
            joblib.dump({
                'model': self.model,
                'vectorizer': self.vectorizer,
                'feature_names': self.feature_names,
                'class_names': self.class_names
            }, f)
        logger.info(f"Model saved to {model_path}")

    def train_model(self, X_vectorized: np.ndarray, labels: List[str]) -> Dict[str, float]:
        """Train the model on the given vectorized features and labels."""
        if not X_vectorized.size or not labels:
            raise ValueError("No training data provided")
        
        # Train the model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X_vectorized, labels)
        
        # Calculate metrics
        y_pred = self.model.predict(X_vectorized)
        metrics = {
            'accuracy': accuracy_score(labels, y_pred),
            'precision': precision_score(labels, y_pred, average='weighted'),
            'recall': recall_score(labels, y_pred, average='weighted'),
            'f1_score': f1_score(labels, y_pred, average='weighted')
        }
        
        logger.info(f"Model training complete. Metrics: {metrics}")
        return metrics

class GuardianAI:
    """Main GuardianAI class for threat detection"""
    
    def __init__(self):
        self.logger = logging.getLogger('GuardianAI')
        self.detector = HighPrecisionThreatDetector()
        self.dataset_processor = DatasetProcessor()
        
    def train(self) -> Dict[str, float]:
        """Train the model using combined datasets"""
        try:
            # Load and combine datasets
            combined_df = self.dataset_processor.combine_datasets()
            X_text = combined_df['text'].astype(str).values
            y = combined_df['ThreatType'].astype(str).values

            # Convert numeric labels to threat types if needed
            threat_types = []
            for label in y:
                if label == '0':
                    threat_types.append('Benign')
                elif label == '1':
                    threat_types.append(np.random.choice(['Malware', 'Phishing', 'DDoS', 'Intrusion']))
                else:
                    threat_types.append(label)

            # Create and fit TF-IDF vectorizer
            self.detector.vectorizer = TfidfVectorizer(max_features=1000)
            X_vectorized = self.detector.vectorizer.fit_transform(X_text).toarray()

            # --- SMOTE for class balancing ---
            try:
                smote = SMOTE(random_state=42)
                X_vectorized, threat_types = smote.fit_resample(X_vectorized, threat_types)
                self.logger.info(f"Applied SMOTE. New class distribution: {dict(pd.Series(threat_types).value_counts())}")
            except Exception as e:
                self.logger.warning(f"SMOTE failed: {e}")

            # --- Cross-validation ---
            from sklearn.model_selection import StratifiedKFold
            skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            scores = []
            for train_idx, test_idx in skf.split(X_vectorized, threat_types):
                X_train, X_test = X_vectorized[train_idx], X_vectorized[test_idx]
                y_train, y_test = np.array(threat_types)[train_idx], np.array(threat_types)[test_idx]
                model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                acc = accuracy_score(y_test, y_pred)
                scores.append(acc)
            avg_cv_acc = np.mean(scores)
            self.logger.info(f"Stratified 5-fold CV accuracy: {avg_cv_acc:.4f}")

            # Train the final model
            metrics = self.detector.train_model(X_vectorized, threat_types)

            # Save the model
            self.detector.save_model('guardian_model.pkl')
            self.logger.info("Model saved successfully to guardian_model.pkl")

            metrics['cv_accuracy'] = avg_cv_acc
            return metrics
        except Exception as e:
            self.logger.error(f"Error in training: {e}")
            raise
    
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