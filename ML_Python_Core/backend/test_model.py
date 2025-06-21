import logging
import numpy as np
from guardian_ai import HighPrecisionThreatDetector, ThreatAnalysisResult
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('GuardianAI')

def test_model():
    """Test the trained model with sample data"""
    try:
        # Initialize detector
        detector = HighPrecisionThreatDetector('guardian_model.pkl')
        
        # Create sample data as a DataFrame
        sample = pd.DataFrame({
            'phishing_Abnormal_URL': [0],
            'phishing_Bwd_Packet_Length_Max': [0],
            'phishing_Bwd_Packet_Length_Mean': [0],
            'phishing_Bwd_Packet_Length_Min': [0],
            'phishing_Bwd_Packet_Length_Std': [0],
            'phishing_DNSRecord': [0],
            'phishing_Destination_Port': [80],
            'phishing_Domain_registeration_length': [365],
            'phishing_Favicon': [0],
            'phishing_Flow_Bytes_per_sec': [0],
            'phishing_Flow_Duration': [0],
            'phishing_Flow_IAT_Max': [0],
            'phishing_Flow_IAT_Mean': [0],
            'phishing_Flow_IAT_Min': [0],
            'phishing_Flow_IAT_Std': [0],
            'phishing_Flow_Packets_per_sec': [0],
            'phishing_Fwd_Packet_Length_Max': [0],
            'phishing_Fwd_Packet_Length_Mean': [0],
            'phishing_Fwd_Packet_Length_Min': [0],
            'phishing_Fwd_Packet_Length_Std': [0],
            'phishing_Google_Index': [0],
            'phishing_HTTPS_token': [0],
            'phishing_Iframe': [0],
            'phishing_Links_in_tags': [0],
            'phishing_Links_pointing_to_page': [0],
            'phishing_Page_Rank': [0],
            'phishing_Prefix_Suffix': [0],
            'phishing_Redirect': [0],
            'phishing_Request_URL': [0],
            'phishing_RightClick': [0],
            'phishing_SFH': [0],
            'phishing_SSLfinal_State': [0],
            'phishing_Shortining_Service': [0],
            'phishing_Statistical_report': [0],
            'phishing_Submitting_to_email': [0],
            'phishing_Total_Backward_Packets': [0],
            'phishing_Total_Fwd_Packets': [0],
            'phishing_Total_Length_of_Bwd_Packets': [0],
            'phishing_Total_Length_of_Fwd_Packets': [0],
            'phishing_URL_Length': [0],
            'phishing_URL_of_Anchor': [0],
            'phishing_age_of_domain': [365],
            'phishing_web_traffic': [0]
        })
        
        # Add all the byte histogram features with 0 values
        for i in range(256):
            sample[f'phishing_byte_entropy_histogram_{i}'] = [0]
            sample[f'phishing_byte_histogram_{i}'] = [0]
        
        # Add all the CICIDS and EMBER features with 0 values
        for prefix in ['cicids_', 'ember_']:
            for col in sample.columns:
                if col.startswith('phishing_'):
                    new_col = col.replace('phishing_', prefix)
                    sample[new_col] = [0]
        
        print("\nTesting model with sample data:")
        print("-" * 50)
        
        # Test with sample data
        print("\nSample 1:")
        features = detector.prepare_features(sample)
        result = detector.predict_threat(features)
        print(f"Threat Type: {result.threat_type}")
        print(f"Specific Threat Name: {result.specific_threat_name}")
        print(f"Confidence: {result.confidence}")
        print(f"Risk Level: {result.risk_level}")
        print(f"Model Predictions: {result.model_predictions}")
        print(f"Feature Importance: {result.feature_importance}")
        print(f"Timestamp: {result.timestamp}")
        print(f"Processing Time: {result.processing_time}")
        
        # Test with another sample (malicious)
        print("\nSample 2 (Malicious):")
        sample2 = sample.copy()
        sample2['phishing_Abnormal_URL'] = [1]
        sample2['phishing_HTTPS_token'] = [1]
        features2 = detector.prepare_features(sample2)
        result2 = detector.predict_threat(features2)
        print(f"Threat Type: {result2.threat_type}")
        print(f"Specific Threat Name: {result2.specific_threat_name}")
        print(f"Confidence: {result2.confidence}")
        print(f"Risk Level: {result2.risk_level}")
        print(f"Model Predictions: {result2.model_predictions}")
        print(f"Feature Importance: {result2.feature_importance}")
        print(f"Timestamp: {result2.timestamp}")
        print(f"Processing Time: {result2.processing_time}")
        
    except Exception as e:
        logger.error("Error testing model: %s", str(e))
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    test_model() 