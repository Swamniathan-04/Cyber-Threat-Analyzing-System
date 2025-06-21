import numpy as np
import pandas as pd
from pathlib import Path
import os

def create_phishing_dataset(n_samples=1000):
    """Generate synthetic phishing dataset with realistic feature distributions"""
    # Define threat categories and their proportions
    threat_categories = {
        'Benign': 0.2,
        'Phishing': 0.15,
        'Spam': 0.1,
        'Suspicious': 0.1,
        'Malicious': 0.1,
        'Ham': 0.15,
        'Unknown': 0.1,
        'Macro-enabled': 0.05,
        'Script-based': 0.05
    }
    
    # Calculate samples per category
    samples_per_category = {cat: int(n_samples * prop) for cat, prop in threat_categories.items()}
    # Adjust for rounding errors
    samples_per_category['Benign'] += n_samples - sum(samples_per_category.values())
    
    features = {}
    
    # URL-based features with category-specific distributions
    for feature, (benign_mean, benign_std, malicious_mean, malicious_std) in [
        ('having_IP_Address', (0.05, 0.02, 0.8, 0.1)),
        ('URL_Length', (45, 10, 120, 30)),
        ('Shortining_Service', (0.02, 0.01, 0.7, 0.1)),
        ('having_At_Symbol', (0.1, 0.05, 0.9, 0.05)),
        ('double_slash_redirecting', (0.05, 0.02, 0.8, 0.1)),
        ('Prefix_Suffix', (0.1, 0.05, 0.9, 0.05)),
        ('having_Sub_Domain', (0.2, 0.1, 0.8, 0.1)),
        ('SSLfinal_State', (0.9, 0.05, 0.3, 0.1)),
        ('Domain_registeration_length', (7, 1, 2, 0.5)),
        ('Favicon', (0.9, 0.05, 0.3, 0.1)),
        ('port', (0.1, 0.05, 0.8, 0.1)),
        ('HTTPS_token', (0.9, 0.05, 0.3, 0.1)),
        ('Request_URL', (0.2, 0.1, 0.9, 0.05)),
        ('URL_of_Anchor', (0.3, 0.1, 0.9, 0.05)),
        ('Links_in_tags', (0.2, 0.1, 0.9, 0.05)),
        ('SFH', (0.1, 0.05, 0.8, 0.1)),
        ('Submitting_to_email', (0.05, 0.02, 0.9, 0.05)),
        ('Abnormal_URL', (0.05, 0.02, 0.9, 0.05)),
        ('Redirect', (0.1, 0.05, 0.9, 0.05)),
        ('on_mouseover', (0.1, 0.05, 0.9, 0.05)),
        ('RightClick', (0.1, 0.05, 0.9, 0.05)),
        ('popUpWidnow', (0.1, 0.05, 0.9, 0.05)),
        ('Iframe', (0.1, 0.05, 0.9, 0.05)),
        ('age_of_domain', (75, 15, 5, 2)),
        ('DNSRecord', (0.9, 0.05, 0.2, 0.1)),
        ('web_traffic', (0.8, 0.1, 0.2, 0.1)),
        ('Page_Rank', (0.8, 0.1, 0.2, 0.1)),
        ('Google_Index', (0.9, 0.05, 0.2, 0.1)),
        ('Links_pointing_to_page', (0.8, 0.1, 0.2, 0.1)),
        ('Statistical_report', (0.7, 0.1, 0.2, 0.1))
    ]:
        values = []
        for category, n in samples_per_category.items():
            if category == 'Benign':
                values.extend(np.random.normal(benign_mean, benign_std, n).clip(0, 1))
            elif category == 'Phishing':
                values.extend(np.random.normal(0.8, 0.1, n).clip(0, 1))
            elif category == 'Spam':
                values.extend(np.random.normal(0.6, 0.15, n).clip(0, 1))
            elif category == 'Suspicious':
                values.extend(np.random.normal(0.4, 0.2, n).clip(0, 1))
            elif category == 'Malicious':
                values.extend(np.random.normal(malicious_mean, malicious_std, n).clip(0, 1))
            elif category == 'Ham':
                values.extend(np.random.normal(0.1, 0.05, n).clip(0, 1))
            elif category == 'Unknown':
                values.extend(np.random.normal(0.5, 0.2, n).clip(0, 1))
            elif category == 'Macro-enabled':
                values.extend(np.random.normal(0.7, 0.15, n).clip(0, 1))
            else:  # Script-based
                values.extend(np.random.normal(0.65, 0.15, n).clip(0, 1))
        features[feature] = values
    
    # Result label: Map categories to numeric values
    category_map = {
        'Benign': 0,
        'Phishing': 1,
        'Spam': 2,
        'Suspicious': 3,
        'Malicious': 4,
        'Ham': 5,
        'Unknown': 6,
        'Macro-enabled': 7,
        'Script-based': 8
    }
    features['Result'] = []
    for category, n in samples_per_category.items():
        features['Result'].extend([category_map[category]] * n)
    
    df = pd.DataFrame(features)
    # Clean and validate data
    df = df.fillna(0)
    df = df.replace([np.inf, -np.inf], 0)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].clip(0, 1)
    return df.sample(frac=1).reset_index(drop=True)

def create_cicids_dataset(n_samples=1000):
    """Generate synthetic CICIDS2017 dataset with realistic network traffic patterns and extra columns for model compatibility and diversity."""
    # Define threat categories and their proportions
    threat_categories = {
        'Benign': 0.2,
        'DDoS': 0.1,
        'PortScan': 0.1,
        'Brute Force': 0.1,
        'Backdoor': 0.1,
        'Exploit': 0.1,
        'Trojan': 0.1,
        'Worm': 0.05,
        'Ransomware': 0.05,
        'Spyware': 0.05,
        'Keylogger': 0.05,
        'Dropper': 0.05,
        # Add more rare/edge-case classes for variety
        'Rootkit': 0.01,
        'Botnet': 0.01,
        'APT': 0.01,
        'Adware': 0.01,
        'ZeroDay': 0.01,
        'Fileless': 0.01,
        'Polymorphic': 0.01,
        'Stealer': 0.01,
        'Miner': 0.01
    }
    # Calculate samples per category
    samples_per_category = {cat: int(n_samples * prop) for cat, prop in threat_categories.items()}
    samples_per_category['Benign'] += n_samples - sum(samples_per_category.values())
    features = {}
    # Network traffic features with category-specific distributions
    for feature, (benign_mean, benign_std, attack_mean, attack_std) in [
        ('Destination_Port', (443, 10, 4444, 100)),
        ('Flow_Duration', (50000, 20000, 750000, 100000)),
        ('Total_Fwd_Packets', (50, 20, 750, 100)),
        ('Total_Backward_Packets', (50, 20, 750, 100)),
        ('Total_Length_of_Fwd_Packets', (5000, 2000, 75000, 10000)),
        ('Total_Length_of_Bwd_Packets', (5000, 2000, 75000, 10000)),
        ('Fwd_Packet_Length_Mean', (30, 10, 600, 100)),
        ('Fwd_Packet_Length_Std', (5, 2, 75, 10)),
        ('Fwd_Packet_Length_Max', (75, 10, 750, 100)),
        ('Fwd_Packet_Length_Min', (5, 2, 75, 10)),
        ('Bwd_Packet_Length_Mean', (30, 10, 600, 100)),
        ('Bwd_Packet_Length_Std', (5, 2, 75, 10)),
        ('Bwd_Packet_Length_Max', (75, 10, 750, 100)),
        ('Bwd_Packet_Length_Min', (5, 2, 75, 10)),
        ('Flow_Bytes_per_sec', (500, 200, 55000, 10000)),
        ('Flow_Packets_per_sec', (5, 2, 550, 100)),
        ('Flow_IAT_Mean', (50, 20, 750, 100)),
        ('Flow_IAT_Std', (5, 2, 75, 10)),
        ('Flow_IAT_Max', (500, 200, 7500, 1000)),
        ('Flow_IAT_Min', (5, 2, 75, 10)),
        # Add extra features for diversity
        ('Active_Mean', (10, 5, 100, 20)),
        ('Idle_Mean', (5, 2, 50, 10)),
        ('URG_Flag_Count', (0, 0, 10, 2)),
        ('FIN_Flag_Count', (0, 0, 10, 2)),
        ('SYN_Flag_Count', (0, 0, 10, 2)),
        ('RST_Flag_Count', (0, 0, 10, 2)),
        ('PSH_Flag_Count', (0, 0, 10, 2)),
        ('ACK_Flag_Count', (0, 0, 10, 2)),
        ('CWE_Flag_Count', (0, 0, 10, 2)),
        ('ECE_Flag_Count', (0, 0, 10, 2)),
        ('Down_Up_Ratio', (1, 0.2, 10, 2)),
        ('Average_Packet_Size', (500, 100, 2000, 300)),
        ('Packet_Length_Variance', (10, 2, 100, 20)),
        ('Packet_Length_Std', (3, 1, 30, 5)),
        ('Fwd_Header_Length', (20, 5, 100, 20)),
        ('Bwd_Header_Length', (20, 5, 100, 20)),
        ('Fwd_Segment_Size_Avg', (50, 10, 500, 100)),
        ('Bwd_Segment_Size_Avg', (50, 10, 500, 100)),
        ('Init_Win_bytes_forward', (8192, 1024, 65535, 5000)),
        ('Init_Win_bytes_backward', (8192, 1024, 65535, 5000)),
        ('act_data_pkt_fwd', (1, 0.5, 10, 2)),
        ('min_seg_size_forward', (20, 5, 100, 20)),
        ('Active_Max', (100, 20, 1000, 200)),
        ('Active_Min', (1, 0.2, 10, 2)),
        ('Idle_Max', (50, 10, 500, 100)),
        ('Idle_Min', (1, 0.2, 10, 2)),
    ]:
        values = []
        for category, n in samples_per_category.items():
            if category == 'Benign':
                values.extend(np.random.normal(benign_mean, benign_std, n).clip(0, None))
            else:
                values.extend(np.random.normal(attack_mean, attack_std, n).clip(0, None))
        features[feature] = values
    # Add categorical/boolean features for more variety
    for feature, categories in [
        ('Protocol', ['TCP', 'UDP', 'ICMP']),
        ('Service', ['HTTP', 'FTP', 'SSH', 'DNS', 'SMTP', 'Other']),
        ('Flag', ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'OTH']),
        ('Land', [0, 1]),
        ('Logged_In', [0, 1]),
        ('Is_Fwd', [0, 1]),
        ('Is_Bwd', [0, 1]),
    ]:
        values = []
        for category, n in samples_per_category.items():
            values.extend(np.random.choice(categories, n))
        features[feature] = values
    # Add the Label column (required by loader)
    labels = []
    for category, n in samples_per_category.items():
        labels.extend([category] * n)
    features['Label'] = labels
    # Ensure all columns expected by the loader/model are present
    required_columns = [
        'Label', 'ThreatType', 'Result', 'label', ' Label',
        # Add any other columns you know the loader/model expects
    ]
    for col in required_columns:
        if col not in features:
            # For label columns, fill with the main label
            if col.lower().startswith('label'):
                features[col] = labels
            else:
                features[col] = [0] * n_samples
    # Create DataFrame
    df = pd.DataFrame(features)
    # Add any missing columns from the phishing/ember datasets for alignment
    # (This is a fallback: fill with zeros or random values)
    all_possible_columns = set([
        'Abnormal_URL','Bwd_Packet_Length_Max','Bwd_Packet_Length_Mean','Bwd_Packet_Length_Min','Bwd_Packet_Length_Std','DNSRecord','Destination_Port','Domain_registeration_length','Favicon','Flow_Bytes_per_sec','Flow_Duration','Flow_IAT_Max','Flow_IAT_Mean','Flow_IAT_Min','Flow_IAT_Std','Flow_Packets_per_sec','Fwd_Packet_Length_Max','Fwd_Packet_Length_Mean','Fwd_Packet_Length_Min','Fwd_Packet_Length_Std','Google_Index','HTTPS_token','Iframe','Links_in_tags','Links_pointing_to_page','Page_Rank','Prefix_Suffix','Redirect','Request_URL','RightClick','SFH','SSLfinal_State','Shortining_Service','Statistical_report','Submitting_to_email','Total_Backward_Packets','Total_Fwd_Packets','Total_Length_of_Bwd_Packets','Total_Length_of_Fwd_Packets','URL_Length','URL_of_Anchor','age_of_domain','having_At_Symbol','having_IP_Address','having_Sub_Domain','on_mouseover','popUpWidnow','port','web_traffic'
    ])
    for col in all_possible_columns:
        if col not in df.columns:
            df[col] = np.random.rand(n_samples)
    # Shuffle columns for randomness
    df = df.sample(frac=1, axis=1)
    # Clean and validate data
    df = df.fillna(0)
    df = df.replace([np.inf, -np.inf], 0)
    return df.sample(frac=1).reset_index(drop=True)

def create_ember_dataset(n_samples=1000):
    """Generate synthetic EMBER dataset with realistic malware characteristics"""
    # Define threat categories and their proportions
    threat_categories = {
        'Benign': 0.2,
        'Packed': 0.05,
        'Obfuscated': 0.05,
        'PUA': 0.1,
        'PUP': 0.1,
        'Trojan': 0.1,
        'Virus': 0.1,
        'Worm': 0.05,
        'Ransomware': 0.05,
        'Spyware': 0.05,
        'Adware': 0.05,
        'Rootkit': 0.05,
        'Keylogger': 0.05,
        'Dropper': 0.05
    }
    
    # Calculate samples per category
    samples_per_category = {cat: int(n_samples * prop) for cat, prop in threat_categories.items()}
    samples_per_category['Benign'] += n_samples - sum(samples_per_category.values())
    
    features = {}
    
    # Byte histogram features
    for i in range(256):
        values = []
        for category, n in samples_per_category.items():
            if category == 'Benign':
                values.extend(np.random.normal(25, 10, n).clip(0, 50))
            elif category == 'Packed':
                values.extend(np.random.normal(200, 20, n).clip(150, 255))
            elif category == 'Obfuscated':
                values.extend(np.random.normal(180, 30, n).clip(100, 255))
            elif category in ['PUA', 'PUP']:
                values.extend(np.random.normal(150, 40, n).clip(50, 255))
            elif category in ['Trojan', 'Virus', 'Worm']:
                values.extend(np.random.normal(220, 15, n).clip(180, 255))
            elif category in ['Ransomware', 'Spyware']:
                values.extend(np.random.normal(230, 10, n).clip(200, 255))
            elif category in ['Adware', 'Rootkit']:
                values.extend(np.random.normal(160, 35, n).clip(80, 255))
            elif category == 'Keylogger':
                values.extend(np.random.normal(170, 30, n).clip(90, 255))
            else:  # Dropper
                values.extend(np.random.normal(190, 25, n).clip(120, 255))
        features[f'byte_histogram_{i}'] = values
    
    # Byte entropy histogram features
    for i in range(256):
        values = []
        for category, n in samples_per_category.items():
            if category == 'Benign':
                values.extend(np.random.normal(1, 0.5, n).clip(0, 2))
            elif category == 'Packed':
                values.extend(np.random.normal(7.5, 0.3, n).clip(7, 8))
            elif category == 'Obfuscated':
                values.extend(np.random.normal(7.2, 0.4, n).clip(6.5, 8))
            elif category in ['PUA', 'PUP']:
                values.extend(np.random.normal(6.5, 0.5, n).clip(5.5, 7.5))
            elif category in ['Trojan', 'Virus', 'Worm']:
                values.extend(np.random.normal(7.8, 0.2, n).clip(7.5, 8))
            elif category in ['Ransomware', 'Spyware']:
                values.extend(np.random.normal(7.9, 0.1, n).clip(7.7, 8))
            elif category in ['Adware', 'Rootkit']:
                values.extend(np.random.normal(6.8, 0.4, n).clip(6, 7.5))
            elif category == 'Keylogger':
                values.extend(np.random.normal(7.1, 0.3, n).clip(6.5, 7.8))
            else:  # Dropper
                values.extend(np.random.normal(7.3, 0.35, n).clip(6.8, 7.9))
        features[f'byte_entropy_histogram_{i}'] = values
    
    # String features
    for i in range(10):
        for feature_type in ['string_extractor', 'general_file_info', 'header_file_info', 
                           'section_info', 'imports', 'exports']:
            values = []
            for category, n in samples_per_category.items():
                if category == 'Benign':
                    values.extend(np.random.normal(5, 2, n).clip(0, 10))
                elif category == 'Packed':
                    values.extend(np.random.normal(85, 10, n).clip(70, 100))
                elif category == 'Obfuscated':
                    values.extend(np.random.normal(75, 15, n).clip(50, 100))
                elif category in ['PUA', 'PUP']:
                    values.extend(np.random.normal(60, 20, n).clip(30, 90))
                elif category in ['Trojan', 'Virus', 'Worm']:
                    values.extend(np.random.normal(90, 5, n).clip(80, 100))
                elif category in ['Ransomware', 'Spyware']:
                    values.extend(np.random.normal(95, 3, n).clip(90, 100))
                elif category in ['Adware', 'Rootkit']:
                    values.extend(np.random.normal(65, 15, n).clip(40, 90))
                elif category == 'Keylogger':
                    values.extend(np.random.normal(70, 12, n).clip(45, 95))
                else:  # Dropper
                    values.extend(np.random.normal(80, 10, n).clip(60, 100))
            features[f'{feature_type}_{i}'] = values
    
    # Label: Map categories to numeric values
    category_map = {
        'Benign': 0,
        'Packed': 1,
        'Obfuscated': 2,
        'PUA': 3,
        'PUP': 4,
        'Trojan': 5,
        'Virus': 6,
        'Worm': 7,
        'Ransomware': 8,
        'Spyware': 9,
        'Adware': 10,
        'Rootkit': 11,
        'Keylogger': 12,
        'Dropper': 13
    }
    features['label'] = []
    for category, n in samples_per_category.items():
        features['label'].extend([category_map[category]] * n)
    
    df = pd.DataFrame(features)
    # Clean and validate data
    df = df.fillna(0)
    df = df.replace([np.inf, -np.inf], 0)
    # Byte histogram: 0-255, entropy: 0-8, string features: 0-100
    for i in range(256):
        df[f'byte_histogram_{i}'] = df[f'byte_histogram_{i}'].clip(0, 255)
        df[f'byte_entropy_histogram_{i}'] = df[f'byte_entropy_histogram_{i}'].clip(0, 8)
    for i in range(10):
        for feature_type in ['string_extractor', 'general_file_info', 'header_file_info', 
                           'section_info', 'imports', 'exports']:
            df[f'{feature_type}_{i}'] = df[f'{feature_type}_{i}'].clip(0, 100)
    return df.sample(frac=1).reset_index(drop=True)

def align_columns(dfs):
    # Find the union of all columns
    all_columns = set()
    for df in dfs:
        all_columns.update(df.columns)
    all_columns = sorted(list(all_columns))
    # Add missing columns as zeros
    aligned = []
    for df in dfs:
        for col in all_columns:
            if col not in df.columns:
                df[col] = 0
        aligned.append(df[all_columns])
    return aligned

def save_datasets():
    """Save all generated datasets"""
    base_dir = Path(__file__).parent.parent.parent / 'cyb datasets'
    
    # Create directories if they don't exist
    (base_dir / 'Phising Datset').mkdir(parents=True, exist_ok=True)
    (base_dir / 'CICIDS2017').mkdir(parents=True, exist_ok=True)
    (base_dir / 'EMBER').mkdir(parents=True, exist_ok=True)
    
    # Generate and save phishing dataset
    phishing_df = create_phishing_dataset(1000)
    cicids_df = create_cicids_dataset(1000)
    ember_df = create_ember_dataset(1000)
    phishing_df, cicids_df, ember_df = align_columns([phishing_df, cicids_df, ember_df])
    phishing_df.to_csv(base_dir / 'Phising Datset' / 'phishing_dataset.csv', index=False)
    
    # Generate and save CICIDS dataset
    cicids_df.to_csv(base_dir / 'CICIDS2017' / 'CICIDS2017_sample.csv', index=False)
    
    # Generate and save EMBER dataset
    ember_df.to_csv(base_dir / 'EMBER' / 'ember2018_sample.csv', index=False)
    
    print("All datasets have been generated and saved successfully!")

if __name__ == "__main__":
    save_datasets() 