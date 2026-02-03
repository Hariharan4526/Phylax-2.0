"""
Feature Extraction Module
Extracts ML-ready features from HTTP requests in the datasets.
"""

import pandas as pd
import numpy as np
import re
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path
from collections import Counter
import urllib.parse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HTTPFeatureExtractor:
    """Extracts features from HTTP requests for ML training."""
    
    # SQL Keywords for detection
    SQL_KEYWORDS = {
        'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
        'union', 'from', 'where', 'and', 'or', 'not', 'in', 'exists',
        'join', 'inner', 'outer', 'left', 'right', 'on', 'group', 'by',
        'having', 'order', 'asc', 'desc', 'limit', 'offset', 'values'
    }
    
    # Command Keywords
    CMD_KEYWORDS = {
        'cat', 'ls', 'whoami', 'id', 'nc', 'bash', 'sh', 'curl', 'wget',
        'ping', 'ifconfig', 'netstat', 'ps', 'kill', 'chmod', 'chown',
        'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'tar', 'zip', 'unzip'
    }
    
    # XSS Dangerous Tags
    XSS_TAGS = {
        'script', 'iframe', 'img', 'svg', 'embed', 'object', 'link',
        'style', 'meta', 'body', 'html', 'form', 'input', 'button'
    }
    
    # Path Traversal Indicators
    PATH_TRAVERSAL_PATTERNS = {
        '../', '..\\\\', '..%2f', '..%5c', '..../', 'etc/passwd',
        'windows/system32', 'c:\\\\', '/var/www'
    }
    
    def __init__(self):
        """Initialize feature extractor."""
        self.feature_names = self._get_feature_names()
    
    def _get_feature_names(self) -> List[str]:
        """Get list of all feature names."""
        return [
            # Length features
            'payload_length',
            'decoded_length',
            'normalized_length',
            
            # Character distribution
            'special_char_ratio',
            'digit_ratio',
            'uppercase_ratio',
            'lowercase_ratio',
            'whitespace_ratio',
            
            # Entropy
            'entropy',
            'compression_ratio',
            
            # SQL Injection indicators
            'sql_keyword_count',
            'sql_keyword_ratio',
            'quote_count',
            'comment_count',
            'union_count',
            'where_count',
            
            # XSS indicators
            'xss_tag_count',
            'script_tag_count',
            'event_handler_count',
            'javascript_uri_count',
            'angle_bracket_count',
            'html_entity_count',
            
            # Command Injection indicators
            'cmd_keyword_count',
            'shell_metachar_count',
            'pipe_count',
            'redirect_count',
            'semicolon_count',
            'ampersand_count',
            'backtick_count',
            
            # Path Traversal indicators
            'dot_slash_count',
            'backslash_count',
            'null_byte_count',
            'sensitive_file_count',
            
            # Encoding indicators
            'percent_sign_count',
            'unicode_escape_count',
            'html_escape_count',
            'hex_pattern_count',
            
            # Structure features
            'word_count',
            'avg_word_length',
            'distinct_char_count',
            'repeated_char_count',
            'long_token_count',  # tokens > 20 chars
            
            # Payload analysis
            'suspicious_pattern_count',
            'encoding_layers',
            'is_binary_looking'
        ]
    
    def extract_features(self, payload: str) -> Dict[str, float]:
        """
        Extract features from HTTP payload/request.
        
        Args:
            payload: HTTP request body/parameters or URL
            
        Returns:
            Dictionary of extracted features
        """
        if not isinstance(payload, str):
            payload = str(payload) if payload is not None else ""
        
        if len(payload) == 0:
            return {name: 0.0 for name in self.feature_names}
        
        features = {}
        
        # Length features
        features['payload_length'] = float(len(payload))
        decoded = self._safe_decode(payload)
        features['decoded_length'] = float(len(decoded))
        normalized = self._normalize(payload)
        features['normalized_length'] = float(len(normalized))
        
        # Character distribution
        char_stats = self._analyze_chars(payload)
        features['special_char_ratio'] = char_stats['special_ratio']
        features['digit_ratio'] = char_stats['digit_ratio']
        features['uppercase_ratio'] = char_stats['upper_ratio']
        features['lowercase_ratio'] = char_stats['lower_ratio']
        features['whitespace_ratio'] = char_stats['space_ratio']
        
        # Entropy
        features['entropy'] = self._calculate_entropy(payload)
        features['compression_ratio'] = self._estimate_compression_ratio(payload)
        
        # SQL Injection
        sql_features = self._analyze_sql(payload)
        features['sql_keyword_count'] = float(sql_features['keyword_count'])
        features['sql_keyword_ratio'] = float(sql_features['keyword_ratio'])
        features['quote_count'] = float(sql_features['quote_count'])
        features['comment_count'] = float(sql_features['comment_count'])
        features['union_count'] = float(sql_features['union_count'])
        features['where_count'] = float(sql_features['where_count'])
        
        # XSS
        xss_features = self._analyze_xss(payload)
        features['xss_tag_count'] = float(xss_features['tag_count'])
        features['script_tag_count'] = float(xss_features['script_count'])
        features['event_handler_count'] = float(xss_features['handler_count'])
        features['javascript_uri_count'] = float(xss_features['js_uri_count'])
        features['angle_bracket_count'] = float(xss_features['bracket_count'])
        features['html_entity_count'] = float(xss_features['entity_count'])
        
        # Command Injection
        cmd_features = self._analyze_command_injection(payload)
        features['cmd_keyword_count'] = float(cmd_features['keyword_count'])
        features['shell_metachar_count'] = float(cmd_features['metachar_count'])
        features['pipe_count'] = float(cmd_features['pipe_count'])
        features['redirect_count'] = float(cmd_features['redirect_count'])
        features['semicolon_count'] = float(cmd_features['semicolon_count'])
        features['ampersand_count'] = float(cmd_features['ampersand_count'])
        features['backtick_count'] = float(cmd_features['backtick_count'])
        
        # Path Traversal
        path_features = self._analyze_path_traversal(payload)
        features['dot_slash_count'] = float(path_features['dot_slash_count'])
        features['backslash_count'] = float(path_features['backslash_count'])
        features['null_byte_count'] = float(path_features['null_count'])
        features['sensitive_file_count'] = float(path_features['sensitive_count'])
        
        # Encoding
        encoding_features = self._analyze_encoding(payload)
        features['percent_sign_count'] = float(encoding_features['percent_count'])
        features['unicode_escape_count'] = float(encoding_features['unicode_count'])
        features['html_escape_count'] = float(encoding_features['html_count'])
        features['hex_pattern_count'] = float(encoding_features['hex_count'])
        
        # Structure
        struct_features = self._analyze_structure(payload)
        features['word_count'] = float(struct_features['word_count'])
        features['avg_word_length'] = float(struct_features['avg_word_len'])
        features['distinct_char_count'] = float(struct_features['distinct_chars'])
        features['repeated_char_count'] = float(struct_features['repeated_chars'])
        features['long_token_count'] = float(struct_features['long_tokens'])
        
        # Suspicious patterns
        features['suspicious_pattern_count'] = float(
            sum(1 for kw in ['<svg', 'onerror', 'onload', '<img', 'javascript:', 'union select']
                if kw.lower() in payload.lower())
        )
        features['encoding_layers'] = float(self._count_encoding_layers(payload))
        features['is_binary_looking'] = float(
            self._has_binary_chars(payload)
        )
        
        return features
    
    def _safe_decode(self, text: str) -> str:
        """Safely decode URL-encoded text."""
        try:
            # First layer
            decoded = urllib.parse.unquote(text)
            # Second layer (for double encoding)
            prev = None
            while prev != decoded:
                prev = decoded
                try:
                    decoded = urllib.parse.unquote(decoded)
                except:
                    break
            return decoded
        except:
            return text
    
    def _normalize(self, text: str) -> str:
        """Normalize text by removing null bytes, extra whitespace."""
        text = text.replace('\x00', '')
        text = re.sub(r'\s+', ' ', text)
        return text.lower()
    
    def _analyze_chars(self, text: str) -> Dict[str, float]:
        """Analyze character distribution."""
        if not text:
            return {
                'special_ratio': 0.0,
                'digit_ratio': 0.0,
                'upper_ratio': 0.0,
                'lower_ratio': 0.0,
                'space_ratio': 0.0
            }
        
        length = len(text)
        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        digits = sum(1 for c in text if c.isdigit())
        upper = sum(1 for c in text if c.isupper())
        lower = sum(1 for c in text if c.islower())
        spaces = sum(1 for c in text if c.isspace())
        
        return {
            'special_ratio': special / length,
            'digit_ratio': digits / length,
            'upper_ratio': upper / length,
            'lower_ratio': lower / length,
            'space_ratio': spaces / length
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
        if not text:
            return 0.0
        
        import math
        freq = Counter(text)
        entropy = 0.0
        
        for count in freq.values():
            p = count / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy / 8.0  # Normalize to 0-1
    
    def _estimate_compression_ratio(self, text: str) -> float:
        """Estimate how compressible text is (repetitiveness)."""
        if len(text) < 2:
            return 0.0
        
        # Count unique characters
        unique_chars = len(set(text))
        # Estimate compression ratio
        ratio = unique_chars / len(text)
        return min(1.0, ratio)
    
    def _analyze_sql(self, text: str) -> Dict[str, Any]:
        """Analyze SQL injection indicators."""
        lower_text = text.lower()
        
        # Count SQL keywords
        keyword_count = sum(1 for kw in self.SQL_KEYWORDS if kw in lower_text)
        keyword_ratio = keyword_count / max(1, len(text) / 10)  # Normalize
        
        # Count quotes
        quote_count = text.count("'") + text.count('"') + text.count('`')
        
        # Count comments
        comment_count = (lower_text.count('--') + lower_text.count('/*') + 
                        lower_text.count('#'))
        
        # Count specific keywords
        union_count = lower_text.count('union')
        where_count = lower_text.count('where')
        
        return {
            'keyword_count': keyword_count,
            'keyword_ratio': min(1.0, keyword_ratio),
            'quote_count': quote_count,
            'comment_count': comment_count,
            'union_count': union_count,
            'where_count': where_count
        }
    
    def _analyze_xss(self, text: str) -> Dict[str, Any]:
        """Analyze XSS indicators."""
        lower_text = text.lower()
        
        # Count tags
        tag_count = sum(1 for tag in self.XSS_TAGS 
                       if f'<{tag}' in lower_text)
        script_count = lower_text.count('<script')
        
        # Event handlers
        handler_count = len(re.findall(r'on\w+\s*=', lower_text, re.IGNORECASE))
        
        # JavaScript URI
        js_uri_count = lower_text.count('javascript:')
        
        # Angle brackets
        bracket_count = text.count('<') + text.count('>')
        
        # HTML entities
        entity_count = len(re.findall(r'&[a-z]{2,6};', lower_text))
        
        return {
            'tag_count': tag_count,
            'script_count': script_count,
            'handler_count': handler_count,
            'js_uri_count': js_uri_count,
            'bracket_count': bracket_count,
            'entity_count': entity_count
        }
    
    def _analyze_command_injection(self, text: str) -> Dict[str, Any]:
        """Analyze command injection indicators."""
        lower_text = text.lower()
        
        # Command keywords
        keyword_count = sum(1 for kw in self.CMD_KEYWORDS if kw in lower_text)
        
        # Shell metacharacters
        metachar_count = (text.count(';') + text.count('|') + text.count('&') +
                         text.count('`') + text.count('$'))
        
        pipe_count = text.count('|')
        redirect_count = text.count('>') + text.count('<')
        semicolon_count = text.count(';')
        ampersand_count = text.count('&')
        backtick_count = text.count('`')
        
        return {
            'keyword_count': keyword_count,
            'metachar_count': metachar_count,
            'pipe_count': pipe_count,
            'redirect_count': redirect_count,
            'semicolon_count': semicolon_count,
            'ampersand_count': ampersand_count,
            'backtick_count': backtick_count
        }
    
    def _analyze_path_traversal(self, text: str) -> Dict[str, Any]:
        """Analyze path traversal indicators."""
        lower_text = text.lower()
        
        # Dot-slash sequences
        dot_slash_count = lower_text.count('../') + lower_text.count('..\\')
        
        # Backslash count
        backslash_count = text.count('\\\\')
        
        # Null bytes
        null_count = text.count('\x00') + lower_text.count('%00')
        
        # Sensitive files
        sensitive_count = sum(1 for pattern in self.PATH_TRAVERSAL_PATTERNS
                             if pattern.lower() in lower_text)
        
        return {
            'dot_slash_count': dot_slash_count,
            'backslash_count': backslash_count,
            'null_count': null_count,
            'sensitive_count': sensitive_count
        }
    
    def _analyze_encoding(self, text: str) -> Dict[str, Any]:
        """Analyze encoding indicators."""
        lower_text = text.lower()
        
        # Percent signs (URL encoding)
        percent_count = text.count('%')
        
        # Unicode escapes \\uXXXX
        unicode_count = len(re.findall(r'\\u[0-9a-f]{4}', lower_text))
        
        # HTML escapes &xxxx;
        html_count = len(re.findall(r'&#?\w+;', lower_text))
        
        # Hex patterns 0x or \x
        hex_count = len(re.findall(r'(?:0x|\\x)[0-9a-f]+', lower_text))
        
        return {
            'percent_count': percent_count,
            'unicode_count': unicode_count,
            'html_count': html_count,
            'hex_count': hex_count
        }
    
    def _analyze_structure(self, text: str) -> Dict[str, Any]:
        """Analyze structural features."""
        # Word count
        words = text.split()
        word_count = len(words)
        
        # Average word length
        avg_word_len = np.mean([len(w) for w in words]) if words else 0
        
        # Distinct characters
        distinct_chars = len(set(text))
        
        # Repeated characters (consecutive)
        repeated_chars = len(re.findall(r'(.)\\1{2,}', text))
        
        # Long tokens (> 20 chars)
        long_tokens = sum(1 for w in words if len(w) > 20)
        
        return {
            'word_count': word_count,
            'avg_word_len': avg_word_len,
            'distinct_chars': distinct_chars,
            'repeated_chars': repeated_chars,
            'long_tokens': long_tokens
        }
    
    def _count_encoding_layers(self, text: str) -> int:
        """Count number of encoding layers."""
        layers = 0
        prev = None
        
        for _ in range(5):  # Max 5 layers
            try:
                decoded = self._safe_decode(text)
                if decoded == prev or decoded == text:
                    break
                prev = text
                text = decoded
                layers += 1
            except:
                break
        
        return layers
    
    def _has_binary_chars(self, text: str) -> bool:
        """Check if text has binary-looking characters."""
        binary_chars = sum(1 for c in text if ord(c) < 32 and c not in '\t\n\r')
        return 1.0 if binary_chars > len(text) * 0.1 else 0.0


class DatasetProcessor:
    """Process datasets and extract features for training."""
    
    def __init__(self, data_dir: str = "Datasets"):
        self.data_dir = Path(data_dir)
        self.extractor = HTTPFeatureExtractor()
    
    def process_csic_dataset(self, output_csv: str = "csic_features.csv") -> pd.DataFrame:
        """
        Process CSIC HTTP dataset.
        Extract features and create labeled training data.
        """
        logger.info("Processing CSIC dataset...")
        
        try:
            # Load dataset
            df = pd.read_csv(
                self.data_dir / "csic_database.csv",
                encoding='utf-8',
                low_memory=False
            )
            
            logger.info(f"Loaded {len(df)} samples")
            logger.info(f"Columns: {df.columns.tolist()}")
            
            # Identify label column (usually last column or contains 'label'/'class')
            label_col = None
            for col in df.columns:
                if 'label' in col.lower() or 'class' in col.lower() or 'attack' in col.lower():
                    label_col = col
                    break
            
            if label_col is None:
                # Assume last column is label
                label_col = df.columns[-1]
                logger.warning(f"Auto-detected label column: {label_col}")
            
            # Identify request column (usually contains 'request' or 'payload')
            request_col = None
            for col in df.columns:
                if 'request' in col.lower() or 'payload' in col.lower() or 'url' in col.lower():
                    request_col = col
                    break
            
            if request_col is None:
                # Use first non-label column
                request_col = df.columns[0]
                logger.warning(f"Auto-detected request column: {request_col}")
            
            logger.info(f"Using columns: request={request_col}, label={label_col}")
            
            # Extract features
            logger.info("Extracting features...")
            features_list = []
            labels_list = []
            
            for idx, row in df.iterrows():
                if idx % 10000 == 0:
                    logger.info(f"  Processed {idx}/{len(df)}")
                
                try:
                    payload = str(row[request_col])
                    label = row[label_col]
                    
                    features = self.extractor.extract_features(payload)
                    features_list.append(features)
                    labels_list.append(label)
                    
                except Exception as e:
                    logger.debug(f"Error processing row {idx}: {e}")
                    continue
            
            # Create output dataframe
            features_df = pd.DataFrame(features_list)
            features_df['label'] = labels_list
            features_df['original_label'] = labels_list
            
            # Binary classification: map labels to 0/1
            features_df['label_numeric'] = features_df['label'].apply(
                self._normalize_label
            )
            
            logger.info(f"Extracted features for {len(features_df)} samples")
            logger.info(f"Label distribution:\n{features_df['label_numeric'].value_counts()}")
            
            # Save to CSV
            features_df.to_csv(output_csv, index=False)
            logger.info(f"Saved to {output_csv}")
            
            return features_df
            
        except Exception as e:
            logger.error(f"Error processing CSIC dataset: {e}")
            raise
    
    def process_iscx_dataset(self, output_csv: str = "iscx_features.csv") -> pd.DataFrame:
        """
        Process ISCX Web Attacks dataset.
        """
        logger.info("Processing ISCX dataset...")
        
        try:
            df = pd.read_csv(
                self.data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                encoding='utf-8',
                low_memory=False
            )
            
            logger.info(f"Loaded {len(df)} samples")
            logger.info(f"Columns: {df.columns.tolist()}")
            
            # Identify label column
            label_col = None
            for col in df.columns:
                if 'label' in col.lower() or 'class' in col.lower():
                    label_col = col
                    break
            
            if label_col:
                logger.info(f"Using label column: {label_col}")
                logger.info(f"Label values: {df[label_col].unique()}")
            else:
                logger.warning("Could not find label column")
                return pd.DataFrame()
            
            # For ISCX, we need to construct payload from available columns
            # Try to use relevant columns
            payload_cols = [col for col in df.columns 
                          if any(x in col.lower() for x in 
                                ['payload', 'data', 'packet', 'flow'])]
            
            if not payload_cols:
                logger.warning("Could not find payload columns")
                payload_cols = [df.columns[0]]
            
            logger.info(f"Using payload columns: {payload_cols}")
            
            # Extract features
            features_list = []
            labels_list = []
            
            for idx, row in df.iterrows():
                if idx % 10000 == 0:
                    logger.info(f"  Processed {idx}/{len(df)}")
                
                try:
                    # Combine payload columns
                    payload = ' '.join([str(row[col]) for col in payload_cols])
                    label = row[label_col]
                    
                    features = self.extractor.extract_features(payload)
                    features_list.append(features)
                    labels_list.append(label)
                    
                except Exception as e:
                    logger.debug(f"Error processing row {idx}: {e}")
                    continue
            
            # Create dataframe
            features_df = pd.DataFrame(features_list)
            features_df['label'] = labels_list
            features_df['label_numeric'] = features_df['label'].apply(
                self._normalize_label
            )
            
            logger.info(f"Extracted features for {len(features_df)} samples")
            logger.info(f"Label distribution:\n{features_df['label_numeric'].value_counts()}")
            
            features_df.to_csv(output_csv, index=False)
            logger.info(f"Saved to {output_csv}")
            
            return features_df
            
        except Exception as e:
            logger.error(f"Error processing ISCX dataset: {e}")
            raise
    
    def _normalize_label(self, label: Any) -> int:
        """Convert label to binary (0=benign, 1=attack)."""
        if isinstance(label, str):
            label = label.lower()
            if any(x in label for x in ['attack', 'malicious', 'anomaly', 'intrusion', 'injection']):
                return 1
            return 0
        
        # Numeric label
        return 1 if label != 0 else 0


if __name__ == "__main__":
    # Process datasets
    processor = DatasetProcessor("Datasets")
    
    # Process both datasets
    print("\n" + "="*80)
    print("PROCESSING DATASETS")
    print("="*80)
    
    try:
        csic_features = processor.process_csic_dataset("csic_features.csv")
        print(f"\nCSIC Features shape: {csic_features.shape}")
    except Exception as e:
        print(f"CSIC processing error: {e}")
    
    try:
        iscx_features = processor.process_iscx_dataset("iscx_features.csv")
        print(f"\nISCX Features shape: {iscx_features.shape}")
    except Exception as e:
        print(f"ISCX processing error: {e}")