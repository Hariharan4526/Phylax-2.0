"""
HTTP Parsing & Normalization Module
Extracts and normalizes HTTP request components for consistent analysis.
"""

import re
import urllib.parse
import unicodedata
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class NormalizedRequest:
    """Represents a normalized HTTP request."""
    method: str
    path: str
    query_params: Dict[str, List[str]]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: str
    
    # Normalized versions
    decoded_path: str = ""
    decoded_body: str = ""
    normalized_path: str = ""
    normalized_body: str = ""
    normalized_headers: Dict[str, str] = field(default_factory=dict)
    
    # Extracted features
    all_parameters: List[Tuple[str, str]] = field(default_factory=list)
    attack_surface: Dict[str, List[str]] = field(default_factory=dict)
    
    # Metadata
    raw_request: str = ""
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for processing."""
        return {
            'method': self.method,
            'path': self.path,
            'query_params': self.query_params,
            'headers': self.headers,
            'cookies': self.cookies,
            'body': self.body,
            'decoded_path': self.decoded_path,
            'decoded_body': self.decoded_body,
            'normalized_body': self.normalized_body,
            'all_parameters': self.all_parameters,
            'attack_surface': self.attack_surface
        }


class HTTPParser:
    """Parses and normalizes HTTP requests."""
    
    # Regex patterns for parsing
    REQUEST_LINE_PATTERN = r'^(\w+)\s+([^\s]+)\s+HTTP/[\d.]+$'
    HEADER_PATTERN = r'^([^:]+):\s*(.+)$'
    COOKIE_PATTERN = r'([^=;]+)=([^;]*)'
    QUERY_PARAM_PATTERN = r'([^=&]+)=?([^&]*)'
    
    def __init__(self):
        """Initialize parser."""
        self.request_line_regex = re.compile(self.REQUEST_LINE_PATTERN)
        self.header_regex = re.compile(self.HEADER_PATTERN)
        self.cookie_regex = re.compile(self.COOKIE_PATTERN)
        self.query_param_regex = re.compile(self.QUERY_PARAM_PATTERN)
    
    def parse_raw_request(self, raw_request: str) -> NormalizedRequest:
        """
        Parse raw HTTP request string into normalized request object.
        
        Args:
            raw_request: Raw HTTP request text
            
        Returns:
            NormalizedRequest object
        """
        lines = raw_request.split('\n')
        
        if not lines:
            raise ValueError("Empty request")
        
        # Parse request line
        request_line = lines[0].strip()
        method, path = self._parse_request_line(request_line)
        
        # Parse headers
        headers = {}
        body_start_idx = 0
        
        for idx, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start_idx = idx + 1
                break
            
            match = self.header_regex.match(line)
            if match:
                header_name, header_value = match.groups()
                headers[header_name.lower()] = header_value
        
        # Extract body
        body = '\n'.join(lines[body_start_idx:]) if body_start_idx < len(lines) else ""
        
        # Parse URL and query parameters
        decoded_path, query_params = self._parse_url(path)
        
        # Parse cookies from headers
        cookies = self._parse_cookies(headers.get('cookie', ''))
        
        # Create normalized request
        norm_req = NormalizedRequest(
            method=method,
            path=path,
            query_params=query_params,
            headers=headers,
            cookies=cookies,
            body=body,
            raw_request=raw_request
        )
        
        # Perform normalization
        self._normalize_request(norm_req)
        
        # Extract attack surface
        self._extract_attack_surface(norm_req)
        
        return norm_req
    
    def _parse_request_line(self, request_line: str) -> Tuple[str, str]:
        """Parse HTTP request line (METHOD PATH HTTP/VERSION)."""
        match = self.request_line_regex.match(request_line)
        if not match:
            raise ValueError(f"Invalid request line: {request_line}")
        
        method, path = match.groups()
        return method.upper(), path
    
    def _parse_url(self, path: str) -> Tuple[str, Dict[str, List[str]]]:
        """
        Parse URL path and extract query parameters.
        
        Returns:
            (decoded_path, query_params_dict)
        """
        if '?' in path:
            path_part, query_part = path.split('?', 1)
        else:
            path_part, query_part = path, ""
        
        # Decode path
        decoded_path = urllib.parse.unquote(path_part)
        
        # Parse query parameters
        query_params = defaultdict(list)
        if query_part:
            for match in self.query_param_regex.finditer(query_part):
                param_name, param_value = match.groups()
                param_name = urllib.parse.unquote_plus(param_name)
                param_value = urllib.parse.unquote_plus(param_value)
                query_params[param_name].append(param_value)
        
        return decoded_path, dict(query_params)
    
    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        """Parse Cookie header into dictionary."""
        cookies = {}
        if not cookie_header:
            return cookies
        
        for match in self.cookie_regex.finditer(cookie_header):
            name, value = match.groups()
            cookies[name.strip()] = value.strip()
        
        return cookies
    
    def _normalize_request(self, req: NormalizedRequest) -> None:
        """Normalize all request components."""
        # Decode paths
        req.decoded_path = self._decode_path(req.path)
        req.decoded_body = self._decode_body(req.body)
        
        # Normalize paths (remove ../, resolve %00, etc.)
        req.normalized_path = self._normalize_path(req.decoded_path)
        req.normalized_body = self._normalize_body(req.decoded_body)
        
        # Normalize headers (lowercase keys)
        req.normalized_headers = {k.lower(): v for k, v in req.headers.items()}
    
    def _decode_path(self, path: str) -> str:
        """
        Multi-layer URL decoding for path.
        Handles common encoding techniques.
        """
        decoded = path
        
        # First pass: standard URL decoding
        decoded = urllib.parse.unquote(decoded)
        
        # Second pass: handle double encoding
        prev = None
        while prev != decoded:
            prev = decoded
            decoded = urllib.parse.unquote(decoded)
        
        # Handle Unicode encoding variations
        decoded = self._normalize_unicode(decoded)
        
        return decoded
    
    def _decode_body(self, body: str) -> str:
        """Decode request body."""
        if not body:
            return ""
        
        decoded = body
        
        # URL decoding
        decoded = urllib.parse.unquote_plus(decoded)
        
        # Multi-layer decoding
        prev = None
        iterations = 0
        while prev != decoded and iterations < 3:  # Limit iterations
            prev = decoded
            try:
                decoded = urllib.parse.unquote_plus(decoded)
            except:
                break
            iterations += 1
        
        # Unicode normalization
        decoded = self._normalize_unicode(decoded)
        
        return decoded
    
    def _normalize_unicode(self, text: str) -> str:
        """
        Normalize Unicode to NFC form.
        Handles various Unicode normalization forms.
        """
        try:
            # Try NFKC first (most aggressive)
            normalized = unicodedata.normalize('NFKC', text)
            # Fall back to NFC if NFKC fails
            normalized = unicodedata.normalize('NFC', normalized)
            return normalized
        except Exception as e:
            logger.warning(f"Unicode normalization failed: {e}")
            return text
    
    def _normalize_path(self, path: str) -> str:
        """
        Normalize path:
        - Remove null bytes (%00, \x00)
        - Remove ../ traversals
        - Convert to lowercase (where safe)
        - Resolve multiple slashes
        """
        # Remove null bytes
        normalized = path.replace('\x00', '').replace('%00', '')
        
        # Remove path traversal attempts
        normalized = re.sub(r'\.{2,}[/\\]', '', normalized)  # Remove ../
        normalized = re.sub(r'[/\\]{2,}', '/', normalized)   # Remove multiple slashes
        
        # Remove trailing slashes (normalize)
        while normalized.endswith('//'):
            normalized = normalized[:-1]
        
        return normalized
    
    def _normalize_body(self, body: str) -> str:
        """
        Normalize request body:
        - Remove null bytes
        - Convert to lowercase (preserve case for now)
        - Collapse whitespace
        """
        if not body:
            return ""
        
        # Remove null bytes
        normalized = body.replace('\x00', '')
        
        # Collapse multiple whitespace (but preserve newlines for structure)
        normalized = re.sub(r' {2,}', ' ', normalized)
        
        return normalized
    
    def _extract_attack_surface(self, req: NormalizedRequest) -> None:
        """Extract all input vectors for attack analysis."""
        attack_surface = defaultdict(list)
        all_params = []
        
        # Query parameters
        for param_name, values in req.query_params.items():
            attack_surface['query_params'].extend(values)
            for value in values:
                all_params.append((f"query:{param_name}", value))
        
        # POST body parameters
        if req.method in ['POST', 'PUT', 'PATCH']:
            # Try to parse as form data
            body_params = self._parse_body_params(req.body, 
                                                  req.headers.get('content-type', ''))
            for param_name, value in body_params:
                attack_surface['body_params'].append(value)
                all_params.append((f"body:{param_name}", value))
        
        # Header values (excluding sensitive headers)
        excluded_headers = {'authorization', 'cookie', 'x-api-key'}
        for header_name, header_value in req.headers.items():
            if header_name not in excluded_headers:
                attack_surface['headers'].append(header_value)
                all_params.append((f"header:{header_name}", header_value))
        
        # Cookie values
        for cookie_name, cookie_value in req.cookies.items():
            attack_surface['cookies'].append(cookie_value)
            all_params.append((f"cookie:{cookie_name}", cookie_value))
        
        # Path segments
        path_segments = req.decoded_path.split('/')
        for segment in path_segments:
            if segment:
                attack_surface['path'].append(segment)
                all_params.append((f"path", segment))
        
        req.attack_surface = dict(attack_surface)
        req.all_parameters = all_params
    
    def _parse_body_params(self, body: str, content_type: str) -> List[Tuple[str, str]]:
        """Parse request body parameters based on content type."""
        params = []
        
        if 'application/x-www-form-urlencoded' in content_type:
            # Parse form data
            for match in self.query_param_regex.finditer(body):
                name, value = match.groups()
                params.append((name, value))
        
        elif 'multipart/form-data' in content_type:
            # Simple multipart parsing (simplified)
            # In production, use proper multipart parser
            boundary = content_type.split('boundary=')[-1].strip()
            parts = body.split(f'--{boundary}')
            
            for part in parts:
                if 'Content-Disposition' in part:
                    # Extract name and value
                    name_match = re.search(r'name="([^"]+)"', part)
                    if name_match:
                        name = name_match.group(1)
                        # Extract value (after headers)
                        value = part.split('\r\n\r\n')[-1].strip()
                        if value:
                            params.append((name, value))
        
        else:
            # Treat entire body as parameter
            params.append(('body', body))
        
        return params
    
    def extract_features_for_ml(self, req: NormalizedRequest) -> Dict[str, Any]:
        """
        Extract features from normalized request for ML processing.
        
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Length features
        features['request_body_length'] = len(req.body)
        features['decoded_body_length'] = len(req.decoded_body)
        features['path_length'] = len(req.path)
        features['total_params'] = len(req.all_parameters)
        
        # Parameter statistics
        param_lengths = [len(v) for _, v in req.all_parameters]
        if param_lengths:
            features['param_avg_length'] = sum(param_lengths) / len(param_lengths)
            features['param_max_length'] = max(param_lengths)
            features['param_min_length'] = min(param_lengths)
        
        # Concatenate all input for analysis
        all_input = ' '.join([v for _, v in req.all_parameters] + [req.body])
        
        # Character statistics
        features['special_char_ratio'] = self._count_special_chars(all_input) / len(all_input) if all_input else 0
        features['digit_ratio'] = sum(1 for c in all_input if c.isdigit()) / len(all_input) if all_input else 0
        features['uppercase_ratio'] = sum(1 for c in all_input if c.isupper()) / len(all_input) if all_input else 0
        
        # Entropy
        features['entropy'] = self._calculate_entropy(all_input)
        
        # SQL keywords
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'where', 'and', 'or']
        features['sql_keyword_count'] = sum(all_input.lower().count(kw) for kw in sql_keywords)
        
        # Command keywords
        cmd_keywords = ['cat', 'ls', 'whoami', 'nc', 'bash', 'sh', 'wget', 'curl']
        features['cmd_keyword_count'] = sum(all_input.lower().count(kw) for kw in cmd_keywords)
        
        # Encoding indicators
        features['percent_signs'] = all_input.count('%')
        features['null_bytes'] = all_input.count('\x00')
        features['quotes_count'] = all_input.count('"') + all_input.count("'")
        
        return features
    
    def _count_special_chars(self, text: str) -> int:
        """Count special characters (non-alphanumeric)."""
        return sum(1 for c in text if not c.isalnum() and not c.isspace())
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text.
        High entropy = more randomness (potential encoding/obfuscation).
        """
        if not text:
            return 0.0
        
        import math
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy


class RequestNormalizer:
    """Additional normalization utilities."""
    
    @staticmethod
    def normalize_for_matching(text: str) -> str:
        """
        Normalize text for regex matching.
        - Lowercase
        - Remove extra whitespace
        - Unescape common HTML entities
        """
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)
        
        # Unescape common HTML entities
        text = text.replace('&lt;', '<').replace('&gt;', '>')
        text = text.replace('&quot;', '"').replace('&#39;', "'")
        text = text.replace('&amp;', '&')
        
        return text


if __name__ == "__main__":
    # Example usage
    parser = HTTPParser()
    
    raw_request = """GET /search?q=test&id=123 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123; user=john
Content-Type: application/x-www-form-urlencoded

username=admin&password=test123"""
    
    try:
        normalized = parser.parse_raw_request(raw_request)
        print("Parsed Request:")
        print(f"  Method: {normalized.method}")
        print(f"  Path: {normalized.path}")
        print(f"  Query Params: {normalized.query_params}")
        print(f"  Headers: {normalized.headers}")
        print(f"  Cookies: {normalized.cookies}")
        print(f"  Attack Surface: {normalized.attack_surface}")
        
        # Extract ML features
        features = parser.extract_features_for_ml(normalized)
        print("\nExtracted Features:")
        for key, value in features.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"Error: {e}")