"""
Regex-Based Signature Detection Module
Detects known attack patterns using OWASP-mapped regex rules.
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class SignatureRule:
    """Represents a single detection rule."""
    rule_id: str
    name: str
    description: str
    pattern: str
    severity: str  # critical, high, medium, low
    risk_score: int  # 0-100
    category: str  # sql_injection, xss, command_injection, etc.
    cvss_score: float
    enabled: bool = True
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class SignatureMatch:
    """Represents a matched signature rule."""
    rule_id: str
    rule_name: str
    severity: str
    risk_score: int
    category: str
    matched_pattern: str
    matched_value: str
    location: str  # query, body, headers, cookies, path
    parameter_name: str
    confidence: float = 1.0


class RegexSignatureEngine:
    """Detects attacks using regex-based signatures."""
    
    # OWASP Attack Categories
    ATTACK_CATEGORIES = {
        'sql_injection': 'SQL Injection (A03:2021)',
        'xss': 'Cross-Site Scripting (A07:2021)',
        'command_injection': 'Command Injection (A03:2021)',
        'path_traversal': 'Path Traversal (A01:2021)',
        'lfi_rfi': 'Local/Remote File Inclusion (A01:2021)',
        'xxe': 'XML External Entity (A05:2021)',
        'ldap_injection': 'LDAP Injection (A03:2021)',
        'expression_injection': 'Expression Injection (A03:2021)',
    }
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize signature engine.
        
        Args:
            rules_dir: Directory containing JSON rule files
        """
        self.rules: Dict[str, SignatureRule] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.rules_dir = rules_dir or Path(__file__).parent.parent / 'rules'
        
        # Load built-in rules
        self._load_builtin_rules()
    
    def _load_builtin_rules(self) -> None:
        """Load built-in OWASP-based rules."""
        
        # SQL Injection Rules
        self._add_rule(
            rule_id='SQL_UNION_BASED',
            name='SQL UNION-Based Injection',
            description='Detects UNION-based SQL injection attempts',
            pattern=r'\bunion\s+(all\s+)?select\b',
            severity='critical',
            risk_score=90,
            category='sql_injection',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='SQL_BOOLEAN_BLIND',
            name='SQL Boolean-Based Blind Injection',
            description='Detects boolean-based blind SQL injection',
            pattern=r'(?:and|or)\s+(?:1\s*=\s*1|1\s*=\s*2|true|false)',
            severity='high',
            risk_score=85,
            category='sql_injection',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='SQL_TIME_BASED_BLIND',
            name='SQL Time-Based Blind Injection',
            description='Detects time-based blind SQL injection',
            pattern=r'(?:sleep|benchmark|pg_sleep|dbms_lock\.sleep)',
            severity='high',
            risk_score=85,
            category='sql_injection',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='SQL_ERROR_BASED',
            name='SQL Error-Based Injection',
            description='Detects error-based SQL injection',
            pattern=r"'?\s*or\s+'?[a-z]\w*\s*=\s*'?[a-z]\w*",
            severity='high',
            risk_score=85,
            category='sql_injection',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='SQL_KEYWORDS',
            name='SQL Dangerous Keywords',
            description='Detects common SQL injection keywords',
            pattern=r'\b(?:select|insert|update|delete|drop|create|alter|exec|execute|script|union|from|where)\b',
            severity='medium',
            risk_score=65,
            category='sql_injection',
            cvss_score=7.5
        )
        
        self._add_rule(
            rule_id='SQL_COMMENT_SYNTAX',
            name='SQL Comment Syntax',
            description='Detects SQL comment sequences used in injection',
            pattern=r'(?:--|#|/\*)',
            severity='medium',
            risk_score=60,
            category='sql_injection',
            cvss_score=7.5
        )
        
        # XSS Rules
        self._add_rule(
            rule_id='XSS_SCRIPT_TAG',
            name='XSS Script Tag',
            description='Detects <script> tag injection',
            pattern=r'<script[^>]*>',
            severity='critical',
            risk_score=95,
            category='xss',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='XSS_IFRAME',
            name='XSS iFrame Injection',
            description='Detects <iframe> tag injection',
            pattern=r'<iframe[^>]*>',
            severity='critical',
            risk_score=90,
            category='xss',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='XSS_EVENT_HANDLER',
            name='XSS Event Handler',
            description='Detects event handler attributes',
            pattern=r'on(?:load|error|click|mouse\w+|blur|focus|change|submit)\s*=',
            severity='high',
            risk_score=85,
            category='xss',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='XSS_JAVASCRIPT_URI',
            name='XSS JavaScript URI',
            description='Detects javascript: URI scheme',
            pattern=r'javascript\s*:',
            severity='high',
            risk_score=85,
            category='xss',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='XSS_DATA_URI',
            name='XSS Data URI',
            description='Detects data: URI with potential payloads',
            pattern=r'data:[^/]+/(?:html|xml|svg)',
            severity='high',
            risk_score=85,
            category='xss',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='XSS_HTML_TAGS',
            name='XSS HTML Tag Injection',
            description='Detects HTML tag injection',
            pattern=r'<(?:img|svg|embed|object|link|style|meta)[^>]*>',
            severity='high',
            risk_score=80,
            category='xss',
            cvss_score=9.8
        )
        
        # Command Injection Rules
        self._add_rule(
            rule_id='CMD_SHELL_SEPARATOR',
            name='Command Injection Shell Separator',
            description='Detects shell command separators',
            pattern=r'[;&|`]\\s*(?:cat|ls|whoami|id|nc|bash|sh|curl|wget)',
            severity='critical',
            risk_score=95,
            category='command_injection',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='CMD_PIPE_CHAIN',
            name='Command Injection Pipe Chain',
            description='Detects piped command chains',
            pattern=r'\|\s*(?:grep|sed|awk|wc|cut|head|tail|sort)',
            severity='high',
            risk_score=85,
            category='command_injection',
            cvss_score=9.8
        )
        
        self._add_rule(
            rule_id='CMD_REDIRECTION',
            name='Command Injection Redirection',
            description='Detects command redirection operators',
            pattern=r'[<>]+\s*(?:/dev/|\.txt|log)',
            severity='high',
            risk_score=85,
            category='command_injection',
            cvss_score=9.8
        )
        
        # Path Traversal Rules
        self._add_rule(
            rule_id='PATH_TRAVERSAL_DOTS',
            name='Path Traversal Directory Traversal',
            description='Detects ../ and equivalent traversal',
            pattern=r'\.{2,}[/\\]|\.{2,}%2[fF]|\.{2,}%5[cC]',
            severity='high',
            risk_score=85,
            category='path_traversal',
            cvss_score=7.5
        )
        
        self._add_rule(
            rule_id='PATH_TRAVERSAL_BACKSLASH',
            name='Path Traversal Backslash',
            description='Detects Windows-style path traversal',
            pattern=r'\.{2,}\\',
            severity='high',
            risk_score=85,
            category='path_traversal',
            cvss_score=7.5
        )
        
        self._add_rule(
            rule_id='PATH_TRAVERSAL_ENCODED',
            name='Path Traversal Encoded',
            description='Detects encoded path traversal',
            pattern=r'%2e%2e[/\\]|\.%2e[/\\]|%2e%2f',
            severity='high',
            risk_score=85,
            category='path_traversal',
            cvss_score=7.5
        )
        
        # LFI/RFI Rules
        self._add_rule(
            rule_id='LFI_SENSITIVE_FILES',
            name='LFI Sensitive File Access',
            description='Detects local file inclusion attempts',
            pattern=r'(?:/etc/passwd|/etc/shadow|/windows/system32|c:\\windows)',
            severity='high',
            risk_score=85,
            category='lfi_rfi',
            cvss_score=9.1
        )
        
        self._add_rule(
            rule_id='RFI_PROTOCOL',
            name='RFI Protocol Handler',
            description='Detects remote file inclusion protocols',
            pattern=r'(?:file|http|ftp|gopher|telnet):\s*///',
            severity='high',
            risk_score=85,
            category='lfi_rfi',
            cvss_score=9.1
        )
        
        self._add_rule(
            rule_id='LFI_WRAPPER',
            name='LFI PHP Wrapper',
            description='Detects PHP filter/input wrappers',
            pattern=r'(?:php://|compress\.|zlib::|bzip2::|rar://)',
            severity='high',
            risk_score=85,
            category='lfi_rfi',
            cvss_score=9.1
        )
        
        # XXE Rules
        self._add_rule(
            rule_id='XXE_DOCTYPE',
            name='XXE DTD Declaration',
            description='Detects DOCTYPE with external entity',
            pattern=r'<!DOCTYPE[^>]*\[<!ENTITY',
            severity='high',
            risk_score=85,
            category='xxe',
            cvss_score=8.8
        )
        
        # LDAP Injection
        self._add_rule(
            rule_id='LDAP_INJECTION',
            name='LDAP Injection',
            description='Detects LDAP filter injection',
            pattern=r'\([|&*]\s*\w+\s*=|[*])(?:\||\()',
            severity='high',
            risk_score=80,
            category='ldap_injection',
            cvss_score=7.5
        )
        
        # Expression Language Injection
        self._add_rule(
            rule_id='EL_INJECTION',
            name='Expression Language Injection',
            description='Detects EL/OGNL injection attempts',
            pattern=r'\$\{[^}]*\}|\$\([^)]*\)|%\{[^}]*\}',
            severity='high',
            risk_score=85,
            category='expression_injection',
            cvss_score=8.8
        )
        
        # Null Byte Injection
        self._add_rule(
            rule_id='NULL_BYTE',
            name='Null Byte Injection',
            description='Detects null byte injection attempts',
            pattern=r'%00|\\x00|\\u0000',
            severity='medium',
            risk_score=70,
            category='path_traversal',
            cvss_score=5.3
        )
    
    def _add_rule(self, rule_id: str, name: str, description: str, 
                  pattern: str, severity: str, risk_score: int, 
                  category: str, cvss_score: float, tags: List[str] = None) -> None:
        """Add a rule to the engine."""
        rule = SignatureRule(
            rule_id=rule_id,
            name=name,
            description=description,
            pattern=pattern,
            severity=severity,
            risk_score=risk_score,
            category=category,
            cvss_score=cvss_score,
            tags=tags or []
        )
        self.rules[rule_id] = rule
        
        # Compile regex pattern (case-insensitive)
        try:
            self.compiled_patterns[rule_id] = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Failed to compile regex for rule {rule_id}: {e}")
    
    def detect(self, text: str, location: str, parameter_name: str = "") -> List[SignatureMatch]:
        """
        Detect signature matches in text.
        
        Args:
            text: Text to analyze
            location: Where text came from (query, body, headers, cookies, path)
            parameter_name: Name of the parameter (if applicable)
            
        Returns:
            List of matched signatures
        """
        matches = []
        
        if not text:
            return matches
        
        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue
            
            if rule_id not in self.compiled_patterns:
                continue
            
            pattern = self.compiled_patterns[rule_id]
            
            # Find all matches
            for match_obj in pattern.finditer(text):
                matched_value = match_obj.group(0)
                
                match = SignatureMatch(
                    rule_id=rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    risk_score=rule.risk_score,
                    category=rule.category,
                    matched_pattern=rule.pattern,
                    matched_value=matched_value,
                    location=location,
                    parameter_name=parameter_name,
                    confidence=1.0
                )
                matches.append(match)
        
        return matches
    
    def detect_in_request(self, normalized_request: Any) -> Dict[str, List[SignatureMatch]]:
        """
        Detect all signatures in a normalized HTTP request.
        
        Args:
            normalized_request: NormalizedRequest object from http_parser
            
        Returns:
            Dictionary mapping locations to signature matches
        """
        all_matches = {}
        
        # Check query parameters
        for param_name, values in normalized_request.query_params.items():
            for value in values:
                matches = self.detect(value, 'query', param_name)
                if matches:
                    if 'query' not in all_matches:
                        all_matches['query'] = []
                    all_matches['query'].extend(matches)
        
        # Check request body
        matches = self.detect(normalized_request.body, 'body')
        if matches:
            all_matches['body'] = matches
        
        # Check decoded body
        matches = self.detect(normalized_request.decoded_body, 'body_decoded')
        if matches:
            if 'body_decoded' not in all_matches:
                all_matches['body_decoded'] = []
            all_matches['body_decoded'].extend(matches)
        
        # Check headers
        for header_name, header_value in normalized_request.headers.items():
            if header_name not in ['authorization', 'cookie']:  # Skip sensitive headers
                matches = self.detect(header_value, 'headers', header_name)
                if matches:
                    if 'headers' not in all_matches:
                        all_matches['headers'] = []
                    all_matches['headers'].extend(matches)
        
        # Check cookies
        for cookie_name, cookie_value in normalized_request.cookies.items():
            matches = self.detect(cookie_value, 'cookies', cookie_name)
            if matches:
                if 'cookies' not in all_matches:
                    all_matches['cookies'] = []
                all_matches['cookies'].extend(matches)
        
        # Check path
        matches = self.detect(normalized_request.path, 'path')
        if matches:
            all_matches['path'] = matches
        
        # Check normalized path
        matches = self.detect(normalized_request.decoded_path, 'path_decoded')
        if matches:
            if 'path_decoded' not in all_matches:
                all_matches['path_decoded'] = []
            all_matches['path_decoded'].extend(matches)
        
        return all_matches
    
    def get_highest_risk_score(self, matches: List[SignatureMatch]) -> int:
        """Get the highest risk score from a list of matches."""
        if not matches:
            return 0
        return max(m.risk_score for m in matches)
    
    def get_summary(self, matches: Dict[str, List[SignatureMatch]]) -> Dict[str, Any]:
        """
        Get summary of all matches.
        
        Returns:
            Summary dictionary with statistics
        """
        all_matches = []
        for match_list in matches.values():
            all_matches.extend(match_list)
        
        if not all_matches:
            return {
                'total_matches': 0,
                'highest_risk_score': 0,
                'threat_categories': [],
                'severity_distribution': {}
            }
        
        severity_dist = {}
        categories = set()
        
        for match in all_matches:
            # Severity distribution
            severity_dist[match.severity] = severity_dist.get(match.severity, 0) + 1
            # Categories
            categories.add(match.category)
        
        return {
            'total_matches': len(all_matches),
            'highest_risk_score': self.get_highest_risk_score(all_matches),
            'threat_categories': sorted(list(categories)),
            'severity_distribution': severity_dist,
            'matched_rules': [m.rule_id for m in all_matches]
        }


if __name__ == "__main__":
    # Test the signature engine
    engine = RegexSignatureEngine()
    
    # Test SQL injection
    sql_payload = "1' UNION SELECT * FROM users--"
    matches = engine.detect(sql_payload, 'query', 'id')
    print(f"SQL Injection Test: {len(matches)} matches")
    for match in matches:
        print(f"  - {match.rule_name}: {match.matched_value}")
    
    # Test XSS
    xss_payload = '<script>alert("xss")</script>'
    matches = engine.detect(xss_payload, 'body')
    print(f"\nXSS Test: {len(matches)} matches")
    for match in matches:
        print(f"  - {match.rule_name}: {match.matched_value}")
    
    # Test Command Injection
    cmd_payload = '; ls -la'
    matches = engine.detect(cmd_payload, 'query', 'cmd')
    print(f"\nCommand Injection Test: {len(matches)} matches")
    for match in matches:
        print(f"  - {match.rule_name}: {match.matched_value}")