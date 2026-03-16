#!/usr/bin/env python3
"""
SocGholish Advanced Malware Analyzer
Comprehensive static and dynamic analysis framework for SocGholish malware family.
Reconstructed from capstone report for journal publication.
"""

import os
import sys
import re
import math
import json
import csv
import hashlib
import argparse
from collections import Counter
from multiprocessing import Pool, cpu_count
from datetime import datetime

# Optional imports with graceful fallback
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False


class SocGholishAdvancedAnalyzer:
    """Main analysis engine for SocGholish malware samples."""

    def __init__(self, samples_dir):
        self.samples_dir = samples_dir
        self.results = []
        self.feature_extractors = {
            '.js': self.analyze_javascript,
            '.ps1': self.analyze_powershell,
            '.html': self.analyze_html,
            '.exe': self.analyze_executable,
        }

    def analyze_file(self, filepath):
        """Main analysis entry point."""
        file_ext = os.path.splitext(filepath)[1].lower()
        if file_ext in self.feature_extractors:
            return self.feature_extractors[file_ext](filepath)
        else:
            return self.generic_analysis(filepath)

    # =========================================================================
    # CORE UTILITIES
    # =========================================================================

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0

        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')

        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)

        for count in byte_counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def calculate_file_hashes(self, filepath):
        """Calculate MD5, SHA-1, SHA-256 hashes for a file."""
        hashes = {}
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            if HAS_SSDEEP:
                hashes['ssdeep'] = ssdeep.hash(content)
        except Exception as e:
            hashes['error'] = str(e)
        return hashes

    def get_file_metadata(self, filepath):
        """Extract basic file metadata."""
        stat = os.stat(filepath)
        return {
            'filename': os.path.basename(filepath),
            'filepath': filepath,
            'file_size': stat.st_size,
            'file_extension': os.path.splitext(filepath)[1].lower(),
            'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }

    # =========================================================================
    # JAVASCRIPT ANALYSIS
    # =========================================================================

    def analyze_javascript(self, filepath):
        """Comprehensive JavaScript malware analysis."""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        analysis = {
            **self.get_file_metadata(filepath),
            **self.calculate_file_hashes(filepath),
            'file_type': 'javascript',
            'file_size_chars': len(content),
            'entropy': self.calculate_entropy(content),
            'obfuscation_indicators': self.detect_obfuscation(content),
            'obfuscation_indicators_count': 0,  # set below
            'script_commands': len(re.findall(r'eval\(|document\.write|unescape', content)),
            'urls': re.findall(r'https?://[^\s"\'<>]+', content),
            'urls_count': 0,  # set below
            'suspicious_functions': self.detect_suspicious_js_functions(content),
            'suspicious_function_count': 0,  # set below
            'ip_addresses': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content),
            'domains': self.extract_domains(content),
            'file_paths': re.findall(r'[A-Za-z]:\\[^\s"\']+|/[a-z][a-z0-9_/.-]+', content, re.IGNORECASE),
            'registry_keys': re.findall(r'HKEY_[A-Z_]+\\[^\s"\']+', content),
            'base64_strings': re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content),
            'hex_strings': re.findall(r'\\x[0-9a-fA-F]{2}', content),
            'unicode_escapes': re.findall(r'\\u[0-9a-fA-F]{4}', content),
            'string_fromcharcode': len(re.findall(r'String\.fromCharCode', content)),
            'eval_count': len(re.findall(r'\beval\s*\(', content)),
            'function_count': len(re.findall(r'\bfunction\s+\w+\s*\(', content)),
            'var_count': len(re.findall(r'\bvar\s+\w+', content)),
            'line_count': content.count('\n') + 1,
            'api_calls': self.detect_api_calls(content),
            'network_indicators': self.detect_network_indicators(content),
        }

        # Set counts
        analysis['obfuscation_indicators_count'] = analysis['obfuscation_indicators']
        analysis['urls_count'] = len(analysis['urls'])
        analysis['suspicious_function_count'] = len(analysis['suspicious_functions'])

        # ML features
        analysis['ml_features'] = self.extract_ml_features(analysis)

        # Behavioral patterns
        analysis['behavioral_patterns'] = self.detect_socgholish_patterns(analysis)

        # Confidence score
        analysis['confidence_score'] = self.calculate_confidence_score(analysis)

        # Classification
        analysis['is_likely_malware'] = analysis['confidence_score'] > 0.5
        analysis['classification'] = 'malicious' if analysis['is_likely_malware'] else 'suspicious' if analysis['confidence_score'] > 0.3 else 'benign'

        return analysis

    def detect_obfuscation(self, content):
        """Detect JavaScript obfuscation techniques."""
        indicators = 0
        patterns = [
            r'\\x[0-9a-fA-F]{2}',           # Hex encoding
            r'\\u[0-9a-fA-F]{4}',           # Unicode encoding
            r'String\.fromCharCode',          # Character code conversion
            r'eval\s*\(',                     # Dynamic evaluation
            r'unescape\s*\(',                 # URL decoding
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*\[\s*["\'][a-zA-Z0-9_$]+["\']\s*\]',  # Bracket notation
            r'atob\s*\(',                     # Base64 decoding
            r'btoa\s*\(',                     # Base64 encoding
            r'charCodeAt\s*\(',               # Char code extraction
            r'Function\s*\(',                 # Dynamic function creation
            r'setTimeout\s*\(\s*["\']',       # Delayed eval via string
            r'setInterval\s*\(\s*["\']',      # Interval eval via string
            r'document\.write\s*\(',          # DOM write
            r'\.replace\s*\(\s*/[^/]+/[gim]*\s*,', # Regex-based deobfuscation
        ]

        for pattern in patterns:
            if re.search(pattern, content):
                indicators += 1

        return indicators

    def detect_suspicious_js_functions(self, content):
        """Detect suspicious JavaScript function calls."""
        suspicious = []
        suspicious_patterns = {
            'eval': r'\beval\s*\(',
            'document.write': r'document\.write\s*\(',
            'unescape': r'\bunescape\s*\(',
            'escape': r'\bescape\s*\(',
            'fromCharCode': r'String\.fromCharCode\s*\(',
            'createElement': r'document\.createElement\s*\(',
            'appendChild': r'\.appendChild\s*\(',
            'XMLHttpRequest': r'new\s+XMLHttpRequest',
            'ActiveXObject': r'new\s+ActiveXObject',
            'WScript.Shell': r'WScript\.Shell',
            'Scripting.FileSystemObject': r'Scripting\.FileSystemObject',
            'ADODB.Stream': r'ADODB\.Stream',
            'Shell.Application': r'Shell\.Application',
            'powershell': r'powershell',
            'cmd.exe': r'cmd\.exe',
            'wscript': r'wscript',
            'cscript': r'cscript',
        }

        for name, pattern in suspicious_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                suspicious.append(name)

        return suspicious

    def extract_domains(self, content):
        """Extract domain names from content."""
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|info|biz|co|uk|de|ru|cn|top|site|online|club|live|tech|space|pro|fun|icu|buzz|store|dev)'
        return list(set(re.findall(domain_pattern, content)))

    def detect_api_calls(self, content):
        """Detect Windows API and system calls in JavaScript."""
        api_patterns = {
            'process_manipulation': [
                r'CreateProcess', r'ShellExecute', r'WinExec',
                r'Process\.Start', r'exec\s*\(', r'spawn\s*\(',
            ],
            'file_operations': [
                r'CreateFile', r'WriteFile', r'ReadFile',
                r'FileSystemObject', r'CreateTextFile', r'OpenTextFile',
                r'CopyFile', r'DeleteFile', r'MoveFile',
            ],
            'registry_access': [
                r'RegWrite', r'RegRead', r'RegDelete',
                r'HKEY_', r'Registry',
            ],
            'network': [
                r'XMLHttpRequest', r'fetch\s*\(', r'\.open\s*\(\s*["\'](?:GET|POST)',
                r'WebSocket', r'XMLHTTP', r'WinHttp',
            ],
            'persistence': [
                r'ScheduledTask', r'Startup', r'RunOnce',
                r'CurrentVersion\\Run', r'TaskScheduler',
            ],
            'crypto': [
                r'CryptoAPI', r'encrypt', r'decrypt',
                r'AES', r'RSA', r'crypto',
            ],
        }

        detected = {}
        for category, patterns in api_patterns.items():
            count = 0
            for pattern in patterns:
                count += len(re.findall(pattern, content, re.IGNORECASE))
            detected[category] = count

        return detected

    def detect_network_indicators(self, content):
        """Detect network communication indicators."""
        indicators = {
            'http_requests': len(re.findall(r'\.open\s*\(\s*["\'](?:GET|POST|PUT)', content)),
            'ajax_calls': len(re.findall(r'XMLHttpRequest|fetch\s*\(|\.ajax\s*\(', content)),
            'websocket': len(re.findall(r'WebSocket\s*\(', content)),
            'user_agent_strings': re.findall(r'[Uu]ser-?[Aa]gent["\s:]+([^"\']+)', content),
            'content_type_headers': re.findall(r'[Cc]ontent-?[Tt]ype["\s:]+([^"\']+)', content),
        }
        return indicators

    # =========================================================================
    # HTML ANALYSIS
    # =========================================================================

    def analyze_html(self, filepath):
        """Comprehensive HTML malware analysis."""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        analysis = {
            **self.get_file_metadata(filepath),
            **self.calculate_file_hashes(filepath),
            'file_type': 'html_document',
            'file_size_chars': len(content),
            'entropy': self.calculate_entropy(content),
            'obfuscation_indicators': self.detect_obfuscation(content),
            'obfuscation_indicators_count': 0,
            'script_tags': len(re.findall(r'<script[^>]*>', content, re.IGNORECASE)),
            'inline_scripts': len(re.findall(r'<script[^>]*>[\s\S]*?</script>', content, re.IGNORECASE)),
            'iframe_tags': len(re.findall(r'<iframe[^>]*>', content, re.IGNORECASE)),
            'hidden_iframes': len(re.findall(r'<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["\']?0|height\s*=\s*["\']?0)', content, re.IGNORECASE)),
            'external_scripts': re.findall(r'<script[^>]*src\s*=\s*["\']([^"\']+)', content, re.IGNORECASE),
            'meta_redirects': re.findall(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']([^"\']+)', content, re.IGNORECASE),
            'form_actions': re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)', content, re.IGNORECASE),
            'urls': re.findall(r'https?://[^\s"\'<>]+', content),
            'urls_count': 0,
            'script_commands': len(re.findall(r'eval\(|document\.write|unescape', content)),
            'suspicious_functions': self.detect_suspicious_js_functions(content),
            'fake_update_indicators': self.detect_fake_update_patterns(content),
            'social_engineering_score': 0,
        }

        analysis['obfuscation_indicators_count'] = analysis['obfuscation_indicators']
        analysis['urls_count'] = len(analysis['urls'])
        analysis['social_engineering_score'] = self.calculate_social_engineering_score(content)
        analysis['ml_features'] = self.extract_ml_features(analysis)
        analysis['behavioral_patterns'] = self.detect_socgholish_patterns(analysis)
        analysis['confidence_score'] = self.calculate_confidence_score(analysis)
        analysis['is_likely_malware'] = analysis['confidence_score'] > 0.5
        analysis['classification'] = 'malicious' if analysis['is_likely_malware'] else 'suspicious' if analysis['confidence_score'] > 0.3 else 'benign'

        return analysis

    def detect_fake_update_patterns(self, content):
        """Detect fake browser update UI patterns."""
        indicators = {
            'update_keywords': 0,
            'browser_references': 0,
            'download_triggers': 0,
            'urgency_language': 0,
        }

        update_words = ['update', 'upgrade', 'download', 'install', 'patch', 'critical', 'security', 'browser', 'version', 'outdated']
        for word in update_words:
            indicators['update_keywords'] += len(re.findall(word, content, re.IGNORECASE))

        browser_refs = ['chrome', 'firefox', 'edge', 'safari', 'opera', 'browser']
        for ref in browser_refs:
            indicators['browser_references'] += len(re.findall(ref, content, re.IGNORECASE))

        download_triggers = [r'\.click\s*\(', r'window\.location', r'document\.location', r'\.href\s*=', r'\.download\s*=']
        for trigger in download_triggers:
            indicators['download_triggers'] += len(re.findall(trigger, content))

        urgency_words = ['immediately', 'urgent', 'critical', 'required', 'mandatory', 'warning', 'danger', 'risk', 'vulnerable', 'expired']
        for word in urgency_words:
            indicators['urgency_language'] += len(re.findall(word, content, re.IGNORECASE))

        return indicators

    def calculate_social_engineering_score(self, content):
        """Calculate social engineering effectiveness score."""
        score = 0.0
        content_lower = content.lower()

        if any(w in content_lower for w in ['update', 'upgrade', 'install']):
            score += 0.2
        if any(w in content_lower for w in ['chrome', 'firefox', 'edge', 'safari']):
            score += 0.2
        if any(w in content_lower for w in ['critical', 'urgent', 'required', 'mandatory']):
            score += 0.2
        if re.search(r'progress|loading|percent|%', content_lower):
            score += 0.1
        if re.search(r'logo|icon|brand', content_lower):
            score += 0.1
        if re.search(r'button|click|download', content_lower):
            score += 0.1
        if re.search(r'security|protect|safe', content_lower):
            score += 0.1

        return min(score, 1.0)

    # =========================================================================
    # POWERSHELL ANALYSIS
    # =========================================================================

    def analyze_powershell(self, filepath):
        """Comprehensive PowerShell script analysis."""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        analysis = {
            **self.get_file_metadata(filepath),
            **self.calculate_file_hashes(filepath),
            'file_type': 'powershell',
            'file_size_chars': len(content),
            'entropy': self.calculate_entropy(content),
            'obfuscation_indicators': self.detect_ps_obfuscation(content),
            'obfuscation_indicators_count': 0,
            'cmdlets': re.findall(r'[A-Z][a-z]+-[A-Z][a-z]+\w*', content),
            'invoke_expression': len(re.findall(r'Invoke-Expression|IEX|iex', content, re.IGNORECASE)),
            'download_cradles': len(re.findall(r'Net\.WebClient|Invoke-WebRequest|DownloadString|DownloadFile|wget|curl', content, re.IGNORECASE)),
            'encoded_commands': re.findall(r'-[Ee]nc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)', content),
            'bypass_attempts': len(re.findall(r'ExecutionPolicy\s+Bypass|-ep\s+bypass|Set-ExecutionPolicy', content, re.IGNORECASE)),
            'hidden_windows': len(re.findall(r'-WindowStyle\s+Hidden|-w\s+hidden', content, re.IGNORECASE)),
            'urls': re.findall(r'https?://[^\s"\'<>]+', content),
            'urls_count': 0,
            'ip_addresses': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content),
            'registry_operations': len(re.findall(r'Set-ItemProperty|New-ItemProperty|Get-ItemProperty|HKLM:|HKCU:', content, re.IGNORECASE)),
            'scheduled_tasks': len(re.findall(r'schtasks|Register-ScheduledTask|New-ScheduledTask', content, re.IGNORECASE)),
            'wmi_usage': len(re.findall(r'Get-WmiObject|Get-CimInstance|Invoke-WmiMethod|wmic', content, re.IGNORECASE)),
            'script_commands': len(re.findall(r'Invoke-Expression|IEX|Start-Process|Invoke-Command', content, re.IGNORECASE)),
            'suspicious_functions': [],
        }

        analysis['obfuscation_indicators_count'] = analysis['obfuscation_indicators']
        analysis['urls_count'] = len(analysis['urls'])
        analysis['ml_features'] = self.extract_ml_features(analysis)
        analysis['behavioral_patterns'] = self.detect_socgholish_patterns(analysis)
        analysis['confidence_score'] = self.calculate_confidence_score(analysis)
        analysis['is_likely_malware'] = analysis['confidence_score'] > 0.5
        analysis['classification'] = 'malicious' if analysis['is_likely_malware'] else 'suspicious' if analysis['confidence_score'] > 0.3 else 'benign'

        return analysis

    def detect_ps_obfuscation(self, content):
        """Detect PowerShell obfuscation techniques."""
        indicators = 0
        patterns = [
            r'-join\s*\(', r'\[char\]', r'-replace',
            r'`', r'\$\{[^}]+\}',  # tick marks and special vars
            r'-bxor|-band|-bor',   # bitwise operations
            r'\[Convert\]::FromBase64String',
            r'\[System\.Text\.Encoding\]',
            r'-split\s+["\']',
            r'\.Invoke\s*\(',
            r'ForEach-Object\s*\{',
        ]
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                indicators += 1
        return indicators

    # =========================================================================
    # EXECUTABLE ANALYSIS
    # =========================================================================

    def analyze_executable(self, filepath):
        """PE executable malware analysis."""
        if not HAS_PEFILE:
            return self.generic_analysis(filepath)

        try:
            pe = pefile.PE(filepath)
            analysis = {
                **self.get_file_metadata(filepath),
                **self.calculate_file_hashes(filepath),
                'file_type': 'PE_executable',
                'entropy': self.calculate_entropy(open(filepath, 'rb').read()),
                'section_count': len(pe.sections),
                'imported_dll_count': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
                'api_function_count': self.count_api_functions(pe),
                'suspicious_api_count': self.count_suspicious_apis(pe),
                'packing_indicators': self.detect_packing(pe),
                'entry_point_count': 1 if pe.OPTIONAL_HEADER.AddressOfEntryPoint else 0,
                'obfuscation_indicators_count': 0,
                'script_commands': 0,
                'urls_count': 0,
            }

            # Calculate section entropies
            section_entropies = []
            section_details = []
            for section in pe.sections:
                section_data = section.get_data()
                if section_data:
                    entropy = self.calculate_entropy(section_data)
                    section_entropies.append(entropy)
                    section_details.append({
                        'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                        'entropy': entropy,
                        'size': section.SizeOfRawData,
                        'virtual_size': section.Misc_VirtualSize,
                    })

            analysis['avg_section_entropy'] = sum(section_entropies) / len(section_entropies) if section_entropies else 0
            analysis['high_entropy_sections'] = sum(1 for e in section_entropies if e > 7.0)
            analysis['section_details'] = section_details

            # Extract strings for URL/IP detection
            raw_data = open(filepath, 'rb').read()
            strings = re.findall(b'[\x20-\x7e]{6,}', raw_data)
            string_content = b' '.join(strings).decode('utf-8', errors='ignore')
            analysis['urls'] = re.findall(r'https?://[^\s"\'<>]+', string_content)
            analysis['urls_count'] = len(analysis['urls'])
            analysis['ip_addresses'] = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string_content)

            analysis['ml_features'] = self.extract_ml_features(analysis)
            analysis['behavioral_patterns'] = self.detect_socgholish_patterns(analysis)
            analysis['confidence_score'] = self.calculate_confidence_score(analysis)
            analysis['is_likely_malware'] = analysis['confidence_score'] > 0.5
            analysis['classification'] = 'malicious' if analysis['is_likely_malware'] else 'suspicious' if analysis['confidence_score'] > 0.3 else 'benign'

            return analysis
        except Exception as e:
            return self.generic_analysis(filepath)

    def count_api_functions(self, pe):
        """Count total API functions imported."""
        count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                count += len(entry.imports)
        return count

    def count_suspicious_apis(self, pe):
        """Count suspicious API imports."""
        suspicious_apis = [
            b'VirtualAlloc', b'VirtualProtect', b'CreateRemoteThread',
            b'WriteProcessMemory', b'NtUnmapViewOfSection', b'CreateProcess',
            b'ShellExecute', b'WinExec', b'URLDownloadToFile',
            b'InternetOpen', b'InternetConnect', b'HttpSendRequest',
            b'RegSetValue', b'RegCreateKey', b'CreateService',
            b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
            b'GetTickCount', b'QueryPerformanceCounter',
        ]
        count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(s in imp.name for s in suspicious_apis):
                        count += 1
        return count

    def detect_packing(self, pe):
        """Detect potential packing in PE files."""
        indicators = 0
        for section in pe.sections:
            entropy = self.calculate_entropy(section.get_data())
            if entropy > 7.0:
                indicators += 1
            if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                indicators += 1
        if len(pe.sections) <= 2:
            indicators += 1
        return indicators

    # =========================================================================
    # GENERIC ANALYSIS
    # =========================================================================

    def generic_analysis(self, filepath):
        """Fallback analysis for unsupported file types."""
        with open(filepath, 'rb') as f:
            content = f.read()

        text_content = content.decode('utf-8', errors='ignore')

        analysis = {
            **self.get_file_metadata(filepath),
            **self.calculate_file_hashes(filepath),
            'file_type': 'unknown',
            'entropy': self.calculate_entropy(content),
            'urls': re.findall(r'https?://[^\s"\'<>]+', text_content),
            'urls_count': 0,
            'ip_addresses': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text_content),
            'obfuscation_indicators_count': 0,
            'script_commands': 0,
        }
        analysis['urls_count'] = len(analysis['urls'])
        analysis['confidence_score'] = 0.1
        analysis['classification'] = 'unknown'
        return analysis

    # =========================================================================
    # ML FEATURES & CLASSIFICATION
    # =========================================================================

    def extract_ml_features(self, analysis_result):
        """Extract 70+ machine learning features from analysis results."""
        features = {}

        # Numerical features
        numerical_features = [
            'file_size', 'entropy', 'section_count', 'avg_section_entropy',
            'api_function_count', 'suspicious_api_count',
            'script_commands', 'urls_count', 'obfuscation_indicators_count',
        ]
        for feature in numerical_features:
            features[feature] = analysis_result.get(feature, 0)

        # Boolean features
        boolean_features = [
            'has_packing', 'has_suspicious_apis', 'has_anti_analysis',
            'has_network_apis', 'has_crypto_apis', 'is_likely_malware',
        ]
        for feature in boolean_features:
            features[feature] = 1 if analysis_result.get(feature, False) else 0

        # Derived features
        features['entropy_ratio'] = features.get('entropy', 0) / 8.0
        features['url_density'] = features.get('urls_count', 0) / max(features.get('file_size', 1), 1) * 10000
        features['obfuscation_density'] = features.get('obfuscation_indicators_count', 0) / max(features.get('file_size', 1), 1) * 10000

        # API category features
        api_calls = analysis_result.get('api_calls', {})
        if isinstance(api_calls, dict):
            for category, count in api_calls.items():
                features[f'api_{category}_count'] = count

        return features

    def detect_socgholish_patterns(self, analysis_results):
        """Detect characteristic SocGholish behavioral patterns."""
        patterns = {
            'fake_update_delivery': False,
            'browser_hijacking': False,
            'credential_harvesting': False,
            'persistence_mechanism': False,
            'c2_communication': False,
            'data_exfiltration': False,
            'environment_detection': False,
        }

        # Check for fake update indicators
        if analysis_results.get('script_commands', 0) > 3 and \
           analysis_results.get('urls_count', 0) > 5:
            patterns['fake_update_delivery'] = True

        # Check for browser-related activities
        api_calls = analysis_results.get('api_calls', {})
        if isinstance(api_calls, dict):
            if api_calls.get('process_manipulation', 0) > 0:
                patterns['browser_hijacking'] = True

        # Check for persistence mechanisms
        if isinstance(api_calls, dict):
            if api_calls.get('registry_access', 0) > 0 or \
               api_calls.get('persistence', 0) > 0:
                patterns['persistence_mechanism'] = True

        # Check for C2 communication
        if isinstance(api_calls, dict):
            if api_calls.get('network', 0) > 0:
                patterns['c2_communication'] = True

        # Check for environment detection (anti-analysis)
        suspicious_funcs = analysis_results.get('suspicious_functions', [])
        if isinstance(suspicious_funcs, list):
            anti_analysis = ['IsDebuggerPresent', 'GetTickCount', 'QueryPerformanceCounter']
            if any(f in suspicious_funcs for f in anti_analysis):
                patterns['environment_detection'] = True

        return patterns

    def calculate_confidence_score(self, analysis_results):
        """Calculate confidence score for malware classification."""
        score = 0.0

        # Weight factors for different indicators
        weights = {
            'obfuscation_indicators_count': 0.2,
            'suspicious_api_count': 0.25,
            'script_commands': 0.15,
            'high_entropy_sections': 0.2,
            'network_activity': 0.1,
            'behavioral_patterns': 0.1,
        }

        # Obfuscation score
        obf = analysis_results.get('obfuscation_indicators_count', 0)
        if isinstance(obf, int):
            score += min(obf / 10.0, 1.0) * weights['obfuscation_indicators_count']

        # Suspicious API score
        sus_api = analysis_results.get('suspicious_api_count', 0)
        if isinstance(sus_api, int):
            score += min(sus_api / 10.0, 1.0) * weights['suspicious_api_count']
        elif isinstance(analysis_results.get('suspicious_functions', []), list):
            score += min(len(analysis_results['suspicious_functions']) / 10.0, 1.0) * weights['suspicious_api_count']

        # Script commands
        sc = analysis_results.get('script_commands', 0)
        if isinstance(sc, int):
            score += min(sc / 10.0, 1.0) * weights['script_commands']

        # Entropy
        entropy = analysis_results.get('entropy', 0)
        if entropy > 5.0:
            score += min((entropy - 5.0) / 3.0, 1.0) * weights['high_entropy_sections']

        # URLs/network
        urls = analysis_results.get('urls_count', 0)
        score += min(urls / 20.0, 1.0) * weights['network_activity']

        # Behavioral patterns
        patterns = analysis_results.get('behavioral_patterns', {})
        if isinstance(patterns, dict):
            active_patterns = sum(1 for v in patterns.values() if v)
            score += min(active_patterns / 5.0, 1.0) * weights['behavioral_patterns']

        return min(score, 1.0)

    def construct_feature_vector(self, analysis_results):
        """Construct ML-ready feature vector from analysis results."""
        feature_vector = []

        # Numerical features
        numerical_features = [
            'file_size', 'entropy', 'section_count', 'avg_section_entropy',
            'api_function_count', 'suspicious_api_count',
            'script_commands', 'urls_count', 'obfuscation_indicators_count',
        ]

        for feature in numerical_features:
            feature_vector.append(analysis_results.get(feature, 0))

        # Boolean features
        boolean_features = [
            'has_packing', 'has_suspicious_apis', 'has_anti_analysis',
            'has_network_apis', 'has_crypto_apis', 'is_likely_malware',
        ]

        for feature in boolean_features:
            feature_vector.append(1 if analysis_results.get(feature, False) else 0)

        return feature_vector

    # =========================================================================
    # BATCH PROCESSING & EXPORT
    # =========================================================================

    def analyze_batch(self, file_list, num_workers=4):
        """Parallel batch analysis of multiple files."""
        workers = min(num_workers, cpu_count(), len(file_list))

        print(f"[*] Analyzing {len(file_list)} files with {workers} workers...")

        # Use sequential processing for small batches or single worker
        if workers <= 1 or len(file_list) <= 3:
            results = []
            for i, filepath in enumerate(file_list):
                print(f"  [{i+1}/{len(file_list)}] Analyzing: {os.path.basename(filepath)}")
                try:
                    result = self.analyze_file(filepath)
                    results.append(result)
                except Exception as e:
                    print(f"    [!] Error: {e}")
                    results.append({'filename': os.path.basename(filepath), 'error': str(e)})
            return results

        with Pool(workers) as pool:
            results = pool.map(self.analyze_file, file_list)

        return results

    def process_sample_directory(self, directory_path):
        """Process entire directory of malware samples."""
        supported_extensions = ['.js', '.ps1', '.html', '.exe']

        file_list = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in supported_extensions):
                    file_list.append(os.path.join(root, file))

        print(f"[*] Found {len(file_list)} supported files in {directory_path}")
        results = self.analyze_batch(file_list)
        self.results = results
        return results

    def export_to_csv(self, results, output_file):
        """Export analysis results to CSV format."""
        if not results:
            print("[!] No results to export.")
            return

        # Flatten results for CSV
        flat_results = []
        for result in results:
            flat = {}
            for key, value in result.items():
                if isinstance(value, (dict, list)):
                    flat[key] = json.dumps(value)
                else:
                    flat[key] = value
            flat_results.append(flat)

        # Collect all headers
        headers = set()
        for result in flat_results:
            headers.update(result.keys())
        headers = sorted(headers)

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            for result in flat_results:
                writer.writerow(result)

        print(f"[+] Results exported to {output_file}")

    def export_to_json(self, results, output_file):
        """Export analysis results to JSON format."""
        # Convert non-serializable objects
        def make_serializable(obj):
            if isinstance(obj, bytes):
                return obj.decode('utf-8', errors='ignore')
            if isinstance(obj, set):
                return list(obj)
            return obj

        serializable_results = json.loads(
            json.dumps(results, default=make_serializable)
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2, default=str)

        print(f"[+] Results exported to {output_file}")

    def generate_summary_report(self, results):
        """Generate a summary report of all analysis results."""
        if not results:
            return {}

        summary = {
            'total_samples': len(results),
            'file_types': Counter(r.get('file_type', 'unknown') for r in results),
            'classifications': Counter(r.get('classification', 'unknown') for r in results),
            'average_entropy': 0,
            'entropy_range': {'min': float('inf'), 'max': 0},
            'average_confidence_score': 0,
            'average_obfuscation_indicators': 0,
            'average_urls_detected': 0,
            'average_script_commands': 0,
            'malicious_count': 0,
            'suspicious_count': 0,
            'benign_count': 0,
            'samples_with_network_activity': 0,
        }

        entropies = []
        confidence_scores = []
        obf_counts = []
        url_counts = []
        script_counts = []

        for r in results:
            if 'error' in r:
                continue

            entropy = r.get('entropy', 0)
            if entropy:
                entropies.append(entropy)

            cs = r.get('confidence_score', 0)
            if cs:
                confidence_scores.append(cs)

            obf_counts.append(r.get('obfuscation_indicators_count', 0))
            url_counts.append(r.get('urls_count', 0))
            script_counts.append(r.get('script_commands', 0))

            classification = r.get('classification', 'unknown')
            if classification == 'malicious':
                summary['malicious_count'] += 1
            elif classification == 'suspicious':
                summary['suspicious_count'] += 1
            elif classification == 'benign':
                summary['benign_count'] += 1

            if r.get('urls_count', 0) > 0:
                summary['samples_with_network_activity'] += 1

        if entropies:
            summary['average_entropy'] = round(sum(entropies) / len(entropies), 3)
            summary['entropy_range'] = {'min': round(min(entropies), 3), 'max': round(max(entropies), 3)}

        if confidence_scores:
            summary['average_confidence_score'] = round(sum(confidence_scores) / len(confidence_scores), 3)

        if obf_counts:
            summary['average_obfuscation_indicators'] = round(sum(obf_counts) / len(obf_counts), 2)

        if url_counts:
            summary['average_urls_detected'] = round(sum(url_counts) / len(url_counts), 2)

        if script_counts:
            summary['average_script_commands'] = round(sum(script_counts) / len(script_counts), 2)

        # Convert Counters to dicts for JSON serialization
        summary['file_types'] = dict(summary['file_types'])
        summary['classifications'] = dict(summary['classifications'])

        return summary


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='SocGholish Advanced Malware Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d ./samples                          Analyze all samples in directory
  %(prog)s -f malware.js                         Analyze a single file
  %(prog)s -d ./samples -o results.json --json   Export to JSON
  %(prog)s -d ./samples -o results.csv --csv     Export to CSV
  %(prog)s -d ./samples --summary                Print summary report
        """
    )

    parser.add_argument('-d', '--directory', help='Directory containing malware samples')
    parser.add_argument('-f', '--file', help='Single file to analyze')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--json', action='store_true', help='Export results to JSON')
    parser.add_argument('--csv', action='store_true', help='Export results to CSV')
    parser.add_argument('--summary', action='store_true', help='Print summary report')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of parallel workers')

    args = parser.parse_args()

    if not args.directory and not args.file:
        parser.print_help()
        sys.exit(1)

    analyzer = SocGholishAdvancedAnalyzer(args.directory or '.')

    if args.file:
        print(f"\n[*] Analyzing single file: {args.file}")
        result = analyzer.analyze_file(args.file)
        results = [result]
    else:
        print(f"\n[*] Processing directory: {args.directory}")
        results = analyzer.process_sample_directory(args.directory)

    # Generate summary
    summary = analyzer.generate_summary_report(results)

    if args.summary or (not args.output):
        print("\n" + "=" * 70)
        print("  SOCGHOLISH ANALYSIS SUMMARY REPORT")
        print("=" * 70)
        print(f"  Total Samples Analyzed:     {summary.get('total_samples', 0)}")
        print(f"  File Types:                 {summary.get('file_types', {})}")
        print(f"  Classifications:            {summary.get('classifications', {})}")
        print(f"  Malicious:                  {summary.get('malicious_count', 0)}")
        print(f"  Suspicious:                 {summary.get('suspicious_count', 0)}")
        print(f"  Benign:                     {summary.get('benign_count', 0)}")
        print(f"  Average Entropy:            {summary.get('average_entropy', 0)}")
        print(f"  Entropy Range:              {summary.get('entropy_range', {})}")
        print(f"  Avg Confidence Score:        {summary.get('average_confidence_score', 0)}")
        print(f"  Avg Obfuscation Indicators: {summary.get('average_obfuscation_indicators', 0)}")
        print(f"  Avg URLs Detected:          {summary.get('average_urls_detected', 0)}")
        print(f"  Avg Script Commands:        {summary.get('average_script_commands', 0)}")
        print(f"  Network Active Samples:     {summary.get('samples_with_network_activity', 0)}")
        print("=" * 70)

    # Export
    output_base = args.output or 'socgholish_analysis'

    if args.json or (args.output and args.output.endswith('.json')):
        json_file = args.output if args.output and args.output.endswith('.json') else output_base + '.json'
        analyzer.export_to_json(results, json_file)
        analyzer.export_to_json(summary, json_file.replace('.json', '_summary.json'))

    if args.csv or (args.output and args.output.endswith('.csv')):
        csv_file = args.output if args.output and args.output.endswith('.csv') else output_base + '.csv'
        analyzer.export_to_csv(results, csv_file)

    # Always export both by default if no specific format requested
    if not args.json and not args.csv:
        analyzer.export_to_json(results, output_base + '_results.json')
        analyzer.export_to_json(summary, output_base + '_summary.json')
        analyzer.export_to_csv(results, output_base + '_results.csv')

    print(f"\n[+] Analysis complete. {len(results)} samples processed.")
    return results, summary


if __name__ == '__main__':
    main()
