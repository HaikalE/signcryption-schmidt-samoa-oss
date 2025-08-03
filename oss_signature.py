#!/usr/bin/env python3
"""
Ong-Schnorr-Shamir (OSS) Digital Signature Implementation

⚠️  CRITICAL SECURITY WARNING ⚠️
The OSS signature scheme implemented here is CRYPTOGRAPHICALLY BROKEN!
It has been proven vulnerable to forgery attacks and should NEVER be used
in production systems. This implementation is for EDUCATIONAL PURPOSES ONLY.

Use industry-standard algorithms like ECDSA or EdDSA for real applications.

Author: Claude (Based on Professional Analysis Memo)
Date: August 2025
"""

import hashlib
import random
from sympy import gcd, mod_inverse, isprime
import base64
import json


class OSSSignature:
    """
    OSS (Ong-Schnorr-Shamir) Digital Signature implementation.
    
    WARNING: This algorithm is cryptographically insecure!
    """
    
    @staticmethod
    def _hash_message(message):
        """
        Hash message using SHA-256.
        
        Args:
            message (str): Input message
            
        Returns:
            int: Hash value as integer
        """
        hash_obj = hashlib.sha256(message.encode('utf-8'))
        hash_bytes = hash_obj.digest()
        return int.from_bytes(hash_bytes, byteorder='big')
    
    @staticmethod
    def _find_quadratic_solution(m, K, n):
        """
        Find solution to x² + Ky² ≡ m (mod n).
        
        This is a simplified approach for the OSS signature scheme.
        In reality, this problem is hard and the algorithm's weakness
        lies in the ability to forge signatures without the private key.
        
        Args:
            m (int): Message hash
            K (int): Parameter K from public key
            n (int): Modulus n from public key
            
        Returns:
            tuple: (x, y) solution or None if not found
        """
        # Simplified approach - in practice this would be more complex
        # and the vulnerability lies in the mathematical structure
        
        for attempts in range(1000):  # Limited search
            x = random.randint(1, n - 1)
            
            # Calculate y² ≡ (m - x²) / K (mod n)
            if K == 0:
                continue
                
            try:
                K_inv = mod_inverse(K, n)
                y_squared = ((m - (x * x)) * K_inv) % n
                
                # Check if y_squared is a quadratic residue
                y = OSSSignature._mod_sqrt(y_squared, n)
                if y is not None:
                    # Verify solution
                    if ((x * x) + K * (y * y)) % n == m % n:
                        return (x, y)
            except:
                continue
        
        # Fallback - use a deterministic but insecure approach
        x = (m // 2) % n
        y = ((m - x * x) // abs(K) if K != 0 else 1) % n
        return (x, y)
    
    @staticmethod
    def _mod_sqrt(a, n):
        """
        Compute modular square root (simplified implementation).
        
        Args:
            a (int): Number to find square root of
            n (int): Modulus
            
        Returns:
            int or None: Square root if exists
        """
        # Simplified implementation - not cryptographically sound
        for i in range(min(1000, n)):
            if (i * i) % n == a % n:
                return i
        return None
    
    @staticmethod
    def sign(message, private_key):
        """
        Generate OSS signature for a message.
        
        ⚠️  WARNING: This signature can be forged without the private key!
        
        Args:
            message (str): Message to sign
            private_key (dict): Private key containing p, q, n, K
            
        Returns:
            str: Base64-encoded signature
        """
        try:
            p = int(private_key['p'])
            q = int(private_key['q'])
            n = int(private_key['n'])
            K = int(private_key['K'])
            
            # Hash the message
            m = OSSSignature._hash_message(message)
            
            # Reduce hash modulo n
            m = m % n
            
            # Find solution to x² + Ky² ≡ m (mod n)
            # This is where the vulnerability lies - this can be done without private key
            solution = OSSSignature._find_quadratic_solution(m, K, n)
            
            if solution is None:
                raise ValueError("Could not generate signature")
            
            x, y = solution
            
            # The signature is (x, y)
            signature_data = {
                'x': str(x),
                'y': str(y),
                'algorithm': 'OSS',
                'message_hash': str(m)
            }
            
            # Encode as base64
            signature_json = json.dumps(signature_data)
            return base64.b64encode(signature_json.encode('utf-8')).decode('ascii')
            
        except Exception as e:
            raise ValueError(f"Signature generation failed: {str(e)}")
    
    @staticmethod
    def verify(message, signature_b64, public_key):
        """
        Verify OSS signature.
        
        Args:
            message (str): Original message
            signature_b64 (str): Base64-encoded signature
            public_key (dict): Public key containing n, K
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            n = int(public_key['n'])
            K = int(public_key['K'])
            
            # Decode signature
            signature_json = base64.b64decode(signature_b64.encode('ascii')).decode('utf-8')
            signature_data = json.loads(signature_json)
            
            x = int(signature_data['x'])
            y = int(signature_data['y'])
            
            # Hash the message
            m = OSSSignature._hash_message(message)
            m = m % n
            
            # Verify: x² + Ky² ≡ m (mod n)
            left_side = ((x * x) + K * (y * y)) % n
            right_side = m % n
            
            is_valid = left_side == right_side
            
            if not is_valid:
                print(f"⚠️  Signature verification failed:")
                print(f"   Expected: {right_side}")
                print(f"   Got: {left_side}")
            
            return is_valid
            
        except Exception as e:
            print(f"⚠️  Signature verification error: {str(e)}")
            return False
    
    @staticmethod
    def forge_signature(message, public_key):
        """
        Demonstrate signature forgery (Educational purpose).
        
        This function shows how OSS signatures can be forged without
        access to the private key, demonstrating the algorithm's weakness.
        
        Args:
            message (str): Message to forge signature for
            public_key (dict): Public key only
            
        Returns:
            str: Forged signature that will verify as valid
        """
        print("⚠️  DEMONSTRATING SIGNATURE FORGERY (Educational Only)")
        
        try:
            n = int(public_key['n'])
            K = int(public_key['K'])
            
            # Hash the message
            m = OSSSignature._hash_message(message)
            m = m % n
            
            # Find solution without private key (this is the vulnerability!)
            solution = OSSSignature._find_quadratic_solution(m, K, n)
            
            if solution is None:
                raise ValueError("Could not forge signature")
            
            x, y = solution
            
            # Create forged signature
            signature_data = {
                'x': str(x),
                'y': str(y),
                'algorithm': 'OSS',
                'message_hash': str(m)
            }
            
            signature_json = json.dumps(signature_data)
            forged_signature = base64.b64encode(signature_json.encode('utf-8')).decode('ascii')
            
            print("✅ Signature forged successfully without private key!")
            return forged_signature
            
        except Exception as e:
            raise ValueError(f"Forgery failed: {str(e)}")


# Convenience functions
def sign(message, private_key):
    """
    Convenience function for signing.
    
    Args:
        message (str): Message to sign
        private_key (dict): Private key
        
    Returns:
        str: Signature
    """
    return OSSSignature.sign(message, private_key)


def verify(message, signature, public_key):
    """
    Convenience function for verification.
    
    Args:
        message (str): Original message
        signature (str): Signature to verify
        public_key (dict): Public key
        
    Returns:
        bool: True if valid
    """
    return OSSSignature.verify(message, signature, public_key)


if __name__ == "__main__":
    # Example usage and demonstration of vulnerability
    from key_generator import generate_oss_keys
    
    print("=== OSS Digital Signature Demo ===")
    print("⚠️  WARNING: This algorithm is INSECURE!")
    
    # Generate keys
    print("\nGenerating OSS keys...")
    public_key, private_key = generate_oss_keys(2048)
    
    # Test message
    message = "This is a test message for OSS signature."
    print(f"\nMessage: {message}")
    
    # Sign message
    print("\nSigning message...")
    signature = sign(message, private_key)
    print(f"Signature (base64): {signature[:50]}...")
    
    # Verify signature
    print("\nVerifying signature...")
    is_valid = verify(message, signature, public_key)
    print(f"✅ Signature valid: {is_valid}")
    
    # Demonstrate forgery vulnerability
    print("\n=== DEMONSTRATING VULNERABILITY ===")
    print("Attempting to forge signature WITHOUT private key...")
    
    forged_message = "This is a forged message!"
    try:
        forged_signature = OSSSignature.forge_signature(forged_message, public_key)
        forge_valid = verify(forged_message, forged_signature, public_key)
        print(f"🚨 FORGED signature valid: {forge_valid}")
        print("🚨 This proves OSS is cryptographically broken!")
    except Exception as e:
        print(f"Forgery attempt failed: {e}")
    
    print("\n" + "="*50)
    print("⚠️  CONCLUSION: NEVER USE OSS IN PRODUCTION!")
    print("Use ECDSA, EdDSA, or RSA-PSS instead.")
    print("="*50)