#!/usr/bin/env python3
"""
Key Generator Module for Signcryption System

This module provides functions to generate key pairs for both:
- Schmidt-Samoa Cryptosystem
- Ong-Schnorr-Shamir (OSS) Digital Signature

Author: Claude (Based on Professional Analysis Memo)
Date: August 2025
Warning: OSS signature scheme is cryptographically insecure!

UPDATED: Now includes safe_chunk_size in keys for robust chunking
"""

import random
import json
from pathlib import Path
from Crypto.Util import number
from sympy import gcd, mod_inverse
import hashlib


class KeyGenerator:
    """Handles key generation for both cryptographic schemes."""
    
    def __init__(self, key_size=2048):
        """
        Initialize key generator.
        
        Args:
            key_size (int): Size in bits for generated keys (minimum 2048)
        """
        if key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")
        self.key_size = key_size
    
    def generate_schmidt_samoa_keys(self):
        """
        Generate Schmidt-Samoa key pair.
        
        The Schmidt-Samoa cryptosystem uses N = p²q where p, q are large primes.
        Public key: (N, g) where g is a generator
        Private key: (p, q, d) where d ≡ N⁻¹ (mod lcm(p-1, q-1))
        
        Returns:
            tuple: (public_key_dict, private_key_dict)
        """
        print("Generating Schmidt-Samoa key pair...")
        
        # Generate two large primes p and q
        p = number.getPrime(self.key_size // 3)
        q = number.getPrime(self.key_size // 3)
        
        # Ensure p != q
        while p == q:
            q = number.getPrime(self.key_size // 3)
        
        # Calculate N = p²q
        N = (p * p) * q
        
        # Calculate lcm(p-1, q-1)
        lcm_val = ((p - 1) * (q - 1)) // gcd(p - 1, q - 1)
        
        # Find generator g (simplified approach)
        g = random.randint(2, N - 1)
        while gcd(g, N) != 1:
            g = random.randint(2, N - 1)
        
        # Calculate private exponent d
        try:
            d = mod_inverse(N, lcm_val)
        except ValueError:
            # If inverse doesn't exist, regenerate
            return self.generate_schmidt_samoa_keys()
        
        # Calculate safe chunk size based on smaller prime
        # This ensures encrypted integers m are always < p and < q
        min_prime = min(p, q)
        safe_chunk_size = max(1, (min_prime.bit_length() - 16) // 8)  # Leave room for safety
        
        public_key = {
            'algorithm': 'Schmidt-Samoa',
            'N': str(N),
            'g': str(g),
            'key_size': self.key_size,
            'safe_chunk_size': safe_chunk_size  # NEW: Safe chunking parameter
        }
        
        private_key = {
            'algorithm': 'Schmidt-Samoa',
            'p': str(p),
            'q': str(q),
            'd': str(d),
            'N': str(N),
            'g': str(g),
            'key_size': self.key_size,
            'safe_chunk_size': safe_chunk_size  # NEW: Safe chunking parameter
        }
        
        print(f"Schmidt-Samoa keys generated (N size: {N.bit_length()} bits)")
        print(f"Safe chunk size: {safe_chunk_size} bytes")
        return public_key, private_key
    
    def generate_oss_keys(self):
        """
        Generate OSS (Ong-Schnorr-Shamir) key pair.
        
        WARNING: OSS is cryptographically broken! This implementation is for
        educational purposes only.
        
        The OSS signature is based on x² + Ky² ≡ m (mod n)
        
        Returns:
            tuple: (public_key_dict, private_key_dict)
        """
        print("⚠️  WARNING: Generating OSS keys (INSECURE ALGORITHM!)")
        
        # Generate two primes for n = pq
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        
        while p == q:
            q = number.getPrime(self.key_size // 2)
        
        n = p * q
        
        # Choose K (small integer, typically -1 or small prime)
        K = -1  # Simplified choice
        
        # Generate random values for private key
        # Private key contains factors p, q and other parameters
        phi_n = (p - 1) * (q - 1)
        
        public_key = {
            'algorithm': 'OSS',
            'n': str(n),
            'K': str(K),
            'key_size': self.key_size
        }
        
        private_key = {
            'algorithm': 'OSS',
            'p': str(p),
            'q': str(q),
            'n': str(n),
            'K': str(K),
            'phi_n': str(phi_n),
            'key_size': self.key_size
        }
        
        print(f"OSS keys generated (n size: {n.bit_length()} bits)")
        return public_key, private_key
    
    def save_keys_to_file(self, keys, filename, key_type="public"):
        """
        Save keys to JSON file.
        
        Args:
            keys (dict): Key dictionary to save
            filename (str): Output filename
            key_type (str): "public" or "private" for file naming
        """
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(keys, f, indent=2)
        
        print(f"{key_type.capitalize()} key saved to: {filepath}")
    
    def load_keys_from_file(self, filename):
        """
        Load keys from JSON file.
        
        Args:
            filename (str): Input filename
            
        Returns:
            dict: Loaded key dictionary
        """
        with open(filename, 'r') as f:
            keys = json.load(f)
        
        print(f"Keys loaded from: {filename}")
        return keys


def generate_schmidt_samoa_keys(key_size=2048):
    """
    Convenience function to generate Schmidt-Samoa keys.
    
    Args:
        key_size (int): Key size in bits
        
    Returns:
        tuple: (public_key, private_key)
    """
    generator = KeyGenerator(key_size)
    return generator.generate_schmidt_samoa_keys()


def generate_oss_keys(key_size=2048):
    """
    Convenience function to generate OSS keys.
    
    Args:
        key_size (int): Key size in bits
        
    Returns:
        tuple: (public_key, private_key)
    """
    generator = KeyGenerator(key_size)
    return generator.generate_oss_keys()


if __name__ == "__main__":
    # Example usage
    print("=== Key Generation Demo ===")
    
    # Generate Schmidt-Samoa keys
    ss_pub, ss_priv = generate_schmidt_samoa_keys(2048)
    print("\nSchmidt-Samoa Public Key:")
    print(f"N: {ss_pub['N'][:50]}...")
    print(f"Safe chunk size: {ss_pub['safe_chunk_size']} bytes")
    
    # Generate OSS keys
    oss_pub, oss_priv = generate_oss_keys(2048)
    print("\nOSS Public Key:")
    print(f"n: {oss_pub['n'][:50]}...")
    
    # Save keys to files
    generator = KeyGenerator()
    generator.save_keys_to_file(ss_pub, "keys/schmidt_samoa_public.json", "public")
    generator.save_keys_to_file(ss_priv, "keys/schmidt_samoa_private.json", "private")
    generator.save_keys_to_file(oss_pub, "keys/oss_public.json", "public")
    generator.save_keys_to_file(oss_priv, "keys/oss_private.json", "private")
    
    print("\n✅ Key generation completed!")
