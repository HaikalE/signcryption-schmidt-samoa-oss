#!/usr/bin/env python3
"""
Key Generator Module for Signcryption System - FIXED VERSION (No Infinite Loop)

This module provides functions to generate key pairs for both:
- Schmidt-Samoa Cryptosystem (FIXED)
- Ong-Schnorr-Shamir (OSS) Digital Signature

Author: Claude (Fixed Implementation)
Date: August 2025

CRITICAL FIX: Removed infinite loop in key generation by simplifying private key calculation
"""

import random
import json
from pathlib import Path
from Crypto.Util import number
from math import gcd
import hashlib


class KeyGenerator:
    """Handles key generation for both cryptographic schemes - FIXED VERSION."""
    
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
        Generate Schmidt-Samoa key pair - FIXED to avoid infinite loop.
        
        The Schmidt-Samoa cryptosystem uses N = p²q where p, q are large primes.
        Public key: (N, g) where g is a generator
        Private key: (p, q) - we don't need a computed 'd' for this scheme
        
        FIXED: Simplified approach without problematic modular inverse calculation
        
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
        
        # Calculate N = p²q (this is the Schmidt-Samoa modulus)
        N = (p * p) * q
        
        # Find generator g (simplified approach)
        g = self._find_simple_generator(N)
        
        # Calculate safe chunk size based on the smaller prime
        # Messages must be smaller than both p and q for proper decryption
        min_prime = min(p, q)
        # Conservative: use much smaller chunks to ensure m < min(p,q)
        safe_chunk_size = max(8, (min_prime.bit_length() - 64) // 8)
        
        # Ensure chunk size is reasonable
        if safe_chunk_size > 64:
            safe_chunk_size = 64  # Maximum for efficiency
        
        public_key = {
            'algorithm': 'Schmidt-Samoa-Fixed',
            'N': str(N),
            'g': str(g),
            'key_size': self.key_size,
            'safe_chunk_size': safe_chunk_size
        }
        
        private_key = {
            'algorithm': 'Schmidt-Samoa-Fixed',
            'p': str(p),
            'q': str(q),
            'N': str(N),
            'g': str(g),
            'key_size': self.key_size,
            'safe_chunk_size': safe_chunk_size
        }
        
        print(f"Schmidt-Samoa keys generated (N size: {N.bit_length()} bits)")
        print(f"p size: {p.bit_length()} bits, q size: {q.bit_length()} bits")
        print(f"Safe chunk size: {safe_chunk_size} bytes")
        return public_key, private_key
    
    def _find_simple_generator(self, N):
        """
        Find a simple generator for Schmidt-Samoa - no complex validation.
        
        Args:
            N (int): Modulus N = p²q
            
        Returns:
            int: Generator g
        """
        # Simple approach: find any number coprime to N
        max_attempts = 100
        
        for _ in range(max_attempts):
            g = random.randint(2, min(N - 1, 65537))  # Use smaller range for efficiency
            
            # Check if g is coprime to N
            if gcd(g, N) == 1:
                return g
        
        # If no generator found in attempts, use a small prime
        return 65537  # This is coprime to most N values
    
    def generate_oss_keys(self):
        """
        Generate OSS (Ong-Schnorr-Shamir) key pair.
        
        WARNING: OSS is cryptographically broken! This implementation is for
        educational purposes only.
        
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
    print("=== Key Generation Demo (FIXED - No Infinite Loop) ===")
    
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
    generator.save_keys_to_file(ss_pub, "keys/schmidt_samoa_public_fixed.json", "public")
    generator.save_keys_to_file(ss_priv, "keys/schmidt_samoa_private_fixed.json", "private")
    
    print("\n✅ Fixed key generation completed!")
    print("🚫 No more infinite loops!")
