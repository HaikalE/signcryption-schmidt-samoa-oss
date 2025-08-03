#!/usr/bin/env python3
"""
Schmidt-Samoa Cryptosystem Implementation

This module implements the Schmidt-Samoa public-key cryptosystem.
The security is based on the difficulty of factoring N = p²q.

Author: Claude (Based on Professional Analysis Memo)
Date: August 2025

FIXED: Major cryptographic implementation issues based on expert analysis
"""

import random
import hashlib
from Crypto.Util import number
from math import gcd  # Using math.gcd instead of sympy for efficiency
import base64
import json


class SchmidtSamoa:
    """Schmidt-Samoa Cryptosystem implementation."""
    
    @staticmethod
    def _calculate_safe_chunk_size(private_key):
        """
        Calculate safe chunk size based on the smallest prime factor.
        
        Args:
            private_key (dict): Private key containing p, q
            
        Returns:
            int: Safe chunk size in bytes
        """
        p = int(private_key['p'])
        q = int(private_key['q'])
        
        # Use the smaller prime to ensure safety
        min_prime = min(p, q)
        
        # Safe chunk size: (bits - 8) / 8 to leave room for padding
        safe_bits = min_prime.bit_length() - 8
        safe_bytes = max(1, safe_bits // 8)
        
        return safe_bytes
    
    @staticmethod
    def _bytes_to_int(data_bytes):
        """
        Convert bytes to integer safely.
        
        Args:
            data_bytes (bytes): Input bytes
            
        Returns:
            int: Integer representation
        """
        if not data_bytes:
            return 0
        return int.from_bytes(data_bytes, byteorder='big')
    
    @staticmethod
    def _int_to_bytes(number, byte_length):
        """
        Convert integer back to bytes.
        
        Args:
            number (int): Integer to convert
            byte_length (int): Expected byte length
            
        Returns:
            bytes: Byte representation
        """
        if number == 0:
            return b'\x00' * byte_length
        
        actual_length = (number.bit_length() + 7) // 8
        target_length = max(byte_length, actual_length)
        
        return number.to_bytes(target_length, byteorder='big')
    
    @staticmethod
    def _apply_pkcs7_padding(data_bytes, block_size=16):
        """
        Apply PKCS#7 padding to bytes.
        
        Args:
            data_bytes (bytes): Original data
            block_size (int): Block size for padding
            
        Returns:
            bytes: Padded data
        """
        padding_length = block_size - (len(data_bytes) % block_size)
        if padding_length == 0:
            padding_length = block_size
        
        padding = bytes([padding_length] * padding_length)
        return data_bytes + padding
    
    @staticmethod
    def _remove_pkcs7_padding(padded_bytes):
        """
        Remove PKCS#7 padding from bytes.
        
        Args:
            padded_bytes (bytes): Padded data
            
        Returns:
            bytes: Original data without padding
        """
        if not padded_bytes:
            raise ValueError("Cannot remove padding from empty data")
        
        padding_length = padded_bytes[-1]
        
        # Validate padding
        if padding_length > len(padded_bytes) or padding_length == 0:
            raise ValueError("Invalid padding length")
        
        # Check if all padding bytes are correct
        padding_bytes = padded_bytes[-padding_length:]
        if not all(b == padding_length for b in padding_bytes):
            raise ValueError("Invalid padding content")
        
        return padded_bytes[:-padding_length]
    
    @staticmethod
    def _encrypt_chunk(chunk_bytes, public_key):
        """
        Encrypt a single chunk of bytes.
        
        Args:
            chunk_bytes (bytes): Chunk to encrypt
            public_key (dict): Public key containing N and g
            
        Returns:
            int: Encrypted chunk as integer
        """
        N = int(public_key['N'])
        g = int(public_key['g'])
        
        # Convert chunk to integer
        m = SchmidtSamoa._bytes_to_int(chunk_bytes)
        
        # Verify m is smaller than N (should always be true with proper chunking)
        if m >= N:
            raise ValueError(f"Message chunk too large: {m} >= {N}")
        
        # Generate random value r
        r = random.randint(2, N - 1)
        while gcd(r, N) != 1:
            r = random.randint(2, N - 1)
        
        # Schmidt-Samoa encryption: c = g^m * r^N mod N
        c1 = pow(g, m, N)
        c2 = pow(r, N, N)
        ciphertext = (c1 * c2) % N
        
        return ciphertext
    
    @staticmethod
    def _decrypt_chunk(ciphertext_int, private_key, expected_length):
        """
        Decrypt a single chunk.
        
        Args:
            ciphertext_int (int): Encrypted chunk
            private_key (dict): Private key
            expected_length (int): Expected byte length of decrypted chunk
            
        Returns:
            bytes: Decrypted chunk
        """
        p = int(private_key['p'])
        q = int(private_key['q'])
        d = int(private_key['d'])
        N = int(private_key['N'])
        
        # Schmidt-Samoa decryption: m = c^d mod N
        m = pow(ciphertext_int, d, N)
        
        # Convert back to bytes
        return SchmidtSamoa._int_to_bytes(m, expected_length)
    
    @staticmethod
    def encrypt(message, public_key):
        """
        Encrypt message using Schmidt-Samoa cryptosystem with proper chunking.
        
        Args:
            message (str): Plaintext message
            public_key (dict): Public key containing N and g
            
        Returns:
            str: Base64-encoded encrypted data structure
        """
        try:
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            # Apply PKCS#7 padding
            padded_bytes = SchmidtSamoa._apply_pkcs7_padding(message_bytes)
            
            # We need private key info to calculate safe chunk size
            # For now, use a conservative approach based on public key
            N = int(public_key['N'])
            # Conservative chunk size: use much smaller chunks to be safe
            safe_chunk_size = min(100, (N.bit_length() // 8) // 4)
            
            # Split into chunks
            chunks = []
            for i in range(0, len(padded_bytes), safe_chunk_size):
                chunk = padded_bytes[i:i+safe_chunk_size]
                chunks.append(chunk)
            
            # Encrypt each chunk
            encrypted_chunks = []
            chunk_sizes = []
            
            for chunk in chunks:
                encrypted_int = SchmidtSamoa._encrypt_chunk(chunk, public_key)
                encrypted_chunks.append(encrypted_int)
                chunk_sizes.append(len(chunk))
            
            # Create result structure
            result = {
                'chunks': [str(chunk) for chunk in encrypted_chunks],  # Convert to strings
                'chunk_sizes': chunk_sizes,
                'total_chunks': len(encrypted_chunks),
                'algorithm': 'Schmidt-Samoa-Fixed'
            }
            
            # Encode final result as base64
            result_json = json.dumps(result)
            return base64.b64encode(result_json.encode('utf-8')).decode('ascii')
            
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt(ciphertext_b64, private_key):
        """
        Decrypt ciphertext using Schmidt-Samoa cryptosystem.
        
        Args:
            ciphertext_b64 (str): Base64-encoded encrypted data structure
            private_key (dict): Private key containing p, q, d, N, g
            
        Returns:
            str: Decrypted plaintext message
        """
        try:
            # Decode base64 and parse JSON structure
            result_json = base64.b64decode(ciphertext_b64.encode('ascii')).decode('utf-8')
            result = json.loads(result_json)
            
            encrypted_chunks = [int(chunk) for chunk in result['chunks']]
            chunk_sizes = result['chunk_sizes']
            
            # Decrypt each chunk
            decrypted_chunks = []
            for i, (encrypted_int, expected_size) in enumerate(zip(encrypted_chunks, chunk_sizes)):
                chunk_bytes = SchmidtSamoa._decrypt_chunk(encrypted_int, private_key, expected_size)
                decrypted_chunks.append(chunk_bytes)
            
            # Combine chunks
            padded_bytes = b''.join(decrypted_chunks)
            
            # Remove padding
            message_bytes = SchmidtSamoa._remove_pkcs7_padding(padded_bytes)
            
            # Convert back to string
            return message_bytes.decode('utf-8')
            
        except (ValueError, TypeError, KeyError) as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Failed to decode decrypted message: {str(e)}")
    
    @staticmethod
    def encrypt_large_message(message, public_key, chunk_size=None):
        """
        Encrypt large messages (now uses the same improved algorithm).
        
        Args:
            message (str): Large plaintext message
            public_key (dict): Public key
            chunk_size (int): Ignored - calculated automatically
            
        Returns:
            str: Encrypted message (same format as encrypt)
        """
        return SchmidtSamoa.encrypt(message, public_key)
    
    @staticmethod
    def decrypt_large_message(encrypted_data, private_key):
        """
        Decrypt large messages (now uses the same improved algorithm).
        
        Args:
            encrypted_data (str): Encrypted message
            private_key (dict): Private key
            
        Returns:
            str: Decrypted complete message
        """
        return SchmidtSamoa.decrypt(encrypted_data, private_key)


# Convenience functions
def encrypt(message, public_key):
    """
    Convenience function for encryption.
    
    Args:
        message (str): Plaintext message
        public_key (dict): Public key
        
    Returns:
        str: Encrypted message
    """
    return SchmidtSamoa.encrypt(message, public_key)


def decrypt(ciphertext, private_key):
    """
    Convenience function for decryption.
    
    Args:
        ciphertext (str): Encrypted message
        private_key (dict): Private key
        
    Returns:
        str: Decrypted message
    """
    return SchmidtSamoa.decrypt(ciphertext, private_key)


if __name__ == "__main__":
    # Example usage and testing
    from key_generator import generate_schmidt_samoa_keys
    
    print("=== Schmidt-Samoa Cryptosystem Demo (FIXED) ===")
    
    # Generate keys
    print("Generating keys...")
    public_key, private_key = generate_schmidt_samoa_keys(2048)
    
    # Test message
    original_message = "Hello, this is a secret message for Schmidt-Samoa encryption!"
    print(f"\nOriginal message: {original_message}")
    
    # Encrypt
    print("\nEncrypting message...")
    encrypted = encrypt(original_message, public_key)
    print(f"Encrypted (base64): {encrypted[:50]}...")
    
    # Decrypt
    print("\nDecrypting message...")
    decrypted = decrypt(encrypted, private_key)
    print(f"Decrypted message: {decrypted}")
    
    # Verify
    success = original_message == decrypted
    print(f"\n✅ Encryption/Decryption successful: {success}")
    
    # Test JSON message (like what signcryption uses)
    print("\n=== Testing JSON Message ===")
    json_message = json.dumps({
        'message': 'Test message',
        'signature': 'fake_signature_for_test',
        'algorithm': 'OSS+Schmidt-Samoa'
    })
    print(f"JSON message: {json_message}")
    
    try:
        encrypted_json = encrypt(json_message, public_key)
        print(f"JSON encrypted: {encrypted_json[:50]}...")
        
        decrypted_json = decrypt(encrypted_json, private_key)
        print(f"JSON decrypted: {decrypted_json}")
        
        parsed_json = json.loads(decrypted_json)
        print(f"✅ JSON decryption successful: {parsed_json}")
        
    except Exception as e:
        print(f"❌ JSON test failed: {e}")
    
    # Test various message sizes
    print("\n=== Testing Various Message Sizes ===")
    test_messages = [
        "",  # Empty
        "A",  # Single char
        "Hello World!",  # Short
        "This is a longer message to test the chunking mechanism." * 5,  # Medium
        "Long message test. " * 100  # Large
    ]
    
    for i, test_msg in enumerate(test_messages):
        try:
            enc = encrypt(test_msg, public_key)
            dec = decrypt(enc, private_key)
            success = test_msg == dec
            print(f"Test {i+1} (len={len(test_msg)}): {'✅' if success else '❌'}")
        except Exception as e:
            print(f"Test {i+1} (len={len(test_msg)}): ❌ Error: {e}")
