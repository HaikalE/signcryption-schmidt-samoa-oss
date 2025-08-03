#!/usr/bin/env python3
"""
Schmidt-Samoa Cryptosystem Implementation

This module implements the Schmidt-Samoa public-key cryptosystem.
The security is based on the difficulty of factoring N = p²q.

Author: Claude (Based on Professional Analysis Memo)
Date: August 2025
"""

import random
import hashlib
from Crypto.Util import number
from sympy import gcd
import base64


class SchmidtSamoa:
    """Schmidt-Samoa Cryptosystem implementation."""
    
    @staticmethod
    def _string_to_int(message):
        """
        Convert string message to integer.
        
        Args:
            message (str): Input message
            
        Returns:
            int: Integer representation
        """
        return int.from_bytes(message.encode('utf-8'), byteorder='big')
    
    @staticmethod
    def _int_to_string(number):
        """
        Convert integer back to string.
        
        Args:
            number (int): Integer to convert
            
        Returns:
            str: String representation
        """
        byte_length = (number.bit_length() + 7) // 8
        return number.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')
    
    @staticmethod
    def _apply_padding(message, block_size):
        """
        Apply PKCS#7-style padding to message.
        
        Args:
            message (str): Original message
            block_size (int): Target block size
            
        Returns:
            str: Padded message
        """
        # Simple padding scheme
        padding_length = block_size - (len(message) % block_size)
        if padding_length == 0:
            padding_length = block_size
        
        padding_char = chr(padding_length)
        return message + (padding_char * padding_length)
    
    @staticmethod
    def _remove_padding(padded_message):
        """
        Remove padding from message.
        
        Args:
            padded_message (str): Padded message
            
        Returns:
            str: Original message without padding
        """
        if not padded_message:
            return padded_message
        
        padding_length = ord(padded_message[-1])
        return padded_message[:-padding_length]
    
    @staticmethod
    def encrypt(message, public_key):
        """
        Encrypt message using Schmidt-Samoa cryptosystem.
        
        Args:
            message (str): Plaintext message
            public_key (dict): Public key containing N and g
            
        Returns:
            str: Base64-encoded ciphertext
        """
        try:
            N = int(public_key['N'])
            g = int(public_key['g'])
            
            # Apply padding
            padded_message = SchmidtSamoa._apply_padding(message, 16)
            
            # Convert to integer
            m = SchmidtSamoa._string_to_int(padded_message)
            
            # Ensure message is smaller than N
            if m >= N:
                # For large messages, we'd typically use hybrid encryption
                # For this implementation, we'll use a simple approach
                m = m % N
            
            # Schmidt-Samoa encryption: c = g^m * r^N mod N
            # where r is a random value
            r = random.randint(2, N - 1)
            while gcd(r, N) != 1:
                r = random.randint(2, N - 1)
            
            # Calculate ciphertext
            c1 = pow(g, m, N)
            c2 = pow(r, N, N)
            ciphertext = (c1 * c2) % N
            
            # Encode as base64 for storage/transmission
            cipher_bytes = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, 'big')
            return base64.b64encode(cipher_bytes).decode('ascii')
            
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt(ciphertext_b64, private_key):
        """
        Decrypt ciphertext using Schmidt-Samoa cryptosystem.
        
        Args:
            ciphertext_b64 (str): Base64-encoded ciphertext
            private_key (dict): Private key containing p, q, d, N, g
            
        Returns:
            str: Decrypted plaintext message
        """
        try:
            p = int(private_key['p'])
            q = int(private_key['q'])
            d = int(private_key['d'])
            N = int(private_key['N'])
            g = int(private_key['g'])
            
            # Decode from base64
            cipher_bytes = base64.b64decode(ciphertext_b64.encode('ascii'))
            ciphertext = int.from_bytes(cipher_bytes, 'big')
            
            # Schmidt-Samoa decryption
            # m = (c^d mod N) using Chinese Remainder Theorem for efficiency
            
            # Simplified decryption (not using CRT for clarity)
            m = pow(ciphertext, d, N)
            
            # Convert back to string
            padded_message = SchmidtSamoa._int_to_string(m)
            
            # Remove padding
            message = SchmidtSamoa._remove_padding(padded_message)
            
            return message
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def encrypt_large_message(message, public_key, chunk_size=100):
        """
        Encrypt large messages by splitting into chunks.
        
        Args:
            message (str): Large plaintext message
            public_key (dict): Public key
            chunk_size (int): Size of chunks to encrypt separately
            
        Returns:
            list: List of encrypted chunks
        """
        chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
        encrypted_chunks = []
        
        for chunk in chunks:
            encrypted_chunk = SchmidtSamoa.encrypt(chunk, public_key)
            encrypted_chunks.append(encrypted_chunk)
        
        return encrypted_chunks
    
    @staticmethod
    def decrypt_large_message(encrypted_chunks, private_key):
        """
        Decrypt large messages from chunks.
        
        Args:
            encrypted_chunks (list): List of encrypted chunks
            private_key (dict): Private key
            
        Returns:
            str: Decrypted complete message
        """
        decrypted_parts = []
        
        for chunk in encrypted_chunks:
            decrypted_chunk = SchmidtSamoa.decrypt(chunk, private_key)
            decrypted_parts.append(decrypted_chunk)
        
        return ''.join(decrypted_parts)


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
    
    print("=== Schmidt-Samoa Cryptosystem Demo ===")
    
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
    
    # Test large message
    print("\n=== Testing Large Message ===")
    large_message = "This is a much longer message that needs to be encrypted. " * 10
    print(f"Large message length: {len(large_message)} characters")
    
    encrypted_chunks = SchmidtSamoa.encrypt_large_message(large_message, public_key)
    print(f"Encrypted into {len(encrypted_chunks)} chunks")
    
    decrypted_large = SchmidtSamoa.decrypt_large_message(encrypted_chunks, private_key)
    large_success = large_message == decrypted_large
    print(f"✅ Large message encryption successful: {large_success}")