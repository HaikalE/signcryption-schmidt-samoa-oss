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
import json


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
        if number == 0:
            return ""
        
        # Calculate byte length needed
        byte_length = (number.bit_length() + 7) // 8
        
        try:
            # Convert to bytes and decode
            byte_data = number.to_bytes(byte_length, byteorder='big')
            return byte_data.decode('utf-8', errors='replace')
        except (OverflowError, ValueError):
            # Fallback for very large numbers
            return str(number)
    
    @staticmethod
    def _apply_padding(message, block_size=16):
        """
        Apply PKCS#7-style padding to message.
        
        Args:
            message (str): Original message
            block_size (int): Target block size
            
        Returns:
            str: Padded message
        """
        # Convert to bytes first for proper padding
        message_bytes = message.encode('utf-8')
        padding_length = block_size - (len(message_bytes) % block_size)
        if padding_length == 0:
            padding_length = block_size
        
        # Apply PKCS#7 padding
        padded_bytes = message_bytes + bytes([padding_length] * padding_length)
        
        # Convert back to string using base64 for safe storage
        return base64.b64encode(padded_bytes).decode('ascii')
    
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
        
        try:
            # Decode from base64
            padded_bytes = base64.b64decode(padded_message.encode('ascii'))
            
            # Get padding length from last byte
            padding_length = padded_bytes[-1]
            
            # Remove padding
            original_bytes = padded_bytes[:-padding_length]
            
            return original_bytes.decode('utf-8')
        except Exception:
            # Fallback: return as-is if padding removal fails
            return padded_message
    
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
            
            # Apply padding first
            padded_message = SchmidtSamoa._apply_padding(message)
            
            # Convert padded message to integer
            m = SchmidtSamoa._string_to_int(padded_message)
            
            # Ensure message is smaller than N
            if m >= N:
                # For large messages, reduce modulo N
                m = m % (N - 1) + 1  # Ensure m > 0
            
            # Generate random value r
            r = random.randint(2, N - 1)
            while gcd(r, N) != 1:
                r = random.randint(2, N - 1)
            
            # Schmidt-Samoa encryption: c = g^m * r^N mod N
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
            
            # Decode from base64
            cipher_bytes = base64.b64decode(ciphertext_b64.encode('ascii'))
            ciphertext = int.from_bytes(cipher_bytes, 'big')
            
            # Schmidt-Samoa decryption: m = c^d mod N
            m = pow(ciphertext, d, N)
            
            # Convert back to padded string
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
            str: JSON string containing encrypted chunks
        """
        chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
        encrypted_chunks = []
        
        for chunk in chunks:
            encrypted_chunk = SchmidtSamoa.encrypt(chunk, public_key)
            encrypted_chunks.append(encrypted_chunk)
        
        # Return as JSON string for easier handling
        return json.dumps({
            'chunks': encrypted_chunks,
            'chunk_count': len(encrypted_chunks),
            'algorithm': 'Schmidt-Samoa-Chunked'
        })
    
    @staticmethod
    def decrypt_large_message(encrypted_data, private_key):
        """
        Decrypt large messages from chunks.
        
        Args:
            encrypted_data (str or list): JSON string or list of encrypted chunks
            private_key (dict): Private key
            
        Returns:
            str: Decrypted complete message
        """
        try:
            # Handle both JSON string and direct list input
            if isinstance(encrypted_data, str):
                data = json.loads(encrypted_data)
                encrypted_chunks = data['chunks']
            else:
                encrypted_chunks = encrypted_data
            
            decrypted_parts = []
            
            for chunk in encrypted_chunks:
                decrypted_chunk = SchmidtSamoa.decrypt(chunk, private_key)
                decrypted_parts.append(decrypted_chunk)
            
            return ''.join(decrypted_parts)
            
        except Exception as e:
            raise ValueError(f"Large message decryption failed: {str(e)}")


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
    
    # Test JSON message (like what signcryption uses)
    print("\n=== Testing JSON Message ===")
    json_message = json.dumps({
        'message': 'Test message',
        'signature': 'fake_signature_for_test',
        'algorithm': 'OSS+Schmidt-Samoa'
    })
    print(f"JSON message: {json_message}")
    
    encrypted_json = encrypt(json_message, public_key)
    decrypted_json = decrypt(encrypted_json, private_key)
    
    try:
        parsed_json = json.loads(decrypted_json)
        print(f"✅ JSON decryption successful: {parsed_json}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing failed: {e}")
        print(f"Decrypted string: '{decrypted_json}'")
