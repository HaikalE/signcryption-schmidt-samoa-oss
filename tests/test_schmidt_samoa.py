#!/usr/bin/env python3
"""
Unit Tests for Schmidt-Samoa Cryptosystem

Author: Claude
Date: August 2025
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schmidt_samoa import SchmidtSamoa, encrypt, decrypt
from key_generator import generate_schmidt_samoa_keys


class TestSchmidtSamoa:
    """Test cases for Schmidt-Samoa cryptosystem."""
    
    @pytest.fixture
    def keys(self):
        """Generate test key pair."""
        return generate_schmidt_samoa_keys(2048)
    
    def test_key_generation(self, keys):
        """Test that keys are generated properly."""
        public_key, private_key = keys
        
        # Check public key structure
        assert 'algorithm' in public_key
        assert public_key['algorithm'] == 'Schmidt-Samoa'
        assert 'N' in public_key
        assert 'g' in public_key
        assert 'key_size' in public_key
        
        # Check private key structure
        assert 'algorithm' in private_key
        assert private_key['algorithm'] == 'Schmidt-Samoa'
        assert 'p' in private_key
        assert 'q' in private_key
        assert 'd' in private_key
        assert 'N' in private_key
        assert 'g' in private_key
        
        # Verify N = p²q
        p = int(private_key['p'])
        q = int(private_key['q'])
        N = int(private_key['N'])
        assert N == (p * p) * q
    
    def test_basic_encryption_decryption(self, keys):
        """Test basic encryption and decryption."""
        public_key, private_key = keys
        
        original_message = "Hello, World!"
        
        # Encrypt
        encrypted = encrypt(original_message, public_key)
        assert encrypted is not None
        assert encrypted != original_message
        
        # Decrypt
        decrypted = decrypt(encrypted, private_key)
        assert decrypted == original_message
    
    def test_empty_message(self, keys):
        """Test encryption of empty message."""
        public_key, private_key = keys
        
        original_message = ""
        
        encrypted = encrypt(original_message, public_key)
        decrypted = decrypt(encrypted, private_key)
        
        assert decrypted == original_message
    
    def test_long_message(self, keys):
        """Test encryption of longer message."""
        public_key, private_key = keys
        
        original_message = "This is a longer message to test the Schmidt-Samoa cryptosystem. " * 5
        
        encrypted = encrypt(original_message, public_key)
        decrypted = decrypt(encrypted, private_key)
        
        assert decrypted == original_message
    
    def test_unicode_message(self, keys):
        """Test encryption of unicode message."""
        public_key, private_key = keys
        
        original_message = "Hello 世界! 🌍 Testing unicode: áéíóú"
        
        encrypted = encrypt(original_message, public_key)
        decrypted = decrypt(encrypted, private_key)
        
        assert decrypted == original_message
    
    def test_probabilistic_encryption(self, keys):
        """Test that encryption is probabilistic (same message produces different ciphertexts)."""
        public_key, private_key = keys
        
        message = "Test message for probabilistic encryption"
        
        # Encrypt same message multiple times
        encrypted1 = encrypt(message, public_key)
        encrypted2 = encrypt(message, public_key)
        
        # Ciphertexts should be different (probabilistic)
        assert encrypted1 != encrypted2
        
        # But both should decrypt to same message
        decrypted1 = decrypt(encrypted1, private_key)
        decrypted2 = decrypt(encrypted2, private_key)
        
        assert decrypted1 == message
        assert decrypted2 == message
        assert decrypted1 == decrypted2
    
    def test_large_message_chunks(self, keys):
        """Test large message encryption using chunking."""
        public_key, private_key = keys
        
        # Create a large message
        large_message = "This is a test of large message encryption. " * 100
        
        # Encrypt using chunking
        encrypted_chunks = SchmidtSamoa.encrypt_large_message(large_message, public_key, chunk_size=50)
        
        # Should have multiple chunks
        assert len(encrypted_chunks) > 1
        
        # Decrypt
        decrypted = SchmidtSamoa.decrypt_large_message(encrypted_chunks, private_key)
        
        assert decrypted == large_message
    
    def test_invalid_ciphertext(self, keys):
        """Test decryption with invalid ciphertext."""
        public_key, private_key = keys
        
        invalid_ciphertext = "This is not a valid ciphertext"
        
        with pytest.raises(ValueError):
            decrypt(invalid_ciphertext, private_key)
    
    def test_wrong_private_key(self, keys):
        """Test decryption with wrong private key."""
        public_key1, private_key1 = keys
        public_key2, private_key2 = generate_schmidt_samoa_keys(2048)
        
        message = "Secret message"
        
        # Encrypt with first public key
        encrypted = encrypt(message, public_key1)
        
        # Try to decrypt with wrong private key
        with pytest.raises(ValueError):
            decrypt(encrypted, private_key2)
    
    def test_string_integer_conversion(self):
        """Test string to integer conversion methods."""
        test_string = "Hello, World!"
        
        # Convert to int and back
        as_int = SchmidtSamoa._string_to_int(test_string)
        back_to_string = SchmidtSamoa._int_to_string(as_int)
        
        assert back_to_string == test_string
    
    def test_padding_removal(self):
        """Test padding application and removal."""
        test_message = "Test message"
        
        # Apply padding
        padded = SchmidtSamoa._apply_padding(test_message, 16)
        assert len(padded) % 16 == 0
        assert len(padded) >= len(test_message)
        
        # Remove padding
        unpadded = SchmidtSamoa._remove_padding(padded)
        assert unpadded == test_message


if __name__ == "__main__":
    pytest.main([__file__])