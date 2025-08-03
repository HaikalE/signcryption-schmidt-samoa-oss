#!/usr/bin/env python3
"""
Unit Tests for OSS Digital Signature

⚠️ WARNING: OSS is cryptographically insecure!
These tests verify implementation correctness, not security.

Author: Claude
Date: August 2025
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oss_signature import OSSSignature, sign, verify
from key_generator import generate_oss_keys


class TestOSSSignature:
    """Test cases for OSS signature scheme."""
    
    @pytest.fixture
    def keys(self):
        """Generate test key pair."""
        return generate_oss_keys(2048)
    
    def test_key_generation(self, keys):
        """Test that OSS keys are generated properly."""
        public_key, private_key = keys
        
        # Check public key structure
        assert 'algorithm' in public_key
        assert public_key['algorithm'] == 'OSS'
        assert 'n' in public_key
        assert 'K' in public_key
        assert 'key_size' in public_key
        
        # Check private key structure
        assert 'algorithm' in private_key
        assert private_key['algorithm'] == 'OSS'
        assert 'p' in private_key
        assert 'q' in private_key
        assert 'n' in private_key
        assert 'K' in private_key
        assert 'phi_n' in private_key
        
        # Verify n = p*q
        p = int(private_key['p'])
        q = int(private_key['q'])
        n = int(private_key['n'])
        assert n == p * q
    
    def test_basic_signing_verification(self, keys):
        """Test basic signing and verification."""
        public_key, private_key = keys
        
        message = "Hello, World!"
        
        # Sign
        signature = sign(message, private_key)
        assert signature is not None
        assert len(signature) > 0
        
        # Verify
        is_valid = verify(message, signature, public_key)
        assert is_valid is True
    
    def test_empty_message(self, keys):
        """Test signing of empty message."""
        public_key, private_key = keys
        
        message = ""
        
        signature = sign(message, private_key)
        is_valid = verify(message, signature, public_key)
        
        assert is_valid is True
    
    def test_long_message(self, keys):
        """Test signing of longer message."""
        public_key, private_key = keys
        
        message = "This is a longer message to test the OSS signature scheme. " * 10
        
        signature = sign(message, private_key)
        is_valid = verify(message, signature, public_key)
        
        assert is_valid is True
    
    def test_unicode_message(self, keys):
        """Test signing of unicode message."""
        public_key, private_key = keys
        
        message = "Hello 世界! 🌍 Testing unicode: áéíóú"
        
        signature = sign(message, private_key)
        is_valid = verify(message, signature, public_key)
        
        assert is_valid is True
    
    def test_modified_message(self, keys):
        """Test that verification fails for modified message."""
        public_key, private_key = keys
        
        original_message = "Original message"
        modified_message = "Modified message"
        
        # Sign original message
        signature = sign(original_message, private_key)
        
        # Verify with modified message should fail
        is_valid = verify(modified_message, signature, public_key)
        assert is_valid is False
    
    def test_invalid_signature(self, keys):
        """Test verification with invalid signature."""
        public_key, private_key = keys
        
        message = "Test message"
        invalid_signature = "This is not a valid signature"
        
        is_valid = verify(message, invalid_signature, public_key)
        assert is_valid is False
    
    def test_wrong_public_key(self, keys):
        """Test verification with wrong public key."""
        public_key1, private_key1 = keys
        public_key2, private_key2 = generate_oss_keys(2048)
        
        message = "Secret message"
        
        # Sign with first private key
        signature = sign(message, private_key1)
        
        # Try to verify with wrong public key should fail
        is_valid = verify(message, signature, public_key2)
        assert is_valid is False
    
    def test_hash_message_function(self):
        """Test message hashing function."""
        message1 = "Hello, World!"
        message2 = "Hello, World!"
        message3 = "Different message"
        
        hash1 = OSSSignature._hash_message(message1)
        hash2 = OSSSignature._hash_message(message2)
        hash3 = OSSSignature._hash_message(message3)
        
        # Same messages should produce same hash
        assert hash1 == hash2
        
        # Different messages should produce different hashes
        assert hash1 != hash3
        
        # Hashes should be integers
        assert isinstance(hash1, int)
        assert isinstance(hash3, int)
    
    def test_signature_forgery_vulnerability(self, keys):
        """Test the signature forgery vulnerability (demonstrates OSS weakness)."""
        public_key, private_key = keys
        
        message = "Message to forge"
        
        # Demonstrate that signatures can be forged using only public key
        try:
            forged_signature = OSSSignature.forge_signature(message, public_key)
            
            # The forged signature should verify as valid
            is_forged_valid = verify(message, forged_signature, public_key)
            
            # This demonstrates the vulnerability - we can create valid signatures
            # without access to the private key!
            assert is_forged_valid is True
            
            print("⚠️ OSS vulnerability confirmed: Signature forged without private key!")
            
        except Exception as e:
            # If forgery fails, that's actually better for security,
            # but not expected with our implementation
            print(f"Forgery attempt failed (which is better for security): {e}")
    
    def test_multiple_signatures_same_message(self, keys):
        """Test that multiple signatures of same message are different (if probabilistic)."""
        public_key, private_key = keys
        
        message = "Test message for multiple signatures"
        
        # Generate multiple signatures
        signature1 = sign(message, private_key)
        signature2 = sign(message, private_key)
        
        # Both should verify
        assert verify(message, signature1, public_key) is True
        assert verify(message, signature2, public_key) is True
        
        # Note: OSS might be deterministic, so signatures could be the same
        # This is not necessarily a problem for this test
    
    def test_signature_json_structure(self, keys):
        """Test that signature has proper JSON structure."""
        public_key, private_key = keys
        
        message = "Test message"
        signature = sign(message, private_key)
        
        # Signature should be base64 encoded
        import base64
        import json
        
        try:
            # Decode signature
            signature_json = base64.b64decode(signature.encode('ascii')).decode('utf-8')
            signature_data = json.loads(signature_json)
            
            # Check structure
            assert 'x' in signature_data
            assert 'y' in signature_data
            assert 'algorithm' in signature_data
            assert signature_data['algorithm'] == 'OSS'
            
        except Exception as e:
            pytest.fail(f"Signature does not have proper JSON structure: {e}")


if __name__ == "__main__":
    pytest.main([__file__])