#!/usr/bin/env python3
"""
Integration Tests for Signcryption System

Tests the complete Sign-then-Encrypt workflow.

Author: Claude
Date: August 2025
"""

import pytest
import sys
import os
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_generator import generate_schmidt_samoa_keys, generate_oss_keys
from schmidt_samoa import encrypt, decrypt
from oss_signature import sign, verify


class TestSigncryptionIntegration:
    """Integration tests for the complete signcryption system."""
    
    @pytest.fixture
    def all_keys(self):
        """Generate all required key pairs."""
        ss_pub, ss_priv = generate_schmidt_samoa_keys(2048)
        oss_pub, oss_priv = generate_oss_keys(2048)
        return {
            'ss_public': ss_pub,
            'ss_private': ss_priv,
            'oss_public': oss_pub,
            'oss_private': oss_priv
        }
    
    def test_complete_signcryption_workflow(self, all_keys):
        """Test the complete Sign-then-Encrypt workflow."""
        original_message = "This is a secret message that needs authentication and confidentiality."
        
        # Step 1: Sign the message (OSS)
        signature = sign(original_message, all_keys['oss_private'])
        assert signature is not None
        
        # Step 2: Combine message and signature
        combined_data = json.dumps({
            'message': original_message,
            'signature': signature,
            'algorithm': 'OSS+Schmidt-Samoa'
        })
        
        # Step 3: Encrypt the combined data (Schmidt-Samoa)
        encrypted_data = encrypt(combined_data, all_keys['ss_public'])
        assert encrypted_data is not None
        assert encrypted_data != combined_data
        
        # Step 4: Decrypt the data (Schmidt-Samoa)
        decrypted_json = decrypt(encrypted_data, all_keys['ss_private'])
        assert decrypted_json == combined_data
        
        # Step 5: Extract message and signature
        combined_result = json.loads(decrypted_json)
        extracted_message = combined_result['message']
        extracted_signature = combined_result['signature']
        
        # Step 6: Verify the signature (OSS)
        is_valid = verify(extracted_message, extracted_signature, all_keys['oss_public'])
        
        # Final verification
        assert extracted_message == original_message
        assert is_valid is True
        assert combined_result['algorithm'] == 'OSS+Schmidt-Samoa'
    
    def test_signcryption_with_tampering(self, all_keys):
        """Test that tampering is detected in the signcryption workflow."""
        original_message = "Important message that should not be tampered with."
        
        # Complete signcryption process
        signature = sign(original_message, all_keys['oss_private'])
        combined_data = json.dumps({
            'message': original_message,
            'signature': signature,
            'algorithm': 'OSS+Schmidt-Samoa'
        })
        encrypted_data = encrypt(combined_data, all_keys['ss_public'])
        
        # Decrypt successfully
        decrypted_json = decrypt(encrypted_data, all_keys['ss_private'])
        combined_result = json.loads(decrypted_json)
        
        # Simulate tampering by modifying the message
        tampered_message = "Tampered message - this should be detected!"
        extracted_signature = combined_result['signature']
        
        # Verify with tampered message should fail
        is_valid_tampered = verify(tampered_message, extracted_signature, all_keys['oss_public'])
        assert is_valid_tampered is False
        
        # Verify with original message should still work
        is_valid_original = verify(original_message, extracted_signature, all_keys['oss_public'])
        assert is_valid_original is True
    
    def test_signcryption_with_wrong_keys(self, all_keys):
        """Test signcryption with wrong keys at different stages."""
        # Generate additional key pairs
        ss_pub2, ss_priv2 = generate_schmidt_samoa_keys(2048)
        oss_pub2, oss_priv2 = generate_oss_keys(2048)
        
        message = "Test message for wrong keys"
        
        # Correct signcryption
        signature = sign(message, all_keys['oss_private'])
        combined_data = json.dumps({
            'message': message,
            'signature': signature
        })
        encrypted_data = encrypt(combined_data, all_keys['ss_public'])
        
        # Try to decrypt with wrong Schmidt-Samoa private key
        with pytest.raises(ValueError):
            decrypt(encrypted_data, ss_priv2)
        
        # Decrypt with correct key
        decrypted_json = decrypt(encrypted_data, all_keys['ss_private'])
        combined_result = json.loads(decrypted_json)
        
        # Try to verify with wrong OSS public key
        is_valid_wrong_key = verify(
            combined_result['message'], 
            combined_result['signature'], 
            oss_pub2
        )
        assert is_valid_wrong_key is False
        
        # Verify with correct key
        is_valid_correct_key = verify(
            combined_result['message'], 
            combined_result['signature'], 
            all_keys['oss_public']
        )
        assert is_valid_correct_key is True
    
    def test_unicode_message_signcryption(self, all_keys):
        """Test signcryption with unicode messages."""
        unicode_message = "Hello 世界! 🌍 Unicode test: áéíóú αβγδε 你好"
        
        # Complete signcryption process
        signature = sign(unicode_message, all_keys['oss_private'])
        combined_data = json.dumps({
            'message': unicode_message,
            'signature': signature,
            'algorithm': 'OSS+Schmidt-Samoa'
        })
        encrypted_data = encrypt(combined_data, all_keys['ss_public'])
        
        # Decrypt and verify
        decrypted_json = decrypt(encrypted_data, all_keys['ss_private'])
        combined_result = json.loads(decrypted_json)
        extracted_message = combined_result['message']
        extracted_signature = combined_result['signature']
        
        is_valid = verify(extracted_message, extracted_signature, all_keys['oss_public'])
        
        assert extracted_message == unicode_message
        assert is_valid is True
    
    def test_empty_message_signcryption(self, all_keys):
        """Test signcryption with empty message."""
        empty_message = ""
        
        # Complete signcryption process
        signature = sign(empty_message, all_keys['oss_private'])
        combined_data = json.dumps({
            'message': empty_message,
            'signature': signature,
            'algorithm': 'OSS+Schmidt-Samoa'
        })
        encrypted_data = encrypt(combined_data, all_keys['ss_public'])
        
        # Decrypt and verify
        decrypted_json = decrypt(encrypted_data, all_keys['ss_private'])
        combined_result = json.loads(decrypted_json)
        extracted_message = combined_result['message']
        extracted_signature = combined_result['signature']
        
        is_valid = verify(extracted_message, extracted_signature, all_keys['oss_public'])
        
        assert extracted_message == empty_message
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__])