#!/usr/bin/env python3
"""
Basic Usage Examples for Signcryption System

Demonstrates how to use the Schmidt-Samoa & OSS signcryption system.

⚠️ WARNING: OSS is cryptographically insecure!
This is for educational purposes only.

Author: Claude
Date: August 2025
"""

import sys
import os
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_generator import generate_schmidt_samoa_keys, generate_oss_keys, KeyGenerator
from schmidt_samoa import encrypt, decrypt
from oss_signature import sign, verify


def show_security_warning():
    """Display security warning."""
    print("=" * 70)
    print("⚠️  SECURITY WARNING ⚠️")
    print("⚠️  OSS (Ong-Schnorr-Shamir) signature scheme is CRYPTOGRAPHICALLY BROKEN!")
    print("⚠️  This implementation is for EDUCATIONAL PURPOSES ONLY!")
    print("⚠️  NEVER use this for real security applications!")
    print("=" * 70)
    print()


def example_1_basic_signcryption():
    """Example 1: Basic signcryption workflow."""
    print("\n" + "=" * 50)
    print("EXAMPLE 1: Basic Signcryption Workflow")
    print("=" * 50)
    
    # Step 1: Generate keys
    print("1. Generating cryptographic keys...")
    ss_public, ss_private = generate_schmidt_samoa_keys(2048)
    oss_public, oss_private = generate_oss_keys(2048)
    print("✅ Keys generated successfully!")
    
    # Step 2: Original message
    original_message = "Hello, this is a confidential message that needs both secrecy and authentication!"
    print(f"\n2. Original message:\n   '{original_message}'")
    
    # Step 3: Sign the message
    print("\n3. Signing message with OSS...")
    signature = sign(original_message, oss_private)
    print(f"✅ Message signed (signature length: {len(signature)} chars)")
    
    # Step 4: Combine message and signature
    combined_data = json.dumps({
        'message': original_message,
        'signature': signature,
        'algorithm': 'OSS+Schmidt-Samoa',
        'timestamp': '2025-08-03T12:00:00Z'
    })
    print(f"\n4. Combined data prepared (length: {len(combined_data)} chars)")
    
    # Step 5: Encrypt the combined data
    print("\n5. Encrypting with Schmidt-Samoa...")
    encrypted_data = encrypt(combined_data, ss_public)
    print(f"✅ Data encrypted (ciphertext length: {len(encrypted_data)} chars)")
    print(f"   Encrypted data preview: {encrypted_data[:50]}...")
    
    # Step 6: Decrypt the data
    print("\n6. Decrypting with Schmidt-Samoa...")
    decrypted_json = decrypt(encrypted_data, ss_private)
    combined_result = json.loads(decrypted_json)
    print("✅ Data decrypted successfully!")
    
    # Step 7: Extract and verify
    extracted_message = combined_result['message']
    extracted_signature = combined_result['signature']
    
    print("\n7. Verifying signature with OSS...")
    is_valid = verify(extracted_message, extracted_signature, oss_public)
    
    # Results
    print(f"\n✅ RESULTS:")
    print(f"   Decrypted message: '{extracted_message}'")
    print(f"   Signature valid: {is_valid}")
    print(f"   Message integrity: {'CONFIRMED' if extracted_message == original_message else 'COMPROMISED'}")
    print(f"   Algorithm used: {combined_result.get('algorithm', 'Unknown')}")
    
    return is_valid and (extracted_message == original_message)


def example_2_tampering_detection():
    """Example 2: Demonstrate tampering detection."""
    print("\n" + "=" * 50)
    print("EXAMPLE 2: Tampering Detection")
    print("=" * 50)
    
    # Generate keys
    ss_public, ss_private = generate_schmidt_samoa_keys(2048)
    oss_public, oss_private = generate_oss_keys(2048)
    
    # Original process
    original_message = "Transfer $1000 to account 12345"
    print(f"Original message: '{original_message}'")
    
    signature = sign(original_message, oss_private)
    combined_data = json.dumps({
        'message': original_message,
        'signature': signature
    })
    encrypted_data = encrypt(combined_data, ss_public)
    
    # Legitimate decryption
    decrypted_json = decrypt(encrypted_data, ss_private)
    combined_result = json.loads(decrypted_json)
    
    # Simulate tampering
    tampered_message = "Transfer $10000 to account 99999"  # Malicious change!
    print(f"Tampered message: '{tampered_message}'")
    
    # Try to verify tampered message with original signature
    original_signature = combined_result['signature']
    is_tampered_valid = verify(tampered_message, original_signature, oss_public)
    is_original_valid = verify(original_message, original_signature, oss_public)
    
    print(f"\n✅ TAMPERING DETECTION RESULTS:")
    print(f"   Original message verification: {is_original_valid} ✅")
    print(f"   Tampered message verification: {is_tampered_valid} ❌")
    print(f"   Tampering detected: {'YES' if not is_tampered_valid else 'NO'}")
    
    return is_original_valid and not is_tampered_valid


def example_3_file_operations():
    """Example 3: Working with files."""
    print("\n" + "=" * 50)
    print("EXAMPLE 3: File Operations")
    print("=" * 50)
    
    # Create examples directory
    examples_dir = Path("examples_output")
    examples_dir.mkdir(exist_ok=True)
    
    # Generate and save keys
    print("1. Generating and saving keys...")
    generator = KeyGenerator(2048)
    ss_public, ss_private = generator.generate_schmidt_samoa_keys()
    oss_public, oss_private = generator.generate_oss_keys()
    
    # Save keys to files
    generator.save_keys_to_file(ss_public, examples_dir / "ss_public.json", "public")
    generator.save_keys_to_file(ss_private, examples_dir / "ss_private.json", "private")
    generator.save_keys_to_file(oss_public, examples_dir / "oss_public.json", "public")
    generator.save_keys_to_file(oss_private, examples_dir / "oss_private.json", "private")
    
    # Create a test message file
    test_message = """This is a confidential document that contains sensitive information.
    
It has multiple lines and should be protected using signcryption.
    
Timestamp: 2025-08-03
Classification: Confidential
Author: Example User
    
End of document."""
    
    message_file = examples_dir / "original_message.txt"
    with open(message_file, 'w', encoding='utf-8') as f:
        f.write(test_message)
    print(f"✅ Test message saved to: {message_file}")
    
    # Load keys from files
    print("\n2. Loading keys from files...")
    loaded_ss_public = generator.load_keys_from_file(examples_dir / "ss_public.json")
    loaded_ss_private = generator.load_keys_from_file(examples_dir / "ss_private.json")
    loaded_oss_public = generator.load_keys_from_file(examples_dir / "oss_public.json")
    loaded_oss_private = generator.load_keys_from_file(examples_dir / "oss_private.json")
    
    # Read message from file
    with open(message_file, 'r', encoding='utf-8') as f:
        file_message = f.read()
    
    # Signcrypt the file content
    print("\n3. Signcrypting file content...")
    signature = sign(file_message, loaded_oss_private)
    combined_data = json.dumps({
        'message': file_message,
        'signature': signature,
        'filename': 'original_message.txt',
        'algorithm': 'OSS+Schmidt-Samoa'
    })
    encrypted_data = encrypt(combined_data, loaded_ss_public)
    
    # Save encrypted data
    encrypted_file = examples_dir / "encrypted_message.enc"
    with open(encrypted_file, 'w', encoding='utf-8') as f:
        f.write(encrypted_data)
    print(f"✅ Encrypted data saved to: {encrypted_file}")
    
    # Load and decrypt
    print("\n4. Loading and decrypting file...")
    with open(encrypted_file, 'r', encoding='utf-8') as f:
        loaded_encrypted = f.read()
    
    decrypted_json = decrypt(loaded_encrypted, loaded_ss_private)
    result = json.loads(decrypted_json)
    
    # Verify
    is_valid = verify(result['message'], result['signature'], loaded_oss_public)
    
    # Save decrypted result
    decrypted_file = examples_dir / "decrypted_message.txt"
    with open(decrypted_file, 'w', encoding='utf-8') as f:
        f.write(result['message'])
    
    print(f"✅ FILE OPERATION RESULTS:")
    print(f"   Original file: {message_file}")
    print(f"   Encrypted file: {encrypted_file}")
    print(f"   Decrypted file: {decrypted_file}")
    print(f"   Signature valid: {is_valid}")
    print(f"   Content integrity: {'CONFIRMED' if result['message'] == file_message else 'COMPROMISED'}")
    print(f"   Original filename: {result.get('filename', 'Unknown')}")
    
    return is_valid and (result['message'] == file_message)


def example_4_oss_vulnerability_demo():
    """Example 4: Demonstrate OSS vulnerability (Educational)."""
    print("\n" + "=" * 50)
    print("EXAMPLE 4: OSS Vulnerability Demonstration")
    print("⚠️  This shows why OSS should NEVER be used in production!")
    print("=" * 50)
    
    # Generate keys
    oss_public, oss_private = generate_oss_keys(2048)
    
    message = "I owe you $100"
    print(f"Target message to forge: '{message}'")
    
    # Legitimate signature
    print("\n1. Creating legitimate signature...")
    legitimate_signature = sign(message, oss_private)
    legitimate_valid = verify(message, legitimate_signature, oss_public)
    print(f"✅ Legitimate signature valid: {legitimate_valid}")
    
    # Attempt forgery using only public key
    print("\n2. Attempting signature forgery with PUBLIC KEY ONLY...")
    try:
        from oss_signature import OSSSignature
        forged_signature = OSSSignature.forge_signature(message, oss_public)
        forged_valid = verify(message, forged_signature, oss_public)
        
        print(f"🚨 CRITICAL: Forged signature valid: {forged_valid}")
        print(f"🚨 This proves OSS is cryptographically BROKEN!")
        print(f"   Forged signature: {forged_signature[:50]}...")
        print(f"   Legitimate sig:   {legitimate_signature[:50]}...")
        print(f"   Signatures different: {forged_signature != legitimate_signature}")
        
        return forged_valid  # Should be True, demonstrating the vulnerability
        
    except Exception as e:
        print(f"Forgery attempt failed: {e}")
        print("(This would actually be better for security!)")
        return False


def main():
    """Run all examples."""
    show_security_warning()
    
    print("SIGNCRYPTION SYSTEM - USAGE EXAMPLES")
    print("Schmidt-Samoa Cryptosystem + OSS Digital Signature")
    print()
    
    results = []
    
    try:
        # Run examples
        results.append(example_1_basic_signcryption())
        results.append(example_2_tampering_detection())
        results.append(example_3_file_operations())
        results.append(example_4_oss_vulnerability_demo())
        
        # Summary
        print("\n" + "=" * 70)
        print("EXAMPLES SUMMARY")
        print("=" * 70)
        print(f"Example 1 (Basic workflow): {'PASSED' if results[0] else 'FAILED'}")
        print(f"Example 2 (Tampering detection): {'PASSED' if results[1] else 'FAILED'}")
        print(f"Example 3 (File operations): {'PASSED' if results[2] else 'FAILED'}")
        print(f"Example 4 (OSS vulnerability): {'DEMONSTRATED' if results[3] else 'NOT DEMONSTRATED'}")
        
        print("\n✅ All examples completed!")
        print("\n⚠️  REMEMBER: This is for educational purposes only!")
        print("⚠️  Use proven cryptographic libraries for real applications!")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()