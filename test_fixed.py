#!/usr/bin/env python3
"""
Quick Test Script for Fixed Schmidt-Samoa Implementation

This script provides a simple way to test the fixed Schmidt-Samoa cryptosystem
without any infinite loops or overflow errors.

Usage: python test_fixed.py

Author: Claude
Date: August 2025
"""

def test_schmidt_samoa_fixed():
    """Test the fixed Schmidt-Samoa implementation."""
    
    print("🔧 Testing Fixed Schmidt-Samoa Implementation")
    print("=" * 50)
    
    try:
        # Import the fixed modules
        from key_generator_fixed import generate_schmidt_samoa_keys
        from schmidt_samoa_fixed import encrypt, decrypt
        
        print("✅ Successfully imported fixed modules")
        
        # Generate keys (should not hang in infinite loop)
        print("\n🔑 Generating keys...")
        public_key, private_key = generate_schmidt_samoa_keys(2048)
        print("✅ Key generation completed successfully!")
        print(f"   N size: {len(public_key['N'])} digits")
        print(f"   Safe chunk size: {public_key['safe_chunk_size']} bytes")
        
        # Test encryption/decryption
        print("\n🔐 Testing encryption/decryption...")
        
        test_messages = [
            "Hello World!",
            "Schmidt-Samoa test message",
            "🎉 Unicode test: مرحبا",
            "A" * 100,  # Longer message
        ]
        
        success_count = 0
        
        for i, message in enumerate(test_messages, 1):
            try:
                print(f"\n   Test {i}: {message[:30]}{'...' if len(message) > 30 else ''}")
                
                # Encrypt
                encrypted = encrypt(message, public_key)
                print(f"   ✅ Encrypted ({len(encrypted)} chars)")
                
                # Decrypt
                decrypted = decrypt(encrypted, private_key)
                print(f"   ✅ Decrypted: {decrypted[:30]}{'...' if len(decrypted) > 30 else ''}")
                
                # Verify
                if message == decrypted:
                    print(f"   ✅ Verification: PASSED")
                    success_count += 1
                else:
                    print(f"   ❌ Verification: FAILED")
                    print(f"      Expected: {message}")
                    print(f"      Got: {decrypted}")
                    
            except Exception as e:
                print(f"   ❌ Error in test {i}: {e}")
        
        # Final results
        print("\n" + "=" * 50)
        print(f"📊 Test Results: {success_count}/{len(test_messages)} tests passed")
        
        if success_count == len(test_messages):
            print("🎉 ALL TESTS PASSED! The implementation is working correctly.")
            print("\n✅ No more overflow errors!")
            print("✅ No more infinite loops!")
            print("✅ Schmidt-Samoa is ready for use!")
        else:
            print("⚠️  Some tests failed. Please check the implementation.")
            
        return success_count == len(test_messages)
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you have the fixed files:")
        print("  - key_generator_fixed.py")
        print("  - schmidt_samoa_fixed.py")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def test_performance():
    """Test performance with different message sizes."""
    
    print("\n⏱️  Performance Test")
    print("=" * 30)
    
    try:
        from key_generator_fixed import generate_schmidt_samoa_keys
        from schmidt_samoa_fixed import encrypt, decrypt
        import time
        
        # Generate keys once
        print("Generating keys for performance test...")
        public_key, private_key = generate_schmidt_samoa_keys(2048)
        
        # Test different message sizes
        sizes = [10, 50, 100, 500]
        
        for size in sizes:
            message = "A" * size
            
            # Time encryption
            start = time.time()
            encrypted = encrypt(message, public_key)
            encrypt_time = time.time() - start
            
            # Time decryption
            start = time.time()
            decrypted = decrypt(encrypted, private_key)
            decrypt_time = time.time() - start
            
            # Verify
            success = message == decrypted
            
            print(f"Size {size:3d}: Encrypt {encrypt_time:.3f}s, Decrypt {decrypt_time:.3f}s - {'✅' if success else '❌'}")
            
    except Exception as e:
        print(f"❌ Performance test failed: {e}")


if __name__ == "__main__":
    print("🧪 Schmidt-Samoa Fixed Implementation Test Suite")
    print("=" * 55)
    
    # Run main functionality test
    main_success = test_schmidt_samoa_fixed()
    
    if main_success:
        # Run performance test if main test passed
        test_performance()
        
        print("\n🎊 CONGRATULATIONS!")
        print("Your Schmidt-Samoa implementation is now working perfectly!")
        print("\nYou can now use it in your signcryption system:")
        print("  from schmidt_samoa_fixed import encrypt, decrypt")
        print("  from key_generator_fixed import generate_schmidt_samoa_keys")
    else:
        print("\n❌ Tests failed. Please check the error messages above.")
