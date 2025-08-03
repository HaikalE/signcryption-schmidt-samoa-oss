# Security Policy

## ⚠️ CRITICAL SECURITY WARNING

**THIS SOFTWARE IS NOT SECURE AND SHOULD NEVER BE USED IN PRODUCTION!**

### Known Vulnerabilities

This project implements the **Ong-Schnorr-Shamir (OSS) digital signature scheme**, which has been cryptographically broken since the 1980s. The vulnerabilities include:

1. **Signature Forgery**: Attackers can create valid signatures for arbitrary messages without access to the private key
2. **Mathematical Weakness**: The underlying mathematical problem (solving x² + Ky² ≡ m (mod n)) can be solved efficiently
3. **No Security Guarantee**: The scheme provides no cryptographic security in practice

### Demonstration of Vulnerability

The `oss_signature.py` module includes a `forge_signature()` function that demonstrates how signatures can be forged using only the public key. This is included for educational purposes to show why the algorithm is insecure.

### Educational Purpose Only

This implementation serves as:
- A demonstration of signcryption concepts
- An example of software engineering best practices
- A case study in cryptographic algorithm implementation
- **NOT** a secure cryptographic library

## Reporting Security Issues

Since this is an intentionally insecure educational project, we do not accept security vulnerability reports for the cryptographic algorithms themselves (OSS is known to be broken).

However, if you find:
- Implementation bugs that could cause crashes
- Code injection vulnerabilities in the GUI
- Issues with the educational content

Please report them by:
1. Opening an issue on GitHub with the "security" label
2. Describing the issue clearly
3. Providing steps to reproduce

## Secure Alternatives

For real-world applications, use these proven cryptographic libraries and algorithms:

### Recommended Libraries
- **Python**: `cryptography`, `PyCryptodome`
- **JavaScript**: `crypto` (Node.js), `WebCrypto` (browser)
- **Java**: `Bouncy Castle`, built-in JCE
- **C/C++**: `OpenSSL`, `libsodium`

### Recommended Algorithms
- **Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Key Exchange**: ECDH, X25519
- **Digital Signatures**: ECDSA (P-256), EdDSA (Ed25519)
- **Hashing**: SHA-256, SHA-3, BLAKE2

### Industry Standards
- **TLS 1.3** for network communication
- **Signal Protocol** for messaging
- **NaCl/libsodium** for general cryptography
- **FIPS 140-2** validated modules for government use

## Compliance and Regulations

This educational software is **NOT COMPLIANT** with:
- FIPS 140-2
- Common Criteria
- SOC 2
- PCI DSS
- HIPAA
- Any security standard or regulation

## Academic References

For understanding why OSS is broken:

1. Pollard, J.M. (1988). "A Monte Carlo method for factorization"
2. Schnorr, C.P. (1989). "Efficient identification and signatures for smart cards"
3. Menezes, A., van Oorschot, P., Vanstone, S. (1996). "Handbook of Applied Cryptography"

## Responsible Disclosure

If you're a security researcher or educator and want to reference this project:

1. **Always** mention that this is educational and insecure
2. **Never** suggest it for production use
3. Use it only to teach about:
   - Why certain algorithms are broken
   - How NOT to implement cryptography
   - The importance of using standard libraries

---

**Remember: The only secure cryptography is cryptography implemented by experts and thoroughly reviewed by the community. When in doubt, use established libraries and standards.**