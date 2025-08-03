# Signcryption System: Schmidt-Samoa & OSS

## ⚠️ PERINGATAN KEAMANAN / SECURITY WARNING

**PENTING:** Implementasi ini menggunakan skema tanda tangan **Ong-Schnorr-Shamir (OSS)** yang **TIDAK AMAN** untuk penggunaan produksi. OSS telah terbukti rentan terhadap serangan pemalsuan tanda tangan. Proyek ini dibuat **hanya untuk tujuan akademis dan pembelajaran**.

**IMPORTANT:** This implementation uses the **Ong-Schnorr-Shamir (OSS)** signature scheme which is **NOT SECURE** for production use. OSS has been proven vulnerable to signature forgery attacks. This project is created **for academic and learning purposes only**.

## Deskripsi Proyek

Proyek ini mengimplementasikan skema *signcryption* yang menggabungkan:
- **Schmidt-Samoa Cryptosystem** untuk enkripsi
- **Ong-Schnorr-Shamir (OSS) Digital Signature** untuk tanda tangan digital
- Arsitektur **Sign-then-Encrypt** untuk keamanan pesan

## Fitur Utama

- ✅ Pembuatan kunci otomatis untuk kedua algoritma
- ✅ Enkripsi dan dekripsi pesan teks
- ✅ Penandatanganan dan verifikasi digital
- ✅ Antarmuka pengguna yang sederhana dengan feedback jelas
- ✅ Manajemen kunci yang mudah
- ✅ Pengujian unit lengkap

## Instalasi

```bash
# Clone repository
git clone https://github.com/HaikalE/signcryption-schmidt-samoa-oss.git
cd signcryption-schmidt-samoa-oss

# Install dependencies
pip install -r requirements.txt
```

## Penggunaan

### Menjalankan Aplikasi GUI

```bash
python main_app.py
```

### Penggunaan Programmatic

```python
from key_generator import generate_schmidt_samoa_keys, generate_oss_keys
from schmidt_samoa import encrypt, decrypt
from oss_signature import sign, verify

# Generate keys
ss_pub, ss_priv = generate_schmidt_samoa_keys()
oss_pub, oss_priv = generate_oss_keys()

# Sign and encrypt message
message = "Hello, World!"
signature = sign(message, oss_priv)
encrypted_data = encrypt(message + "|" + signature, ss_pub)

# Decrypt and verify
decrypted_data = decrypt(encrypted_data, ss_priv)
original_msg, received_sig = decrypted_data.split("|")
is_valid = verify(original_msg, received_sig, oss_pub)
```

## Struktur Proyek

```
├── README.md
├── requirements.txt
├── key_generator.py      # Pembuatan kunci untuk kedua algoritma
├── schmidt_samoa.py      # Implementasi Schmidt-Samoa Cryptosystem
├── oss_signature.py      # Implementasi OSS Digital Signature
├── main_app.py          # Aplikasi utama dengan GUI
├── tests/               # Unit tests
│   ├── test_schmidt_samoa.py
│   ├── test_oss_signature.py
│   └── test_integration.py
└── examples/            # Contoh penggunaan
    └── basic_usage.py
```

## Pengujian

```bash
# Menjalankan semua unit tests
python -m pytest tests/ -v

# Menjalankan test specific
python -m pytest tests/test_schmidt_samoa.py -v
```

## Kontribusi

Proyek ini dibuat untuk tujuan akademis. Jika Anda ingin berkontribusi:
1. Fork repository ini
2. Buat branch fitur (`git checkout -b feature/amazing-feature`)
3. Commit perubahan (`git commit -m 'Add amazing feature'`)
4. Push ke branch (`git push origin feature/amazing-feature`)
5. Buat Pull Request

## Lisensi

Proyek ini menggunakan lisensi MIT. Lihat file `LICENSE` untuk detail.

## Referensi

- Schmidt-Samoa Cryptosystem: [Original Paper]
- Ong-Schnorr-Shamir Signature: [Original Paper]
- Cryptanalysis of OSS: Pollard & Schnorr attacks

---

**Disclaimer:** Implementasi ini tidak dimaksudkan untuk penggunaan produksi. Gunakan algoritma standar industri seperti RSA, ECDSA, atau EdDSA untuk aplikasi nyata.