# PALE

**PALE** is a python based CLI tool dedicated to secure file handling. Its core feature is a **File Encryption/Decryption tool** using **AES-256-GCM** with password-based key derivation. The project is designed to be user-friendly, secure, and efficient, supporting large files through streaming encryption.

Created by: Om Joshi

GitHub: [https://github.com/iamomjoshi](https://github.com/iamomjoshi)

Repository: [https://github.com/iamomjoshi/pale](https://github.com/iamomjoshi/pale)

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/iamomjoshi/pale.git
cd pale
```

2. Install Python 3.8+ and the required dependencies:

```bash
pip install cryptography
```

3. Make the script executable (Linux/macOS):

```bash
chmod +x pale.py
```

---

## Usage

### Encrypt a file

```bash
python3 pale.py encrypt -i secret.txt
```

* Will prompt for a password and confirmation
* Default output: `secret.txt.enc`


### Decrypt a file

```bash
python3 pale.py decrypt -i secret.txt.enc
```

* Will prompt for a password
* Default output: `secret.txt` (or `secret.txt.dec` if input filename doesn’t end with `.enc`)

---

## Example

Encrypt a file:

```bash
python3 pale.py encrypt -i example.txt
```

Decrypt the file:

```bash
python3 pale.py decrypt -i example.txt.enc
```

---
