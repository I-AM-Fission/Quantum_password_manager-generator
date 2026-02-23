# Quantum Password Manager 🔐⚛️

A modern Python password manager that combines real quantum randomness with strong local encryption.

Generate high-entropy passwords using IBM Quantum hardware and store them securely in an encrypted local vault.

---

## 🚀 Features

- ⚛️ **Quantum-generated passwords** (IBM QPU backend)
- 🎛 **Adjustable password length** (8–64 characters)
- 🔤 **Optional symbols toggle**
- 📋 **One-click copy to clipboard**
- 🔐 **Encrypted local vault** (`vault.enc`)
- 🧠 **Memory-hard key derivation (scrypt)**
- 🗂 **Save & view entries** (site, username, password)
- 🔍 **Vault search**
- 🌙 **Modern dark UI (CustomTkinter)**

---

## 🔐 Security Overview

### Password Generation
1. 1-qubit Hadamard circuit runs on IBM Quantum hardware  
2. Raw bitstream collected  
3. Von Neumann extraction removes bias  
4. Bits mapped uniformly to character set  
5. Fisher–Yates shuffle ensures distribution  

A 20-character password from the default 69-character alphabet provides approximately **122 bits of entropy**.

---

### Vault Encryption

- 🔒 **AES-256-GCM** (authenticated encryption)
- 🧠 **scrypt KDF** (memory-hard, brute-force resistant)
- ⚛️ **Quantum-generated salt** (fallback to OS CSPRNG)
- 💾 Stored as encrypted binary file: `vault.enc`

Vault security depends entirely on your **master password strength**.

There is **no recovery mechanism** if the master password is lost.

---

## 🛠 Requirements

### Python
- Python **3.10+** recommended

### Install Dependencies

```bash
pip install customtkinter cryptography qiskit qiskit-ibm-runtime
```

Libraries used:
- `customtkinter`
- `cryptography`
- `qiskit`
- `qiskit-ibm-runtime`

---

## 🔑 IBM Quantum Setup

1. Create a file named:

```
api_key.json
```

2. Add your IBM Quantum API token:

```json
{
  "token": "YOUR_IBM_QUANTUM_API_TOKEN"
}
```

3. Launch the Password Manager.py and click **Load Token**.

Get your API token from:
https://quantum.ibm.com/

---

## ▶️ Run

```bash
python Password Manager.py
```

---

## 📁 Project Structure

```
Password Manager.py
Quantum_Protected_Password_generator.py
Vault.py
vault.enc      (generated automatically)
api_key.json
```

---

## ⚠️ Important Notes

- 🔑 Your master password is never stored.
- ❌ If you forget it, the vault cannot be recovered.
- 🛡 All encryption occurs locally.
- ⚛️ Quantum randomness improves entropy but does not replace classical cryptographic standards.


