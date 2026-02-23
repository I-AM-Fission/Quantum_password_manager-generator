# Quantum Password Manager

A Python-based password manager that uses IBM Quantum hardware to generate high-entropy passwords and stores them securely in an encrypted local vault.

This project combines quantum-generated randomness with modern encryption to create a secure desktop password manager.

---

## Overview

The application generates passwords using quantum measurements from IBM Quantum backends. Those measurements are processed to remove statistical bias and then mapped into a secure character set.

All saved credentials are stored locally in an encrypted vault file.

No credential data is transmitted or stored remotely.

---

## Features

- Quantum-generated password generation (IBM QPU backend)
- Adjustable password length (8–64 characters)
- Optional symbol inclusion
- One-click clipboard copy
- Encrypted local vault (`vault.enc`)
- Memory-hard key derivation (scrypt)
- Save and view entries (site, username, password)
- Search functionality
- Dark-themed desktop UI (CustomTkinter)

---

## Security Design

### Password Generation

1. A 1-qubit Hadamard circuit is executed on IBM Quantum hardware  
2. Measurement results are collected as a raw bitstream  
3. Von Neumann extraction removes statistical bias  
4. Bits are mapped uniformly to a selected character set  
5. Fisher–Yates shuffle ensures proper distribution  

A 20-character password generated from the default 69-character alphabet provides approximately 122 bits of entropy.

---

### Vault Encryption

- AES-256-GCM authenticated encryption  
- scrypt key derivation (memory-hard)  
- Quantum-generated salt (fallback to OS cryptographic randomness)  
- Encrypted binary storage file: `vault.enc`  

The security of the vault depends entirely on the strength of the master password.

There is no recovery mechanism if the master password is lost.

---

## Requirements

### Python
- Python 3.10 or newer recommended

### Install Dependencies

```bash
pip install customtkinter cryptography qiskit qiskit-ibm-runtime
```

Libraries used:
- customtkinter  
- cryptography  
- qiskit  
- qiskit-ibm-runtime  

---

## IBM Quantum Setup

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

3. Launch the application and click **Load Token**.

IBM Quantum API tokens can be obtained at:
https://quantum.ibm.com/

---

## Running the Application

```bash
python Password Manager.py
```

---

## Project Structure

```
Password Manager.py
Quantum_Protected_Password_generator.py
Vault.py
vault.enc      (generated automatically)
api_key.json
```

---

## Notes

- The master password is never stored.
- If it is forgotten, the vault cannot be recovered.
- All encryption operations occur locally.
