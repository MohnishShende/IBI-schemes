# IBI-Schemes  
### Identity-Based Identification (IBI) Schemes in Python using ECC  

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python Version](https://img.shields.io/badge/Python-3.10+-yellow.svg)
![ECC](https://img.shields.io/badge/Cryptography-ECC-green.svg)
![Research](https://img.shields.io/badge/Focus-Cryptography%20Research-orange.svg)

---

## 📘 Overview  

This repository provides a **comparative implementation and analysis** of five Identity-Based Identification (IBI) schemes, all developed in **Python** using **Elliptic Curve Cryptography (ECC)**.  

The goal is to evaluate the **runtime performance and memory efficiency** of various IBI protocols, with special attention to **resource-constrained devices** such as **IoT nodes and smart cards**.

---

## 🧠 Implemented Schemes  

| Scheme | Description |
|--------|--------------|
| **1. Twin-Schnorr IBI Scheme** | Improves security using two parallel Schnorr signatures. |
| **2. Modified-Schnorr IBI Scheme** | Pairing-free variant balancing efficiency and security. |
| **3. Sakai–Kasahara IBI Scheme** | ECC pairing-based, providing robust identification guarantees. |
| **4. Fiat–Shamir IBI Scheme** | Zero-knowledge proof system with strong simplicity. |
| **5. Efficient Zero-Knowledge IBI Scheme** | Optimized for smart cards with minimal computation and memory footprint. |

---

## ⚙️ Key Features  

- **Full Python Implementation:** Built using the `cryptography` and `tinyec` libraries.  
- **Profiling Metrics:** Uses Python’s `time` and `tracemalloc` modules to record **runtime** and **memory usage**.  
- **Server–Client Simulation:** Flask-based environment mimicking real-world authentication flow.  
- **ECC-Focused:** Designed to operate over elliptic curves for lightweight performance.  
- **Research-Oriented:** Enables comparative analysis across five cryptographic IBI frameworks.  

---

## 🧩 Repository Structure  

```

IBI-schemes/
├─ keygen.py              # ECC key generation
├─ protocol.py            # Protocol operations (prove/verify)
├─ /static /templates     # For Flask-based web simulation
├─ requirements.txt       # Python dependencies
├─ LICENSE
└─ README.md

````

---

## 🚀 How to Use  

### 1. Clone the Repository  
```bash
git clone https://github.com/MohnishShende/IBI-schemes.git
cd IBI-schemes
````

### 2. Set Up a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the Schemes

```bash
python keygen.py     # Key generation phase
python protocol.py   # Protocol simulation phase
```

### 4. Flask Server (Optional)

If the repository includes a Flask-based simulation:

```bash
python app.py
```

Then open the local interface in your browser:

```
http://127.0.0.1:5000/
```

---

## 📊 Results and Analysis

The project benchmarks **runtime (seconds)** and **memory (KB)** for the following operations:

* Key Generation
* Proving
* Verification

Each scheme was profiled under identical conditions to ensure fair comparison.

Future iterations may include automated chart generation for visual performance comparison.

---

## 🔬 Research Significance

This implementation provides a practical comparison of several IBI approaches, offering insight into:

* Performance trade-offs between pairing-based and pairing-free methods.
* Resource efficiency in elliptic-curve-based identity verification.
* Applicability of IBI systems in lightweight IoT or embedded devices.

---

## 🤝 Contributing

Contributions are welcome!

* Extend additional IBI schemes or pairing algorithms.
* Optimize ECC curve implementations.
* Submit pull requests for performance tests or visualization scripts.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 📚 References

* Shamir, A. (1984). *Identity-Based Cryptosystems and Signature Schemes.*
* Boneh, D., & Franklin, M. (2001). *Identity-Based Encryption from the Weil Pairing.*
* Chin, J. J., & Tan, S. Y. (2015). *Twin-Schnorr: A Security Upgrade for the Schnorr Identity-Based Identification Scheme.*

---

## 👤 Author

**Mohnish Shende**
Cybersecurity Researcher | Cryptography & AI Integration
GitHub: [https://github.com/MohnishShende](https://github.com/MohnishShende)

---

