# IBI-schemes
IBI Schemes in python using ECC

Here's some brief text you can use for the information section of your GitHub repository:

---

## Identity-Based Identification (IBI) Schemes: Comparative Analysis

### Overview

This repository contains the implementation and analysis of five different Identity-Based Identification (IBI) schemes using Python and Elliptic Curve Cryptography (ECC). The project is focused on evaluating the runtime efficiency and memory usage of these schemes, particularly in resource-constrained environments such as IoT devices and smart cards.

### Implemented Schemes

1. **Twin-Schnorr IBI Scheme**  
   - Enhances security using two parallel Schnorr signatures.

2. **Modified-Schnorr IBI Scheme**  
   - A pairing-free variant that balances security and efficiency.

3. **Sakai-Kasahara IBI Scheme**  
   - Utilizes elliptic curve pairings for robust security.

4. **Fiat-Shamir IBI Scheme**  
   - A simple zero-knowledge proof-based scheme.

5. **Efficient Zero-Knowledge IBI Scheme**  
   - Designed for smart cards, offering high efficiency and low memory usage.

### Key Features

- **Python Implementation:** Developed using Python with ECC, leveraging the `cryptography` and `tinyec` libraries.
- **Profiling Tools:** Utilized `time` and `tracemalloc` modules for measuring runtime efficiency and memory usage.
- **Server-Client Setup:** Includes Flask-based server-client communication to simulate real-world environments.

### How to Use

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/IBI-schemes.git
   cd IBI-schemes
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Schemes**:
   ```bash
   python keygen.py   # Run the key generation
   python protocol.py # Run the protocol operations
   ```

### Results

The repository includes performance metrics such as runtime and memory usage for key operations (key generation, proving, verification) across all five schemes.

### Contribution

Contributions to improve the implementation or expand the analysis are welcome. Feel free to fork the repository and submit pull requests.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### References

- Shamir, A. (1984). Identity-Based Cryptosystems and Signature Schemes.
- Boneh, D., & Franklin, M. (2001). Identity-Based Encryption from the Weil Pairing.
- Chin, J.J., & Tan, S.Y. (2015). Twin-Schnorr: A Security Upgrade for the Schnorr Identity-Based Identification Scheme.

---
