# RSA Implementation

## What is RSA?
RSA (Rivest–Shamir–Adleman) is one of the most widely used public-key cryptosystems for secure data transmission. It relies on the mathematical difficulty of factoring the product of two large prime numbers. The RSA algorithm is fundamental to cryptography and underpins many secure communication protocols.

RSA involves three primary operations:

* Key Generation: Create a public/private key pair using two large prime numbers.
* Encryption: Convert plaintext into ciphertext using the recipient’s public key.
* Decryption: Recover the original plaintext from the ciphertext using the private key.

This implementation of RSA was scratched without using built-in RSA libraries. It also explores real-world cryptanalysis and compares RSA’s performance with symmetric encryption (AES).

This repository contains a Java-based implementation of three cryptographic scenarios involving RSA encryption. It includes the complete RSA algorithm from scratch, a vulnerability demonstration using a common modulus attack, and a performance comparison between RSA and AES.

## Code Structure

This project includes three key components:

### 1. RSA Key Generation, Encryption, and Decryption

#### 📌 Scenario

Implements RSA public-key cryptography using large 1536-bit prime numbers. The process includes generating public and private keys, encrypting a plaintext message, and decrypting the ciphertext using the private key.

#### ⚙️ Implementation Details

- **Key Generation**
  - Compute modulus: `n = p × q`
  - Calculate totient: `φ(n) = (p - 1)(q - 1)`
  - Choose public exponent `e` such that `gcd(e, φ(n)) = 1`
  - Compute private exponent: `d = e⁻¹ mod φ(n)`

- **Encryption**
  - `c = m^e mod n`

- **Decryption using CRT**
  - Compute `dp = d mod (p - 1)` and `dq = d mod (q - 1)`
  - Compute `mp = c^dp mod p`, `mq = c^dq mod q`
  - Use Chinese Remainder Theorem:
    ```
    m = (mp × q × q⁻¹ mod p) + (mq × p × p⁻¹ mod q) mod n
    ```

#### Run the code

By running the code three scenario will be appeared: 

```
Scenario 1 : RSA Encryption and Decryption 
Scenario 2 : Cracking a Credit card
Scenario 3 : Comparing RSA and AES time: 

Enter number for question to be run : 
```


