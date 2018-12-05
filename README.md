# ZeroCipher

Desktop block-cipher tool for encrypting/decrypting files and plain texts using the Advanced Encryption Standard (AES) symmetric-key algorithm. Details can be found at https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

# Features

The following are some characteristics that should be highlighted about this particular implementation of the Rijndael encryption:

- Cipher Block Chaining (CBC) mode of operation: *A chain of consecutive XORs on every block of raw data is applied before the encryption. This mode of operation ensures the diffusion of the generated ciphertext, drastically reducing the appearance of data patterns.*
- Public-Key Cryptography Standards #5 (PKCS5) Padding: *A standard padding algorithm to ensure the size of AES blocks. Extra bytes are added to the unencrypted data so that the overall size of the information corresponds with a exact multiple of 16 bytes. The specifications of PKCS5 scheme can be found here: https://cryptosys.net/pki/manpki/pki_paddingschemes.html*
- Password-Based Key Derivation Function 2 (PBKDF2): *A secure-key generation function used to increment the computational cost of possible brute-force and dictionary attacks. This specific implementation uses a Hash-Based Message Authentication Code (HMAC) calculated with the SHA256 cryptographic hash function.*
- Pseudo-Random Initialization Vector and Salt: *The initialization vector (16 bytes long) used in the creation of the CBC blocks and the salt (8 bytes long) used in the password hashing are created as two random arrays of bytes and, subsequently, attached to the ciphertext as metadata. The decryption function is capable of retrieve both in order to reconstruct the original data.*

# Installation and usage

1. Download the current release from the "Releases" section.
2. Open the installation directory using the command line interface.
3. Apply one of the following commands:

````
Usage: 
java -jar "ZeroCipher.jar" {-f | -t} {-e | -d} <textOrPath> <password>
java -jar "ZeroCipher.jar" -h
   -f: file manipulation
   -t: plain text manipulation
   -e: encryption mode
   -d: decryption mode
   -h: help
````

# To-Do List

- Graphical User Interface (GUI) using Java FX
- Custom file extension association (crypted files are stored as .zcf files)
