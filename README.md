# Java PKI Tutorial
This a simple implementation of JCE API.

## Screens :
![Drag Racing](signer.PNG) ![Drag Racing](singer_loggedin.PNG)


## Features
1. generating symmetric and asymmetric keys.
2. generating certificates.
3. Support for PKCS11 and PKCS12 keystores.
4. Importing certificates into keystores.
5. Deleting keys and certificates from keystores.
6. Sign and verify signature for files.

## Supported keystores
1. (*.P12) keystores.
2. ST3 crypto token.
3. Bit4id crypto token.

### App Packages:
* **crypto** - contains :
  * CrytoOperations class - for encryption, decryption, hash and digital signature.
  * KeyGenerator class - for generateing symmetric and asymmetric keys.
  * **cert** - contains class for loading certificates and displaying its content.
  * **keystore** - contains classes needed to interact with soft and hardware keystores.
  * **util** - contains utils needed for reading files, certificates and keystores from hard drive.
* **ui** - contains java frame interface for signing and verifying files.



