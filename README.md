# Java PKI Tutorial
This a simple implementation of JCE API.

## Screens :
![Drag Racing](signer.PNG) 


## Features
1. Generating symmetric and asymmetric keys.
2. Generating certificates.
3. Support for PKCS11 and PKCS12 keystores.
4. Importing certificates into keystores.
5. Deleting keys and certificates from keystores.
6. Sign and verify signature for files.
7. Ejbca web service interface.

## Supported keystores
1. (*.P12) keystores.
2. ST3 crypto token.
3. Bit4id crypto token.

### App Packages:
  * **core** - contains :
    * CrytoOperations class - for encryption, decryption, hash and digital signature.
    * KeyFactory class - for generateing symmetric and asymmetric keys.
  * **certificate** - contains class for loading certificates and displaying its content.
  * **keystore** - contains classes needed to interact with soft and hardware keystores.
  * **ejbca** - contains Ejbca interface for issuing and managing certificates.
  * **util** - contains utils needed for reading files, certificates and keystores from hard drive.
  * **ui** - contains java frame interface for signing and verifying files.



