# quickcrypt 

Simple CLI tool to quickly sanity check d/encrypted values


## Example Usage

View if JWT is valid and its contents:
```sh
quickcrypt view jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJpYXQiOjE3NTkxODcxMjcsImV4cCI6MTc5MDcyMzEyNywiYXVkIjoicXVpY2tjcnlwdCIsInN1YiI6ImV4YW1wbGUiLCJkb2NzIjoiTWFkZSB5b3UgbG9vayEifQ.kCPGDD0Zvf9sTPalvvPanCJDEOGt8DUPRByJY89bRFQ
```

Create JWT from stringified json:
```sh
quickcrypt create jwt '{"iss":"","iat":1759187127,"exp":1790723127,"aud":"quickcrypt","sub":"example"}'
```

Validate if PEM cert file has valid format:
```sh
quickcrypt view PEM ./certs/key.pem
```


## Supported Cryptographic Operations
* JWT
* UUID
* Argon2 (encode, verify)
* Bcrypt (encode, verify)
* Base64
* SHA1
* SHA2-256
* SHA2-512
* SHA3-256
* Blake2b-512
* Blake3
* MD5
* PEM
* RSA
* AES (AES-256-GCM)


## Installation

```sh
brew install quickcrypt 
```

or

```sh
curl -L https://github.com/4dawit/quickcrypt/releases/download/v1.0.0/quickcrypt_1.0.0_windows_x86_64.zip
```


## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International Public License - see the [LICENSE.txt](https://github.com/4dawit/quickcrypt/blob/main/LICENSE.txt).
