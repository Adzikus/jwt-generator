# Biblioteka generowania JWT

Biblioteka generowania JWT w C#

## Generowanie kluczy EDCsa

```powershell
openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem
openssl ec -in es256-private.pem -pubout -outform DER -out es256-public.der
openssl ec -in es256-private.pem -outform DER -out es256-private.der
```
