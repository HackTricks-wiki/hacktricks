# TLS y Certificados

{{#include ../../banners/hacktricks-training.md}}


Esta sección trata sobre el **análisis, los formatos, las conversiones y los errores comunes de X.509**.

## X.509: análisis, formatos y errores comunes

### Análisis rápido
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campos útiles para inspeccionar:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (¿es una CA?)
- Ventana de validez (NotBefore/NotAfter)
- Algoritmo de firma (¿MD5? ¿SHA1?)

### Formatos y conversión

- PEM (Base64 con encabezados BEGIN/END)
- DER (binario)
- PKCS#7 (`.p7b`) (cadena de certificados, sin private key)
- PKCS#12 (`.pfx/.p12`) (certificado + private key + cadena)

Conversiones:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Ángulos ofensivos comunes

- Confiar en roots proporcionadas por el usuario / falta de validación de la cadena
- Algoritmos de firma débiles (legacy)
- Restricciones de nombres / errores de parsing de SAN (específicos de la implementación)
- Problemas de confused deputy con un misbinding de la autenticación mediante certificados de cliente

### Registros CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
