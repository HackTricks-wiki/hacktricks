# TLS y Certificados

{{#include ../../banners/hacktricks-training.md}}

Esta área trata sobre **análisis de X.509, formatos, conversiones y errores comunes**.

## X.509: análisis, formatos y errores comunes

### Análisis rápido
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campos útiles para inspeccionar:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (¿es un CA?)
- Ventana de validez (NotBefore/NotAfter)
- Algoritmo de firma (MD5? SHA1?)

### Formatos & conversión

- PEM (Base64 con encabezados BEGIN/END)
- DER (binario)
- PKCS#7 (`.p7b`) (cadena de certificados, sin clave privada)
- PKCS#12 (`.pfx/.p12`) (certificado + clave privada + cadena)

Conversiones:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Vectores ofensivos comunes

- Confiar en raíces proporcionadas por el usuario / falta de validación de la cadena
- Algoritmos de firma débiles (obsoletos)
- Restricciones de nombre / bugs en el parsing de SAN (específicos de la implementación)
- Problemas de Confused deputy con client-certificate authentication misbinding

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
