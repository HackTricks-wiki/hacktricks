# TLS & Certificados

{{#include ../../banners/hacktricks-training.md}}

Esta área trata sobre **el análisis (parsing) de X.509, formatos, conversiones y errores comunes**.

## X.509: análisis, formatos y errores comunes

### Análisis rápido
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campos útiles para inspeccionar:

- Sujeto / Emisor / SAN
- Uso de clave / EKU
- Restricciones básicas (¿es una CA?)
- Ventana de validez (NotBefore/NotAfter)
- Algoritmo de firma (MD5? SHA1?)

### Formatos y conversión

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
### Ángulos ofensivos comunes

- Confiar en certificados raíz proporcionados por el usuario / validación de la cadena ausente
- Algoritmos de firma débiles (obsoletos)
- Restricciones de nombre / errores de parseo de SAN (específicos de la implementación)
- Problemas de Confused deputy con misbinding en la autenticación client-certificate

### Registros CT

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
