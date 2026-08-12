# TLS y certificados

{{#include ../../banners/hacktricks-training.md}}

Esta sección cubre la inspección de X.509, las codificaciones, las conversiones y los errores de validación relevantes para la seguridad.

## Análisis de X.509

OpenSSL puede mostrar los campos decodificados de un certificado, mientras que `asn1parse` muestra la estructura ASN.1 subyacente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Revisa al menos:

- el sujeto, el emisor y el Subject Alternative Name (SAN);
- el key usage y el extended key usage;
- las basic constraints y las restricciones de longitud de ruta;
- los tiempos de validez `notBefore` y `notAfter`;
- los parámetros de la clave pública y el algoritmo de firma.

Las firmas legacy, como las firmas de certificados basadas en MD5 o SHA-1, son hallazgos especialmente importantes, aunque la aceptación exacta y el impacto dependen del validador y del contexto de confianza.<sup>[[3]](#references)</sup>

RFC 5280 define el perfil X.509 de Internet y las reglas de procesamiento para extensiones como SAN, key usage, name constraints y basic constraints.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **Codificación textual de estilo PEM:** datos Base64 entre delimitadores `BEGIN` y `END`.
- **DER:** la representación binaria Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** normalmente contiene certificados y una cadena de certificados, pero no claves privadas.
- **PKCS#12 (`.p12` o `.pfx`):** puede contener claves privadas, certificados y certificados complementarios.

RFC 7468 especifica las codificaciones textuales utilizadas para estructuras PKIX, PKCS y CMS; el comando `pkcs12` de OpenSSL crea y analiza archivos PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Trata `out.pem` como sensible: a menos que se utilicen opciones como `-nokeys`, la salida puede contener material de clave privada.<sup>[[5]](#references)</sup>

## Lista de comprobación de la revisión de seguridad

Aplica los requisitos de procesamiento de certificados de RFC 5280 al revisar un validador o una decisión de confianza.<sup>[[3]](#references)</sup>

- Verifica la cadena completa hasta un ancla de confianza explícitamente confiable; no confíes implícitamente en raíces proporcionadas por el usuario.
- Confirma el nombre de host o la identidad del servicio con los valores SAN.<sup>[[8]](#references)</sup>
- Aplica las restricciones básicas, las restricciones de nombre, el uso de clave y el uso extendido de clave.
- Rechaza los certificados expirados o aún no válidos, así como los algoritmos de clave o firma no permitidos.
- Vincula las identidades de los certificados de cliente con la cuenta de aplicación y el contexto de autorización correctos.

## Registros de Certificate Transparency

Certificate Transparency proporciona registros auditables públicamente de los certificados emitidos.<sup>[[6]](#references)</sup> Busca un dominio con crt.sh durante el descubrimiento autorizado de activos.<sup>[[7]](#references)</sup>

## References

- [1] [Documentación de OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Documentación de OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Perfil de certificados y CRL de la infraestructura de clave pública X.509 de Internet](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Codificaciones textuales de estructuras PKIX, PKCS y CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Documentación de OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency versión 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Búsqueda de certificados](https://crt.sh/)
- [8] [RFC 9525 - Identidad del servicio en TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
