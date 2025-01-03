# Certificados

{{#include ../banners/hacktricks-training.md}}

## Qué es un Certificado

Un **certificado de clave pública** es una identificación digital utilizada en criptografía para probar que alguien posee una clave pública. Incluye los detalles de la clave, la identidad del propietario (el sujeto) y una firma digital de una autoridad de confianza (el emisor). Si el software confía en el emisor y la firma es válida, es posible la comunicación segura con el propietario de la clave.

Los certificados son emitidos principalmente por [autoridades de certificación](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) en una [infraestructura de clave pública](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Otro método es la [web de confianza](https://en.wikipedia.org/wiki/Web_of_trust), donde los usuarios verifican directamente las claves de los demás. El formato común para los certificados es [X.509](https://en.wikipedia.org/wiki/X.509), que puede adaptarse a necesidades específicas como se detalla en el RFC 5280.

## Campos Comunes de x509

### **Campos Comunes en Certificados x509**

En los certificados x509, varios **campos** juegan roles críticos para asegurar la validez y seguridad del certificado. Aquí hay un desglose de estos campos:

- **Número de Versión** significa la versión del formato x509.
- **Número de Serie** identifica de manera única el certificado dentro del sistema de una Autoridad de Certificación (CA), principalmente para el seguimiento de revocaciones.
- El campo **Sujeto** representa al propietario del certificado, que podría ser una máquina, un individuo o una organización. Incluye identificación detallada como:
- **Nombre Común (CN)**: Dominios cubiertos por el certificado.
- **País (C)**, **Localidad (L)**, **Estado o Provincia (ST, S, o P)**, **Organización (O)** y **Unidad Organizativa (OU)** proporcionan detalles geográficos y organizativos.
- **Nombre Distinguido (DN)** encapsula la identificación completa del sujeto.
- **Emisor** detalla quién verificó y firmó el certificado, incluyendo subcampos similares al Sujeto para la CA.
- El **Período de Validez** está marcado por las marcas de tiempo **No Antes** y **No Después**, asegurando que el certificado no se use antes o después de una cierta fecha.
- La sección de **Clave Pública**, crucial para la seguridad del certificado, especifica el algoritmo, tamaño y otros detalles técnicos de la clave pública.
- Las **extensiones x509v3** mejoran la funcionalidad del certificado, especificando **Uso de Clave**, **Uso de Clave Extendida**, **Nombre Alternativo del Sujeto** y otras propiedades para afinar la aplicación del certificado.

#### **Uso de Clave y Extensiones**

- **Uso de Clave** identifica las aplicaciones criptográficas de la clave pública, como la firma digital o el cifrado de clave.
- **Uso de Clave Extendida** delimita aún más los casos de uso del certificado, por ejemplo, para la autenticación de servidores TLS.
- **Nombre Alternativo del Sujeto** y **Restricción Básica** definen nombres de host adicionales cubiertos por el certificado y si es un certificado de CA o de entidad final, respectivamente.
- Identificadores como **Identificador de Clave del Sujeto** y **Identificador de Clave de Autoridad** aseguran la unicidad y trazabilidad de las claves.
- **Acceso a Información de Autoridad** y **Puntos de Distribución de CRL** proporcionan rutas para verificar la CA emisora y comprobar el estado de revocación del certificado.
- **SCTs de Precertificado CT** ofrecen registros de transparencia, cruciales para la confianza pública en el certificado.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Diferencia entre OCSP y Puntos de Distribución de CRL**

**OCSP** (**RFC 2560**) implica que un cliente y un respondedor trabajen juntos para verificar si un certificado digital de clave pública ha sido revocado, sin necesidad de descargar el **CRL** completo. Este método es más eficiente que el **CRL** tradicional, que proporciona una lista de números de serie de certificados revocados pero requiere descargar un archivo potencialmente grande. Los CRLs pueden incluir hasta 512 entradas. Más detalles están disponibles [aquí](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Qué es la Transparencia de Certificados**

La Transparencia de Certificados ayuda a combatir amenazas relacionadas con certificados al garantizar que la emisión y existencia de certificados SSL sean visibles para los propietarios de dominios, CAs y usuarios. Sus objetivos son:

- Prevenir que las CAs emitan certificados SSL para un dominio sin el conocimiento del propietario del dominio.
- Establecer un sistema de auditoría abierto para rastrear certificados emitidos por error o de manera maliciosa.
- Proteger a los usuarios contra certificados fraudulentos.

#### **Registros de Certificados**

Los registros de certificados son registros auditables públicamente, de solo adición, de certificados, mantenidos por servicios de red. Estos registros proporcionan pruebas criptográficas para fines de auditoría. Tanto las autoridades de emisión como el público pueden enviar certificados a estos registros o consultarlos para verificación. Si bien el número exacto de servidores de registro no es fijo, se espera que sea menos de mil a nivel mundial. Estos servidores pueden ser gestionados de manera independiente por CAs, ISPs o cualquier entidad interesada.

#### **Consulta**

Para explorar los registros de Transparencia de Certificados para cualquier dominio, visita [https://crt.sh/](https://crt.sh).

Existen diferentes formatos para almacenar certificados, cada uno con sus propios casos de uso y compatibilidad. Este resumen cubre los formatos principales y proporciona orientación sobre la conversión entre ellos.

## **Formatos**

### **Formato PEM**

- Formato más utilizado para certificados.
- Requiere archivos separados para certificados y claves privadas, codificados en Base64 ASCII.
- Extensiones comunes: .cer, .crt, .pem, .key.
- Utilizado principalmente por Apache y servidores similares.

### **Formato DER**

- Un formato binario de certificados.
- Carece de las declaraciones "BEGIN/END CERTIFICATE" que se encuentran en los archivos PEM.
- Extensiones comunes: .cer, .der.
- A menudo utilizado con plataformas Java.

### **Formato P7B/PKCS#7**

- Almacenado en Base64 ASCII, con extensiones .p7b o .p7c.
- Contiene solo certificados y certificados de cadena, excluyendo la clave privada.
- Soportado por Microsoft Windows y Java Tomcat.

### **Formato PFX/P12/PKCS#12**

- Un formato binario que encapsula certificados de servidor, certificados intermedios y claves privadas en un solo archivo.
- Extensiones: .pfx, .p12.
- Utilizado principalmente en Windows para la importación y exportación de certificados.

### **Conversión de Formatos**

**Las conversiones PEM** son esenciales para la compatibilidad:

- **x509 a PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM a DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER a PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM a P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 a PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Las conversiones PFX** son cruciales para gestionar certificados en Windows:

- **PFX a PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX a PKCS#8** implica dos pasos:
1. Convertir PFX a PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convertir PEM a PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B a PFX** también requiere dos comandos:
1. Convertir P7B a CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Convertir CER y clave privada a PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
--- 

{{#include ../banners/hacktricks-training.md}}
