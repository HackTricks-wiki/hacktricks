# Certificados

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ¿Qué es un Certificado

Un **certificado de clave pública** es una identificación digital utilizada en criptografía para demostrar que alguien es dueño de una clave pública. Incluye los detalles de la clave, la identidad del propietario (el sujeto) y una firma digital de una autoridad de confianza (el emisor). Si el software confía en el emisor y la firma es válida, es posible una comunicación segura con el propietario de la clave.

Los certificados son emitidos principalmente por [autoridades de certificación](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) en una configuración de [infraestructura de clave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Otro método es la [red de confianza](https://en.wikipedia.org/wiki/Web\_of\_trust), donde los usuarios verifican directamente las claves de los demás. El formato común para los certificados es [X.509](https://en.wikipedia.org/wiki/X.509), que puede adaptarse a necesidades específicas según lo descrito en el RFC 5280.

## Campos Comunes de x509

### **Campos Comunes en Certificados x509**

En los certificados x509, varios **campos** desempeñan roles críticos para garantizar la validez y seguridad del certificado. Aquí tienes un desglose de estos campos:

* El **Número de Versión** indica la versión del formato x509.
* El **Número de Serie** identifica de forma única el certificado dentro del sistema de una Autoridad de Certificación (CA), principalmente para el seguimiento de revocaciones.
* El campo **Sujeto** representa al propietario del certificado, que puede ser una máquina, un individuo o una organización. Incluye una identificación detallada como:
* **Nombre Común (CN)**: Dominios cubiertos por el certificado.
* **País (C)**, **Localidad (L)**, **Estado o Provincia (ST, S o P)**, **Organización (O)** y **Unidad Organizativa (OU)** proporcionan detalles geográficos y organizativos.
* El **Nombre Distinguido (DN)** encapsula la identificación completa del sujeto.
* El **Emisor** detalla quién verificó y firmó el certificado, incluyendo subcampos similares al Sujeto para la CA.
* El **Período de Validez** está marcado por marcas de tiempo de **No Antes** y **No Después**, asegurando que el certificado no se use antes o después de una fecha determinada.
* La sección de **Clave Pública**, crucial para la seguridad del certificado, especifica el algoritmo, tamaño y otros detalles técnicos de la clave pública.
* Las **extensiones x509v3** mejoran la funcionalidad del certificado, especificando **Uso de Clave**, **Uso Extendido de Clave**, **Nombre Alternativo del Sujeto** y otras propiedades para ajustar la aplicación del certificado.

#### **Uso de Clave y Extensiones**

* El **Uso de Clave** identifica las aplicaciones criptográficas de la clave pública, como firma digital o cifrado de clave.
* El **Uso Extendido de Clave** reduce aún más los casos de uso del certificado, por ejemplo, para la autenticación del servidor TLS.
* **Nombre Alternativo del Sujeto** y **Restricción Básica** definen nombres de host adicionales cubiertos por el certificado y si es un certificado de CA o de entidad final, respectivamente.
* Identificadores como **Identificador de Clave del Sujeto** e **Identificador de Clave de Autoridad** garantizan la singularidad y trazabilidad de las claves.
* **Acceso a la Información de la Autoridad** y **Puntos de Distribución de la Lista de Revocación (CRL)** proporcionan rutas para verificar la CA emisora y verificar el estado de revocación del certificado.
* **CT Precertificate SCTs** ofrecen registros de transparencia, cruciales para la confianza pública en el certificado.
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
### **Diferencia entre los Puntos de Distribución OCSP y CRL**

**OCSP** (**RFC 2560**) implica que un cliente y un respondedor trabajen juntos para verificar si un certificado de clave pública digital ha sido revocado, sin necesidad de descargar la **CRL** completa. Este método es más eficiente que la tradicional **CRL**, que proporciona una lista de números de serie de certificados revocados pero requiere la descarga de un archivo potencialmente grande. Las CRL pueden incluir hasta 512 entradas. Más detalles están disponibles [aquí](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **¿Qué es la Transparencia de Certificados?**

La Transparencia de Certificados ayuda a combatir las amenazas relacionadas con certificados al garantizar que la emisión y existencia de certificados SSL sean visibles para los propietarios de dominios, las Autoridades de Certificación y los usuarios. Sus objetivos son:

* Evitar que las Autoridades de Certificación emitan certificados SSL para un dominio sin el conocimiento del propietario del dominio.
* Establecer un sistema de auditoría abierto para rastrear certificados emitidos por error o de manera maliciosa.
* Proteger a los usuarios contra certificados fraudulentos.

#### **Registros de Certificados**

Los registros de certificados son registros públicamente auditables y de solo adición de certificados, mantenidos por servicios de red. Estos registros proporcionan pruebas criptográficas con fines de auditoría. Tanto las autoridades de emisión como el público pueden enviar certificados a estos registros o consultarlos para su verificación. Aunque el número exacto de servidores de registro no está fijo, se espera que sea inferior a mil a nivel mundial. Estos servidores pueden ser gestionados de forma independiente por Autoridades de Certificación, proveedores de servicios de Internet o cualquier entidad interesada.

#### **Consulta**

Para explorar los registros de Transparencia de Certificados para cualquier dominio, visita [https://crt.sh/](https://crt.sh).

## **Formatos**

### **Formato PEM**

* Formato más ampliamente utilizado para certificados.
* Requiere archivos separados para certificados y claves privadas, codificados en Base64 ASCII.
* Extensiones comunes: .cer, .crt, .pem, .key.
* Principalmente utilizado por servidores Apache y similares.

### **Formato DER**

* Un formato binario de certificados.
* Carece de las declaraciones "BEGIN/END CERTIFICATE" que se encuentran en archivos PEM.
* Extensiones comunes: .cer, .der.
* A menudo utilizado con plataformas Java.

### **Formato P7B/PKCS#7**

* Almacenado en Base64 ASCII, con extensiones .p7b o .p7c.
* Contiene solo certificados y certificados de cadena, excluyendo la clave privada.
* Compatible con Microsoft Windows y Java Tomcat.

### **Formato PFX/P12/PKCS#12**

* Un formato binario que encapsula certificados de servidor, certificados intermedios y claves privadas en un solo archivo.
* Extensiones: .pfx, .p12.
* Principalmente utilizado en Windows para la importación y exportación de certificados.

### **Conversión de Formatos**

Las **conversiones PEM** son esenciales para la compatibilidad:

* **x509 a PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM a DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER a PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM a P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 a PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Conversiones PFX** son cruciales para gestionar certificados en Windows:

* **PFX a PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX a PKCS#8** implica dos pasos:
1. Convertir PFX a PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convertir PEM a PKCS8

Para convertir un archivo PEM a formato PKCS8, puedes utilizar la herramienta OpenSSL con el siguiente comando:

```bash
openssl pkcs8 -topk8 -inform PEM -outform DER -in archivo.pem -out archivo.pk8 -nocrypt
```

Esto convertirá el archivo PEM a formato PKCS8 y lo guardará como archivo.pk8 en formato DER.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B a PFX** también requiere dos comandos:
1. Convertir P7B a CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Convertir CER y Clave Privada a PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
¡Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síganos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
