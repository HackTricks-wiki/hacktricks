# Certificados

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ¿Qué es un Certificado

En criptografía, un **certificado de clave pública**, también conocido como **certificado digital** o **certificado de identidad**, es un documento electrónico utilizado para demostrar la propiedad de una clave pública. El certificado incluye información sobre la clave, información sobre la identidad de su propietario (llamado el sujeto) y la firma digital de una entidad que ha verificado el contenido del certificado (llamado el emisor). Si la firma es válida y el software que examina el certificado confía en el emisor, entonces puede usar esa clave para comunicarse de forma segura con el sujeto del certificado.

En un esquema típico de [infraestructura de clave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI), el emisor del certificado es una [autoridad de certificación](https://en.wikipedia.org/wiki/Certificate\_authority) (CA), generalmente una empresa que cobra a los clientes por emitir certificados para ellos. En contraste, en un esquema de [red de confianza](https://en.wikipedia.org/wiki/Web\_of\_trust), los individuos firman directamente las claves de los demás, en un formato que realiza una función similar a la de un certificado de clave pública.

El formato más común para los certificados de clave pública está definido por [X.509](https://en.wikipedia.org/wiki/X.509). Debido a que X.509 es muy general, el formato está aún más restringido por perfiles definidos para ciertos casos de uso, como [Infraestructura de Clave Pública (X.509)](https://en.wikipedia.org/wiki/PKIX) como se define en RFC 5280.

## Campos Comunes de x509

* **Número de Versión:** Versión del formato x509.
* **Número de Serie**: Utilizado para identificar de forma única el certificado dentro de los sistemas de una CA. En particular, se utiliza para hacer un seguimiento de la información de revocación.
* **Sujeto**: La entidad a la que pertenece un certificado: una máquina, un individuo o una organización.
* **Nombre Común**: Dominios afectados por el certificado. Puede ser 1 o más y puede contener comodines.
* **País (C)**: País
* **Nombre Distintivo (DN)**: Todo el sujeto: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **Localidad (L)**: Lugar local
* **Organización (O)**: Nombre de la organización
* **Unidad Organizativa (OU)**: División de una organización (como "Recursos Humanos").
* **Estado o Provincia (ST, S o P)**: Lista de nombres de estados o provincias
* **Emisor**: La entidad que verificó la información y firmó el certificado.
* **Nombre Común (CN)**: Nombre de la autoridad de certificación
* **País (C)**: País de la autoridad de certificación
* **Nombre Distintivo (DN)**: Nombre distintivo de la autoridad de certificación
* **Localidad (L)**: Lugar local donde se puede encontrar la organización.
* **Organización (O)**: Nombre de la organización
* **Unidad Organizativa (OU)**: División de una organización (como "Recursos Humanos").
* **No Antes de**: La fecha y hora más temprana en la que el certificado es válido. Por lo general, se establece unas horas o días antes del momento en que se emitió el certificado, para evitar problemas de [desviación de reloj](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network).
* **No Después de**: La fecha y hora después de la cual el certificado ya no es válido.
* **Clave Pública**: Una clave pública perteneciente al sujeto del certificado. (Esta es una de las partes principales ya que es lo que firma la CA)
* **Algoritmo de Clave Pública**: Algoritmo utilizado para generar la clave pública. Como RSA.
* **Curva de Clave Pública**: La curva utilizada por el algoritmo de clave pública de curva elíptica (si aplica). Como nistp521.
* **Exponente de Clave Pública**: Exponente utilizado para derivar la clave pública (si aplica). Como 65537.
* **Tamaño de Clave Pública**: El tamaño del espacio de clave pública en bits. Como 2048.
* **Algoritmo de Firma**: El algoritmo utilizado para firmar el certificado de clave pública.
* **Firma**: Una firma del cuerpo del certificado por la clave privada del emisor.
* **Extensiones x509v3**
* **Uso de Clave**: Los usos criptográficos válidos de la clave pública del certificado. Los valores comunes incluyen validación de firma digital, cifrado de clave y firma de certificado.
* En un certificado web esto aparecerá como una _extensión X509v3_ y tendrá el valor `Firma Digital`
* **Uso Extendido de Clave**: Las aplicaciones en las que se puede utilizar el certificado. Los valores comunes incluyen autenticación de servidor TLS, protección de correo electrónico y firma de código.
* En un certificado web esto aparecerá como una _extensión X509v3_ y tendrá el valor `Autenticación de Servidor Web TLS`
* **Nombre Alternativo del Sujeto:** Permite a los usuarios especificar nombres de host adicionales para un solo **certificado** SSL. El uso de la extensión SAN es una práctica estándar para los certificados SSL y está en camino de reemplazar el uso del **nombre** común.
* **Restricción Básica:** Esta extensión describe si el certificado es un certificado de CA o un certificado de entidad final. Un certificado de CA es algo que firma certificados de otros y un certificado de entidad final es el certificado utilizado en una página web, por ejemplo (la última parte de la cadena).
* **Identificador de Clave del Sujeto** (SKI): Esta extensión declara un **identificador** único para la **clave pública** en el certificado. Es necesario en todos los certificados de CA. Las CA propagan su propio SKI a la extensión Identificador de Clave del Emisor (AKI) en los certificados emitidos. Es el hash de la clave pública del sujeto.
* **Identificador de Clave de Autoridad**: Contiene un identificador de clave que se deriva de la clave pública en el certificado del emisor. Es el hash de la clave pública del emisor.
* **Acceso a la Información de la Autoridad** (AIA): Esta extensión contiene como máximo dos tipos de información:
* Información sobre **cómo obtener el emisor de este certificado** (método de acceso del emisor de la CA)
* Dirección del **respondedor OCSP desde donde se puede verificar la revocación de este certificado** (método de acceso OCSP).
* **Puntos de Distribución de la LCR**: Esta extensión identifica la ubicación de la LCR desde la cual se puede verificar la revocación de este certificado. La aplicación que procesa el certificado puede obtener la ubicación de la LCR desde esta extensión, descargar la LCR y luego verificar la revocación de este certificado.
* **CT Precertificate SCTs**: Registros de transparencia de certificados con respecto al certificado

### Diferencia entre OCSP y Puntos de Distribución de la LCR

**OCSP** (RFC 2560) es un protocolo estándar que consiste en un **cliente OCSP y un respondedor OCSP**. Este protocolo **determina el estado de revocación de un certificado digital de clave pública dado** **sin** tener que **descargar** la **LCR completa**.\
**LCR** es el **método tradicional** para verificar la validez del certificado. Una **LCR proporciona una lista de números de serie de certificados** que han sido revocados o ya no son válidos. Las LCR permiten al verificador verificar el estado de revocación del certificado presentado mientras lo verifica. Las LCR están limitadas a 512 entradas.\
De [aquí](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### ¿Qué es la Transparencia de Certificados

La Transparencia de Certificados tiene como objetivo remediar las amenazas basadas en certificados al **hacer que la emisión y existencia de certificados SSL sean visibles para la escrutinio de los propietarios de dominios, las CAs y los usuarios de dominios**. Específicamente, la Transparencia de Certificados tiene tres objetivos principales:

* Hacer imposible (o al menos muy difícil) que una CA **emita un certificado SSL para un dominio sin que el propietario** de ese dominio **pueda ver el certificado**.
* Proporcionar un **sistema de auditoría y monitoreo abierto** que permita a cualquier propietario de dominio o CA determinar si se han emitido certificados por error o maliciosamente.
* **Proteger a los usuarios** (en la medida de lo posible) de ser engañados por certificados que se hayan emitido por error o maliciosamente.

#### **Registros de Certificados**

Los registros de certificados son servicios de red simples que mantienen **registros de certificados garantizados criptográficamente, públicamente auditables, de solo adición**. **Cualquiera puede enviar certificados a un registro**, aunque es probable que las autoridades de certificación sean los principales remitentes. Del mismo modo, cualquiera puede consultar un registro para obtener una prueba criptográfica, que se puede utilizar para verificar que el registro esté funcionando correctamente o verificar que un certificado en particular haya sido registrado. El número de servidores de registro no tiene por qué ser grande (digamos, mucho menos de mil en todo el mundo), y cada uno podría ser operado de forma independiente por una CA, un ISP o cualquier otra parte interesada.

#### Consulta

Puedes consultar los registros de Transparencia de Certificados de cualquier dominio en [https://crt.sh/](https://crt.sh).

## Formatos

Existen diferentes formatos que se pueden utilizar para almacenar un certificado.

#### **Formato PEM**

* Es el formato más común utilizado para los certificados
* La mayoría de los servidores (por ejemplo, Apache) esperan que los certificados y la clave privada estén en archivos separados\
\- Por lo general, son archivos ASCII codificados en Base64\
\- Las extensiones utilizadas para los certificados PEM son .cer, .crt, .pem, .key\
\- Apache y servidores similares utilizan certificados en formato PEM

#### **Formato DER**

* El formato DER es la forma binaria del certificado
* Todos los tipos de certificados y claves privadas pueden codificarse en formato DER
* Los certificados en formato DER no contienen las declaraciones "BEGIN CERTIFICATE/END CERTIFICATE"
* Los certificados en formato DER suelen usar las extensiones ‘.cer’ y '.der'
* DER se utiliza típicamente en Plataformas Java

#### **Formato P7B/PKCS#7**

* El formato PKCS#7 o P7B se almacena en formato Base64 ASCII y tiene una extensión de archivo .p7b o .p7c
* Un archivo P7B solo contiene certificados y certificados de cadena (CAs intermedias), no la clave privada
* Las plataformas más comunes que admiten archivos P7B son Microsoft Windows y Java Tomcat

#### **Formato PFX/P12/PKCS#12**

* El formato PKCS#12 o PFX/P12 es un formato binario para almacenar el certificado del servidor, certificados intermedios y la clave privada en un archivo cifrable
* Estos archivos suelen tener extensiones como .pfx y .p12
* Se utilizan típicamente en máquinas Windows para importar y exportar certificados y claves privadas

### Conversiones de Formatos

**Convertir x509 a PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Convertir PEM a DER**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**Convertir DER a PEM**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Convertir PEM a P7B**

**Nota:** El formato PKCS#7 o P7B se almacena en formato Base64 ASCII y tiene una extensión de archivo .p7b o .p7c. Un archivo P7B solo contiene certificados y certificados de cadena (CAs intermedios), no la clave privada. Las plataformas más comunes que admiten archivos P7B son Microsoft Windows y Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Convertir PKCS7 a PEM**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Convertir pfx a PEM**

**Nota:** El formato PKCS#12 o PFX es un formato binario para almacenar el certificado del servidor, certificados intermedios y la clave privada en un archivo encriptable. Los archivos PFX suelen tener extensiones como .pfx y .p12. Los archivos PFX se utilizan típicamente en máquinas con Windows para importar y exportar certificados y claves privadas.
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**Convertir PFX a PKCS#8**\
**Nota:** Esto requiere 2 comandos

**1- Convertir PFX a PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- Convertir PEM a PKCS8**
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**Convertir P7B a PFX**\
**Nota:** Esto requiere 2 comandos

1- **Convertir P7B a CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- Convertir CER y Clave Privada a PFX**
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síganos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud). 

</details>
