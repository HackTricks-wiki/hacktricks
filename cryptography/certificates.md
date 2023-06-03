# Certificados

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ¿Qué es un certificado?

En criptografía, un **certificado de clave pública**, también conocido como **certificado digital** o **certificado de identidad**, es un documento electrónico utilizado para demostrar la propiedad de una clave pública. El certificado incluye información sobre la clave, información sobre la identidad de su propietario (llamado el sujeto) y la firma digital de una entidad que ha verificado el contenido del certificado (llamado el emisor). Si la firma es válida y el software que examina el certificado confía en el emisor, entonces puede usar esa clave para comunicarse de manera segura con el sujeto del certificado.

En un esquema típico de [infraestructura de clave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI), el emisor del certificado es una [autoridad de certificación](https://en.wikipedia.org/wiki/Certificate\_authority) (CA), generalmente una empresa que cobra a los clientes por emitir certificados para ellos. En contraste, en un esquema de [red de confianza](https://en.wikipedia.org/wiki/Web\_of\_trust), los individuos firman las claves de los demás directamente, en un formato que realiza una función similar a la de un certificado de clave pública.

El formato más común para los certificados de clave pública está definido por [X.509](https://en.wikipedia.org/wiki/X.509). Debido a que X.509 es muy general, el formato está más restringido por perfiles definidos para ciertos casos de uso, como [Infraestructura de Clave Pública (X.509)](https://en.wikipedia.org/wiki/PKIX) como se define en RFC 5280.

## Campos comunes de x509

* **Número de versión:** Versión del formato x509.
* **Número de serie**: Se utiliza para identificar de manera única el certificado dentro de los sistemas de una CA. En particular, se utiliza para realizar un seguimiento de la información de revocación.
* **Sujeto**: La entidad a la que pertenece un certificado: una máquina, un individuo o una organización.
  * **Nombre común**: Dominios afectados por el certificado. Puede ser 1 o más y puede contener comodines.
  * **País (C)**: País
  * **Nombre distinguido (DN)**: Todo el sujeto: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
  * **Localidad (L)**: Lugar local
  * **Organización (O)**: Nombre de la organización
  * **Unidad organizativa (OU)**: División de una organización (como "Recursos Humanos").
  * **Estado o provincia (ST, S o P)**: Lista de nombres de estados o provincias
* **Emisor**: La entidad que verificó la información y firmó el certificado.
  * **Nombre común (CN)**: Nombre de la autoridad de certificación
  * **País (C)**: País de la autoridad de certificación
  * **Nombre distinguido (DN)**: Nombre distinguido de la autoridad de certificación
  * **Localidad (L)**: Lugar local donde se puede encontrar la organización.
  * **Organización (O)**: Nombre de la organización
  * **Unidad organizativa (OU)**: División de una organización (como "Recursos Humanos").
* **No antes de**: La
#### **Formato DER**

* El formato DER es la forma binaria del certificado
* Todos los tipos de certificados y claves privadas pueden ser codificados en formato DER
* Los certificados en formato DER no contienen las declaraciones "BEGIN CERTIFICATE/END CERTIFICATE"
* Los certificados en formato DER usan más comúnmente las extensiones '.cer' y '.der'
* DER se utiliza típicamente en plataformas Java

#### **Formato P7B/PKCS#7**

* El formato PKCS#7 o P7B se almacena en formato Base64 ASCII y tiene una extensión de archivo de '.p7b' o '.p7c'
* Un archivo P7B sólo contiene certificados y certificados de cadena (CA intermedios), no la clave privada
* Las plataformas más comunes que admiten archivos P7B son Microsoft Windows y Java Tomcat

#### **Formato PFX/P12/PKCS#12**

* El formato PKCS#12 o PFX/P12 es un formato binario para almacenar el certificado del servidor, los certificados intermedios y la clave privada en un solo archivo cifrado
* Estos archivos suelen tener extensiones como '.pfx' y '.p12'
* Se utilizan típicamente en máquinas Windows para importar y exportar certificados y claves privadas

### Conversiones de formatos

**Convertir x509 a PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Convertir PEM a DER**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**Convertir DER a PEM**

Para convertir un certificado en formato DER a formato PEM, se puede utilizar el siguiente comando:

```
openssl x509 -inform der -in certificate.der -out certificate.pem
```

Donde `certificate.der` es el nombre del archivo en formato DER y `certificate.pem` es el nombre del archivo de salida en formato PEM.
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Convertir PEM a P7B**

**Nota:** El formato PKCS#7 o P7B se almacena en formato Base64 ASCII y tiene una extensión de archivo de .p7b o .p7c. Un archivo P7B solo contiene certificados y certificados de cadena (CA intermedios), no la clave privada. Las plataformas más comunes que admiten archivos P7B son Microsoft Windows y Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Convertir PKCS7 a PEM**

Para convertir un archivo PKCS7 a formato PEM, se puede utilizar el siguiente comando:

```
openssl pkcs7 -print_certs -in file.p7b -out file.pem
```

Esto imprimirá los certificados en el archivo PKCS7 y los guardará en un archivo PEM.
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Convertir pfx a PEM**

**Nota:** El formato PKCS#12 o PFX es un formato binario para almacenar el certificado del servidor, los certificados intermedios y la clave privada en un archivo cifrable. Los archivos PFX suelen tener extensiones como .pfx y .p12. Los archivos PFX se utilizan típicamente en máquinas con Windows para importar y exportar certificados y claves privadas.
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
![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utiliza [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
