# Certificados

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ¿Qué es un Certificado?

En criptografía, un **certificado de clave pública**, también conocido como **certificado digital** o **certificado de identidad**, es un documento electrónico utilizado para demostrar la propiedad de una clave pública. El certificado incluye información sobre la clave, información sobre la identidad de su propietario (llamado el sujeto) y la firma digital de una entidad que ha verificado el contenido del certificado (llamada el emisor). Si la firma es válida y el software que examina el certificado confía en el emisor, entonces puede utilizar esa clave para comunicarse de forma segura con el sujeto del certificado.

En un esquema típico de [infraestructura de clave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI), el emisor del certificado es una [autoridad de certificación](https://en.wikipedia.org/wiki/Certificate\_authority) (CA), generalmente una empresa que cobra a los clientes por emitir certificados para ellos. En cambio, en un esquema de [red de confianza](https://en.wikipedia.org/wiki/Web\_of\_trust), las personas firman las claves de los demás directamente, en un formato que realiza una función similar a la de un certificado de clave pública.

El formato más común para los certificados de clave pública está definido por [X.509](https://en.wikipedia.org/wiki/X.509). Debido a que X.509 es muy general, el formato está adicionalmente restringido por perfiles definidos para ciertos casos de uso, como [Infraestructura de Clave Pública (X.509)](https://en.wikipedia.org/wiki/PKIX) según se define en RFC 5280.

## Campos Comunes de x509

* **Número de Versión:** Versión del formato x509.
* **Número de Serie**: Utilizado para identificar de manera única el certificado dentro de los sistemas de una CA. En particular, se utiliza para rastrear información de revocación.
* **Sujeto**: La entidad a la que pertenece el certificado: una máquina, un individuo o una organización.
* **Nombre Común**: Dominios afectados por el certificado. Puede ser 1 o más y puede contener comodines.
* **País (C)**: País
* **Nombre Distinguido (DN)**: El sujeto completo: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **Localidad (L)**: Lugar local
* **Organización (O)**: Nombre de la organización
* **Unidad Organizativa (OU)**: División de una organización (como "Recursos Humanos").
* **Estado o Provincia (ST, S o P)**: Lista de nombres de estado o provincia
* **Emisor**: La entidad que verificó la información y firmó el certificado.
* **Nombre Común (CN)**: Nombre de la autoridad de certificación
* **País (C)**: País de la autoridad de certificación
* **Nombre Distinguido (DN)**: Nombre distinguido de la autoridad de certificación
* **Localidad (L)**: Lugar local donde se puede encontrar la organización.
* **Organización (O)**: Nombre de la organización
* **Unidad Organizativa (OU)**: División de una organización (como "Recursos Humanos").
* **No Antes**: La fecha y hora más temprana en la que el certificado es válido. Por lo general, se establece unas horas o días antes del momento en que se emitió el certificado, para evitar problemas de [desviación de reloj](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network).
* **No Después**: La fecha y hora a partir de la cual el certificado ya no es válido.
* **Clave Pública**: Una clave pública perteneciente al sujeto del certificado. (Esta es una de las partes principales, ya que es lo que firma la CA)
* **Algoritmo de Clave Pública**: Algoritmo utilizado para generar la clave pública. Como RSA.
* **Curva de Clave Pública**: La curva utilizada por el algoritmo de clave pública de curva elíptica (si corresponde). Como nistp521.
* **Exponente de Clave Pública**: Exponente utilizado para derivar la clave pública (si corresponde). Como 65537.
* **Tamaño de Clave Pública**: El tamaño del espacio de la clave pública en bits. Como 2048.
* **Algoritmo de Firma**: El algoritmo utilizado para firmar el certificado de clave pública.
* **Firma**: Una firma del cuerpo del certificado por la clave privada del emisor.
* **Extensiones x509v3**
* **Uso de Clave**: Los usos criptográficos válidos de la clave pública del certificado. Los valores comunes incluyen validación de firma digital, cifrado de clave y firma de certificado.
* En un certificado web, esto aparecerá como una _extensión X509v3_ y tendrá el valor `Firma Digital`
* **Uso Extendido de Clave**: Las aplicaciones en las que se puede utilizar el certificado. Los valores comunes incluyen autenticación de servidor TLS, protección de correo electrónico y firma de código.
* En un certificado web, esto aparecerá como una _extensión X509v3_ y tendrá el valor `Autenticación de Servidor Web TLS`
* **Nombre Alternativo del Sujeto:** Permite a los usuarios especificar nombres de host adicionales para un solo **certificado** SSL. El uso de la extensión SAN es una práctica estándar para los certificados SSL y está en camino de reemplazar el uso del **nombre** común.
* **Restricción Básica:** Esta extensión describe si el certificado es un certificado de CA o un certificado de entidad final. Un certificado de CA es algo que firma certificados de otros y un certificado de entidad final es el certificado utilizado en una página web, por ejemplo (la última parte de la cadena).
* **Identificador de clave del sujeto** (SKI): Esta extensión declara un **identificador único** para la **clave pública** en el certificado. Es requerido en todos los certificados de la CA. Las CAs propagan su propio SKI a la extensión de **Identificador de clave del emisor** (AKI) en los certificados emitidos. Es el hash de la clave pública del sujeto.
* **Identificador de clave de autoridad**: Contiene un identificador de clave que se deriva de la clave pública en el certificado del emisor. Es el hash de la clave pública del emisor.
* **Acceso a la información de la autoridad** (AIA): Esta extensión contiene como máximo dos tipos de información:
* Información sobre **cómo obtener el emisor de este certificado** (método de acceso del emisor de la CA)
* Dirección del **respondedor OCSP desde donde se puede verificar la revocación de este certificado** (método de acceso OCSP).
* **Puntos de distribución de la lista de revocación** (CRL): Esta extensión identifica la ubicación de la CRL desde la cual se puede verificar la revocación de este certificado. La aplicación que procesa el certificado puede obtener la ubicación de la CRL de esta extensión, descargar la CRL y luego verificar la revocación de este certificado.
* **CT Precertificate SCTs**: Registros de transparencia de certificados con respecto al certificado.

### Diferencia entre OCSP y Puntos de distribución de la lista de revocación

**OCSP** (RFC 2560) es un protocolo estándar que consta de un **cliente OCSP y un respondedor OCSP**. Este protocolo **determina el estado de revocación de un certificado de clave pública digital dado** **sin tener que descargar** la **lista de revocación completa**.\
**CRL** es el **método tradicional** para verificar la validez del certificado. Una **CRL proporciona una lista de números de serie de certificados** que han sido revocados o ya no son válidos. Las CRL permiten al verificador verificar el estado de revocación del certificado presentado mientras lo verifica. Las CRL están limitadas a 512 entradas.\
De [aquí](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### ¿Qué es la transparencia de certificados?

La transparencia de certificados tiene como objetivo remediar las amenazas basadas en certificados al **hacer que la emisión y existencia de certificados SSL sean visibles para el escrutinio de los propietarios de dominios, las CAs y los usuarios de dominios**. Específicamente, la transparencia de certificados tiene tres objetivos principales:

* Hacer imposible (o al menos muy difícil) que una CA **emita un certificado SSL para un dominio sin que el propietario** de ese dominio **pueda ver el certificado**.
* Proporcionar un **sistema de auditoría y monitoreo abierto** que permita a cualquier propietario de dominio o CA determinar si se han emitido certificados por error o de manera maliciosa.
* **Proteger a los usuarios** (en la medida de lo posible) de ser engañados por certificados que se hayan emitido por error o de manera maliciosa.

#### **Registros de certificados**

Los registros de certificados son servicios de red simples que mantienen **registros de certificados asegurados criptográficamente, auditables públicamente y de solo agregado**. **Cualquiera puede enviar certificados a un registro**, aunque es probable que las autoridades de certificación sean los principales remitentes. Del mismo modo, cualquiera puede consultar un registro para obtener una prueba criptográfica, que se puede utilizar para verificar que el registro se esté comportando correctamente o verificar que un certificado en particular se haya registrado. El número de servidores de registro no tiene que ser grande (digamos, mucho menos de mil en todo el mundo), y cada uno podría ser operado de forma independiente por una CA, un ISP o cualquier otra parte interesada.

#### Consulta

Puede consultar los registros de transparencia de certificados de cualquier dominio en [https://crt.sh/](https://crt.sh).

## Formatos

Existen diferentes formatos que se pueden utilizar para almacenar un certificado.

#### **Formato PEM**

* Es el formato más común utilizado para los certificados.
* La mayoría de los servidores (por ejemplo, Apache) esperan que los certificados y la clave privada estén en archivos separados.
\- Por lo general, son archivos ASCII codificados en Base64.
\- Las extensiones utilizadas para los certificados PEM son .cer, .crt, .pem, .key.
\- Apache y servidores similares utilizan certificados en formato PEM.

#### **Formato DER**

* El formato DER es la forma binaria del certificado.
* Todos los tipos de certificados y claves privadas se pueden codificar en formato DER.
* Los certificados en formato DER no contienen las declaraciones "BEGIN CERTIFICATE/END CERTIFICATE".
* Los certificados en formato DER suelen utilizar las extensiones ‘.cer’ y '.der'.
* DER se utiliza típicamente en plataformas Java.

#### **Formato P7B/PKCS#7**

* El formato PKCS#7 o P7B se almacena en formato Base64 ASCII y tiene una extensión de archivo .p7b o .p7c.
* Un archivo P7B solo contiene certificados y certificados de cadena (CA intermedias), no la clave privada.
* Las plataformas más comunes que admiten archivos P7B son Microsoft Windows y Java Tomcat.

#### **Formato PFX/P12/PKCS#12**

* El formato PKCS#12 o PFX/P12 es un formato binario para almacenar el certificado del servidor, certificados intermedios y la clave privada en un solo archivo cifrable.
* Estos archivos suelen tener extensiones como .pfx y .p12.
* Se utilizan típicamente en máquinas con Windows para importar y exportar certificados y claves privadas.

### Conversiones de formatos

**Convertir x509 a PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Convertir PEM a DER**

To convert a PEM (Privacy-Enhanced Mail) certificate file to DER (Distinguished Encoding Rules) format, you can use the OpenSSL command-line tool.

Para convertir un archivo de certificado PEM (Privacy-Enhanced Mail) a formato DER (Distinguished Encoding Rules), puedes utilizar la herramienta de línea de comandos OpenSSL.

```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
```

Replace `certificate.pem` with the path to your PEM certificate file, and `certificate.der` with the desired output path for the DER certificate file.

Reemplaza `certificate.pem` con la ruta de tu archivo de certificado PEM, y `certificate.der` con la ruta de salida deseada para el archivo de certificado DER.

This command will convert the PEM certificate to DER format and save it as a new file.

Este comando convertirá el certificado PEM al formato DER y lo guardará como un nuevo archivo.
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
To convert a DER (Distinguished Encoding Rules) certificate to PEM (Privacy Enhanced Mail) format, you can use the OpenSSL command-line tool. The following command can be used:

```bash
openssl x509 -inform der -in certificate.der -out certificate.pem
```

Replace `certificate.der` with the path to your DER certificate file. After running the command, a new PEM certificate file named `certificate.pem` will be created.

**Convert PEM to DER**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Convertir PEM a P7B**

**Nota:** El formato PKCS#7 o P7B se almacena en formato Base64 ASCII y tiene una extensión de archivo .p7b o .p7c. Un archivo P7B solo contiene certificados y certificados de cadena (CA intermedios), no la clave privada. Las plataformas más comunes que admiten archivos P7B son Microsoft Windows y Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Convertir PKCS7 a PEM**

A veces, es posible que necesites convertir un archivo en formato PKCS7 a formato PEM para su uso en diferentes aplicaciones o sistemas. Aquí te mostramos cómo hacerlo:

1. Abre una terminal y asegúrate de tener instalado OpenSSL en tu sistema.

2. Ejecuta el siguiente comando para convertir el archivo PKCS7 a formato PEM:

   ```plaintext
   openssl pkcs7 -print_certs -in archivo.p7b -out archivo.pem
   ```

   Asegúrate de reemplazar "archivo.p7b" con la ruta y el nombre de tu archivo PKCS7.

3. Una vez que se ejecute el comando, se generará un nuevo archivo en formato PEM con el nombre "archivo.pem". Este archivo contendrá los certificados extraídos del archivo PKCS7.

Ahora has convertido con éxito un archivo PKCS7 a formato PEM. Puedes utilizar el archivo PEM resultante en diferentes aplicaciones o sistemas que admitan este formato.
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Convertir pfx a PEM**

**Nota:** El formato PKCS#12 o PFX es un formato binario para almacenar el certificado del servidor, los certificados intermedios y la clave privada en un archivo encriptable. Los archivos PFX suelen tener extensiones como .pfx y .p12. Los archivos PFX se utilizan típicamente en máquinas con Windows para importar y exportar certificados y claves privadas.
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

A veces, es posible que necesites convertir un archivo en formato PEM a PKCS8. Esto puede ser útil si estás trabajando con certificados o claves privadas y necesitas cambiar el formato para que sea compatible con ciertas aplicaciones o sistemas.

Para convertir un archivo PEM a PKCS8, puedes utilizar la herramienta OpenSSL. Asegúrate de tener OpenSSL instalado en tu sistema antes de continuar.

1. Abre una terminal y navega hasta la ubicación del archivo PEM que deseas convertir.

2. Ejecuta el siguiente comando para convertir el archivo PEM a PKCS8:

   ```bash
   openssl pkcs8 -topk8 -inform PEM -outform DER -in archivo.pem -out archivo.pk8
   ```

   Asegúrate de reemplazar "archivo.pem" con el nombre de tu archivo PEM y "archivo.pk8" con el nombre que deseas para el archivo PKCS8 resultante.

3. Se te pedirá que ingreses una contraseña para proteger la clave privada en el archivo PKCS8. Ingresa una contraseña segura y recuérdala, ya que la necesitarás para acceder a la clave privada en el futuro.

4. Una vez que se complete el proceso, tendrás un archivo en formato PKCS8 listo para usar.

Recuerda que la conversión de PEM a PKCS8 solo cambia el formato del archivo y no afecta la clave privada en sí. Asegúrate de proteger adecuadamente el archivo PKCS8 y la contraseña asociada para mantener la seguridad de tu clave privada.
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

En algunos casos, es posible que necesite convertir un archivo de certificado en formato CER y una clave privada en formato PEM a un archivo de intercambio de información personal (PFX). Un archivo PFX combina el certificado y la clave privada en un solo archivo, lo que facilita su uso en diferentes aplicaciones y sistemas.

Para convertir el archivo CER y la clave privada a PFX, puede utilizar la herramienta OpenSSL. A continuación se muestra el comando que puede utilizar:

```bash
openssl pkcs12 -export -out certificate.pfx -inkey privatekey.pem -in certificate.cer
```

Este comando toma el archivo de clave privada `privatekey.pem` y el archivo de certificado `certificate.cer` y los combina en un archivo PFX llamado `certificate.pfx`. Durante el proceso, se le pedirá que proporcione una contraseña para proteger el archivo PFX.

Una vez que haya convertido con éxito el archivo CER y la clave privada a PFX, puede utilizar el archivo resultante en aplicaciones y sistemas que admitan el formato PFX.
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
