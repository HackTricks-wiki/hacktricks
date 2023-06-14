# Certificados AD

## Información básica

### Partes de un certificado

* **Sujeto** - El propietario del certificado.
* **Clave pública** - Asocia el sujeto con una clave privada almacenada por separado.
* **Fechas de inicio y finalización** - Definen la duración durante la cual el certificado es válido.
* **Número de serie** - Un identificador para el certificado asignado por la CA.
* **Emisor** - Identifica quién emitió el certificado (comúnmente una CA).
* **SubjectAlternativeName** - Define uno o más nombres alternativos que el sujeto puede tener. (_Ver abajo_)
* **Restricciones básicas** - Identifica si el certificado es una CA o una entidad final, y si hay alguna restricción al usar el certificado.
* **Usos extendidos de claves (EKUs)** - Identificadores de objetos (OID) que describen **cómo se usará el certificado**. También conocido como Uso mejorado de claves en el lenguaje de Microsoft. Los OID EKU comunes incluyen:
  * Firma de código (OID 1.3.6.1.5.5.7.3.3) - El certificado es para firmar código ejecutable.
  * Sistema de archivos cifrado (OID 1.3.6.1.4.1.311.10.3.4) - El certificado es para cifrar sistemas de archivos.
  * Correo electrónico seguro (1.3.6.1.5.5.7.3.4) - El certificado es para cifrar correo electrónico.
  * Autenticación de cliente (OID 1.3.6.1.5.5.7.3.2) - El certificado es para la autenticación en otro servidor (por ejemplo, en AD).
  * Inicio de sesión con tarjeta inteligente (OID 1.3.6.1.4.1.311.20.2.2) - El certificado es para su uso en la autenticación con tarjeta inteligente.
  * Autenticación de servidor (OID 1.3.6.1.5.5.7.3.1) - El certificado es para identificar servidores (por ejemplo, certificados HTTPS).
* **Algoritmo de firma** - Especifica el algoritmo utilizado para firmar el certificado.
* **Firma** - La firma del cuerpo del certificado realizada con la clave privada del emisor (por ejemplo, de una CA).

#### Nombres alternativos de sujetos

Un **nombre alternativo de sujeto** (SAN) es una extensión X.509v3. Permite que se vinculen **identidades adicionales** a un **certificado**. Por ejemplo, si un servidor web aloja **contenido para varios dominios**, **cada** dominio **aplicable** podría ser **incluido** en el **SAN** para que el servidor web solo necesite un certificado HTTPS.

Por defecto, durante la autenticación basada en certificados, AD mapea los certificados a las cuentas de usuario basándose en un UPN especificado en el SAN. Si un atacante puede **especificar un SAN arbitrario** al solicitar un certificado que tenga un **EKU que habilite la autenticación del cliente**, y la CA crea y firma un certificado usando el SAN suministrado por el atacante, el **atacante puede convertirse en cualquier usuario del dominio**.

### CAs

AD CS define los certificados de CA en cuatro ubicaciones en el contenedor `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>` que difieren en su propósito:

* El contenedor **Certification Authorities** define los **certificados de CA raíz de confianza**. Estas CAs están en la **parte superior de la jerarquía del árbol PKI** y son la base de la confianza en los entornos de AD CS. Cada CA se representa como un objeto AD dentro del contenedor donde la **objectClass** se establece en **`certificationAuthority`** y la propiedad **`cACertificate`** contiene los **bytes del certificado de la CA**. Windows propaga estos certificados de CA a la tienda de certificados de Autoridades de Certificación Raíz de Confianza en **cada máquina con Windows**. Para que AD considere un certificado como **confiable**, la cadena de confianza del certificado debe terminar eventualmente con **uno de los CA raíz** definidos en este contenedor.
* El contenedor **Enrolment Services** define cada **CA empresarial** (es decir, CAs creadas en AD CS con el rol de CA empresarial habilitado). Cada CA empresarial tiene un objeto AD con los siguientes atributos:
  * Un atributo **objectClass** a **`pKIEnrollmentService`**
  * Un atributo **`cACertificate`** que contiene los **bytes del certificado de la CA**
  * Un atributo **`dNSHostName`** que establece el **host DNS de la CA**
  * Un campo **certificateTemplates** que define las **plantillas de certificado habilitadas**. Las plantillas de certificado son un "modelo" de configuración que la CA utiliza al crear un certificado, e incluyen cosas como los EKUs, los permisos de inscripción, la caducidad del certificado, los requisitos de emisión y la configuración de la criptografía. Discutiremos las plantillas de certificado con más detalle más adelante.

{% hint style="info" %}
En los entornos de AD, los **clientes interactúan con las CAs empresariales para solicitar un certificado** basado en la configuración definida en una
### Derechos de inscripción de plantillas de certificados

* **El ACE otorga a un principal el derecho extendido de inscripción de certificados**. El ACE bruto otorga al principal el derecho de acceso `RIGHT_DS_CONTROL_ACCESS45` donde el **ObjectType** se establece en `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. Este GUID corresponde al derecho extendido de **inscripción de certificados**.
* **El ACE otorga a un principal el derecho extendido de autoinscripción de certificados**. El ACE bruto otorga al principal el derecho de acceso `RIGHT_DS_CONTROL_ACCESS48` donde el **ObjectType** se establece en `a05b8cc2-17bc-4802-a710-e7c15ab866a249`. Este GUID corresponde al derecho extendido de **autoinscripción de certificados**.
* **Un ACE otorga a un principal todos los derechos extendidos**. El ACE bruto habilita el derecho de acceso `RIGHT_DS_CONTROL_ACCESS` donde el **ObjectType** se establece en `00000000-0000-0000-0000-000000000000`. Este GUID corresponde a **todos los derechos extendidos**.
* **Un ACE otorga a un principal FullControl/GenericAll**. El ACE bruto habilita el derecho de acceso FullControl/GenericAll.

### Derechos de inscripción de CA empresarial

El **descriptor de seguridad** configurado en el **CA empresarial** define estos derechos y es **visible** en la instantánea MMC del certificado `certsrv.msc` al hacer clic derecho en el CA → Propiedades → Seguridad.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

Esto finalmente termina configurando el valor del registro de seguridad en la clave **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<NOMBRE DE CA>`** en el servidor CA. Hemos encontrado varios servidores AD CS que otorgan a los usuarios de bajo privilegio acceso remoto a esta clave a través del registro remoto:

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

Los usuarios de bajo privilegio también pueden **enumerar esto a través de DCOM** utilizando el método `GetCASecurity` de la interfaz COM `ICertAdminD2`. Sin embargo, los clientes normales de Windows deben instalar las Herramientas de administración remota del servidor (RSAT) para usarlo, ya que la interfaz COM y cualquier objeto COM que la implemente no están presentes en Windows de forma predeterminada.

### Requisitos de emisión

Podrían existir otros requisitos para controlar quién puede obtener un certificado.

#### Aprobación del administrador

La aprobación del **administrador del certificado de CA** resulta en que la plantilla de certificado establece el bit `CT_FLAG_PEND_ALL_REQUESTS` (0x2) en el atributo `msPKI-EnrollmentFlag` del objeto AD. Esto pone todas las **solicitudes de certificado** basadas en la plantilla en el estado **pendiente** (visible en la sección "Solicitudes pendientes" en `certsrv.msc`), lo que requiere que un administrador de certificados **apruebe o deniegue** la solicitud antes de que se emita el certificado:

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### Agentes de inscripción, firmas autorizadas y políticas de aplicación

**Este número de firmas autorizadas** y la **política de aplicación**. El primero controla el **número de firmas requeridas** en el CSR para que el CA lo acepte. El último define los **OID de EKU que el certificado de firma de CSR debe tener**.

Un uso común para estas configuraciones es para **agentes de inscripción**. Un agente de inscripción es un término de AD CS dado a una entidad que puede **solicitar certificados en nombre de otro usuario**. Para hacerlo, el CA debe emitir al agente de inscripción una cuenta de certificado que contenga al menos el **EKU de agente de solicitud de certificado** (OID 1.3.6.1.4.1.311.20.2.1). Una vez emitido, el agente de inscripción puede **firmar CSR y solicitar certificados en nombre de otros usuarios**. El CA emitirá al agente de inscripción un **certificado** como **otro usuario** solo bajo el siguiente conjunto no exhaustivo de **condiciones** (implementado principalmente en el módulo de política predeterminado `certpdef.dll`):

* El usuario de Windows que se autentica en el CA tiene derechos de inscripción en la plantilla de certificado de destino.
* Si la versión del esquema de la plantilla de certificado es 1, el CA requerirá que los certificados de firma tengan el OID de agente de solicitud de certificado antes de emitir el certificado. La versión del esquema de la plantilla se especifica en la propiedad msPKI-Template-Schema-Version del objeto AD.
* Si la versión del esquema de la plantilla de certificado es 2:
  * La plantilla debe establecer la configuración "Este número de firmas autorizadas" y el número especificado de agentes de inscripción debe firmar el CSR (el atributo AD mspkira-signature de la plantilla define esta configuración). En otras palabras, esta configuración especifica cuántos agentes de inscripción deben firmar un CSR antes de que el CA siquiera considere emitir un certificado.
  * La restricción de emisión de "Política de aplicación" de la plantilla debe establecerse en "Agente de solicitud de certificado".

### Solicitar certificados

1. Usando el **Protocolo de inscripción de certificados de cliente de Windows**
## Enumeración de AD CS

Al igual que para la mayoría de AD, toda la información cubierta hasta ahora está disponible mediante la consulta de LDAP como un usuario autenticado en el dominio, pero de lo contrario sin privilegios.

Si queremos **enumerar los CAs empresariales** y sus configuraciones, se puede consultar LDAP utilizando el filtro LDAP `(objectCategory=pKIEnrollmentService)` en la base de búsqueda `CN=Configuration,DC=<dominio>,DC=<com>` (esta base de búsqueda corresponde con el contexto de nomenclatura de Configuración del bosque de AD). Los resultados identificarán el nombre DNS del servidor CA, el nombre del CA en sí, las fechas de inicio y finalización del certificado, varias banderas, plantillas de certificados publicadas y más.

**Herramientas para enumerar certificados vulnerables:**

* [**Certify**](https://github.com/GhostPack/Certify) es una herramienta en C# que puede **enumerar información útil de configuración e infraestructura sobre entornos AD CS** y puede solicitar certificados de diversas maneras.
* [**Certipy**](https://github.com/ly4k/Certipy) es una herramienta en **python** para poder **enumerar y abusar** de los Servicios de Certificado de Active Directory (**AD CS**) **desde cualquier sistema** (con acceso al DC) que pueda generar una salida para BloodHound creada por [**Lyak**](https://twitter.com/ly4k\_) (buena persona, mejor hacker).
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## Referencias

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
