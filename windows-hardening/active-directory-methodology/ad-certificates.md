# AD Certificates

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

### Partes de un certificado

* **Subject** - El propietario del certificado.
* **Public Key** - Asocia al Subject con una clave privada almacenada por separado.
* **Fechas NotBefore y NotAfter** - Definen la duración de la validez del certificado.
* **Serial Number** - Un identificador para el certificado asignado por la CA.
* **Issuer** - Identifica quién emitió el certificado (comúnmente una CA).
* **SubjectAlternativeName** - Define uno o más nombres alternativos por los que puede ser conocido el Subject. (_Ver abajo_)
* **Basic Constraints** - Identifica si el certificado es una CA o una entidad final, y si hay restricciones en el uso del certificado.
* **Extended Key Usages (EKUs)** - Identificadores de objeto (OIDs) que describen **cómo se utilizará el certificado**. También conocido como Uso de Clave Mejorado en la terminología de Microsoft. Los OIDs de EKU comunes incluyen:
* Code Signing (OID 1.3.6.1.5.5.7.3.3) - El certificado es para firmar código ejecutable.
* Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - El certificado es para cifrar sistemas de archivos.
* Secure Email (1.3.6.1.5.5.7.3.4) - El certificado es para cifrar correo electrónico.
* Client Authentication (OID 1.3.6.1.5.5.7.3.2) - El certificado es para autenticación a otro servidor (por ejemplo, a AD).
* Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - El certificado es para usar en autenticación con tarjeta inteligente.
* Server Authentication (OID 1.3.6.1.5.5.7.3.1) - El certificado es para identificar servidores (por ejemplo, certificados HTTPS).
* **Signature Algorithm** - Especifica el algoritmo utilizado para firmar el certificado.
* **Signature** - La firma del cuerpo del certificado hecha con la clave privada del emisor (por ejemplo, una CA).

#### Subject Alternative Names

Un **Subject Alternative Name** (SAN) es una extensión X.509v3. Permite **identidades adicionales** a ser vinculadas a un **certificado**. Por ejemplo, si un servidor web aloja **contenido para múltiples dominios**, **cada** dominio aplicable podría ser **incluido** en el **SAN** para que el servidor web solo necesite un único certificado HTTPS.

Por defecto, durante la autenticación basada en certificados, una forma en que AD mapea certificados a cuentas de usuario se basa en un UPN especificado en el SAN. Si un atacante puede **especificar un SAN arbitrario** al solicitar un certificado que tiene un **EKU que permite la autenticación del cliente**, y la CA crea y firma un certificado usando el SAN suministrado por el atacante, el **atacante puede convertirse en cualquier usuario del dominio**.

### CAs

AD CS define los certificados de CA que el bosque de AD confía en cuatro ubicaciones bajo el contenedor `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`, cada uno difiere por su propósito:

* El contenedor **Certification Authorities** define **certificados de CA raíz de confianza**. Estas CAs están en la **cima de la jerarquía del árbol PKI** y son la base de la confianza en los entornos de AD CS. Cada CA está representada como un objeto de AD dentro del contenedor donde el **objectClass** está configurado a **`certificationAuthority`** y la propiedad **`cACertificate`** contiene los **bytes** del **certificado de la CA**. Windows propaga estos certificados de CA a la tienda de certificados de Autoridades de Certificación Raíz de Confianza en **cada máquina Windows**. Para que AD considere un certificado como **de confianza**, la cadena de confianza del certificado debe eventualmente **terminar** con **una de las CAs raíz** definidas en este contenedor.
* El contenedor **Enrolment Services** define cada **CA Empresarial** (es decir, CAs creadas en AD CS con el rol de CA Empresarial habilitado). Cada CA Empresarial tiene un objeto de AD con los siguientes atributos:
* Un atributo **objectClass** configurado a **`pKIEnrollmentService`**
* Un atributo **`cACertificate`** que contiene los **bytes del certificado de la CA**
* Una propiedad **`dNSHostName`** que establece el **nombre de host DNS de la CA**
* Un campo **certificateTemplates** que define las **plantillas de certificado habilitadas**. Las plantillas de certificado son un "plano" de configuraciones que la CA utiliza al crear un certificado e incluyen cosas como los EKUs, permisos de inscripción, la expiración del certificado, requisitos de emisión y configuraciones de criptografía. Discutiremos las plantillas de certificado más en detalle más adelante.

{% hint style="info" %}
En entornos de AD, **los clientes interactúan con CAs Empresariales para solicitar un certificado** basado en las configuraciones definidas en una plantilla de certificado. Los certificados de CA Empresarial se propagan a la tienda de certificados de Autoridades de Certificación Intermedias en cada máquina Windows.
{% endhint %}

* El objeto AD **NTAuthCertificates** define certificados de CA que habilitan la autenticación a AD. Este objeto tiene un **objectClass** de **`certificationAuthority`** y la propiedad **`cACertificate`** del objeto define un arreglo de **certificados de CA de confianza**. Las máquinas Windows unidas a AD propagan estas CAs a la tienda de certificados de Autoridades de Certificación Intermedias en cada máquina. Las aplicaciones **cliente** pueden **autenticarse** a AD usando un certificado solo si una de las **CAs definidas por el objeto NTAuthCertificates** ha **firmado** el certificado del cliente autenticador.
* El contenedor **AIA** (Authority Information Access) contiene los objetos AD de CAs intermedias y cruzadas. **Las CAs intermedias son "hijas" de CAs raíz** en la jerarquía del árbol PKI; como tal, este contenedor existe para ayudar en la **validación de cadenas de certificados**. Al igual que el contenedor Certification Authorities, cada **CA está representada como un objeto AD** en el contenedor AIA donde el atributo objectClass está configurado a certificationAuthority y la propiedad **`cACertificate`** contiene los **bytes** del **certificado de la CA**. Estas CAs se propagan a la tienda de certificados de Autoridades de Certificación Intermedias en cada máquina Windows.

### Flujo de Solicitud de Certificado del Cliente

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

Es el proceso para **obtener un certificado** de AD CS. A un alto nivel, durante la inscripción los clientes primero **encuentran una CA Empresarial** basada en los **objetos en el contenedor Enrolment Services** discutido anteriormente.

1. Los clientes luego generan un **par de claves pública-privada** y
2. colocan la clave pública en un mensaje de **solicitud de firma de certificado (CSR)** junto con otros detalles como el sujeto del certificado y el **nombre de la plantilla de certificado**. Luego, los clientes **firman el CSR con su clave privada** y envían el CSR a un servidor de CA Empresarial.
3. El servidor **CA** verifica si el cliente **puede solicitar certificados**. Si es así, determina si emitirá un certificado buscando el objeto AD de la **plantilla de certificado** especificada en el CSR. La CA verificará si los permisos del objeto AD de la plantilla de certificado **permiten** que la cuenta autenticadora **obtenga un certificado**.
4. Si es así, la **CA genera un certificado** usando las configuraciones de "plano" definidas por la **plantilla de certificado** (por ejemplo, EKUs, configuraciones de criptografía y requisitos de emisión) y usando la otra información suministrada en el CSR si es permitido por las configuraciones de la plantilla del certificado. La **CA firma el certificado** usando su clave privada y luego lo devuelve al cliente.

### Plantillas de Certificado

AD CS almacena las plantillas de certificado disponibles como objetos AD con un **objectClass** de **`pKICertificateTemplate`** ubicados en el siguiente contenedor:

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

Los atributos del objeto de plantilla de certificado de AD **definen sus configuraciones, y su descriptor de seguridad controla** qué **principales pueden inscribirse** en el certificado o **editar** la plantilla de certificado.

El atributo **`pKIExtendedKeyUsage`** en un objeto de plantilla de certificado de AD contiene un **arreglo de OIDs** habilitados en la plantilla. Estos OIDs de EKU afectan **para qué se puede usar el certificado**. Puedes encontrar una [lista de posibles OIDs aquí](https://www.pkisolutions.com/object-identifiers-oid-in-pki/).

#### OIDs de Autenticación

* `1.3.6.1.5.5.7.3.2`: Client Authentication
* `1.3.6.1.5.2.3.4`: PKINIT Client Authentication (necesita ser agregado manualmente)
* `1.3.6.1.4.1.311.20.2.2`: Smart Card Logon
* `2.5.29.37.0`: Cualquier propósito
* `(sin EKUs)`: SubCA
* Un OID de EKU adicional que encontramos que podríamos abusar es el OID de Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`). Los certificados con este OID se pueden usar para **solicitar certificados en nombre de otro usuario** a menos que se establezcan restricciones específicas.

## Inscripción de Certificado

Un administrador necesita **crear la plantilla de certificado** y luego una **CA Empresarial "publica"** la plantilla, haciéndola disponible para que los clientes se inscriban. AD CS especifica que una plantilla de certificado está habilitada en una CA Empresarial al **agregar el nombre de la plantilla al campo `certificatetemplates`** del objeto AD.

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
AD CS define los derechos de inscripción - qué **principales pueden solicitar** un certificado – usando dos descriptores de seguridad: uno en el objeto AD de la **plantilla de certificado** y otro en la **CA Empresarial en sí**.\
Un cliente necesita ser otorgado en ambos descriptores de seguridad para poder solicitar un certificado.
{% endhint %}

### Derechos de Inscripción de Plantillas de Certificado

* **El ACE otorga a un principal el derecho extendido de Certificate-Enrollment**. El ACE bruto otorga al principal el derecho de acceso `RIGHT_DS_CONTROL_ACCESS45` donde el **ObjectType** está configurado a `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. Este GUID corresponde con el derecho extendido de **Certificate-Enrolment**.
* **El ACE otorga a un principal el derecho extendido de Certificate-AutoEnrollment**. El ACE bruto otorga al principal el derecho de acceso `RIGHT_DS_CONTROL_ACCESS48` donde el **ObjectType** está configurado a `a05b8cc2-17bc-4802-a710-e7c15ab866a249`. Este GUID corresponde con el derecho extendido de **Certificate-AutoEnrollment**.
* **Un ACE otorga a un principal todos los ExtendedRights**. El ACE bruto habilita el derecho de acceso `RIGHT_DS_CONTROL_ACCESS` donde el **ObjectType** está configurado a `00000000-0000-0000-0000-000000000000`. Este GUID corresponde con **todos los derechos extendidos**.
* **Un ACE otorga a un principal FullControl/GenericAll**. El ACE bruto habilita el derecho de acceso FullControl/GenericAll.

### Derechos de Inscripción de CA Empresarial

El **descriptor de seguridad** configurado en la **CA Empresarial** define estos derechos y es **visible** en el complemento MMC de Autoridad de Certificación `certsrv.msc` haciendo clic derecho en la CA → Propiedades → Seguridad.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

Esto finalmente termina configurando el valor de Seguridad en el registro en la clave **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`** en el servidor CA. Nos hemos encontrado con varios servidores de AD CS que otorgan a usuarios con privilegios bajos acceso remoto a esta clave a través del registro remoto:

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

Los usuarios con privilegios bajos también pueden **enumerar esto a través de DCOM** usando la interfaz COM `ICertAdminD2` y su método `GetCASecurity`. Sin embargo, los clientes normales de Windows necesitan instalar las Herramientas de Administración de Servidores Remotos (RSAT) para usarlo ya que la interfaz COM y cualquier objeto COM que la implemente no están presentes en Windows por defecto.

### Requisitos de Emisión

Otros requisitos podrían estar en lugar para controlar quién puede obtener un certificado.

#### Aprobación del Gerente

**La aprobación del gerente de certificados de CA** resulta en que la plantilla de certificado configure el bit `CT_FLAG_PEND_ALL_REQUESTS` (0x2) en el atributo `msPKI-EnrollmentFlag` del objeto AD. Esto pone todas las **solicitudes de certificado** basadas en la plantilla en el **estado pendiente** (visible en la sección "Solicitudes Pendientes" en `certsrv.msc`), lo que requiere que un gerente de certificados **apruebe o deniegue** la solicitud antes de que se emita el certificado:

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### Agentes de Inscripción, Firmas Autorizadas y Políticas de Aplicación

**El número de firmas autorizadas** y la **Política de aplicación**. El primero controla el **número de firmas requeridas** en el CSR para que la CA lo acepte. El segundo define los **OIDs de EKU que el certificado de firma del CSR debe tener**.

Un uso común para estas configuraciones es para **agentes de inscripción**. Un agente de inscripción es un término de AD CS dado a una entidad que puede **solicitar certificados en nombre de otro usuario**. Para hacerlo, la CA debe emitir al agente de inscripción una cuenta de certificado que contenga al menos el **EKU de Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1). Una vez emitido, el agente de inscripción puede entonces **firmar CSRs y solicitar certificados en nombre de
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

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
