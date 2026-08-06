# Certificados de AD

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** hace referencia a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el sujeto, lo que mejora la flexibilidad de identificación.
- **Basic Constraints** indica si el certificado es para una CA o una entidad final, y define las restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los fines específicos del certificado, como la firma de código o el cifrado de correo electrónico, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método utilizado para firmar el certificado.
- La **Signature**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.<sup>[[4]](#references)</sup>

### Consideraciones especiales

- Los **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, algo crucial para servidores con varios dominios. Los procesos seguros de emisión son fundamentales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA en un bosque de AD mediante contenedores designados, cada uno con funciones específicas:<sup>[[4]](#references)</sup>

- El contenedor **Certification Authorities** contiene los certificados de las CA raíz de confianza.
- El contenedor **Enrolment Services** detalla las CA Enterprise y sus plantillas de certificados.
- El objeto **NTAuthCertificates** incluye los certificados de CA autorizados para la autenticación en AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados mediante certificados intermedios y de CA cruzadas.

### Adquisición de certificados: flujo de solicitud de certificados del cliente

1. El proceso de solicitud comienza cuando los clientes localizan una CA Enterprise.
2. Se crea una CSR que contiene una clave pública y otros datos, después de generar un par de claves pública-privada.
3. La CA evalúa la CSR con respecto a las plantillas de certificados disponibles y emite el certificado según los permisos de la plantilla.
4. Tras su aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.<sup>[[4]](#references)</sup>

### Plantillas de certificados

Definidas dentro de AD, estas plantillas especifican la configuración y los permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de inscripción o modificación, que son fundamentales para gestionar el acceso a los servicios de certificados.<sup>[[4]](#references)</sup>

**La versión del esquema de la plantilla es importante.** Las plantillas **v1** heredadas (por ejemplo, la plantilla integrada **WebServer**) carecen de varios controles de enforcement modernos. La investigación sobre **ESC15/EKUwu** demostró que, en las plantillas **v1**, un solicitante puede incluir **Application Policies/EKUs** en la CSR que tienen **preferencia sobre** los EKUs configurados en la plantilla, lo que permite obtener certificados de client-auth, enrollment agent o code-signing con solo derechos de inscripción. Se recomienda utilizar plantillas **v2/v3**, eliminar o reemplazar las plantillas v1 predeterminadas y limitar estrictamente los EKUs al propósito previsto.<sup>[[1]](#references)</sup>

## Inscripción de certificados

El proceso de inscripción de certificados se inicia cuando un administrador **crea una plantilla de certificados**, que posteriormente es **publicada** por una Certificate Authority (CA) Enterprise. Esto hace que la plantilla esté disponible para la inscripción de clientes, un paso que se consigue añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.<sup>[[4]](#references)</sup>

Para que un cliente pueda solicitar un certificado, deben concederse **derechos de inscripción**. Estos derechos se definen mediante descriptores de seguridad en la plantilla de certificados y en la propia CA Enterprise. Los permisos deben concederse en ambas ubicaciones para que una solicitud tenga éxito.

### Derechos de inscripción de la plantilla

Estos derechos se especifican mediante Access Control Entries (ACEs), que detallan permisos como:

- Derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUIDs específicos.
- **ExtendedRights**, que permite todos los permisos extendidos.
- **FullControl/GenericAll**, que proporciona control total sobre la plantilla.

### Derechos de inscripción de la CA Enterprise

Los derechos de la CA se describen en su descriptor de seguridad, accesible mediante la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten el acceso remoto a usuarios con pocos privilegios, lo que podría suponer un riesgo de seguridad.

### Controles adicionales de emisión

Pueden aplicarse determinados controles, como:

- **Manager Approval**: coloca las solicitudes en estado pendiente hasta que sean aprobadas por un administrador de certificados.
- **Enrolment Agents and Authorized Signatures**: especifica el número de firmas necesarias en una CSR y los Application Policy OIDs requeridos.

### Métodos para solicitar certificados

Los certificados se pueden solicitar mediante:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilizando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), mediante named pipes o TCP/IP.
3. La **interfaz web de inscripción de certificados**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), junto con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, utilizando el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados mediante la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación mediante certificados

Active Directory (AD) admite la autenticación mediante certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para obtener un Ticket Granting Ticket (TGT) se firma utilizando la **clave privada** del certificado del usuario. Esta solicitud se somete a varias validaciones por parte del controlador de dominio, incluida la **validez**, la **ruta** y el estado de **revocación** del certificado. Las validaciones también incluyen verificar que el certificado provenga de una fuente de confianza y confirmar la presencia del emisor en el **almacén de certificados NTAUTH**. Las validaciones exitosas dan como resultado la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, ubicado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es fundamental para establecer la confianza en la autenticación mediante certificados.<sup>[[4]](#references)</sup>

Desde el despliegue de **KB5014754**, la autenticación moderna de Kerberos mediante certificados se centra principalmente en la **fuerza del mapping**, no solo en los EKU.<sup>[[2]](#references)</sup> En los forests reforzados:

- Un certificado que solo incluya un **UPN/DNS SAN** puede dejar de ser suficiente para el logon.
- El KDC prefiere un **strong binding**, normalmente la **SID security extension** (`1.3.6.1.4.1.311.25.2`) o un mapping explícito fuerte en `altSecurityIdentities`.
- Si el certificado carece de un mapping fuerte, los DC registran **Kdcsvc Event ID 39/41** en compatibility mode y rechazan la autenticación en enforcement mode.
- En attack paths mixtos, **ESC9/ESC16** son relevantes porque eliminan la SID extension de los certificados emitidos; los operadores recurren entonces a mappings explícitos o a formatos de SID en SAN URL cuando el attack path lo permite.

### Autenticación de Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras. Durante el handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapping de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.<sup>[[4]](#references)</sup>

Schannel también es el fallback práctico cuando **PKINIT** no está disponible. Por ejemplo, si un domain controller no dispone de un certificado adecuado de **Smart Card Logon**, `certipy auth`/PKINIT tooling puede fallar al obtener un TGT, pero el mismo certificado puede seguir siendo utilizable contra **LDAPS** o **LDAP StartTLS** para la autenticación y las operaciones LDAP.

### Enumeración de AD Certificate Services

Los certificate services de AD pueden enumerarse mediante consultas LDAP, revelando información sobre las **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Cualquier usuario autenticado en el dominio puede acceder a esta información sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para la enumeración y la evaluación de vulnerabilidades en entornos de AD CS.

Los comandos para utilizar estas herramientas incluyen:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilidades recientes y actualizaciones de seguridad (2022-2025)

| Año | ID / Nombre | Impacto | Puntos clave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalada de privilegios* mediante la suplantación de certificados de cuentas de máquina durante PKINIT. | El parche se incluye en las actualizaciones de seguridad del **10 de mayo de 2022**. Los controles de auditoría y strong-mapping se introdujeron mediante **KB5014754**; los entornos ahora deberían estar en modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Ejecución remota de código* en los roles AD CS Web Enrollment (certsrv) y CES. | Los PoC públicos son limitados, pero los componentes IIS vulnerables suelen estar expuestos internamente. Parcheado desde el Patch Tuesday de **julio de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | En las **plantillas v1**, un solicitante con permisos de enrollment puede incluir **Application Policies/EKUs** en la CSR, que tienen prioridad sobre los EKUs de la plantilla, generando certificados de client-auth, enrollment agent o code-signing. | Parcheado desde el **12 de noviembre de 2024**. Reemplace o sustituya las plantillas v1 (por ejemplo, WebServer predeterminada), restrinja los EKUs según su propósito y limite los permisos de enrollment. |

### Cronología de hardening de Microsoft (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para alejar la autenticación de certificados Kerberos de los mappings implícitos débiles. Desde el **11 de febrero de 2025**, los controladores de dominio cambian automáticamente a **Full Enforcement** si el valor de registro `StrongCertificateBindingEnforcement` no está establecido. Posteriormente, Microsoft actualizó la cronología para que el fallback al modo de compatibilidad siga siendo posible hasta la actualización de seguridad del **9 de septiembre de 2025**.<sup>[[2]](#references)</sup> Los administradores deben:

1. Aplicar los parches a todos los DC y servidores AD CS (mayo de 2022 o posteriores).
2. Supervisar los eventos ID 39/41 para detectar mappings débiles durante la fase de *Audit*.
3. Volver a emitir certificados de client-auth con la nueva **extensión SID** o configurar mappings manuales strong antes de que Enforcement bloquee los mappings débiles.

### Notas para operadores de forests con hardening

- **ESC1/ESC6 por sí solos ya no representan toda la situación** en entornos de 2025+. Si solicita un cert para otra principal, normalmente también necesita un artefacto de strong mapping, como la extensión SID o un mapping explícito.
- **ESC15 (EKUwu)** resulta principalmente útil en entornos sin parchear porque convierte plantillas **v1** inofensivas, como **WebServer**, en certificados capaces de autenticación o enrollment-agent mediante la inyección de **Application Policies**. Kerberos PKINIT sigue evaluando los EKUs, pero **LDAP Schannel** también respeta las Application Policies, lo que mantiene relevante el abuso basado en LDAP.<sup>[[1]](#references)</sup>
- **ESC16** es un ajuste global de la CA: si la CA deshabilita globalmente la extensión de seguridad SID, todos los certificados emitidos vuelven a comportarse según mappings más débiles, a menos que la attack chain inyecte un SID mediante otro formato compatible.

---

## Mejoras de detección y hardening

* El **sensor AD CS de Defender for Identity (2023-2024)** ahora muestra evaluaciones de posture para ESC1-ESC8/ESC11 y genera alertas en tiempo real, como *“Domain-controller certificate issuance for a non-DC”* (ESC8) y *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Asegúrese de desplegar sensores en todos los servidores AD CS para beneficiarse de estas detecciones.<sup>[[3]](#references)</sup>
* Deshabilite o limite estrictamente la opción **“Supply in the request”** en todas las plantillas; prefiera valores SAN/EKU definidos explícitamente.
* Elimine **Any Purpose** o **No EKU** de las plantillas salvo que sea absolutamente necesario (aborda escenarios ESC2).
* Requiera **aprobación del manager** o workflows de Enrollment Agent dedicados para plantillas sensibles (por ejemplo, WebServer / CodeSigning).
* Restrinja el web enrollment (`certsrv`) y los endpoints CES/NDES a redes de confianza o sitúelos detrás de autenticación mediante client-certificate.
* Aplique el cifrado de enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). El flag está **habilitado por defecto**, pero a menudo se deshabilita para clientes legacy, lo que vuelve a abrir el riesgo de relay.
* Proteja los **endpoints de enrollment basados en IIS** (CES/Certsrv): deshabilite NTLM cuando sea posible o requiera HTTPS + Extended Protection para bloquear los relays ESC8.

---

## Referencias

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
