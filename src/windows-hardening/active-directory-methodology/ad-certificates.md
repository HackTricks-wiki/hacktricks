# Certificados de AD

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado denota su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su dueño legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** se refiere a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el subject, aumentando la flexibilidad de identificación.
- **Basic Constraints** identifican si el certificado es para una CA o una entidad final y definen restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como code signing o email encryption, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método para firmar el certificado.
- La **Signature**, creada con la clave privada del issuer, garantiza la autenticidad del certificado.

### Consideraciones especiales

- **Subject Alternative Names (SANs)** expanden la aplicabilidad de un certificado a múltiples identidades, crucial para servidores con múltiples dominios. Procesos de emisión seguros son vitales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce certificados de CA en un bosque de AD a través de contenedores designados, cada uno con roles únicos:

- El contenedor **Certification Authorities** almacena certificados de CA raíz de confianza.
- El contenedor **Enrolment Services** detalla Enterprise CAs y sus certificate templates.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para autenticación en AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados con certificados intermedios y cross CA.

### Adquisición de certificados: Flujo de solicitud de certificado del cliente

1. El proceso de solicitud comienza con los clientes encontrando una Enterprise CA.
2. Se crea un CSR, que contiene una public key y otros detalles, después de generar un par de claves pública-privada.
3. La CA evalúa el CSR contra los certificate templates disponibles, emitiendo el certificado en función de los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.

### Certificate Templates

Definidas dentro de AD, estas plantillas delinean las configuraciones y permisos para emitir certificados, incluyendo EKUs permitidos y derechos de enrollment o modificación, críticos para gestionar el acceso a los servicios de certificados.

**La versión del esquema de la plantilla importa.** Las plantillas legacy **v1** (por ejemplo, la plantilla incorporada **WebServer**) carecen de varias palancas de enforcement modernas. La investigación **ESC15/EKUwu** mostró que en **v1 templates**, un solicitante puede incrustar **Application Policies/EKUs** en el CSR que son **preferidas sobre** los EKUs configurados en la plantilla, permitiendo certificados de client-auth, enrollment agent, o code-signing con solo derechos de enrollment. Prefiera **v2/v3 templates**, elimine o suprima los valores predeterminados v1 y restrinja estrechamente los EKUs al propósito previsto.

## Solicitud de certificados

El proceso de enrollment de certificados lo inicia un administrador que **crea una certificate template**, la cual luego es **publicada** por una Enterprise Certificate Authority (CA). Esto hace que la plantilla esté disponible para el enrollment de clientes, un paso que se logra añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.

Para que un cliente solicite un certificado, deben otorgarse **enrollment rights**. Estos derechos se definen mediante security descriptors en la certificate template y en la propia Enterprise CA. Los permisos deben concederse en ambos lugares para que una solicitud tenga éxito.

### Template Enrollment Rights

Estos derechos se especifican a través de Access Control Entries (ACEs), detallando permisos como:

- **Certificate-Enrollment** y **Certificate-AutoEnrollment** rights, cada uno asociado con GUIDs específicos.
- **ExtendedRights**, que permiten todos los permisos extendidos.
- **FullControl/GenericAll**, proporcionando control completo sobre la plantilla.

### Enterprise CA Enrollment Rights

Los derechos de la CA se describen en su security descriptor, accesible desde la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten que usuarios de bajo privilegio accedan de forma remota, lo que podría ser un riesgo de seguridad.

### Controles adicionales de emisión

Pueden aplicarse ciertos controles, tales como:

- **Manager Approval**: Coloca las solicitudes en un estado pendiente hasta que sean aprobadas por un certificate manager.
- **Enrolment Agents and Authorized Signatures**: Especifican el número de firmas requeridas en un CSR y los Application Policy OIDs necesarios.

### Métodos para solicitar certificados

Los certificados pueden solicitarse mediante:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), a través de named pipes o TCP/IP.
3. La **certificate enrollment web interface**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), en conjunto con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, usando el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados vía GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o PowerShell's `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación por certificado

Active Directory (AD) admite la autenticación por certificado, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un Ticket Granting Ticket (TGT) de un usuario se firma con la **clave privada** del certificado del usuario. Esta solicitud se somete a varias validaciones por parte del controlador de dominio, incluyendo la **validez**, la **ruta** y el **estado de revocación** del certificado. Las validaciones también incluyen verificar que el certificado provenga de una fuente confiable y confirmar la presencia del emisor en el **almacén de certificados NTAUTH**. Las validaciones exitosas resultan en la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, que se encuentra en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
Es central para establecer la confianza en la autenticación mediante certificados.

### Autenticación de Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras, donde durante un handshake el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapeo de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.

### Enumeración de los servicios de certificados de AD

Los servicios de certificados de AD pueden enumerarse mediante consultas LDAP, revelando información sobre las **Autoridades de Certificación Empresariales (CAs)** y sus configuraciones. Esto es accesible para cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se usan para la enumeración y evaluación de vulnerabilidades en entornos AD CS.

Los comandos para usar estas herramientas incluyen:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para mover la autenticación de certificados Kerberos lejos de mapeos implícitos débiles. As of **February 11 2025**, domain controllers automatically switch to **Full Enforcement** if the `StrongCertificateBindingEnforcement` registry value is not set. Administrators should:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
