# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un Certificate

- El **Subject** del certificate denota a su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificate con su legítimo propietario.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificate.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificate.
- El **Issuer** se refiere a la CA que ha emitido el certificate.
- **SubjectAlternativeName** permite nombres adicionales para el subject, mejorando la flexibilidad de identificación.
- **Basic Constraints** identifican si el certificate es para una CA o una entidad final y definen restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificate, como code signing o email encryption, a través de Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método para firmar el certificate.
- La **Signature**, creada con la clave privada del issuer, garantiza la autenticidad del certificate.

### Consideraciones especiales

- **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificate a múltiples identidades, algo crucial para servers con múltiples domains. Los procesos de emisión seguros son vitales para evitar riesgos de suplantación por parte de attackers que manipulan la especificación SAN.

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificates de CA en un AD forest mediante contenedores designados, cada uno con funciones únicas:

- El contenedor **Certification Authorities** almacena trusted root CA certificates.
- El contenedor **Enrolment Services** detalla las Enterprise CAs y sus certificate templates.
- El objeto **NTAuthCertificates** incluye CA certificates autorizados para AD authentication.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena del certificate con intermediate y cross CA certificates.

### Obtención de certificates: flujo de solicitud de un Client Certificate

1. El proceso de solicitud comienza cuando los clients encuentran una Enterprise CA.
2. Se crea un CSR, que contiene una public key y otros detalles, después de generar un par de claves pública-privada.
3. La CA evalúa el CSR frente a los available certificate templates, emitiendo el certificate según los permisos del template.
4. Tras la aprobación, la CA firma el certificate con su clave privada y lo devuelve al client.

### Certificate Templates

Definidos dentro de AD, estos templates describen la configuración y los permisos para emitir certificates, incluidos los EKUs permitidos y los derechos de enrollment o modificación, cruciales para gestionar el acceso a los certificate services.

**La versión del schema del template importa.** Los templates heredados **v1** (por ejemplo, el template integrado **WebServer**) carecen de varios mecanismos modernos de enforcement. La investigación **ESC15/EKUwu** mostró que, en **v1 templates**, un requester puede incrustar **Application Policies/EKUs** en el CSR que son **preferidos sobre** los EKUs configurados en el template, habilitando certificates de client-auth, enrollment agent o code-signing con solo derechos de enrollment. Prefiere **v2/v3 templates**, elimina o reemplaza los valores predeterminados de v1, y delimita los EKUs estrictamente al propósito previsto.

## Certificate Enrollment

El proceso de enrollment de certificates es iniciado por un administrator que **crea un certificate template**, que luego es **published** por una Enterprise Certificate Authority (CA). Esto hace que el template esté disponible para el client enrollment, un paso que se logra añadiendo el nombre del template al campo `certificatetemplates` de un Active Directory object.

Para que un client solicite un certificate, deben concederse **enrollment rights**. Estos derechos se definen mediante security descriptors en el certificate template y en la propia Enterprise CA. Los permisos deben concederse en ambas ubicaciones para que una solicitud tenga éxito.

### Template Enrollment Rights

Estos derechos se especifican mediante Access Control Entries (ACEs), detallando permisos como:

- Derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado con GUIDs específicos.
- **ExtendedRights**, permitiendo todos los permisos extendidos.
- **FullControl/GenericAll**, proporcionando control completo sobre el template.

### Enterprise CA Enrollment Rights

Los derechos de la CA se describen en su security descriptor, accesible a través de la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten acceso remoto a usuarios con pocos privilegios, lo que podría ser un problema de seguridad.

### Additional Issuance Controls

Pueden aplicarse ciertos controles, como:

- **Manager Approval**: coloca las solicitudes en estado pendiente hasta que las apruebe un certificate manager.
- **Enrolment Agents and Authorized Signatures**: especifican el número de firmas requeridas en un CSR y los Application Policy OIDs necesarios.

### Methods to Request Certificates

Los certificates pueden solicitarse mediante:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), a través de named pipes o TCP/IP.
3. La **certificate enrollment web interface**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), junto con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para network devices, usando el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificates mediante la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación con Certificate

Active Directory (AD) soporta la autenticación con certificate, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para un Ticket Granting Ticket (TGT) se firma usando la **private key** del certificate del usuario. Esta solicitud pasa por varias validaciones por parte del domain controller, incluyendo la **validity**, la **path** y el estado de **revocation** del certificate. Las validaciones también incluyen verificar que el certificate proviene de una fuente de confianza y confirmar la presencia del issuer en el **NTAUTH certificate store**. Si las validaciones tienen éxito, se emite un TGT. El objeto **`NTAuthCertificates`** en AD, encontrado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es central para establecer confianza en la autenticación por certificado.

Desde el despliegue de **KB5014754**, la autenticación moderna de certificados Kerberos trata sobre todo de **mapping strength**, no solo de EKUs. En bosques endurecidos:

- Un certificado que solo lleva un **UPN/DNS SAN** puede que ya no sea suficiente para iniciar sesión.
- El KDC prefiere un **strong binding**, normalmente la **SID security extension** (`1.3.6.1.4.1.311.25.2`) o un strong explicit mapping en `altSecurityIdentities`.
- Si el cert carece de un strong mapping, los DC registran **Kdcsvc Event ID 39/41** en compatibility mode y deniegan la auth en enforcement mode.
- En rutas de ataque mixtas, **ESC9/ESC16** importan porque eliminan la extensión SID de los certs emitidos; entonces los operadores dependen de explicit mappings o de formatos SAN URL SID cuando la ruta de ataque los soporta.

### Secure Channel (Schannel) Authentication

Schannel facilita conexiones seguras TLS/SSL, donde durante un handshake, el cliente presenta un certificado que, si se valida con éxito, autoriza el acceso. El mapping de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.

Schannel también es el fallback práctico cuando **PKINIT** no está disponible. Por ejemplo, si un domain controller no tiene un certificado adecuado de **Smart Card Logon**, es posible que `certipy auth`/las herramientas de PKINIT no puedan obtener un TGT, pero el mismo certificado aún puede ser utilizable contra **LDAPS** o **LDAP StartTLS** para autenticación y operaciones LDAP.

### AD Certificate Services Enumeration

Los servicios de certificados de AD se pueden enumerar mediante consultas LDAP, revelando información sobre **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Esto está accesible para cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se usan para la enumeración y la evaluación de vulnerabilidades en entornos de AD CS.

Los comandos para usar estas herramientas incluyen:
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

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalada de privilegios* mediante suplantación de certificados de cuentas de máquina durante PKINIT. | El parche está incluido en las actualizaciones de seguridad del **10 de mayo de 2022**. La auditoría y los controles de *strong-mapping* se introdujeron mediante **KB5014754**; los entornos ahora deberían estar en modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Ejecución remota de código* en los roles AD CS Web Enrollment (certsrv) y CES. | Los PoC públicos son limitados, pero los componentes IIS vulnerables suelen estar expuestos internamente. Parche a partir de **julio de 2023** en Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | En plantillas **v1**, un solicitante con derechos de inscripción puede incrustar **Application Policies/EKUs** en la CSR que tienen preferencia sobre los EKUs de la plantilla, produciendo certificados de client-auth, enrollment agent o code-signing. | Corregido a partir del **12 de noviembre de 2024**. Reemplaza o sustituye las plantillas v1 (por ejemplo, WebServer por defecto), restringe los EKUs según la intención y limita los derechos de inscripción. |

### Microsoft hardening timeline (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para mover la autenticación Kerberos basada en certificados lejos de los mapeos implícitos débiles. A fecha de **11 de febrero de 2025**, los domain controllers cambian automáticamente a **Full Enforcement** si el valor de registro `StrongCertificateBindingEnforcement` no está establecido. Más tarde, Microsoft actualizó la cronología para que el retorno al modo de compatibilidad siga siendo posible hasta la actualización de seguridad del **9 de septiembre de 2025**. Los administradores deberían:

1. Aplicar parches a todos los DCs y servidores AD CS (mayo de 2022 o posterior).
2. Supervisar Event ID 39/41 para mapeos débiles durante la fase *Audit*.
3. Reemitir certificados de client-auth con la nueva **SID extension** o configurar mapeos manuales fuertes antes de que Enforcement bloquee los mapeos débiles.

### Operator notes for hardened forests

- **ESC1/ESC6 alone is no longer the whole story** en entornos 2025+. Si solicitas un certificado para otro principal, normalmente también necesitas un artefacto de strong mapping como la SID extension o un mapeo explícito.
- **ESC15 (EKUwu)** es sobre todo útil en entornos sin parchear porque convierte plantillas **v1** inocuas como **WebServer** en certificados capaces de autenticación o de enrollment-agent mediante la inyección de **Application Policies**. Kerberos PKINIT sigue evaluando EKUs, pero **LDAP Schannel** también acepta Application Policies, lo que mantiene relevante el abuso basado en LDAP.
- **ESC16** es un ajuste a nivel de CA: si la CA desactiva globalmente la SID security extension, todos los certificados emitidos vuelven a un comportamiento de mapeo más débil, salvo que la cadena de ataque inyecte una SID mediante otro formato admitido.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** ahora muestra evaluaciones de postura para ESC1-ESC8/ESC11 y genera alertas en tiempo real como *“Domain-controller certificate issuance for a non-DC”* (ESC8) y *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Asegúrate de desplegar los sensores en todos los servidores AD CS para aprovechar estas detecciones.
* Deshabilita o restringe estrictamente la opción **“Supply in the request”** en todas las plantillas; prefiere valores SAN/EKU definidos explícitamente.
* Elimina **Any Purpose** o **No EKU** de las plantillas salvo que sea absolutamente necesario (cubre escenarios ESC2).
* Exige aprobación del manager o flujos dedicados de Enrollment Agent para plantillas sensibles (por ejemplo, WebServer / CodeSigning).
* Restringe los endpoints de web enrollment (`certsrv`) y CES/NDES a redes de confianza o colócalos detrás de autenticación con certificado de cliente.
* Impón el cifrado de inscripción RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). El flag está **activado por defecto**, pero a menudo se deshabilita para clientes antiguos, lo que reabre el riesgo de relay.
* Protege los **IIS-based enrollment endpoints** (CES/Certsrv): deshabilita NTLM cuando sea posible o exige HTTPS + Extended Protection para bloquear relays ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
