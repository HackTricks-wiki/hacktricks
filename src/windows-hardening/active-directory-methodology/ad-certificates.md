# Certificados AD

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** se refiere a la CA que emitió el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el subject, aumentando la flexibilidad de identificación.
- **Basic Constraints** identifican si el certificado es para una CA o una entidad final y definen restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como firma de código o cifrado de correo, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método para firmar el certificado.
- La **Signature**, creada con la clave privada del issuer, garantiza la autenticidad del certificado.

### Consideraciones especiales

- **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, crucial para servidores con múltiples dominios. Los procesos de emisión seguros son vitales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce certificados de CA en un forest de AD mediante contenedores designados, cada uno con roles únicos:

- El contenedor **Certification Authorities** contiene los certificados root de CA de confianza.
- El contenedor **Enrolment Services** detalla las Enterprise CAs y sus certificate templates.
- El objeto **NTAuthCertificates** incluye los certificados de CA autorizados para la autenticación en AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados con certificados intermedios y cross CA.

### Adquisición de certificados: Flujo de solicitud de certificado por parte del cliente

1. El proceso de solicitud comienza con los clientes localizando una Enterprise CA.
2. Se crea un CSR, que contiene una public key y otros datos, después de generar un par de claves pública-privada.
3. La CA evalúa el CSR frente a los certificate templates disponibles, emitiendo el certificado según los permisos del template.
4. Una vez aprobado, la CA firma el certificado con su clave privada y lo devuelve al cliente.

### Certificate Templates

Definidas dentro de AD, estas plantillas describen las configuraciones y permisos para emitir certificados, incluyendo EKUs permitidos y derechos de enrollment o modificación, críticos para gestionar el acceso a los servicios de certificado.

La versión del esquema de la plantilla importa. Las plantillas legacy **v1** (por ejemplo, la plantilla incorporada **WebServer**) carecen de varias opciones de enforcement modernas. La investigación **ESC15/EKUwu** mostró que en **v1 templates**, un solicitante puede incrustar **Application Policies/EKUs** en el CSR que son **preferidos sobre** los EKUs configurados en la plantilla, permitiendo certificados de client-auth, enrollment agent o code-signing con solo derechos de enrollment. Preferir plantillas **v2/v3**, eliminar o reemplazar los valores por defecto de v1, y delimitar estrictamente los EKUs al propósito previsto.

## Inscripción de certificados

El proceso de inscripción de certificados lo inicia un administrador que **crea un certificate template**, el cual luego es **publicado** por una Enterprise Certificate Authority (CA). Esto hace que la plantilla esté disponible para la inscripción de clientes, un paso que se logra añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.

Para que un cliente solicite un certificado, deben otorgarse **enrollment rights**. Estos derechos se definen mediante descriptores de seguridad en el certificate template y en la Enterprise CA misma. Los permisos deben concederse en ambas ubicaciones para que una solicitud sea exitosa.

### Derechos de inscripción en la plantilla

Estos derechos se especifican mediante Access Control Entries (ACEs), detallando permisos como:

- **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUIDs específicos.
- **ExtendedRights**, que permiten todos los permisos extendidos.
- **FullControl/GenericAll**, que proporcionan control completo sobre la plantilla.

### Derechos de inscripción en la Enterprise CA

Los derechos de la CA se describen en su security descriptor, accesible desde la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten a usuarios de bajo privilegio acceso remoto, lo cual puede ser un problema de seguridad.

### Controles adicionales de emisión

Pueden aplicarse ciertos controles, como:

- **Manager Approval**: coloca las solicitudes en estado pendiente hasta que sean aprobadas por un manager de certificados.
- **Enrolment Agents and Authorized Signatures**: especifican el número de firmas requeridas en un CSR y los Application Policy OIDs necesarios.

### Métodos para solicitar certificados

Los certificados se pueden solicitar a través de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), mediante named pipes o TCP/IP.
3. La interfaz web de certificate enrollment, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), en combinación con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, usando el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados vía GUI (`certmgr.msc` o `certlm.msc`) o mediante herramientas de línea de comandos (`certreq.exe` o el comando Get-Certificate de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación de certificados

Active Directory (AD) admite la autenticación mediante certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para un Ticket Granting Ticket (TGT) se firma usando la **clave privada** del certificado del usuario. Dicha solicitud pasa por varias validaciones efectuadas por el controlador de dominio, incluyendo la **validez**, la **ruta** y el **estado de revocación** del certificado. Las validaciones también incluyen verificar que el certificado proviene de una fuente de confianza y confirmar la presencia del emisor en la **NTAUTH certificate store**. Las validaciones exitosas resultan en la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, ubicado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es central para establecer la confianza en la autenticación por certificado.

### Autenticación de Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras, donde durante un handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapeo de un certificado a una cuenta de AD puede implicar la función de Kerberos **S4U2Self** o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.

### Enumeración de AD Certificate Services

Los servicios de certificados de AD pueden enumerarse mediante consultas LDAP, revelando información sobre **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Esto es accesible para cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se usan para la enumeración y evaluación de vulnerabilidades en entornos AD CS.

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

## Vulnerabilidades recientes y actualizaciones de seguridad (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* por suplantación de certificados de cuentas de máquina durante PKINIT. | El parche está incluido en las actualizaciones de seguridad del **10 de mayo de 2022**. Se introdujeron controles de auditoría y de mapeo fuerte vía **KB5014754**; los entornos deberían ahora estar en modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* en los roles AD CS Web Enrollment (certsrv) y CES. | Los PoC públicos son limitados, pero los componentes vulnerables de IIS suelen estar expuestos internamente. Parche disponible desde el Patch Tuesday de **julio de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | En plantillas **v1**, un requester con derechos de enrollment puede incrustar **Application Policies/EKUs** en el CSR que prevalecen sobre los EKU de la plantilla, produciendo certificados de client-auth, enrollment agent, o code-signing. | Parcheado desde **12 de noviembre de 2024**. Reemplazar o sobrescribir plantillas v1 (p. ej., default WebServer), restringir los EKU a su intención y limitar los derechos de enrollment. |

### Microsoft hardening timeline (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para alejar la autenticación de certificados Kerberos de mapeos implícitos débiles. A partir del **11 de febrero de 2025**, los domain controllers cambian automáticamente a **Full Enforcement** si el valor de registro `StrongCertificateBindingEnforcement` no está establecido. Los administradores deben:

1. Parchear todos los DCs y servidores AD CS (May 2022 o posterior).
2. Monitorizar Event ID 39/41 para mapeos débiles durante la fase *Audit*.
3. Reemitir certificados client-auth con la nueva **SID extension** o configurar mapeos fuertes manuales antes de febrero de 2025.

---

## Detección y mejoras de hardening

* **Defender for Identity AD CS sensor (2023-2024)** ahora muestra evaluaciones de postura para ESC1-ESC8/ESC11 y genera alertas en tiempo real como *“Domain-controller certificate issuance for a non-DC”* (ESC8) y *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Asegurar que los sensores estén desplegados en todos los servidores AD CS para beneficiarse de estas detecciones.
* Deshabilitar o restringir fuertemente la opción **“Supply in the request”** en todas las plantillas; preferir valores SAN/EKU explícitamente definidos.
* Eliminar **Any Purpose** o **No EKU** de las plantillas salvo que sean absolutamente necesarios (atiende escenarios ESC2).
* Requerir aprobación del responsable o flujos de Enrollment Agent dedicados para plantillas sensibles (p. ej., WebServer / CodeSigning).
* Restringir web enrollment (`certsrv`) y los endpoints CES/NDES a redes de confianza o detrás de autenticación por certificado de cliente.
* Forzar el cifrado de enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). La flag **está activada por defecto**, pero a menudo se deshabilita para clientes legacy, lo que reabre el riesgo de relay.
* Asegurar los **IIS-based enrollment endpoints** (CES/Certsrv): deshabilitar NTLM cuando sea posible o requerir HTTPS + Extended Protection para bloquear relays ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
