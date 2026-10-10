# Certificados de AD

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica quién es su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, determina el período de vigencia del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** hace referencia a la CA que emitió el certificado.
- **SubjectAlternativeName** permite añadir nombres para el sujeto, lo que aporta flexibilidad a la identificación.
- **Basic Constraints** indica si el certificado es para una CA o una entidad final, y define las restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los fines específicos del certificado, como la firma de código o el cifrado de correo electrónico, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método utilizado para firmar el certificado.
- La **Signature**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.<sup>[[4]](#references)</sup>

### Consideraciones especiales

- Los **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a varias identidades, algo crucial para servidores con varios dominios. Los procesos seguros de emisión son esenciales para evitar el riesgo de suplantación por parte de atacantes que manipulen la especificación SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA de un bosque de AD mediante contenedores específicos, cada uno con una función distinta:<sup>[[4]](#references)</sup>

- El contenedor **Certification Authorities** contiene certificados de confianza de las CA raíz.
- El contenedor **Enrolment Services** detalla las CA empresariales y sus plantillas de certificado.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para la autenticación de AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados mediante certificados intermedios y de CA cruzadas.

### Obtención de certificados: flujo de solicitud de certificado del cliente

1. El proceso de solicitud comienza cuando los clientes buscan una CA empresarial.
2. Tras generar un par de claves pública y privada, se crea una CSR que contiene una clave pública y otros datos.
3. La CA evalúa la CSR con las plantillas de certificado disponibles y emite el certificado según los permisos de la plantilla.
4. Una vez aprobada, la CA firma el certificado con su clave privada y se lo devuelve al cliente.<sup>[[4]](#references)</sup>

### Plantillas de certificado

Estas plantillas, definidas en AD, especifican la configuración y los permisos para emitir certificados, incluidos los EKU permitidos y los derechos de inscripción o modificación, que son fundamentales para administrar el acceso a los servicios de certificados.<sup>[[4]](#references)</sup>

**La versión del esquema de la plantilla es importante.** Las plantillas heredadas **v1** (por ejemplo, la plantilla integrada **WebServer**) carecen de varios controles de aplicación modernos. La investigación sobre **ESC15/EKUwu** demostró que, en las plantillas **v1**, quien solicita el certificado puede incluir **Application Policies/EKUs** en la CSR, que tienen **preferencia sobre** los EKU configurados en la plantilla. Esto permite obtener certificados de autenticación de cliente, de agente de inscripción o de firma de código con solo derechos de inscripción. Se recomienda usar plantillas **v2/v3**, quitar o reemplazar las plantillas v1 predeterminadas y limitar estrictamente los EKU al fin previsto.<sup>[[1]](#references)</sup>

## Inscripción de certificados

El proceso de inscripción de certificados lo inicia un administrador, que **crea una plantilla de certificado** que luego **publica** una Enterprise Certificate Authority (CA). Así, la plantilla queda disponible para que los clientes se inscriban. Para ello, se añade el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.<sup>[[4]](#references)</sup>

Para que un cliente solicite un certificado, se le deben conceder **derechos de inscripción**. Estos derechos se definen mediante descriptores de seguridad en la plantilla de certificado y en la propia CA empresarial. Para que una solicitud se complete correctamente, se deben conceder permisos en ambas ubicaciones.

### Derechos de inscripción de plantillas

Estos derechos se especifican mediante Access Control Entries (ACEs), que detallan permisos como:

- Los derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUID específicos.
- **ExtendedRights**, que permite todos los permisos extendidos.
- **FullControl/GenericAll**, que proporciona control total sobre la plantilla.

### Derechos de inscripción de la CA empresarial

Los derechos de la CA se especifican en su descriptor de seguridad, al que se puede acceder desde la consola de administración de Certificate Authority. Algunos ajustes incluso permiten el acceso remoto a usuarios con pocos privilegios, lo que podría suponer un riesgo de seguridad.

### Controles adicionales de emisión

Pueden aplicarse ciertos controles, como:

- **Manager Approval**: deja las solicitudes pendientes hasta que las apruebe un administrador de certificados.
- **Enrolment Agents and Authorized Signatures**: especifica el número de firmas requeridas en una CSR y los OID de Application Policy necesarios.

### Métodos para solicitar certificados

Los certificados se pueden solicitar mediante:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), mediante interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), mediante named pipes o TCP/IP.
3. La **interfaz web de inscripción de certificados**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), junto con el servicio Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) para dispositivos de red, mediante Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados mediante la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticación mediante certificados

Active Directory (AD) admite la autenticación mediante certificados, principalmente mediante los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

Durante el proceso de autenticación Kerberos, la solicitud de un usuario para obtener un Ticket Granting Ticket (TGT) se firma con la **clave privada** del certificado del usuario. El controlador de dominio somete esta solicitud a varias validaciones, entre ellas la **validez**, la **cadena de certificación** y el estado de revocación del certificado. Las validaciones también incluyen comprobar que el certificado provenga de una fuente de confianza y confirmar que el emisor esté presente en el **almacén de certificados NTAUTH**. Si las validaciones se realizan correctamente, se emite un TGT. El objeto **`NTAuthCertificates`** de AD se encuentra en:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

es fundamental para establecer la confianza en la autenticación mediante certificados.<sup>[[4]](#references)</sup>

Desde el despliegue de **KB5014754**, la autenticación moderna de Kerberos mediante certificados depende principalmente de la **solidez de la asignación**, no solo de los EKU.<sup>[[2]](#references)</sup> En bosques reforzados:

- Puede que un certificado que solo incluya un **UPN/DNS SAN** ya no sea suficiente para iniciar sesión.
- El KDC prefiere una **vinculación sólida**, normalmente la **extensión de seguridad SID** (`1.3.6.1.4.1.311.25.2`) o una asignación explícita sólida en `altSecurityIdentities`.
- Si el certificado no tiene una asignación sólida, los DC registran **Kdcsvc Event ID 39/41** en modo de compatibilidad y deniegan la autenticación en modo de cumplimiento.
- En rutas de ataque mixtas, **ESC9/ESC16** son importantes porque eliminan la extensión SID de los certificados emitidos; luego, los operadores recurren a asignaciones explícitas o a formatos de SID de SAN URL cuando la ruta de ataque lo permite.

### Autenticación de canal seguro (Schannel)

Schannel facilita conexiones TLS/SSL seguras. Durante el handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. La asignación de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.<sup>[[4]](#references)</sup>

Schannel también es la alternativa práctica cuando **PKINIT** no está disponible. Por ejemplo, si un controlador de dominio no tiene un certificado adecuado de **Smart Card Logon**, las herramientas `certipy auth`/PKINIT pueden no conseguir un TGT, pero el mismo certificado puede seguir siendo válido para autenticarse y realizar operaciones LDAP mediante **LDAPS** o **LDAP StartTLS**.

### Enumeración de AD Certificate Services

Los servicios de certificados de AD se pueden enumerar mediante consultas LDAP, que revelan información sobre las **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Cualquier usuario autenticado en el dominio puede acceder a esta información sin privilegios especiales. Se utilizan herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** para la enumeración y la evaluación de vulnerabilidades en entornos AD CS.

Entre los comandos para utilizar estas herramientas se incluyen:

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

| Año | ID / Nombre | Impacto | Conclusiones clave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* mediante la suplantación de certificados de cuentas de equipo durante PKINIT. | El parche está incluido en las actualizaciones de seguridad del **10 de mayo de 2022**. Los controles de auditoría y strong-mapping se introdujeron mediante **KB5014754**; los entornos ahora deberían estar en modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* en los roles de AD CS Web Enrollment (certsrv) y CES. | Los PoC públicos son limitados, pero los componentes IIS vulnerables suelen estar expuestos internamente. Se corrigió en el Patch Tuesday de **julio de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | En las **plantillas v1**, un solicitante con derechos de inscripción puede incluir **Application Policies/EKUs** en el CSR, que tienen prioridad sobre los EKU de la plantilla, y obtener certificados de autenticación de cliente, de agente de inscripción o de firma de código. | Corregido a partir del **12 de noviembre de 2024**. Reemplace o sustituya las plantillas v1 (p. ej., WebServer predeterminada), restrinja los EKU según su propósito y limite los derechos de inscripción. |

### Cronología del hardening de Microsoft (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para alejar la autenticación de certificados Kerberos de las asignaciones implícitas débiles. A partir del **11 de febrero de 2025**, los controladores de dominio cambian automáticamente a **Full Enforcement** si el valor del registro `StrongCertificateBindingEnforcement` no está establecido. Posteriormente, Microsoft actualizó la cronología para que sea posible volver al modo de compatibilidad hasta la actualización de seguridad del **9 de septiembre de 2025**.<sup>[[2]](#references)</sup> Los administradores deberían:

1. Aplicar los parches a todos los DC y servidores AD CS (de mayo de 2022 o posteriores).
2. Supervisar los eventos ID 39/41 para detectar asignaciones débiles durante la fase *Audit*.
3. Volver a emitir los certificados de autenticación de cliente con la nueva **extensión SID** o configurar asignaciones manuales sólidas antes de que la aplicación de la directiva bloquee las asignaciones débiles.

### Notas para operadores de bosques reforzados

- **ESC1/ESC6 por sí solos ya no cuentan toda la historia** en entornos de 2025 en adelante. Si solicita un certificado para otra entidad principal, normalmente también necesita un artefacto de asignación sólida, como la extensión SID o una asignación explícita.
- **ESC15 (EKUwu)** es útil sobre todo en entornos sin parchear, porque convierte plantillas **v1** aparentemente inofensivas, como **WebServer**, en certificados capaces de autenticación o de actuar como agente de inscripción mediante la inyección de **Application Policies**. Kerberos PKINIT sigue evaluando los EKU, pero **LDAP Schannel** también respeta las Application Policies, por lo que el abuso basado en LDAP sigue siendo relevante.<sup>[[1]](#references)</sup>
- **ESC16** es una configuración que afecta a toda la CA: si la CA deshabilita globalmente la extensión de seguridad SID, todos los certificados emitidos vuelven a un comportamiento de asignación más débil, a menos que la cadena de ataque inyecte un SID mediante otro formato compatible.
- **Los derechos ESC7 son distintos:** un permiso `ManageCA` en la CA puede permitir cambios en opciones como `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), mientras que `ManageCertificates` controla la aprobación de solicitudes. Una denegación explícita de los derechos de administrador de certificados puede bloquear esa vía de aprobación incluso si también existe un permiso Allow; evalúe la ACL efectiva de la CA antes de encadenar configuraciones y plantillas. Consulte [la evaluación de ACL de CA de Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Mejoras en la detección y el hardening

* El sensor AD CS de **Defender for Identity (2023-2024)** ahora muestra evaluaciones de la postura de seguridad para ESC1-ESC8/ESC11 y genera alertas en tiempo real, como *“Emisión de certificados de controlador de dominio para una entidad que no es un DC”* (ESC8) y *“Impedir la inscripción de certificados con Application Policies arbitrarias”* (ESC15). Asegúrese de implementar sensores en todos los servidores AD CS para aprovechar estas detecciones.<sup>[[3]](#references)</sup>
* Deshabilite o limite estrictamente la opción **“Supply in the request”** en todas las plantillas; prefiera valores SAN/EKU definidos explícitamente.
* Elimine **Any Purpose** o **No EKU** de las plantillas, salvo que sean absolutamente necesarios (aborda los escenarios ESC2).
* Exija la **aprobación del administrador** o flujos de trabajo específicos de Enrollment Agent para las plantillas sensibles (p. ej., WebServer / CodeSigning).
* Restrinja la inscripción web (`certsrv`) y los endpoints CES/NDES a redes de confianza o detrás de la autenticación con certificados de cliente.
* Aplique el cifrado de inscripción RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). La opción está **activada de forma predeterminada**, pero a menudo se deshabilita para clientes heredados, lo que vuelve a abrir el riesgo de relay.
* Proteja los **endpoints de inscripción basados en IIS** (CES/Certsrv): deshabilite NTLM cuando sea posible o exija HTTPS + Extended Protection para bloquear los ataques de relay ESC8.

Evalúe ESC11 en el host que ejecuta la CA, que puede ser un servidor miembro del dominio y no un controlador de dominio. Lea `InterfaceFlags` de la CA activa en `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; si el valor no se puede leer o no existe, el resultado es desconocido, no una prueba de que el cifrado RPC esté deshabilitado. Que el bit `IF_ENFORCEENCRYPTICERTREQUEST` esté desactivado es una pista de configuración que aún requiere un endpoint de inscripción RPC accesible, credenciales que puedan forzarse y una plantilla de certificado utilizable. Para ESC8, un desafío HTTP NTLM por sí solo no es suficiente: confirme que exista un endpoint de inscripción funcional.

---

## References

- [1] [EKUwu: No es otro ESC de AD CS más](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Cambios en la autenticación basada en certificados en los controladores de dominio de Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Evaluaciones de la postura de seguridad de los certificados - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abuso de Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
