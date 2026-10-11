# Certificados AD

{{#include ../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica quién es su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, indica el período durante el cual el certificado es válido.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** es la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite añadir nombres para el sujeto, lo que aporta flexibilidad a la identificación.
- **Basic Constraints** indica si el certificado es para una CA o una entidad final, y define restricciones de uso.
- **Extended Key Usages (EKUs)** definen los propósitos específicos del certificado, como la firma de código o el cifrado de correo electrónico, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método utilizado para firmar el certificado.
- La **Signature**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.<sup>[[4]](#references)</sup>

### Consideraciones especiales

- Los **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a varias identidades, algo crucial para los servidores con varios dominios. Es fundamental que los procesos de emisión sean seguros para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA de un bosque de AD mediante contenedores específicos, cada uno con una función distinta:<sup>[[4]](#references)</sup>

- El contenedor **Certification Authorities** contiene certificados de CA raíz de confianza.
- El contenedor **Enrolment Services** describe las Enterprise CAs y sus plantillas de certificado.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para la autenticación de AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados con certificados intermedios y de CA cruzada.

### Obtención de certificados: flujo de solicitud de certificados del cliente

1. El proceso de solicitud comienza cuando los clientes buscan una Enterprise CA.
2. Tras generar un par de claves pública y privada, se crea una CSR que contiene una clave pública y otros detalles.
3. La CA evalúa la CSR según las plantillas de certificado disponibles y emite el certificado de acuerdo con los permisos de la plantilla.
4. Tras aprobarla, la CA firma el certificado con su clave privada y se lo devuelve al cliente.<sup>[[4]](#references)</sup>

### Plantillas de certificado

Definidas en AD, estas plantillas especifican la configuración y los permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de inscripción o modificación. Son esenciales para gestionar el acceso a los servicios de certificados.<sup>[[4]](#references)</sup>

**La versión del esquema de la plantilla es importante.** Las plantillas **v1** heredadas (por ejemplo, la plantilla integrada **WebServer**) carecen de varios controles de cumplimiento modernos. La investigación sobre **ESC15/EKUwu** demostró que, en las plantillas **v1**, quien realiza la solicitud puede incluir **Application Policies/EKUs** en la CSR, que tienen **preferencia sobre** los EKUs configurados en la plantilla. Esto permite obtener certificados de client-auth, enrollment agent o code-signing con solo tener derechos de inscripción. Es preferible usar plantillas **v2/v3**, eliminar o reemplazar las plantillas v1 predeterminadas y limitar estrictamente los EKUs al propósito previsto.<sup>[[1]](#references)</sup>

## Inscripción de certificados

El proceso de inscripción de certificados comienza cuando un administrador **crea una plantilla de certificado**, que luego una Enterprise Certificate Authority (CA) **publica**. Esto hace que la plantilla esté disponible para que los clientes se inscriban. Para ello, se añade el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.<sup>[[4]](#references)</sup>

Para que un cliente solicite un certificado, deben concedérsele **derechos de inscripción**. Estos derechos se definen mediante descriptores de seguridad en la plantilla de certificado y en la propia Enterprise CA. Para que la solicitud tenga éxito, deben concederse permisos en ambas ubicaciones.

### Derechos de inscripción de la plantilla

Estos derechos se especifican mediante Access Control Entries (ACEs), que detallan permisos como:

- Los derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUID específicos.
- **ExtendedRights**, que permite todos los permisos extendidos.
- **FullControl/GenericAll**, que proporciona control total sobre la plantilla.

### Derechos de inscripción de Enterprise CA

Los derechos de la CA se describen en su descriptor de seguridad, al que se puede acceder desde la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten el acceso remoto a usuarios con pocos privilegios, lo que puede suponer un problema de seguridad.

### Controles de emisión adicionales

Se pueden aplicar ciertos controles, como:

- **Aprobación del administrador**: deja las solicitudes pendientes hasta que las aprueba un administrador de certificados.
- **Agentes de inscripción y firmas autorizadas**: especifican el número de firmas necesarias en una CSR y los OIDs de Application Policy requeridos.

### Métodos para solicitar certificados

Se pueden solicitar certificados mediante:

1. El **Windows Client Certificate Enrollment Protocol** (MS-WCCE), que utiliza interfaces DCOM.
2. El **ICertPassage Remote Protocol** (MS-ICPR), mediante named pipes o TCP/IP.
3. La **interfaz web de inscripción de certificados**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), junto con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, mediante el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados mediante la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticación de certificados

Active Directory (AD) admite la autenticación con certificados, principalmente mediante los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para obtener un Ticket Granting Ticket (TGT) se firma con la **clave privada** del certificado del usuario. El controlador de dominio realiza varias validaciones de esta solicitud, entre ellas, la **validez**, la **ruta** y el estado de **revocación** del certificado. Las validaciones también incluyen comprobar que el certificado provenga de una fuente de confianza y confirmar que el emisor esté presente en el **almacén de certificados NTAUTH**. Si las validaciones se realizan correctamente, se emite un TGT. El objeto **`NTAuthCertificates`** de AD se encuentra en:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

es fundamental para establecer la confianza en la autenticación de certificados.<sup>[[4]](#references)</sup>

Desde el despliegue de **KB5014754**, la autenticación moderna de Kerberos mediante certificados depende principalmente de la **robustez del mapeo**, no solo de los EKU.<sup>[[2]](#references)</sup> En los bosques reforzados:

- Un certificado que solo incluya un **UPN/DNS SAN** puede dejar de ser suficiente para iniciar sesión.
- El KDC prefiere un **strong binding**, normalmente la **extensión de seguridad SID** (`1.3.6.1.4.1.311.25.2`) o un mapeo explícito sólido en `altSecurityIdentities`.
- Si el certificado no tiene un mapeo sólido, los DC registran **Kdcsvc Event ID 39/41** en modo de compatibilidad y deniegan la autenticación en modo de cumplimiento.
- En rutas de ataque mixtas, **ESC9/ESC16** son importantes porque eliminan la extensión SID de los certificados emitidos; entonces, los operadores recurren a mapeos explícitos o a formatos de SID en URL SAN cuando la ruta de ataque lo permite.

### Autenticación mediante Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras. Durante el handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapeo de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.<sup>[[4]](#references)</sup>

Schannel también es la alternativa práctica cuando **PKINIT** no está disponible. Por ejemplo, si un controlador de dominio no tiene un certificado adecuado de **Smart Card Logon**, las herramientas `certipy auth`/PKINIT pueden fallar al intentar obtener un TGT, pero el mismo certificado puede seguir siendo útil para autenticarse y realizar operaciones LDAP mediante **LDAPS** o **LDAP StartTLS**.

### Enumeración de AD Certificate Services

Los servicios de certificados de AD se pueden enumerar mediante consultas LDAP, que revelan información sobre las **Enterprise Certificate Authorities (CA)** y sus configuraciones. Cualquier usuario autenticado en el dominio puede acceder a esta información sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para enumerar y evaluar vulnerabilidades en entornos AD CS.

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

| Año | ID / Nombre | Impacto | Conclusiones clave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalada de privilegios* mediante la suplantación de certificados de cuentas de equipo durante PKINIT. | El parche está incluido en las actualizaciones de seguridad del **10 de mayo de 2022**. Los controles de auditoría y de asignación segura se introdujeron mediante **KB5014754**; los entornos ya deberían estar en modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Ejecución remota de código* en los roles AD CS Web Enrollment (certsrv) y CES. | Los PoC públicos son limitados, pero los componentes IIS vulnerables suelen estar expuestos internamente. Aplicar el parche publicado en el Patch Tuesday de **julio de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | En las plantillas **v1**, un solicitante con derechos de inscripción puede insertar **Application Policies/EKUs** en la CSR, que tienen prioridad sobre los EKU de la plantilla, lo que permite obtener certificados de autenticación de cliente, de agente de inscripción o de firma de código. | Corregido el **12 de noviembre de 2024**. Reemplazar las plantillas v1 o crear otras que las sustituyan (por ejemplo, WebServer predeterminada), restringir los EKU según su finalidad y limitar los derechos de inscripción. |

### Cronología del refuerzo de seguridad de Microsoft (KB5014754)

Microsoft introdujo un despliegue en tres fases (Compatibility → Audit → Enforcement) para dejar de usar asignaciones implícitas débiles en la autenticación de certificados Kerberos. A partir del **11 de febrero de 2025**, los controladores de dominio cambian automáticamente a **Full Enforcement** si el valor de registro `StrongCertificateBindingEnforcement` no está configurado. Más adelante, Microsoft actualizó el cronograma para permitir volver al modo de compatibilidad hasta la actualización de seguridad del **9 de septiembre de 2025**.<sup>[[2]](#references)</sup> Los administradores deberían:

1. Aplicar los parches a todos los DC y servidores AD CS (de mayo de 2022 o posteriores).
2. Supervisar los eventos con ID 39/41 para detectar asignaciones débiles durante la fase *Audit*.
3. Volver a emitir los certificados de autenticación de cliente con la nueva **extensión SID** o configurar asignaciones manuales seguras antes de que la aplicación obligatoria bloquee las asignaciones débiles.

### Notas para operadores de bosques reforzados

- **ESC1/ESC6 por sí solos ya no cuentan toda la historia** en entornos de 2025 en adelante. Si solicitas un certificado para otra entidad de seguridad, normalmente también necesitas un elemento de asignación segura, como la extensión SID o una asignación explícita.
- **ESC15 (EKUwu)** es principalmente útil en entornos sin parchear, ya que convierte plantillas **v1** aparentemente inofensivas, como **WebServer**, en certificados capaces de autenticar o actuar como agentes de inscripción mediante la inyección de **Application Policies**. Kerberos PKINIT sigue evaluando los EKU, pero **LDAP Schannel** también aplica las Application Policies, por lo que el abuso basado en LDAP sigue siendo relevante.<sup>[[1]](#references)</sup>
- **ESC16** es una configuración de ámbito de CA: si la CA deshabilita globalmente la extensión de seguridad SID, todos los certificados emitidos vuelven a depender de un comportamiento de asignación más débil, salvo que la cadena de ataque inyecte un SID mediante otro formato compatible.
- **Los derechos ESC7 son distintos:** una concesión de `ManageCA` en la CA puede permitir cambiar configuraciones como `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), mientras que `ManageCertificates` controla la aprobación de solicitudes. Una denegación explícita de derechos de administrador de certificados puede bloquear esa vía de aprobación aunque también exista una regla de permisos Allow; evalúa la ACL efectiva de la CA antes de combinar configuraciones y plantillas. Consulta [la evaluación de ACL de CA de Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Mejoras de detección y refuerzo de seguridad

* El **sensor AD CS de Defender for Identity (2023-2024)** ahora muestra evaluaciones del nivel de seguridad para ESC1-ESC8/ESC11 y genera alertas en tiempo real, como *“Emisión de certificados de controlador de dominio para una entidad que no es un DC”* (ESC8) y *“Impedir la inscripción de certificados con Application Policies arbitrarias”* (ESC15). Asegúrate de implementar sensores en todos los servidores AD CS para aprovechar estas detecciones.<sup>[[3]](#references)</sup>
* Deshabilita o limita estrictamente la opción **“Supply in the request”** en todas las plantillas; es preferible definir explícitamente los valores SAN/EKU.
* Elimina **Any Purpose** o **No EKU** de las plantillas, salvo que sean absolutamente necesarios (mitiga escenarios ESC2).
* Exige la **aprobación del administrador** o flujos de trabajo específicos de Enrollment Agent para las plantillas sensibles (por ejemplo, WebServer / CodeSigning).
* Restringe la inscripción web (`certsrv`) y los endpoints CES/NDES a redes de confianza o protégelos mediante autenticación con certificados de cliente.
* Exige el cifrado de inscripción RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (relay RPC). La opción está **habilitada de forma predeterminada**, pero a menudo se deshabilita para clientes heredados, lo que vuelve a abrir el riesgo de relay.
* Protege los **endpoints de inscripción basados en IIS** (CES/Certsrv): deshabilita NTLM cuando sea posible o exige HTTPS + Extended Protection para bloquear los relays ESC8.

Evalúa ESC11 en el host que ejecuta la CA, que puede ser un servidor miembro del dominio y no un controlador de dominio. Lee `InterfaceFlags` de la CA activa en `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; si el valor no se puede leer o no existe, el resultado es desconocido, no una prueba de que el cifrado RPC esté deshabilitado. La ausencia del bit `IF_ENFORCEENCRYPTICERTREQUEST` indica una posible configuración problemática, pero aún se necesitan un endpoint de inscripción RPC accesible, credenciales que puedan ser forzadas y una plantilla de certificado utilizable. Para ESC8, un desafío HTTP NTLM por sí solo no basta: confirma que existe un endpoint de inscripción operativo.

---

## References

- [1] [EKUwu: no es otro ESC de AD CS más](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Cambios en la autenticación basada en certificados en los controladores de dominio de Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Evaluaciones del nivel de seguridad de los certificados - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: abuso de Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
