# Certificados AD

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un Certificado

- El **Subject** del certificado indica su propietario.
- Una **Public Key** está emparejada con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Autoridad de Certificación (CA), identifica cada certificado.
- El **Issuer** se refiere a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el sujeto, mejorando la flexibilidad de identificación.
- **Basic Constraints** identifican si el certificado es para una CA o una entidad final y definen restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como code signing o email encryption, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método para firmar el certificado.
- La **Signature**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.

### Consideraciones Especiales

- **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, crucial para servidores con múltiples dominios. Procesos de emisión seguros son vitales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.

### Autoridades de Certificación (CAs) en Active Directory (AD)

AD CS reconoce certificados de CA en un bosque de Active Directory mediante contenedores designados, cada uno con roles únicos:

- **Certification Authorities** container contiene certificados de CA raíz de confianza.
- **Enrolment Services** container detalla Enterprise CAs y sus certificate templates.
- **NTAuthCertificates** object incluye certificados de CA autorizados para autenticación en AD.
- **AIA (Authority Information Access)** container facilita la validación de la cadena de certificados con certificados intermedios y cross CA.

### Adquisición de Certificados: Flujo de Solicitud de Certificado del Cliente

1. El proceso de solicitud comienza con que los clientes encuentren una Enterprise CA.
2. Se crea un CSR que contiene una clave pública y otros detalles, después de generar un par de claves pública-privada.
3. La CA evalúa el CSR contra los certificate templates disponibles, emitiendo el certificado según los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.

### Certificate Templates

Definidas dentro de AD, estas plantillas delinean la configuración y permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de enrollment o modificación, críticos para gestionar el acceso a los servicios de certificado.

## Certificate Enrollment

El proceso de enrollment para certificados es iniciado por un administrador que **crea un certificate template**, y luego es **publicado** por una Enterprise Certificate Authority (CA). Esto hace la plantilla disponible para el enrollment de clientes, un paso logrado añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.

Para que un cliente solicite un certificado, deben concederse **enrollment rights**. Estos derechos están definidos por los security descriptors en el certificate template y en la propia Enterprise CA. Los permisos deben concederse en ambas ubicaciones para que una solicitud sea exitosa.

### Template Enrollment Rights

Estos derechos se especifican mediante Access Control Entries (ACEs), detallando permisos como:

- **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado con GUIDs específicos.
- **ExtendedRights**, permitiendo todos los permisos extendidos.
- **FullControl/GenericAll**, proporcionando control completo sobre la plantilla.

### Enterprise CA Enrollment Rights

Los derechos de la CA se describen en su security descriptor, accesible vía la consola de administración de la Certificate Authority. Algunas configuraciones incluso permiten que usuarios con pocos privilegios accedan de forma remota, lo cual podría ser un problema de seguridad.

### Controles Adicionales de Emisión

Pueden aplicarse ciertos controles, como:

- **Manager Approval**: Coloca las solicitudes en estado pendiente hasta que sean aprobadas por un certificate manager.
- **Enrolment Agents and Authorized Signatures**: Especifican el número de firmas requeridas en un CSR y los Application Policy OIDs necesarios.

### Métodos para Solicitar Certificados

Los certificados pueden solicitarse a través de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), a través de named pipes o TCP/IP.
3. La interfaz web de certificate enrollment, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), junto con el servicio **Certificate Enrollment Policy** (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, usando el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados vía la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación de certificados

Active Directory (AD) admite la autenticación mediante certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para un Ticket Granting Ticket (TGT) se firma usando la **clave privada** del certificado del usuario. Dicha solicitud pasa por varias validaciones por parte del controlador de dominio, incluyendo la **validez**, la **ruta** y el **estado de revocación** del certificado. Las validaciones también incluyen verificar que el certificado proviene de una fuente de confianza y confirmar la presencia del emisor en el **NTAUTH certificate store**. Las validaciones exitosas resultan en la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, ubicado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es fundamental para establecer la confianza en la autenticación mediante certificados.

### Secure Channel (Schannel) Authentication

Schannel facilita conexiones TLS/SSL seguras, donde durante el handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapeo de un certificado a una cuenta de AD puede implicar la función de Kerberos **S4U2Self** o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.

### AD Certificate Services Enumeration

Los servicios de certificados de AD pueden enumerarse mediante consultas LDAP, revelando información sobre las **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Esto es accesible por cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se usan para la enumeración y la evaluación de vulnerabilidades en entornos AD CS.

Los comandos para usar estas herramientas incluyen:
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
## Referencias

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
