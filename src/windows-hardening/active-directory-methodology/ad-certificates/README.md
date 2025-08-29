# Certificados AD

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica su propietario.
- Una **Public Key** está emparejada con una clave privada para vincular el certificado con su legítimo propietario.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** se refiere a la CA que emitió el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el subject, aumentando la flexibilidad de identificación.
- **Basic Constraints** identifican si el certificado es para una CA o una entidad final y definen restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como code signing o email encryption, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método para firmar el certificado.
- La **Signature**, creada con la clave privada del issuer, garantiza la autenticidad del certificado.

### Consideraciones especiales

- **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, crucial para servidores con múltiples dominios. Procesos de emisión seguros son vitales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce certificados de CA en un forest de AD mediante contenedores designados, cada uno con roles específicos:

- El contenedor **Certification Authorities** almacena certificados de root CA de confianza.
- El contenedor **Enrolment Services** detalla las Enterprise CAs y sus certificate templates.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para autenticación en AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados con certificados intermedios y cross CA.

### Adquisición de certificados: Flujo de solicitud de certificado

1. El proceso de solicitud comienza con los clientes buscando una Enterprise CA.
2. Se crea un CSR, que contiene una public key y otros detalles, tras generar un par de claves pública-privada.
3. La CA evalúa el CSR frente a los certificate templates disponibles, emitiendo el certificado según los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.

### Certificate Templates

Definidas dentro de AD, estas plantillas describen las configuraciones y permisos para emitir certificados, incluyendo EKUs permitidos y derechos de enrollment o modificación, críticos para gestionar el acceso a los servicios de certificados.

## Inscripción de certificados

El proceso de inscripción de certificados lo inicia un administrador que **crea un certificate template**, el cual es **publicado** por una Enterprise Certificate Authority (CA). Esto hace la plantilla disponible para el enrollment de clientes, un paso que se logra añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.

Para que un cliente solicite un certificado, deben concederse **enrollment rights**. Estos derechos se definen mediante security descriptors en el certificate template y en la Enterprise CA misma. Deben concederse permisos en ambos lugares para que la solicitud tenga éxito.

### Derechos de inscripción de la plantilla

Estos derechos se especifican mediante Access Control Entries (ACEs), detallando permisos como:

- Los derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado con GUIDs específicos.
- **ExtendedRights**, que permiten todos los permisos extendidos.
- **FullControl/GenericAll**, que proporcionan control completo sobre la plantilla.

### Derechos de inscripción de la Enterprise CA

Los derechos de la CA están descritos en su security descriptor, accesible a través de la consola de administración Certificate Authority. Algunas configuraciones incluso permiten que usuarios de bajos privilegios accedan de forma remota, lo que puede ser una preocupación de seguridad.

### Controles adicionales de emisión

Pueden aplicarse ciertos controles, como:

- **Manager Approval**: coloca las solicitudes en estado pendiente hasta que un certificate manager las apruebe.
- **Enrolment Agents and Authorized Signatures**: especifican el número de firmas requeridas en un CSR y los Application Policy OIDs necesarios.

### Métodos para solicitar certificados

Los certificados se pueden solicitar a través de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), mediante named pipes o TCP/IP.
3. La **certificate enrollment web interface**, con el rol Certificate Authority Web Enrollment instalado.
4. El **Certificate Enrollment Service** (CES), en conjunto con el servicio Certificate Enrollment Policy (CEP).
5. El **Network Device Enrollment Service** (NDES) para dispositivos de red, usando el Simple Certificate Enrollment Protocol (SCEP).

Los usuarios de Windows también pueden solicitar certificados vía la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando Get-Certificate de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación con certificados

Active Directory (AD) admite la autenticación mediante certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para un Ticket Granting Ticket (TGT) se firma usando la **clave privada** del certificado del usuario. Esta solicitud pasa por varias validaciones realizadas por el controlador de dominio, incluyendo la **validez**, la **ruta** y el **estado de revocación** del certificado. Las validaciones también incluyen verificar que el certificado provenga de una fuente de confianza y confirmar la presencia del emisor en el **almacén de certificados NTAUTH**. Las validaciones exitosas resultan en la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, ubicado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es central para establecer la confianza para la autenticación mediante certificados.

### Autenticación de Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras, donde durante un handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapeo de un certificado a una cuenta de AD puede involucrar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.

### Enumeración de AD Certificate Services

Los servicios de certificados de AD pueden enumerarse mediante consultas LDAP, revelando información sobre **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Esto es accesible para cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se usan para la enumeración y la evaluación de vulnerabilidades en entornos AD CS.

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
