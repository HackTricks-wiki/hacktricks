# Certificados de AD

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado indica su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** hace referencia a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el subject, mejorando la flexibilidad de identificación.
- **Basic Constraints** identifica si el certificado es para una CA o una entidad final, y define las restricciones de uso.
- Los **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como la firma de código o el cifrado de correo electrónico, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método utilizado para firmar el certificado.
- La **Signature**, creada con la clave privada del issuer, garantiza la autenticidad del certificado.<sup>[[1]](#references)</sup>

### Consideraciones especiales

- Los **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, algo crucial para servidores con varios dominios. Los procesos seguros de emisión son vitales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA en un bosque de AD mediante contenedores designados, cada uno con funciones únicas:<sup>[[1]](#references)</sup>

- El contenedor **Certification Authorities** contiene certificados de CA raíz de confianza.
- El contenedor **Enrolment Services** proporciona información sobre las CAs empresariales y sus plantillas de certificados.
- El objeto **NTAuthCertificates** incluye los certificados de CA autorizados para la autenticación de AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados con certificados intermedios y de CAs cruzadas.

### Adquisición de certificados: flujo de solicitud de certificados del cliente

1. El proceso de solicitud comienza cuando los clientes encuentran una CA empresarial.
2. Se crea una CSR que contiene una clave pública y otros detalles, después de generar un par de claves pública-privada.
3. La CA evalúa la CSR respecto a las plantillas de certificados disponibles y emite el certificado según los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.<sup>[[1]](#references)</sup>

### Plantillas de certificados

Definidas dentro de AD, estas plantillas describen la configuración y los permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de enrollment o modificación, algo fundamental para gestionar el acceso a los servicios de certificados.<sup>[[1]](#references)</sup>

## Inscripción de certificados

El proceso de inscripción de certificados lo inicia un administrador que **crea una plantilla de certificados**, que posteriormente es **publicada** por una Enterprise Certificate Authority (CA). Esto hace que la plantilla esté disponible para la inscripción de clientes, un paso que se consigue añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.<sup>[[1]](#references)</sup>

Para que un cliente pueda solicitar un certificado, deben concederse **derechos de inscripción**. Estos derechos se definen mediante descriptores de seguridad en la plantilla de certificados y en la Enterprise CA. Los permisos deben concederse en ambas ubicaciones para que una solicitud tenga éxito.<sup>[[1]](#references)</sup>

### Derechos de inscripción de plantillas

Estos derechos se especifican mediante Access Control Entries (ACEs), que detallan permisos como:<sup>[[1]](#references)</sup>

- Los derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUIDs específicos.
- **ExtendedRights**, que permite todos los permisos extendidos.
- **FullControl/GenericAll**, que proporciona control total sobre la plantilla.

### Derechos de inscripción de la Enterprise CA

Los derechos de la CA se describen en su descriptor de seguridad, accesible mediante la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten el acceso remoto a usuarios con pocos privilegios, lo que podría suponer un problema de seguridad.<sup>[[1]](#references)</sup>

### Controles adicionales de emisión

Pueden aplicarse ciertos controles, como:<sup>[[1]](#references)</sup>

- **Manager Approval**: coloca las solicitudes en estado pendiente hasta que un administrador de certificados las aprueba.
- **Enrolment Agents and Authorized Signatures**: especifican el número de firmas requeridas en una CSR y los OIDs de Application Policy necesarios.

### Métodos para solicitar certificados

Los certificados pueden solicitarse mediante:<sup>[[1]](#references)</sup>

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

Active Directory (AD) admite la autenticación mediante certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Proceso de autenticación de Kerberos

En el proceso de autenticación de Kerberos, la solicitud de un usuario para obtener un Ticket Granting Ticket (TGT) se firma utilizando la **clave privada** del certificado del usuario. Esta solicitud se somete a varias validaciones por parte del controlador de dominio, incluida la **validez**, la **ruta** y el estado de **revocación** del certificado. Las validaciones también incluyen verificar que el certificado provenga de una fuente de confianza y confirmar la presencia del emisor en el **almacén de certificados NTAUTH**. Las validaciones correctas dan como resultado la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, ubicado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es fundamental para establecer la confianza en la autenticación mediante certificados.<sup>[[1]](#references)</sup>

### Autenticación de Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras; durante un handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso.<sup>[[2]](#references)</sup> El mapeo de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.<sup>[[1]](#references)</sup>

### Enumeración de AD Certificate Services

Los servicios de certificados de AD se pueden enumerar mediante consultas LDAP, revelando información sobre las **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Esto está disponible para cualquier usuario autenticado en el dominio sin privilegios especiales.<sup>[[1]](#references)</sup> Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para la enumeración y la evaluación de vulnerabilidades en entornos de AD CS.<sup>[[3]](#references)</sup>

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
Rubeus también puede utilizar un certificado PFX protegido con contraseña para la autenticación PKINIT y solicitar un TGT. El switch opcional `/getcredentials` solicita un ticket de servicio U2U e intenta recuperar el hash NT de la cuenta:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certificado de segunda mano: abuso de los servicios de certificados de Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [¿Qué es la autenticación de cliente SSL/TLS y cómo funciona?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
