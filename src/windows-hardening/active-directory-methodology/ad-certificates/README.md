# Certificados de AD

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un certificado

- El **Subject** del certificado designa a su propietario.
- Una **Public Key** se empareja con una clave privada para vincular el certificado con su propietario legítimo.
- El **Validity Period**, definido por las fechas **NotBefore** y **NotAfter**, indica la duración efectiva del certificado.
- Un **Serial Number** único, proporcionado por la Certificate Authority (CA), identifica cada certificado.
- El **Issuer** hace referencia a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite añadir nombres adicionales para el subject, lo que aumenta la flexibilidad de identificación.
- **Basic Constraints** indica si el certificado corresponde a una CA o a una entidad final, y define las restricciones de uso.
- **Extended Key Usages (EKUs)** delimitan los propósitos específicos del certificado, como la firma de código o el cifrado de correo electrónico, mediante Object Identifiers (OIDs).
- El **Signature Algorithm** especifica el método utilizado para firmar el certificado.
- La **Signature**, creada con la clave privada del issuer, garantiza la autenticidad del certificado.<sup>[[1]](#references)</sup>

### Consideraciones especiales

- Los **Subject Alternative Names (SANs)** amplían la aplicabilidad de un certificado a varias identidades, algo fundamental para servidores con múltiples dominios. Los procesos de emisión seguros son esenciales para evitar riesgos de suplantación por parte de atacantes que manipulen la especificación SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA en un bosque de AD mediante contenedores designados, cada uno con funciones específicas:<sup>[[1]](#references)</sup>

- El contenedor **Certification Authorities** almacena los certificados de las CA raíz de confianza.
- El contenedor **Enrolment Services** proporciona información sobre las CA Enterprise y sus plantillas de certificados.
- El objeto **NTAuthCertificates** incluye los certificados de CA autorizados para la autenticación de AD.
- El contenedor **AIA (Authority Information Access)** facilita la validación de la cadena de certificados mediante certificados intermedios y de CA cruzadas.

### Adquisición de certificados: flujo de solicitud de certificados del cliente

1. El proceso de solicitud comienza cuando los clientes localizan una CA Enterprise.
2. Se crea una CSR que contiene una clave pública y otros datos después de generar un par de claves pública-privada.
3. La CA evalúa la CSR según las plantillas de certificados disponibles y emite el certificado basándose en los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.<sup>[[1]](#references)</sup>

### Plantillas de certificados

Definidas dentro de AD, estas plantillas describen la configuración y los permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de inscripción o modificación, que son fundamentales para gestionar el acceso a los servicios de certificados.<sup>[[1]](#references)</sup>

## Inscripción de certificados

El proceso de inscripción de certificados lo inicia un administrador que **crea una plantilla de certificado**, que posteriormente es **publicada** por una Certificate Authority (CA) Enterprise. Esto hace que la plantilla esté disponible para la inscripción de clientes, un paso que se logra añadiendo el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.<sup>[[1]](#references)</sup>

Para que un cliente pueda solicitar un certificado, deben concederse **derechos de inscripción**. Estos derechos se definen mediante descriptores de seguridad en la plantilla de certificado y en la propia CA Enterprise. Los permisos deben concederse en ambas ubicaciones para que una solicitud tenga éxito.<sup>[[1]](#references)</sup>

### Derechos de inscripción de plantillas

Estos derechos se especifican mediante Access Control Entries (ACEs), que detallan permisos como los siguientes:<sup>[[1]](#references)</sup>

- Los derechos **Certificate-Enrollment** y **Certificate-AutoEnrollment**, cada uno asociado a GUID específicos.
- **ExtendedRights**, que permite todos los permisos extendidos.
- **FullControl/GenericAll**, que proporciona control total sobre la plantilla.

### Derechos de inscripción de la CA Enterprise

Los derechos de la CA se describen en su descriptor de seguridad, accesible mediante la consola de administración de Certificate Authority. Algunas configuraciones incluso permiten el acceso remoto a usuarios con pocos privilegios, lo que podría suponer un problema de seguridad.<sup>[[1]](#references)</sup>

### Controles de emisión adicionales

Pueden aplicarse ciertos controles, como los siguientes:<sup>[[1]](#references)</sup>

- **Manager Approval**: coloca las solicitudes en estado pendiente hasta que un administrador de certificados las aprueba.
- **Enrolment Agents and Authorized Signatures**: especifica el número de firmas necesarias en una CSR y los OID de Application Policy requeridos.

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

### Proceso de autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un usuario para obtener un Ticket Granting Ticket (TGT) se firma utilizando la **clave privada** del certificado del usuario. Esta solicitud se somete a varias validaciones por parte del controlador de dominio, incluida la **validez**, la **ruta** y el estado de **revocación** del certificado. Las validaciones también incluyen comprobar que el certificado proviene de una fuente de confianza y confirmar la presencia del emisor en el **almacén de certificados NTAUTH**. Las validaciones correctas dan como resultado la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, ubicado en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es fundamental para establecer la confianza en la autenticación mediante certificados.<sup>[[1]](#references)</sup>

### Autenticación mediante Secure Channel (Schannel)

Schannel facilita conexiones TLS/SSL seguras en las que, durante un handshake, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso.<sup>[[2]](#references)</sup> La asignación de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Subject Alternative Name (SAN)** del certificado, entre otros métodos.<sup>[[1]](#references)</sup>

### Enumeración de AD Certificate Services

Los servicios de certificados de AD se pueden enumerar mediante consultas LDAP, lo que revela información sobre las **Enterprise Certificate Authorities (CAs)** y sus configuraciones. Cualquier usuario autenticado en el dominio puede acceder a esta información sin privilegios especiales.<sup>[[1]](#references)</sup> Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para la enumeración y la evaluación de vulnerabilidades en entornos de AD CS.<sup>[[3]](#references)</sup>

Los comandos para utilizar estas herramientas incluyen:
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

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [What Is SSL/TLS Client Authentication & How Does It Work?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
