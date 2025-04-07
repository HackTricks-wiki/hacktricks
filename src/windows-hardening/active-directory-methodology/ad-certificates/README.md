# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

### Componentes de un Certificado

- El **Sujeto** del certificado denota su propietario.
- Una **Clave Pública** se empareja con una clave privada para vincular el certificado a su legítimo propietario.
- El **Período de Validez**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Número de Serie** único, proporcionado por la Autoridad de Certificación (CA), identifica cada certificado.
- El **Emisor** se refiere a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el sujeto, mejorando la flexibilidad de identificación.
- **Restricciones Básicas** identifican si el certificado es para una CA o una entidad final y definen restricciones de uso.
- **Usos de Clave Extendidos (EKUs)** delinean los propósitos específicos del certificado, como la firma de código o la encriptación de correos electrónicos, a través de Identificadores de Objetos (OIDs).
- El **Algoritmo de Firma** especifica el método para firmar el certificado.
- La **Firma**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.

### Consideraciones Especiales

- **Nombres Alternativos del Sujeto (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, crucial para servidores con múltiples dominios. Los procesos de emisión seguros son vitales para evitar riesgos de suplantación por parte de atacantes que manipulan la especificación SAN.

### Autoridades de Certificación (CAs) en Active Directory (AD)

AD CS reconoce los certificados de CA en un bosque de AD a través de contenedores designados, cada uno con roles únicos:

- El contenedor de **Autoridades de Certificación** contiene certificados de CA raíz de confianza.
- El contenedor de **Servicios de Inscripción** detalla las CAs empresariales y sus plantillas de certificados.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para la autenticación de AD.
- El contenedor de **AIA (Acceso a Información de Autoridad)** facilita la validación de la cadena de certificados con certificados de CA intermedios y cruzados.

### Adquisición de Certificados: Flujo de Solicitud de Certificado del Cliente

1. El proceso de solicitud comienza con los clientes encontrando una CA empresarial.
2. Se crea un CSR, que contiene una clave pública y otros detalles, después de generar un par de claves pública-privada.
3. La CA evalúa el CSR contra las plantillas de certificados disponibles, emitiendo el certificado basado en los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y se lo devuelve al cliente.

### Plantillas de Certificados

Definidas dentro de AD, estas plantillas describen la configuración y permisos para emitir certificados, incluyendo EKUs permitidos y derechos de inscripción o modificación, críticos para gestionar el acceso a los servicios de certificados.

## Inscripción de Certificados

El proceso de inscripción para certificados es iniciado por un administrador que **crea una plantilla de certificado**, que luego es **publicada** por una Autoridad de Certificación Empresarial (CA). Esto hace que la plantilla esté disponible para la inscripción del cliente, un paso logrado al agregar el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.

Para que un cliente solicite un certificado, deben otorgarse **derechos de inscripción**. Estos derechos están definidos por descriptores de seguridad en la plantilla de certificado y en la CA empresarial misma. Los permisos deben otorgarse en ambas ubicaciones para que una solicitud sea exitosa.

### Derechos de Inscripción de Plantilla

Estos derechos se especifican a través de Entradas de Control de Acceso (ACEs), detallando permisos como:

- Derechos de **Inscripción de Certificado** y **Autoinscripción de Certificado**, cada uno asociado con GUIDs específicos.
- **Derechos Extendidos**, que permiten todos los permisos extendidos.
- **ControlTotal/GenericAll**, proporcionando control completo sobre la plantilla.

### Derechos de Inscripción de CA Empresarial

Los derechos de la CA están delineados en su descriptor de seguridad, accesible a través de la consola de gestión de la Autoridad de Certificación. Algunas configuraciones incluso permiten a usuarios con bajos privilegios acceso remoto, lo que podría ser una preocupación de seguridad.

### Controles Adicionales de Emisión

Ciertos controles pueden aplicarse, como:

- **Aprobación del Gerente**: Coloca las solicitudes en un estado pendiente hasta que sean aprobadas por un gerente de certificados.
- **Agentes de Inscripción y Firmas Autorizadas**: Especifican el número de firmas requeridas en un CSR y los OIDs de Política de Aplicación necesarios.

### Métodos para Solicitar Certificados

Los certificados se pueden solicitar a través de:

1. **Protocolo de Inscripción de Certificados de Cliente de Windows** (MS-WCCE), utilizando interfaces DCOM.
2. **Protocolo Remoto ICertPassage** (MS-ICPR), a través de tuberías nombradas o TCP/IP.
3. La **interfaz web de inscripción de certificados**, con el rol de Inscripción Web de la Autoridad de Certificación instalado.
4. El **Servicio de Inscripción de Certificados** (CES), en conjunto con el servicio de Política de Inscripción de Certificados (CEP).
5. El **Servicio de Inscripción de Dispositivos de Red** (NDES) para dispositivos de red, utilizando el Protocolo Simple de Inscripción de Certificados (SCEP).

Los usuarios de Windows también pueden solicitar certificados a través de la GUI (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación de Certificados

Active Directory (AD) admite la autenticación de certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de Autenticación de Kerberos

En el proceso de autenticación de Kerberos, la solicitud de un usuario para un Ticket Granting Ticket (TGT) se firma utilizando la **clave privada** del certificado del usuario. Esta solicitud pasa por varias validaciones por parte del controlador de dominio, incluyendo la **validez**, **ruta** y **estado de revocación** del certificado. Las validaciones también incluyen verificar que el certificado provenga de una fuente confiable y confirmar la presencia del emisor en el **almacén de certificados NTAUTH**. Las validaciones exitosas resultan en la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, se encuentra en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
es central para establecer confianza en la autenticación de certificados.

### Autenticación de Canal Seguro (Schannel)

Schannel facilita conexiones seguras TLS/SSL, donde durante un apretón de manos, el cliente presenta un certificado que, si se valida con éxito, autoriza el acceso. La asignación de un certificado a una cuenta de AD puede involucrar la función **S4U2Self** de Kerberos o el **Nombre Alternativo del Sujeto (SAN)** del certificado, entre otros métodos.

### Enumeración de Servicios de Certificados de AD

Los servicios de certificados de AD se pueden enumerar a través de consultas LDAP, revelando información sobre **Autoridades de Certificación (CAs) Empresariales** y sus configuraciones. Esto es accesible para cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para la enumeración y evaluación de vulnerabilidades en entornos de AD CS.

Los comandos para usar estas herramientas incluyen:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referencias

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../../banners/hacktricks-training.md}}
