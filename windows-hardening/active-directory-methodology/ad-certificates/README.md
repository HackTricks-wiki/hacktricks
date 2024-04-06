# Certificados de AD

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

### Componentes de un Certificado

- El **Sujeto** del certificado denota su propietario.
- Una **Clave Pública** se empareja con una clave privada para vincular el certificado con su legítimo propietario.
- El **Período de Validez**, definido por las fechas **NotBefore** y **NotAfter**, marca la duración efectiva del certificado.
- Un **Número de Serie** único, proporcionado por la Autoridad de Certificación (CA), identifica cada certificado.
- El **Emisor** se refiere a la CA que ha emitido el certificado.
- **SubjectAlternativeName** permite nombres adicionales para el sujeto, mejorando la flexibilidad de identificación.
- **Restricciones Básicas** identifican si el certificado es para una CA o una entidad final y definen restricciones de uso.
- **Usos Extendidos de Clave (EKUs)** delimitan los propósitos específicos del certificado, como la firma de código o el cifrado de correo electrónico, a través de Identificadores de Objetos (OIDs).
- El **Algoritmo de Firma** especifica el método para firmar el certificado.
- La **Firma**, creada con la clave privada del emisor, garantiza la autenticidad del certificado.

### Consideraciones Especiales

- Los **Nombres Alternativos del Sujeto (SANs)** amplían la aplicabilidad de un certificado a múltiples identidades, siendo crucial para servidores con múltiples dominios. Los procesos seguros de emisión son vitales para evitar riesgos de suplantación por parte de atacantes que manipulan la especificación SAN.

### Autoridades de Certificación (CAs) en Active Directory (AD)

AD CS reconoce certificados de CA en un bosque de AD a través de contenedores designados, cada uno con roles únicos:

- El contenedor de **Autoridades de Certificación** contiene certificados raíz de CA de confianza.
- El contenedor de **Servicios de Inscripción** detalla CAs empresariales y sus plantillas de certificado.
- El objeto **NTAuthCertificates** incluye certificados de CA autorizados para autenticación de AD.
- El contenedor **AIA (Acceso a la Información de la Autoridad)** facilita la validación de la cadena de certificados con certificados intermedios y cruzados.

### Adquisición de Certificados: Flujo de Solicitud de Certificado del Cliente

1. El proceso de solicitud comienza con los clientes encontrando una CA empresarial.
2. Se crea una CSR, que contiene una clave pública y otros detalles, después de generar un par de claves pública-privada.
3. La CA evalúa la CSR frente a las plantillas de certificado disponibles, emitiendo el certificado en función de los permisos de la plantilla.
4. Tras la aprobación, la CA firma el certificado con su clave privada y lo devuelve al cliente.

### Plantillas de Certificado

Definidas dentro de AD, estas plantillas describen la configuración y permisos para emitir certificados, incluidos los EKUs permitidos y los derechos de inscripción o modificación, fundamentales para gestionar el acceso a los servicios de certificados.

## Inscripción de Certificados

El proceso de inscripción de certificados es iniciado por un administrador que **crea una plantilla de certificado**, la cual es luego **publicada** por una Autoridad de Certificación Empresarial (CA). Esto hace que la plantilla esté disponible para la inscripción de clientes, un paso logrado al agregar el nombre de la plantilla al campo `certificatetemplates` de un objeto de Active Directory.

Para que un cliente solicite un certificado, se deben otorgar **derechos de inscripción**. Estos derechos están definidos por descriptores de seguridad en la plantilla de certificado y en la propia CA empresarial. Los permisos deben ser otorgados en ambos lugares para que una solicitud sea exitosa.

### Derechos de Inscripción de Plantillas

Estos derechos se especifican a través de Entradas de Control de Acceso (ACEs), detallando permisos como:
- Derechos de **Certificado-Inscripción** y **Certificado-AutoInscripción**, cada uno asociado con GUIDs específicos.
- **ExtendedRights**, permitiendo todos los permisos extendidos.
- **ControlTotal/GenericAll**, proporcionando control completo sobre la plantilla.

### Derechos de Inscripción de CA Empresarial

Los derechos de la CA están delineados en su descriptor de seguridad, accesible a través de la consola de administración de la Autoridad de Certificación. Algunas configuraciones incluso permiten a usuarios con pocos privilegios acceso remoto, lo que podría ser un problema de seguridad.

### Controles de Emisión Adicionales

Pueden aplicarse ciertos controles, como:
- **Aprobación del Gerente**: Coloca las solicitudes en un estado pendiente hasta que sean aprobadas por un gerente de certificados.
- **Agentes de Inscripción y Firmas Autorizadas**: Especifican el número de firmas requeridas en una CSR y las Políticas de Aplicación OIDs necesarias.

### Métodos para Solicitar Certificados

Los certificados pueden solicitarse a través de:
1. **Protocolo de Inscripción de Certificado de Cliente de Windows** (MS-WCCE), utilizando interfaces DCOM.
2. **Protocolo Remoto ICertPassage** (MS-ICPR), a través de tuberías con nombre o TCP/IP.
3. La **interfaz web de inscripción de certificados**, con el rol de Inscripción Web de Autoridad de Certificación instalado.
4. El **Servicio de Inscripción de Certificados** (CES), en conjunto con el servicio de Política de Inscripción de Certificados (CEP).
5. El **Servicio de Inscripción de Dispositivos de Red** (NDES) para dispositivos de red, utilizando el Protocolo Simple de Inscripción de Certificados (SCEP).

Los usuarios de Windows también pueden solicitar certificados a través de la interfaz gráfica de usuario (`certmgr.msc` o `certlm.msc`) o herramientas de línea de comandos (`certreq.exe` o el comando `Get-Certificate` de PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticación de Certificados

Active Directory (AD) admite la autenticación de certificados, utilizando principalmente los protocolos **Kerberos** y **Secure Channel (Schannel)**.

### Proceso de Autenticación Kerberos

En el proceso de autenticación Kerberos, la solicitud de un Ticket Granting Ticket (TGT) de un usuario se firma utilizando la **clave privada** del certificado del usuario. Esta solicitud pasa por varias validaciones por parte del controlador de dominio, que incluyen la **validez**, **ruta** y **estado de revocación** del certificado. Las validaciones también incluyen verificar que el certificado provenga de una fuente confiable y confirmar la presencia del emisor en la tienda de certificados **NTAUTH**. Las validaciones exitosas resultan en la emisión de un TGT. El objeto **`NTAuthCertificates`** en AD, se encuentra en:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### Autenticación del Canal Seguro (Schannel)

Schannel facilita conexiones seguras TLS/SSL, donde durante un saludo, el cliente presenta un certificado que, si se valida correctamente, autoriza el acceso. El mapeo de un certificado a una cuenta de AD puede implicar la función **S4U2Self** de Kerberos o el **Nombre Alternativo del Sujeto (SAN)** del certificado, entre otros métodos.

### Enumeración de Servicios de Certificados de AD

Los servicios de certificados de AD pueden ser enumerados a través de consultas LDAP, revelando información sobre **Autoridades de Certificación Empresariales (CAs)** y sus configuraciones. Esto es accesible por cualquier usuario autenticado en el dominio sin privilegios especiales. Herramientas como **[Certify](https://github.com/GhostPack/Certify)** y **[Certipy](https://github.com/ly4k/Certipy)** se utilizan para enumeración y evaluación de vulnerabilidades en entornos de AD CS.

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

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
