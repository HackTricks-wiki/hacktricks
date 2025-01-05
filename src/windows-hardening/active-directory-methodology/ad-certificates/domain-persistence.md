# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este es un resumen de las técnicas de persistencia de dominio compartidas en [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Revísalo para más detalles.

## Forjando Certificados con Certificados CA Robados - DPERSIST1

¿Cómo puedes saber si un certificado es un certificado CA?

Se puede determinar que un certificado es un certificado CA si se cumplen varias condiciones:

- El certificado está almacenado en el servidor CA, con su clave privada asegurada por el DPAPI de la máquina, o por hardware como un TPM/HSM si el sistema operativo lo soporta.
- Los campos de Emisor y Sujeto del certificado coinciden con el nombre distinguido de la CA.
- Una extensión de "Versión CA" está presente exclusivamente en los certificados CA.
- El certificado carece de campos de Uso de Clave Extendida (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor CA es el método soportado a través de la GUI incorporada. No obstante, este certificado no difiere de otros almacenados dentro del sistema; por lo tanto, se pueden aplicar métodos como la [técnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para la extracción.

El certificado y la clave privada también se pueden obtener utilizando Certipy con el siguiente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Al adquirir el certificado CA y su clave privada en formato `.pfx`, se pueden utilizar herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) para generar certificados válidos:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> El usuario objetivo para la falsificación de certificados debe estar activo y ser capaz de autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt es ineficaz.

Este certificado falsificado será **válido** hasta la fecha de finalización especificada y **mientras el certificado CA raíz sea válido** (generalmente de 5 a **10+ años**). También es válido para **máquinas**, por lo que, combinado con **S4U2Self**, un atacante puede **mantener persistencia en cualquier máquina del dominio** mientras el certificado CA sea válido.\
Además, los **certificados generados** con este método **no pueden ser revocados** ya que la CA no tiene conocimiento de ellos.

## Confianza en Certificados CA Maliciosos - DPERSIST2

El objeto `NTAuthCertificates` está definido para contener uno o más **certificados CA** dentro de su atributo `cacertificate`, que utiliza Active Directory (AD). El proceso de verificación por parte del **controlador de dominio** implica comprobar el objeto `NTAuthCertificates` en busca de una entrada que coincida con la **CA especificada** en el campo Emisor del **certificado** autenticador. La autenticación continúa si se encuentra una coincidencia.

Un certificado CA autofirmado puede ser agregado al objeto `NTAuthCertificates` por un atacante, siempre que tenga control sobre este objeto de AD. Normalmente, solo se otorgan permisos para modificar este objeto a los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administrators** en el **dominio raíz del bosque**. Pueden editar el objeto `NTAuthCertificates` usando `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, o empleando la [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Esta capacidad es especialmente relevante cuando se utiliza en conjunto con un método previamente descrito que involucra ForgeCert para generar certificados dinámicamente.

## Configuración Maliciosa - DPERSIST3

Las oportunidades para la **persistencia** a través de **modificaciones del descriptor de seguridad de los componentes de AD CS** son abundantes. Las modificaciones descritas en la sección "[Domain Escalation](domain-escalation.md)" pueden ser implementadas maliciosamente por un atacante con acceso elevado. Esto incluye la adición de "derechos de control" (por ejemplo, WriteOwner/WriteDACL/etc.) a componentes sensibles como:

- El objeto de computadora AD del **servidor CA**
- El **servidor RPC/DCOM del servidor CA**
- Cualquier **objeto o contenedor AD descendiente** en **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el contenedor de Plantillas de Certificado, el contenedor de Autoridades de Certificación, el objeto NTAuthCertificates, etc.)
- **Grupos AD con derechos delegados para controlar AD CS** por defecto o por la organización (como el grupo incorporado Cert Publishers y cualquiera de sus miembros)

Un ejemplo de implementación maliciosa implicaría a un atacante, que tiene **permisos elevados** en el dominio, agregando el permiso **`WriteOwner`** a la plantilla de certificado **`User`** por defecto, siendo el atacante el principal para el derecho. Para explotar esto, el atacante primero cambiaría la propiedad de la plantilla **`User`** a sí mismo. Después de esto, el **`mspki-certificate-name-flag`** se establecería en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitiendo a un usuario proporcionar un Nombre Alternativo de Sujeto en la solicitud. Posteriormente, el atacante podría **inscribirse** usando la **plantilla**, eligiendo un nombre de **administrador de dominio** como nombre alternativo, y utilizar el certificado adquirido para autenticarse como el DA.

{{#include ../../../banners/hacktricks-training.md}}
