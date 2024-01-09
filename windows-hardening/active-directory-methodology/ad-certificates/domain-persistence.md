# Persistencia en el Dominio de AD CS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Falsificación de Certificados con Certificados CA Robados - DPERSIST1

¿Cómo puedes saber que un certificado es un certificado CA?

* El certificado CA existe en el **servidor CA en sí**, con su **clave privada protegida por DPAPI de la máquina** (a menos que el SO utilice un TPM/HSM/u otro hardware para protección).
* El **Emisor** y el **Sujeto** del certificado están configurados con el **nombre distinguido de la CA**.
* Los certificados CA (y solo los certificados CA) **tienen una extensión de “Versión CA”**.
* No hay **EKUs**

La forma soportada por la GUI integrada para **extraer esta clave privada del certificado** es con `certsrv.msc` en el servidor CA.\
Sin embargo, este certificado **no es diferente** de otros certificados almacenados en el sistema, así que por ejemplo, revisa la técnica [**THEFT2**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para ver cómo **extraerlos**.

También puedes obtener el certificado y la clave privada usando [**certipy**](https://github.com/ly4k/Certipy):
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una vez que tengas el **certificado CA** con la clave privada en formato `.pfx`, puedes usar [**ForgeCert**](https://github.com/GhostPack/ForgeCert) para crear certificados válidos:
```bash
# Create new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Create new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Use new certificate with Rubeus to authenticate
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# User new certi with certipy to authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
**Nota**: El **usuario** objetivo especificado al forjar el certificado debe estar **activo/habilitado** en AD y **capaz de autenticarse**, ya que todavía se producirá un intercambio de autenticación como este usuario. Intentar forjar un certificado para la cuenta krbtgt, por ejemplo, no funcionará.
{% endhint %}

Este certificado falsificado será **válido** hasta la fecha de finalización especificada y mientras el certificado de la CA raíz sea **válido** (generalmente de 5 a **más de 10 años**). También es válido para **máquinas**, por lo que combinado con **S4U2Self**, un atacante puede **mantener persistencia en cualquier máquina del dominio** mientras el certificado de la CA sea válido.\
Además, los **certificados generados** con este método **no pueden ser revocados**, ya que la CA no tiene conocimiento de ellos.

## Confianza en Certificados de CA Falsos - DPERSIST2

El objeto `NTAuthCertificates` define uno o más **certificados de CA** en su **atributo** `cacertificate` y AD lo utiliza: Durante la autenticación, el **controlador de dominio** verifica si el objeto **`NTAuthCertificates`** **contiene** una entrada para la **CA especificada** en el campo Emisor del **certificado** que se autentica. Si **es así, la autenticación procede**.

Un atacante podría generar un **certificado de CA autofirmado** y **añadirlo** al objeto **`NTAuthCertificates`**. Los atacantes pueden hacer esto si tienen **control** sobre el objeto AD **`NTAuthCertificates`** (en configuraciones predeterminadas solo los miembros del grupo **Enterprise Admin** y miembros de los **Domain Admins** o **Administrators** en el **dominio raíz del bosque** tienen estos permisos). Con el acceso elevado, uno puede **editar** el objeto **`NTAuthCertificates`** desde cualquier sistema con `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, o utilizando la [**Herramienta de Salud PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).&#x20;

El certificado especificado debería **funcionar con el método de falsificación previamente detallado con ForgeCert** para generar certificados bajo demanda.

## Configuración Maliciosa - DPERSIST3

Hay una miríada de oportunidades para **persistencia** a través de **modificaciones del descriptor de seguridad de los componentes de AD CS**. Cualquier escenario descrito en la sección “[Escalada de Dominio](domain-escalation.md)” podría ser implementado maliciosamente por un atacante con acceso elevado, así como la adición de "derechos de control" (es decir, WriteOwner/WriteDACL/etc.) a componentes sensibles. Esto incluye:

* El objeto **computadora de servidor CA** de AD
* El **servidor RPC/DCOM del servidor CA**
* Cualquier **objeto o contenedor AD descendiente** en el contenedor **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el contenedor de Plantillas de Certificados, el contenedor de Autoridades de Certificación, el objeto NTAuthCertificates, etc.)
* **Grupos de AD delegados con derechos para controlar AD CS por defecto o por la organización actual** (por ejemplo, el grupo Cert Publishers integrado y cualquiera de sus miembros)

Por ejemplo, un atacante con **permisos elevados** en el dominio podría agregar el permiso **`WriteOwner`** a la plantilla de certificado **`User`** predeterminada, donde el atacante es el principal para el derecho. Para abusar de esto más tarde, el atacante primero modificaría la propiedad de la plantilla **`User`** a sí mismo, y luego **establecería** **`mspki-certificate-name-flag`** en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`** (es decir, permitiendo que un usuario suministre un Nombre Alternativo del Sujeto en la solicitud). Luego, el atacante podría **inscribirse** en la **plantilla**, especificando un nombre de administrador de dominio como nombre alternativo, y usar el certificado resultante para autenticarse como el DA.

## Referencias

* Toda la información de esta página fue tomada de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
