# Persistencia de Dominio AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Falsificación de Certificados con Certificados de CA Robados - DPERSIST1

¿Cómo se puede saber que un certificado es un certificado de CA?

* El certificado de CA existe en el **servidor de CA en sí mismo**, con su **clave privada protegida por DPAPI de la máquina** (a menos que el sistema operativo use un TPM/HSM/otro hardware para la protección).
* El **Emisor** y el **Asunto** del certificado están ambos establecidos en el **nombre distinguido de la CA**.
* Los certificados de CA (y solo los certificados de CA) **tienen una extensión de "Versión de CA"**.
* No hay EKUs

La forma admitida por la GUI incorporada para **extraer esta clave privada del certificado** es con `certsrv.msc` en el servidor de CA.\
Sin embargo, este certificado **no es diferente** de otros certificados almacenados en el sistema, por lo que, por ejemplo, consulte la técnica [**THEFT2**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para ver cómo **extraerlos**.

También puede obtener el certificado y la clave privada usando [**certipy**](https://github.com/ly4k/Certipy):
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una vez que tengas el **certificado de la CA** con la clave privada en formato `.pfx`, puedes usar [**ForgeCert**](https://github.com/GhostPack/ForgeCert) para crear certificados válidos:
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
**Nota**: El usuario objetivo especificado al forjar el certificado debe estar **activo/habilitado** en AD y **capaz de autenticarse** ya que se producirá un intercambio de autenticación como este usuario. Intentar forjar un certificado para la cuenta krbtgt, por ejemplo, no funcionará.
{% endhint %}

Este certificado falsificado será **válido** hasta la fecha de finalización especificada y mientras el certificado de CA raíz sea válido (generalmente de 5 a **10+ años**). También es válido para **máquinas**, por lo que combinado con **S4U2Self**, un atacante puede **mantener la persistencia en cualquier máquina de dominio** mientras el certificado de CA sea válido.\
Además, los **certificados generados** con este método **no pueden ser revocados** ya que la CA no está al tanto de ellos.

## Confiando en certificados de CA falsos - DPERSIST2

El objeto `NTAuthCertificates` define uno o más **certificados de CA** en su **atributo** `cacertificate` y AD lo utiliza: Durante la autenticación, el **controlador de dominio** comprueba si el objeto **`NTAuthCertificates`** **contiene** una entrada para la **CA especificada** en el campo Issuer del **certificado** que se está autenticando. Si **es así, la autenticación procede**.

Un atacante podría generar un **certificado de CA auto-firmado** y **añadirlo** al objeto **`NTAuthCertificates`**. Los atacantes pueden hacer esto si tienen **control** sobre el objeto **`NTAuthCertificates`** de AD (en configuraciones predeterminadas solo los miembros del grupo **Enterprise Admin** y los miembros de los grupos **Domain Admins** o **Administrators** en el **dominio raíz del bosque** tienen estos permisos). Con el acceso elevado, se puede **editar** el objeto **`NTAuthCertificates`** desde cualquier sistema con `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, o utilizando la [**Herramienta de salud de PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).&#x20;

El certificado especificado debería **funcionar con el método de falsificación detallado anteriormente con ForgeCert** para generar certificados a demanda.

## Configuración maliciosa - DPERSIST3

Hay una miríada de oportunidades para **persistencia** a través de **modificaciones de los descriptores de seguridad de los componentes de AD CS**. Cualquier escenario descrito en la sección "[Escalada de dominio](domain-escalation.md)" podría ser implementado maliciosamente por un atacante con acceso elevado, así como la adición de "derechos de control" (es decir, WriteOwner/WriteDACL/etc.) a componentes sensibles. Esto incluye:

* El objeto de **computadora AD del servidor CA**
* El servidor **RPC/DCOM del servidor CA**
* Cualquier **objeto o contenedor AD descendiente** en el contenedor **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el contenedor de plantillas de certificados, el contenedor de autoridades de certificación, el objeto NTAuthCertificates, etc.)
* **Grupos de AD delegados con derechos para controlar AD CS por defecto o por la organización actual** (por ejemplo, el grupo Cert Publishers integrado y cualquiera de sus miembros)

Por ejemplo, un atacante con **permisos elevados** en el dominio podría agregar el permiso **`WriteOwner`** a la plantilla de certificado **`User`** predeterminada, donde el atacante es el principal para el derecho. Para abusar de esto en un momento posterior, el atacante primero modificaría la propiedad de propiedad de la plantilla **`User`** a sí mismo, y luego **establecería** **`mspki-certificate-name-flag`** en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`** (es decir, permitiendo que un usuario proporcione un nombre alternativo de sujeto en la solicitud). El atacante podría luego **inscribirse** en la **plantilla**, especificando un nombre de **administrador de dominio** como nombre alternativo, y usar el certificado resultante para la autenticación como el DA.

## Referencias

* Toda la información de esta página fue tomada de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿o quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
