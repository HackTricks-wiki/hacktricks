# macOS Red Teaming

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abusando de MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Si logras **comprometer credenciales de administrador** para acceder a la plataforma de gestión, puedes **comprometer potencialmente todos los ordenadores** distribuyendo tu malware en las máquinas.

Para red teaming en entornos MacOS, es altamente recomendable tener cierto entendimiento de cómo funcionan los MDMs:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como un C2

Un MDM tendrá permiso para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador locales, establecer contraseña de firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM necesitas **tu CSR firmado por un proveedor**, lo cual podrías intentar obtener con [**https://mdmcert.download/**](https://mdmcert.download/). Y para ejecutar tu propio MDM para dispositivos Apple podrías usar [**MicroMDM**](https://github.com/micromdm/micromdm).

Sin embargo, para instalar una aplicación en un dispositivo inscrito, aún necesitas que esté firmada por una cuenta de desarrollador... sin embargo, al inscribirse en el MDM, el **dispositivo agrega el certificado SSL del MDM como una CA de confianza**, por lo que ahora puedes firmar cualquier cosa.

Para inscribir el dispositivo en un MDM necesitas instalar un archivo **`mobileconfig`** como root, que podría ser entregado a través de un archivo **pkg** (podrías comprimirlo en zip y cuando se descargue desde safari se descomprimirá).

**El agente Mythic Orthrus** utiliza esta técnica.

### Abusando de JAMF PRO

JAMF puede ejecutar **scripts personalizados** (scripts desarrollados por el sysadmin), **cargas útiles nativas** (creación de cuentas locales, establecimiento de contraseña EFI, monitoreo de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).

#### Autoinscripción en JAMF

Ve a una página como `https://<nombre-de-la-empresa>.jamfcloud.com/enroll/` para ver si tienen **autoinscripción habilitada**. Si la tienen, podría **pedir credenciales para acceder**.

Podrías usar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de rociado de contraseñas.

Además, después de encontrar las credenciales adecuadas, podrías ser capaz de forzar bruscamente otros nombres de usuario con el siguiente formulario:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Autenticación de dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

El binario **`jamf`** contenía el secreto para abrir el llavero que en el momento del descubrimiento era **compartido** entre todos y era: **`jk23ucnq91jfu9aj`**.\
Además, jamf **persiste** como un **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Toma de control de dispositivo JAMF

La **URL de JSS** (Jamf Software Server) que **`jamf`** usará se encuentra en **`/Library/Preferences/com.jamfsoftware.jamf.plist`**. \
Este archivo básicamente contiene la URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Por lo tanto, un atacante podría introducir un paquete malicioso (`pkg`) que **sobrescribe este archivo** al instalarse, configurando la **URL para un escucha de Mythic C2 de un agente Typhon** para ahora poder abusar de JAMF como C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Suplantación de JAMF

Para **suplantar la comunicación** entre un dispositivo y JMF necesitas:

* El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* El **llavero de JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain` que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID de Hardware robado** y con **SIP desactivado**, suelta el **llavero de JAMF,** **intercepta** al agente de Jamf y roba su información.

#### Robo de secretos

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

También podrías monitorear la ubicación `/Library/Application Support/Jamf/tmp/` para los **scripts personalizados** que los administradores podrían querer ejecutar a través de Jamf, ya que se **colocan aquí, se ejecutan y se eliminan**. Estos scripts **podrían contener credenciales**.

Sin embargo, las **credenciales** podrían pasarse a estos scripts como **parámetros**, por lo que necesitarías monitorear `ps aux | grep -i jamf` (sin siquiera ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar la adición de nuevos archivos y nuevos argumentos de procesos.

### Acceso Remoto en macOS

Y también sobre los **protocolos de red** "especiales" de **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

En algunas ocasiones encontrarás que el **ordenador MacOS está conectado a un AD**. En este escenario, deberías intentar **enumerar** el directorio activo como estás acostumbrado. Encuentra **ayuda** en las siguientes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Una **herramienta local de MacOS** que también puede ayudarte es `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS que permiten enumerar automáticamente el AD y jugar con kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto en Objective-C diseñado para interactuar con las APIs de krb5 de Heimdal en macOS. El objetivo del proyecto es permitir una mejor prueba de seguridad en torno a Kerberos en dispositivos macOS utilizando APIs nativas sin requerir ningún otro marco o paquetes en el objetivo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta de JavaScript para Automatización (JXA) para hacer enumeración de Active Directory.

### Información de Dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuarios

Los tres tipos de usuarios de MacOS son:

* **Usuarios Locales** — Gestionados por el servicio OpenDirectory local, no están conectados de ninguna manera con el Active Directory.
* **Usuarios de Red** — Usuarios volátiles de Active Directory que requieren una conexión con el servidor DC para autenticarse.
* **Usuarios Móviles** — Usuarios de Active Directory con una copia de seguridad local para sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ está en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de usar los bordes HasSession y AdminTo, **MacHound añade tres nuevos bordes** a la base de datos de Bloodhound:

* **CanSSH** - entidad permitida para realizar SSH al host
* **CanVNC** - entidad permitida para realizar VNC al host
* **CanAE** - entidad permitida para ejecutar scripts de AppleEvent en el host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Más información en [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Accediendo al Llavero

El Llavero probablemente contiene información sensible que, si se accede sin generar un aviso, podría ayudar a avanzar en un ejercicio de red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Servicios Externos

El Red Teaming en MacOS es diferente al Red Teaming regular en Windows ya que normalmente **MacOS está integrado directamente con varias plataformas externas**. Una configuración común de MacOS es acceder al ordenador utilizando **credenciales sincronizadas de OneLogin y acceder a varios servicios externos** (como github, aws...) a través de OneLogin:

![](<../../.gitbook/assets/image (563).png>)

## Técnicas Misceláneas de Red Team

### Safari

Cuando se descarga un archivo en Safari, si es un archivo "seguro", se **abrirá automáticamente**. Por ejemplo, si **descargas un zip**, se descomprimirá automáticamente:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Referencias

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Ven al Lado Oscuro, Tenemos Manzanas: Convirtiendo la Gestión de macOS en Malvada**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "Una Perspectiva del Atacante sobre las Configuraciones de Jamf" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
