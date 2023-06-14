# macOS Red Teaming

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abusando de los MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Si logras **comprometer las credenciales de administrador** para acceder a la plataforma de gestión, puedes **potencialmente comprometer todas las computadoras** distribuyendo tu malware en las máquinas.

Para el red teaming en entornos MacOS, es altamente recomendable tener cierta comprensión de cómo funcionan los MDMs:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como C2

Un MDM tendrá permiso para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador locales, establecer contraseñas de firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM, necesitas **tu CSR firmado por un proveedor**, que podrías intentar obtener con [**https://mdmcert.download/**](https://mdmcert.download/). Y para ejecutar tu propio MDM para dispositivos Apple, podrías usar [**MicroMDM**](https://github.com/micromdm/micromdm).

Sin embargo, para instalar una aplicación en un dispositivo inscrito, aún necesitas que esté firmada por una cuenta de desarrollador... sin embargo, al inscribirse en MDM, el **dispositivo agrega el certificado SSL del MDM como una CA de confianza**, por lo que ahora puedes firmar cualquier cosa.

Para inscribir el dispositivo en un MDM, necesitas instalar un archivo **`mobileconfig`** como root, que podría entregarse a través de un archivo **pkg** (podrías comprimirlo en zip y cuando se descargue desde Safari se descomprimirá).

El agente Mythic Orthrus utiliza esta técnica.

### Abusando de JAMF PRO

JAMF puede ejecutar **scripts personalizados** (scripts desarrollados por el administrador del sistema), **cargas útiles nativas** (creación de cuentas locales, establecimiento de contraseñas EFI, monitoreo de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).

#### Autoinscripción de JAMF

Ve a una página como `https://<company-name>.jamfcloud.com/enroll/` para ver si tienen **autoinscripción habilitada**. Si lo tienen, podría **pedir credenciales para acceder**.

Podrías usar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de spraying de contraseñas.

Además, después de encontrar las credenciales adecuadas, podrías ser capaz de realizar un ataque de fuerza bruta en otros nombres de usuario con el siguiente formulario:

![](<../../.gitbook/assets/image (6).png>)

#### Autenticación de dispositivos JAMF

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

El binario **`jamf`** contenía el secreto para abrir el llavero que en el momento del descubrimiento estaba **compartido** entre todos y era: **`jk23ucnq91jfu9aj`**.\
Además, jamf **persiste** como un **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Toma de control del dispositivo JAMF

La **URL** de **JSS** (Jamf Software Server) que **`jamf`** utilizará se encuentra en **`/Library/Preferences/com.jamfsoftware.jamf.plist`**. \
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

Por lo tanto, un atacante podría dejar caer un paquete malicioso (`pkg`) que **sobrescribe este archivo** cuando se instala, estableciendo la **URL en un escucha de Mythic C2 desde un agente de Typhon** para poder abusar de JAMF como C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Suplantación de JAMF

Para **suplantar la comunicación** entre un dispositivo y JMF necesitas:

* El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* El **llavero JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain` que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID** de hardware **robado** y con **SIP deshabilitado**, deja caer el **llavero JAMF,** **engancha** el agente de Jamf y roba su información.

#### Robo de secretos

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption><p>a</p></figcaption></figure>

También puedes monitorear la ubicación `/Library/Application Support/Jamf/tmp/` para los **scripts personalizados** que los administradores puedan querer ejecutar a través de Jamf, ya que se **colocan aquí, se ejecutan y se eliminan**. Estos scripts **pueden contener credenciales**.

Sin embargo, las **credenciales** podrían pasarse a estos scripts como **parámetros**, por lo que tendrías que monitorear `ps aux | grep -i jamf` (sin siquiera ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar la adición de nuevos archivos y nuevos argumentos de proceso.

### Acceso remoto a macOS

Y también sobre los **protocolos de red** "especiales" de **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

En algunas ocasiones encontrarás que la **computadora MacOS está conectada a un AD**. En este escenario, debes intentar **enumerar** el directorio activo como estás acostumbrado. Encuentra **ayuda** en las siguientes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Algunas **herramientas locales de MacOS** que también pueden ayudarte son `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS para enumerar automáticamente el AD y jugar con Kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts de MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto Objective-C diseñado para interactuar con las APIs de Heimdal krb5 en macOS. El objetivo del proyecto es permitir una mejor prueba de seguridad en torno a Kerberos en dispositivos macOS utilizando APIs nativas sin requerir ningún otro marco o paquete en el objetivo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta de JavaScript para Automatización (JXA) para hacer enumeración de Active Directory.
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuarios

Los tres tipos de usuarios de MacOS son:

* **Usuarios locales** - Administrados por el servicio local de OpenDirectory, no están conectados de ninguna manera al Active Directory.
* **Usuarios de red** - Usuarios volátiles de Active Directory que requieren una conexión al servidor DC para autenticarse.
* **Usuarios móviles** - Usuarios de Active Directory con una copia de seguridad local para sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ está en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de utilizar los bordes HasSession y AdminTo, **MacHound agrega tres nuevos bordes** a la base de datos Bloodhound:

* **CanSSH** - entidad permitida para SSH al host
* **CanVNC** - entidad permitida para VNC al host
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

## Servicios Externos

El Red Teaming de MacOS es diferente al Red Teaming regular de Windows ya que usualmente **MacOS está integrado con varias plataformas externas directamente**. Una configuración común de MacOS es acceder a la computadora usando **credenciales sincronizadas de OneLogin y acceder a varios servicios externos** (como github, aws...) a través de OneLogin:

![](<../../.gitbook/assets/image (563).png>)

## Técnicas Misc de Red Team

### Safari

Cuando se descarga un archivo en Safari, si es un archivo "seguro", se **abrirá automáticamente**. Por ejemplo, si se **descarga un archivo zip**, se descomprimirá automáticamente:

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

## Referencias

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
