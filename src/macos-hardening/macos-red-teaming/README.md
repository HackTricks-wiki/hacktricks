# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abusando de MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Si consigues **comprometer credenciales de administrador** para acceder a la plataforma de gestión, **potencialmente puedes comprometer todos los ordenadores** distribuyendo tu malware en ellos.

Para hacer Red Teaming en entornos MacOS, se recomienda encarecidamente tener ciertos conocimientos sobre el funcionamiento de los MDMs:


{{#ref}}
macos-mdm/
{{#endref}}

### Usar MDM como C2

Un MDM tendrá permisos para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador locales, establecer la contraseña del firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM necesitas que **tu CSR esté firmado por un proveedor**, lo que puedes intentar conseguir en [**https://mdmcert.download/**](https://mdmcert.download/). Y para ejecutar tu propio MDM para dispositivos Apple puedes utilizar [**MicroMDM**](https://github.com/micromdm/micromdm).

Sin embargo, para instalar una aplicación en un dispositivo inscrito, esta todavía debe estar firmada por una cuenta de desarrollador... no obstante, durante la inscripción en el MDM, el **dispositivo añade el certificado SSL del MDM como una CA de confianza**, por lo que ahora puedes firmar cualquier cosa.<sup>[[4]](#references)</sup>

Para inscribir el dispositivo en un MDM, necesitas instalar un archivo **`mobileconfig`** como root, que podría distribuirse mediante un archivo **pkg** (puedes comprimirlo en zip y, al descargarlo desde Safari, se descomprimirá).

El **agente Mythic Orthrus** utiliza esta técnica.

### Abusando de JAMF PRO

JAMF puede ejecutar **scripts personalizados** (scripts desarrollados por el sysadmin), **payloads nativos** (creación de cuentas locales, establecer la contraseña EFI, monitorización de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).<sup>[[5]](#references)</sup>

#### Autoinscripción en JAMF

Visita una página como `https://<company-name>.jamfcloud.com/enroll/` para comprobar si tienen la **autoinscripción habilitada**. Si la tienen, podría **solicitar credenciales para acceder**.

Puedes utilizar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de password spraying.

Además, después de encontrar credenciales válidas, podrías ser capaz de aplicar fuerza bruta a otros nombres de usuario mediante el siguiente formulario:

![Abusando de JAMF PRO - Autoinscripción en JAMF: Además, después de encontrar credenciales válidas, podrías ser capaz de aplicar fuerza bruta a otros nombres de usuario mediante el siguiente formulario](<../../images/image (107).png>)

#### Autenticación de dispositivos JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

El binario **`jamf`** contenía el secreto para abrir el keychain que, en el momento del descubrimiento, estaba **compartido** entre todos y era: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Además, jamf **persiste** como un **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Toma de control de dispositivos JAMF

La **URL del JSS** (Jamf Software Server) que utilizará **`jamf`** se encuentra en **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Este archivo básicamente contiene la URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Por lo tanto, un atacante podría dejar un paquete malicioso (`pkg`) que **sobrescriba este archivo** al instalarse, estableciendo la **URL de un listener de Mythic C2 desde un agente Typhon** para poder abusar de JAMF como C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Impersonación de JAMF

Para **impersonar la comunicación** entre un dispositivo y JMF necesitas:

- El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- El **JAMF keychain** de: `/Library/Application\ Support/Jamf/JAMF.keychain`, que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID** de Hardware **robado** y con **SIP deshabilitado**, deposita el **JAMF keychain**, haz **hook** al **agent** de Jamf y roba su información.

#### Robo de secretos

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

También podrías monitorizar la ubicación `/Library/Application Support/Jamf/tmp/` en busca de **custom scripts** que los administradores podrían querer ejecutar mediante Jamf, ya que se **colocan aquí, se ejecutan y se eliminan**. Estos scripts **podrían contener credenciales**.

Sin embargo, las **credenciales** podrían pasarse a estos scripts como **parámetros**, por lo que tendrías que monitorizar `ps aux | grep -i jamf` (sin necesidad de ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar cuando se añaden nuevos archivos y nuevos argumentos de procesos.

### Acceso remoto en macOS

Y también sobre los **protocolos** de **red** "especiales" de **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

En algunas ocasiones encontrarás que el **ordenador MacOS está conectado a un AD**. En este escenario, deberías intentar **enumerar** el active directory como estás acostumbrado. Encuentra algo de **ayuda** en las siguientes páginas:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Algunas **herramientas locales de MacOS** que también podrían ayudarte son `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS que permiten enumerar automáticamente AD y trabajar con kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto Objective-C diseñado para interactuar con las APIs krb5 de Heimdal en macOS. El objetivo del proyecto es permitir mejores pruebas de seguridad relacionadas con Kerberos en dispositivos macOS mediante APIs nativas, sin requerir ningún otro framework o paquete en el objetivo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta JavaScript for Automation (JXA) para realizar enumeración de Active Directory.

### Información del dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuarios

Los tres tipos de usuarios de MacOS son:

- **Usuarios locales** — Administrados por el servicio local OpenDirectory; no están conectados de ninguna manera a Active Directory.
- **Usuarios de red** — Usuarios volátiles de Active Directory que requieren una conexión al servidor DC para autenticarse.
- **Usuarios móviles** — Usuarios de Active Directory con una copia de seguridad local de sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ está en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de utilizar los edges HasSession y AdminTo, **MacHound añade tres nuevos edges** a la base de datos de Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entidad autorizada a utilizar SSH en el host
- **CanVNC** - entidad autorizada a utilizar VNC en el host
- **CanAE** - entidad autorizada a ejecutar scripts de AppleEvent en el host
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
Más información en [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Contraseña de Computer$

Obtén contraseñas usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Es posible acceder a la contraseña de **`Computer$`** dentro del llavero del sistema.

### Over-Pass-The-Hash

Obtén un TGT para un usuario y servicio específicos:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Una vez recopilado el TGT, es posible inyectarlo en la sesión actual con:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Con los tickets de servicio obtenidos, es posible intentar acceder a recursos compartidos en otros equipos:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accediendo al Keychain

El Keychain probablemente contiene información sensible que, si se accede a ella sin generar un aviso, podría ayudar a avanzar en un ejercicio de red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Servicios externos

El Red Teaming de MacOS es diferente del Red Teaming habitual de Windows, ya que normalmente **MacOS está integrado directamente con varias plataformas externas**. Una configuración común de MacOS consiste en acceder al equipo utilizando **credenciales sincronizadas de OneLogin y acceder a varios servicios externos** (como github, aws...) mediante OneLogin.

## Técnicas diversas de Red Team

### Safari

Cuando se descarga un archivo en Safari, si es un archivo "seguro", se **abrirá automáticamente**. Por ejemplo, si **descargas un zip**, se descomprimirá automáticamente:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referencias

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
