# Red Teaming en macOS

{{#include ../../banners/hacktricks-training.md}}


## Abusando de los MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Si consigues **comprometer credenciales de administrador** para acceder a la plataforma de gestión, puedes **comprometer potencialmente todos los ordenadores** distribuyendo tu malware en ellos.

Para hacer red teaming en entornos MacOS, es muy recomendable tener ciertos conocimientos sobre cómo funcionan los MDMs:


{{#ref}}
macos-mdm/
{{#endref}}

### Usando MDM como C2

Un MDM tendrá permisos para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador locales, establecer la contraseña del firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM necesitas que **tu CSR esté firmado por un proveedor**, lo que podrías intentar conseguir en [**https://mdmcert.download/**](https://mdmcert.download/). Y para ejecutar tu propio MDM para dispositivos Apple puedes usar [**MicroMDM**](https://github.com/micromdm/micromdm).

Sin embargo, para instalar una aplicación en un dispositivo enrolled, todavía necesitas que esté firmada por una cuenta de desarrollador... no obstante, durante el enrolment en el MDM, el **dispositivo añade el certificado SSL del MDM como una CA de confianza**, por lo que ahora puedes firmar cualquier cosa.<sup>[[4]](#references)</sup>

Para enrolar el dispositivo en un MDM necesitas instalar un archivo **`mobileconfig`** como root, que podría distribuirse mediante un archivo **pkg** (puedes comprimirlo en zip y, al descargarlo desde Safari, se descomprimirá).

El **agent Orthrus de Mythic** utiliza esta técnica.

### Abusando de JAMF PRO

JAMF puede ejecutar **custom scripts** (scripts desarrollados por el sysadmin), **native payloads** (creación de cuentas locales, establecimiento de la contraseña EFI, monitorización de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Accede a una página como `https://<company-name>.jamfcloud.com/enroll/` para comprobar si tienen el **self-enrolment habilitado**. Si lo tienen, podría **solicitar credenciales para acceder**.

Podrías usar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de password spraying.

Además, después de encontrar credenciales válidas, podrías hacer brute-force de otros nombres de usuario con el siguiente formulario:

![Abusando de JAMF PRO - JAMF self-enrolment: Además, después de encontrar credenciales válidas, podrías hacer brute-force de otros nombres de usuario con el siguiente formulario](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

El binario **`jamf`** contenía el secreto para abrir el keychain, que en el momento del descubrimiento era **compartido** entre todos y era: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Además, jamf **persist** como un **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

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
Por lo tanto, un atacante podría desplegar un paquete malicioso (`pkg`) que **sobrescriba este archivo** al instalarse, configurando la **URL de un listener de Mythic C2 de un agente Typhon** para poder abusar de JAMF como C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Para **impersonate la comunicación** entre un dispositivo y JMF necesitas:

- El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- El **JAMF keychain** de: `/Library/Application\ Support/Jamf/JAMF.keychain`, que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID** de Hardware **robado** y con **SIP deshabilitado**, coloca el **JAMF keychain**, haz **hook** del **agent** de Jamf y roba su información.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

También podrías monitorizar la ubicación `/Library/Application Support/Jamf/tmp/` en busca de los **custom scripts** que los administradores podrían querer ejecutar mediante Jamf, ya que se **colocan aquí, se ejecutan y se eliminan**. Estos scripts **podrían contener credenciales**.

Sin embargo, las **credenciales** podrían pasarse a estos scripts como **parámetros**, por lo que tendrías que monitorizar `ps aux | grep -i jamf` (sin necesidad de ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar la adición de nuevos archivos y los argumentos de nuevos procesos.

### Acceso remoto a macOS

Y también sobre los **protocolos** de **red** "especiales" de **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

En algunas ocasiones encontrarás que el **equipo MacOS está conectado a un AD**. En este escenario, deberías intentar **enumerar** el active directory como estás acostumbrado. Encuentra algo de **ayuda** en las siguientes páginas:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Alguna **herramienta local de MacOS** que también podría ayudarte es `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS para enumerar automáticamente el AD y trabajar con kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditing Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto de Objective-C diseñado para interactuar con las APIs de Heimdal krb5 en macOS. El objetivo del proyecto es permitir mejores pruebas de seguridad en torno a Kerberos en dispositivos macOS utilizando APIs nativas, sin requerir ningún otro framework o paquete en el objetivo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta de JavaScript for Automation (JXA) para realizar la enumeración de Active Directory.

### Información del dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuarios

Los tres tipos de usuarios de macOS son:

- **Usuarios locales** — Gestionados por el servicio local OpenDirectory; no están conectados de ninguna forma a Active Directory.
- **Usuarios de red** — Usuarios volátiles de Active Directory que requieren una conexión al servidor DC para autenticarse.
- **Usuarios móviles** — Usuarios de Active Directory con una copia de seguridad local de sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ se encuentra en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de utilizar los edges HasSession y AdminTo, **MacHound añade tres nuevos edges** a la base de datos de Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entidad autorizada para usar SSH en el host
- **CanVNC** - entidad autorizada para usar VNC en el host
- **CanAE** - entidad autorizada para ejecutar scripts de AppleEvent en el host
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

### Contraseña de Computer$

Obtén contraseñas mediante:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Es posible acceder a la contraseña de **`Computer$`** dentro del keychain del sistema.

### Over-Pass-The-Hash

Obtén un TGT para un usuario y servicio específicos:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Una vez obtenido el TGT, es posible inyectarlo en la sesión actual con:
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
Con los service tickets obtenidos es posible intentar acceder a recursos compartidos en otros equipos:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accediendo al Keychain

El Keychain probablemente contiene información sensible que, si se accede a ella sin generar un prompt, podría ayudar a avanzar en un ejercicio de red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Servicios externos

El Red Teaming de MacOS es diferente del Red Teaming habitual de Windows, ya que normalmente **MacOS está integrado directamente con varias plataformas externas**. Una configuración común de MacOS consiste en acceder al ordenador utilizando **credenciales sincronizadas con OneLogin y acceder a varios servicios externos** (como github, aws...) mediante OneLogin.

## Técnicas de Red Team varias

### Safari

Cuando se descarga un archivo en Safari, si es un archivo "seguro", se **abrirá automáticamente**. Por ejemplo, si **descargas un zip**, se descomprimirá automáticamente:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referencias

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
