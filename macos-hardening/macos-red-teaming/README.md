# Red Teaming en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Métodos comunes de gestión

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Si logras **comprometer las credenciales de administrador** para acceder a la plataforma de gestión, puedes **potencialmente comprometer todas las computadoras** distribuyendo tu malware en las máquinas.

Para el red teaming en entornos de macOS, es muy recomendable tener cierta comprensión de cómo funcionan los MDM:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

Y también sobre los **protocolos de red** "especiales" de **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

En algunas ocasiones, encontrarás que la **computadora macOS está conectada a un AD**. En este escenario, debes intentar **enumerar** el directorio activo como estás acostumbrado. Encuentra **ayuda** en las siguientes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Alguna **herramienta local de MacOS** que también puede ayudarte es `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS para enumerar automáticamente el AD y jugar con Kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto Objective-C diseñado para interactuar con las APIs de Heimdal krb5 en macOS. El objetivo del proyecto es permitir una mejor prueba de seguridad en torno a Kerberos en dispositivos macOS utilizando APIs nativas sin requerir ningún otro marco o paquete en el objetivo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta de JavaScript para Automatización (JXA) para hacer enumeración de Active Directory. 

### Información del dominio
```
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

El Red Teaming de MacOS es diferente al Red Teaming regular de Windows ya que usualmente **MacOS está integrado directamente con varias plataformas externas**. Una configuración común de MacOS es acceder a la computadora usando **credenciales sincronizadas con OneLogin, y accediendo a varios servicios externos** (como github, aws...) a través de OneLogin:

![](<../../.gitbook/assets/image (563).png>)

###

## Referencias

* [https://www.youtube.com/watch?v=IiMladUbL6E](https://www.youtube.com/watch?v=IiMladUbL6E)
* [https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
