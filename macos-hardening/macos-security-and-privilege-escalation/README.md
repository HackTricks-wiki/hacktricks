# Seguridad y Escalada de Privilegios en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Participa en contenido que explora la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado sobre los últimos lanzamientos de recompensas por errores y actualizaciones importantes de plataformas.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo.

## Conceptos Básicos de MacOS

Si no estás familiarizado con macOS, debes comenzar aprendiendo los conceptos básicos de macOS:

* **Archivos y permisos especiales** de macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Usuarios comunes de macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* La **arquitectura** del **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servicios y protocolos de red comunes de macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS de **código abierto**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Para descargar un archivo `tar.gz`, cambia una URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) a [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

En las empresas, los sistemas **macOS** probablemente estén **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspección, Depuración y Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protecciones de Seguridad en MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superficie de Ataque

### Permisos de Archivos

Si un **proceso que se ejecuta como root** escribe un archivo que puede ser controlado por un usuario, el usuario podría aprovechar esto para **elevar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

* El archivo utilizado ya fue creado por un usuario (propiedad del usuario).
* El archivo utilizado es escribible por el usuario debido a un grupo.
* El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo).
* El archivo utilizado está dentro de un directorio propiedad de root, pero el usuario tiene acceso de escritura sobre él debido a un grupo (el usuario podría crear el archivo).

Poder **crear un archivo** que va a ser **utilizado por root**, permite a un usuario aprovechar su contenido o incluso crear **enlaces simbólicos/hardlinks** para apuntarlo a otro lugar.

Para este tipo de vulnerabilidades, no olvides **verificar los instaladores `.pkg`** vulnerables:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}
### Manejadores de aplicaciones de extensiones de archivos y esquemas de URL

Las aplicaciones extrañas registradas por extensiones de archivos pueden ser abusadas y diferentes aplicaciones pueden registrarse para abrir protocolos específicos.

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Escalada de privilegios TCC / SIP en macOS

En macOS, las aplicaciones y binarios pueden tener permisos para acceder a carpetas o configuraciones que los hacen más privilegiados que otros.

Por lo tanto, un atacante que desee comprometer con éxito una máquina macOS deberá **elevar sus privilegios de TCC** (o incluso **burlar SIP**, dependiendo de sus necesidades).

Estos privilegios generalmente se otorgan en forma de **derechos** con los que la aplicación está firmada, o la aplicación puede solicitar algunos accesos y después de que el **usuario los apruebe**, se pueden encontrar en las **bases de datos de TCC**. Otra forma en que un proceso puede obtener estos privilegios es siendo un **hijo de un proceso** con esos **privilegios**, ya que generalmente se **heredan**.

Siga estos enlaces para encontrar diferentes formas de [**elevar privilegios en TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), para [**burlar TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) y cómo en el pasado se ha **burlado SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalada de privilegios tradicional en macOS

Por supuesto, desde la perspectiva de los equipos de seguridad, también debería estar interesado en elevarse a root. Consulte la siguiente publicación para obtener algunas pistas:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Referencias

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Hacking Insights**\
Participa en contenido que profundiza en la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado sobre los nuevos programas de recompensas por errores que se lanzan y las actualizaciones importantes de las plataformas.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
