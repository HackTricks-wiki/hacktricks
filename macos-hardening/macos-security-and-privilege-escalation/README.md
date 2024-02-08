# Seguridad y Escalada de Privilegios en macOS

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Involúcrate con contenido que explora la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado sobre los nuevos programas de recompensas por errores y actualizaciones importantes de plataformas.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

## Conceptos Básicos de MacOS

Si no estás familiarizado con macOS, deberías comenzar aprendiendo los conceptos básicos de macOS:

* Archivos y permisos especiales de macOS:

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

* La **arquitectura** del **núcleo**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servicios y protocolos de red comunes de macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS **de código abierto**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Para descargar un `tar.gz` cambia una URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) a [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM en macOS

En las empresas, los sistemas **macOS** probablemente estén **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### macOS - Inspección, Depuración y Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protecciones de Seguridad en macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superficie de Ataque

### Permisos de Archivos

Si un **proceso en ejecución como root escribe** un archivo que puede ser controlado por un usuario, el usuario podría abusar de esto para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

* El archivo utilizado ya fue creado por un usuario (propiedad del usuario)
* El archivo utilizado es escribible por el usuario debido a un grupo
* El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo)
* El archivo utilizado está dentro de un directorio propiedad de root pero el usuario tiene acceso de escritura sobre él debido a un grupo (el usuario podría crear el archivo)

Poder **crear un archivo** que va a ser **utilizado por root**, permite a un usuario **aprovechar su contenido** o incluso crear **enlaces simbólicos/duros** para apuntarlo a otro lugar.

Para este tipo de vulnerabilidades, no olvides **verificar los instaladores `.pkg` vulnerables**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Extensión de Archivos y Manejadores de Aplicaciones de Esquema de URL

Las aplicaciones extrañas registradas por extensiones de archivo podrían ser abusadas y diferentes aplicaciones pueden registrarse para abrir protocolos específicos

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Escalada de Privilegios TCC / SIP en macOS

En macOS, las **aplicaciones y binarios pueden tener permisos** para acceder a carpetas o configuraciones que los hacen más privilegiados que otros.

Por lo tanto, un atacante que quiera comprometer con éxito una máquina macOS necesitará **escalar sus privilegios TCC** (o incluso **burlar SIP**, dependiendo de sus necesidades).

Estos privilegios suelen otorgarse en forma de **derechos** con los que la aplicación está firmada, o la aplicación podría haber solicitado algunos accesos y después de que el **usuario los apruebe** pueden encontrarse en las **bases de datos de TCC**. Otra forma en que un proceso puede obtener estos privilegios es siendo un **hijo de un proceso** con esos **privilegios**, ya que suelen ser **heredados**.

Sigue estos enlaces para encontrar diferentes formas de [**escalar privilegios en TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), para [**burlar TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) y cómo en el pasado se ha [**burlado SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalada de Privilegios Tradicional en macOS

Por supuesto, desde la perspectiva de un equipo de red, también deberías estar interesado en escalar a root. Consulta el siguiente post para obtener algunas pistas:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Referencias

* [**Respuesta a Incidentes de OS X: Scripting y Análisis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Involúcrate con contenido que explora la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado sobre los nuevos programas de recompensas por errores y actualizaciones importantes de plataformas.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
