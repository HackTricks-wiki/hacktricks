# Seguridad y Escalada de Privilegios en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

¡Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores!

**Perspectivas de Hacking**\
Interactúa con contenido que profundiza en la emoción y los desafíos del hacking

**Noticias de Hacking en Tiempo Real**\
Mantente al día con el mundo del hacking de ritmo rápido a través de noticias e insights en tiempo real

**Últimos Anuncios**\
Mantente informado con los lanzamientos de nuevas recompensas por errores y actualizaciones críticas de la plataforma

**¡Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

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

* La **arquitectura** del **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servicios y protocolos de red comunes en macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Para descargar un `tar.gz` cambia una URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) a [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM de MacOS

En las empresas, los sistemas **macOS** probablemente estarán **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante es interesante saber **cómo funciona eso**:

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

Si un **proceso ejecutándose como root escribe** un archivo que puede ser controlado por un usuario, el usuario podría abusar de esto para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

* El archivo utilizado ya fue creado por un usuario (propiedad del usuario)
* El archivo utilizado es escribible por el usuario debido a un grupo
* El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo)
* El archivo utilizado está dentro de un directorio propiedad de root pero el usuario tiene acceso de escritura sobre él debido a un grupo (el usuario podría crear el archivo)

Ser capaz de **crear un archivo** que va a ser **utilizado por root**, permite a un usuario **aprovechar su contenido** o incluso crear **symlinks/hardlinks** para apuntarlo a otro lugar.

Para este tipo de vulnerabilidades no olvides **revisar instaladores `.pkg` vulnerables**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Manejadores de Extensiones de Archivos y Esquemas de URL de Aplicaciones

Aplicaciones extrañas registradas por extensiones de archivos podrían ser abusadas y diferentes aplicaciones pueden registrarse para abrir protocolos específicos

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Escalada de Privilegios TCC / SIP en macOS

En macOS **las aplicaciones y binarios pueden tener permisos** para acceder a carpetas o configuraciones que los hacen más privilegiados que otros.

Por lo tanto, un atacante que quiera comprometer con éxito una máquina macOS necesitará **escalar sus privilegios TCC** (o incluso **burlar SIP**, dependiendo de sus necesidades).

Estos privilegios generalmente se otorgan en forma de **entitlements** con los que se firma la aplicación, o la aplicación podría haber solicitado algunos accesos y después de que el **usuario los apruebe** se pueden encontrar en las **bases de datos TCC**. Otra forma en que un proceso puede obtener estos privilegios es siendo un **hijo de un proceso** con esos **privilegios**, ya que generalmente se **heredan**.

Sigue estos enlaces para encontrar diferentes formas de [**escalar privilegios en TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), de [**burlar TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) y cómo en el pasado se ha [**burlado SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalada de Privilegios Tradicional en macOS

Por supuesto, desde la perspectiva de un equipo rojo también deberías estar interesado en escalar a root. Revisa el siguiente post para algunas pistas:

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

¡Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores!

**Perspectivas de Hacking**\
Interactúa con contenido que profundiza en la emoción y los desafíos del hacking

**Noticias de Hacking en Tiempo Real**\
Mantente al día con el mundo del hacking de ritmo rápido a través de noticias e insights en tiempo real

**Últimos Anuncios**\
Mantente informado con los lanzamientos de nuevas recompensas por errores y actualizaciones críticas de la plataforma

**¡Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
