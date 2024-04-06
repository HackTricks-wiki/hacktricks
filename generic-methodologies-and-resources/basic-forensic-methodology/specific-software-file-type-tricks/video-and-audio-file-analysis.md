<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**La manipulación de archivos de audio y video** es fundamental en los desafíos de **forenses de CTF**, aprovechando la **esteganografía** y el análisis de metadatos para ocultar o revelar mensajes secretos. Herramientas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** y **`exiftool`** son esenciales para inspeccionar metadatos de archivos e identificar tipos de contenido.

Para desafíos de audio, **[Audacity](http://www.audacityteam.org/)** destaca como una herramienta principal para ver formas de onda y analizar espectrogramas, esencial para descubrir texto codificado en audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** es muy recomendado para un análisis detallado de espectrogramas. **Audacity** permite la manipulación de audio como ralentizar o revertir pistas para detectar mensajes ocultos. **[Sox](http://sox.sourceforge.net/)**, una utilidad de línea de comandos, sobresale en la conversión y edición de archivos de audio.

La manipulación de **Bits Menos Significativos (LSB)** es una técnica común en la esteganografía de audio y video, explotando los fragmentos de tamaño fijo de los archivos multimedia para incrustar datos discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** es útil para decodificar mensajes ocultos como tonos **DTMF** o **código Morse**.

Los desafíos de video a menudo involucran formatos de contenedor que agrupan flujos de audio y video. **[FFmpeg](http://ffmpeg.org/)** es el recurso principal para analizar y manipular estos formatos, capaz de desmultiplexar y reproducir contenido. Para desarrolladores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra las capacidades de FFmpeg en Python para interacciones scriptables avanzadas.

Esta variedad de herramientas subraya la versatilidad requerida en los desafíos de CTF, donde los participantes deben emplear un amplio espectro de técnicas de análisis y manipulación para descubrir datos ocultos dentro de archivos de audio y video.

# Referencias
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) 

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
