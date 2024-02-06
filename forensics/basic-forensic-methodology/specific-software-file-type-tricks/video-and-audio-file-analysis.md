<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Desde: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Al igual que con los formatos de archivos de imagen, la manipulación de archivos de audio y video es un tema común en los desafíos forenses de CTF, no porque el hacking o el ocultamiento de datos ocurran de esta manera en el mundo real, sino simplemente porque el audio y el video son divertidos. Al igual que con los formatos de archivos de imagen, la esteganografía podría usarse para incrustar un mensaje secreto en los datos de contenido, y nuevamente deberías revisar las áreas de metadatos del archivo en busca de pistas. Tu primer paso debería ser echar un vistazo con la herramienta [mediainfo](https://mediaarea.net/en/MediaInfo) (o `exiftool`) e identificar el tipo de contenido y mirar sus metadatos.

[Audacity](http://www.audacityteam.org/) es la principal herramienta de código abierto para archivos de audio y visualización de formas de onda. A los autores de desafíos de CTF les encanta codificar texto en formas de onda de audio, que puedes ver utilizando la vista de espectrograma (aunque una herramienta especializada llamada [Sonic Visualiser](http://www.sonicvisualiser.org/) es mejor para esta tarea en particular). Audacity también te permite ralentizar, revertir y realizar otras manipulaciones que podrían revelar un mensaje oculto si sospechas que hay uno (si puedes escuchar audio distorsionado, interferencia o estática). [Sox](http://sox.sourceforge.net/) es otra útil herramienta de línea de comandos para convertir y manipular archivos de audio.

También es común verificar los bits menos significativos (LSB) en busca de un mensaje secreto. La mayoría de los formatos de medios de audio y video utilizan "trozos" discretos (de tamaño fijo) para que puedan transmitirse; los LSB de esos trozos son un lugar común para contrabandear algunos datos sin afectar visiblemente el archivo.

Otras veces, un mensaje podría estar codificado en el audio como tonos [DTMF](http://dialabc.com/sound/detect/index.html) o código morse. Para estos casos, intenta trabajar con [multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng) para decodificarlos.

Los formatos de archivos de video son contenedores que contienen flujos separados de audio y video que se multiplexan juntos para la reproducción. Para analizar y manipular formatos de archivos de video, se recomienda [FFmpeg](http://ffmpeg.org/). `ffmpeg -i` proporciona un análisis inicial del contenido del archivo. También puede desmultiplexar o reproducir los flujos de contenido. El poder de FFmpeg se expone a Python mediante [ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html).

</details>
