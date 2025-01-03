{{#include ../../../banners/hacktricks-training.md}}

**La manipulación de archivos de audio y video** es un elemento básico en **los desafíos forenses de CTF**, aprovechando **la esteganografía** y el análisis de metadatos para ocultar o revelar mensajes secretos. Herramientas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** y **`exiftool`** son esenciales para inspeccionar los metadatos de los archivos e identificar tipos de contenido.

Para los desafíos de audio, **[Audacity](http://www.audacityteam.org/)** se destaca como una herramienta principal para visualizar formas de onda y analizar espectrogramas, esenciales para descubrir texto codificado en audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** es muy recomendable para un análisis detallado de espectrogramas. **Audacity** permite la manipulación de audio, como ralentizar o invertir pistas para detectar mensajes ocultos. **[Sox](http://sox.sourceforge.net/)**, una utilidad de línea de comandos, sobresale en la conversión y edición de archivos de audio.

La manipulación de **Bits Menos Significativos (LSB)** es una técnica común en la esteganografía de audio y video, explotando los fragmentos de tamaño fijo de los archivos multimedia para incrustar datos de manera discreta. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** es útil para decodificar mensajes ocultos como **tonos DTMF** o **código Morse**.

Los desafíos de video a menudo implican formatos de contenedor que agrupan flujos de audio y video. **[FFmpeg](http://ffmpeg.org/)** es la herramienta preferida para analizar y manipular estos formatos, capaz de desmultiplexar y reproducir contenido. Para desarrolladores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra las capacidades de FFmpeg en Python para interacciones avanzadas y programables.

Esta variedad de herramientas subraya la versatilidad requerida en los desafíos de CTF, donde los participantes deben emplear un amplio espectro de técnicas de análisis y manipulación para descubrir datos ocultos dentro de archivos de audio y video.

## Referencias

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
