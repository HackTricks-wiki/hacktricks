# Análisis de archivos de video y audio

La **manipulación de archivos de audio y video** es fundamental en los **retos de forensics de CTF**, ya que utiliza **steganography** y el análisis de metadatos para ocultar o revelar mensajes secretos. Herramientas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** y **`exiftool`** son esenciales para inspeccionar los metadatos de los archivos e identificar los tipos de contenido.<sup>[[1]](#references)</sup>

Para los retos de audio, **[Audacity](http://www.audacityteam.org/)** destaca como una herramienta excelente para visualizar formas de onda y analizar espectrogramas, algo esencial para descubrir texto codificado en el audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** es muy recomendable para realizar análisis detallados de espectrogramas. **Audacity** permite manipular el audio, por ejemplo, ralentizando o invirtiendo las pistas para detectar mensajes ocultos. **[Sox](http://sox.sourceforge.net/)**, una utilidad de línea de comandos, destaca en la conversión y edición de archivos de audio.<sup>[[1]](#references)</sup>

La manipulación de **Least Significant Bits (LSB)** es una técnica común en la esteganografía de audio y video, que aprovecha los bloques de tamaño fijo de los archivos multimedia para insertar datos discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** es útil para decodificar mensajes ocultos como **tonos DTMF** o **código Morse**.<sup>[[1]](#references)</sup>

Los retos de video suelen incluir formatos contenedores que agrupan flujos de audio y video. **[FFmpeg](http://ffmpeg.org/)** es la herramienta principal para analizar y manipular estos formatos, ya que puede desmultiplexar y reproducir contenido. Para los desarrolladores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra las capacidades de FFmpeg en Python para interacciones avanzadas mediante scripts.<sup>[[1]](#references)</sup>

Esta variedad de herramientas subraya la versatilidad necesaria en los retos de CTF, donde los participantes deben emplear un amplio espectro de técnicas de análisis y manipulación para descubrir datos ocultos en archivos de audio y video.

## References

- [1] [Análisis de archivos de video y audio – Guía de campo de CTF de Trail of Bits](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
