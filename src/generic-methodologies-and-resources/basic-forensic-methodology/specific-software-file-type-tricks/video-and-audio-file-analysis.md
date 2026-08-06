# Análisis de archivos de video y audio

{{#include ../../../banners/hacktricks-training.md}}

La **manipulación de archivos de audio y video** es un elemento fundamental en los **desafíos de forensics de CTF**, ya que utiliza **steganography** y el análisis de metadatos para ocultar o revelar mensajes secretos. Herramientas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** y **`exiftool`** son esenciales para inspeccionar los metadatos de los archivos e identificar los tipos de contenido.<sup>[[1]](#references)</sup>

Para los desafíos de audio, **[Audacity](http://www.audacityteam.org/)** destaca como una herramienta excelente para visualizar formas de onda y analizar espectrogramas, algo esencial para descubrir texto codificado en el audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** es muy recomendable para realizar análisis detallados de espectrogramas. **Audacity** permite manipular el audio, por ejemplo, ralentizando o invirtiendo pistas para detectar mensajes ocultos. **[Sox](http://sox.sourceforge.net/)**, una utilidad de línea de comandos, es especialmente eficaz para convertir y editar archivos de audio.<sup>[[1]](#references)</sup>

La manipulación de **Least Significant Bits (LSB)** es una técnica común en **steganography** de audio y video, que aprovecha los fragmentos de tamaño fijo de los archivos multimedia para incrustar datos discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** resulta útil para decodificar mensajes ocultos como **tonos DTMF** o **código Morse**.<sup>[[1]](#references)</sup>

Los desafíos de video suelen implicar formatos contenedores que agrupan streams de audio y video. **[FFmpeg](http://ffmpeg.org/)** es la herramienta principal para analizar y manipular estos formatos, ya que permite demultiplexar y reproducir el contenido. Para los desarrolladores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra las capacidades de FFmpeg en Python para realizar interacciones avanzadas mediante scripts.<sup>[[1]](#references)</sup>

Este conjunto de herramientas demuestra la versatilidad necesaria en los desafíos de CTF, donde los participantes deben emplear un amplio espectro de técnicas de análisis y manipulación para descubrir datos ocultos dentro de archivos de audio y video.

## Referencias

- [1] [Video and Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
