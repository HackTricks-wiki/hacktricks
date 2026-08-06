# Analyse von Video- und Audiodateien

{{#include ../../../banners/hacktricks-training.md}}

**Die Manipulation von Audio- und Videodateien** ist ein fester Bestandteil von **CTF-Forensik-Challenges**, wobei **steganography** und die Analyse von Metadaten eingesetzt werden, um geheime Nachrichten zu verbergen oder aufzudecken. Tools wie **[mediainfo](https://mediaarea.net/en/MediaInfo)** und **`exiftool`** sind unverzichtbar, um Dateimetadaten zu untersuchen und Inhaltstypen zu identifizieren.<sup>[[1]](#references)</sup>

Für Audio-Challenges ist **[Audacity](http://www.audacityteam.org/)** ein herausragendes Tool zur Darstellung von Wellenformen und zur Analyse von Spektrogrammen, was entscheidend ist, um in Audiodateien codierten Text aufzudecken. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** wird für eine detaillierte Spektrogrammanalyse dringend empfohlen. **Audacity** ermöglicht Audiomanipulationen wie das Verlangsamen oder Umkehren von Tracks, um versteckte Nachrichten zu erkennen. **[Sox](http://sox.sourceforge.net/)**, ein Kommandozeilen-Tool, eignet sich hervorragend zum Konvertieren und Bearbeiten von Audiodateien.<sup>[[1]](#references)</sup>

Die Manipulation der **Least Significant Bits (LSB)** ist eine gängige Technik in der Audio- und Video-steganography. Dabei werden die Blöcke mit fester Größe von Mediendateien genutzt, um Daten unauffällig einzubetten. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** ist nützlich, um Nachrichten zu decodieren, die als **DTMF-Töne** oder **Morsecode** verborgen wurden.<sup>[[1]](#references)</sup>

Video-Challenges beinhalten häufig Containerformate, die Audio- und Videostreams bündeln. **[FFmpeg](http://ffmpeg.org/)** ist das bevorzugte Tool zur Analyse und Manipulation dieser Formate und kann Inhalte demultiplexen und wiedergeben. Für Entwickler integriert **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** die Funktionen von FFmpeg in Python und ermöglicht fortgeschrittene, skriptbasierte Interaktionen.<sup>[[1]](#references)</sup>

Diese Auswahl an Tools verdeutlicht die erforderliche Vielseitigkeit bei CTF-Challenges, bei denen Teilnehmer ein breites Spektrum an Analyse- und Manipulationstechniken einsetzen müssen, um verborgene Daten in Audio- und Videodateien aufzudecken.

## Referenzen

- [1] [Analyse von Video- und Audiodateien – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
