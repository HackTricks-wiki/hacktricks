# Analyse von Video- und Audiodateien

{{#include ../../../banners/hacktricks-training.md}}

**Die Manipulation von Audio- und Videodateien** ist ein fester Bestandteil von **CTF-Forensik-Challenges** und nutzt **Steganography** sowie die Metadatenanalyse, um geheime Nachrichten zu verbergen oder aufzudecken. Tools wie **[mediainfo](https://mediaarea.net/en/MediaInfo)** und **`exiftool`** sind unverzichtbar, um Dateimetadaten zu untersuchen und Inhaltstypen zu identifizieren.<sup>[[1]](#references)</sup>

Für Audio-Challenges ist **[Audacity](http://www.audacityteam.org/)** ein herausragendes Tool zum Anzeigen von Wellenformen und Analysieren von Spektrogrammen, was entscheidend ist, um in Audio codierten Text aufzudecken. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** wird für detaillierte Spektrogrammanalysen dringend empfohlen. **Audacity** ermöglicht die Audiomanipulation, etwa das Verlangsamen oder Umkehren von Tracks, um versteckte Nachrichten zu erkennen. **[Sox](http://sox.sourceforge.net/)**, ein Kommandozeilenprogramm, eignet sich hervorragend zum Konvertieren und Bearbeiten von Audiodateien.<sup>[[1]](#references)</sup>

Die Manipulation der **Least Significant Bits (LSB)** ist eine gängige Technik in der Audio- und Video-Steganography, bei der die Blöcke fester Größe von Mediendateien ausgenutzt werden, um Daten unauffällig einzubetten. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** eignet sich zum Decodieren von Nachrichten, die als **DTMF-Töne** oder **Morsecode** verborgen sind.<sup>[[1]](#references)</sup>

Video-Challenges beinhalten häufig Containerformate, die Audio- und Videostreams bündeln. **[FFmpeg](http://ffmpeg.org/)** ist das Standardtool zum Analysieren und Bearbeiten dieser Formate und kann Inhalte demultiplexen und wiedergeben. Für Entwickler integriert **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** die Funktionen von FFmpeg in Python und ermöglicht fortgeschrittene, skriptbasierte Interaktionen.<sup>[[1]](#references)</sup>

Diese Auswahl an Tools verdeutlicht die erforderliche Vielseitigkeit bei CTF-Challenges, bei denen Teilnehmer ein breites Spektrum an Analyse- und Manipulationstechniken einsetzen müssen, um versteckte Daten in Audio- und Videodateien aufzudecken.

## References

- [1] [Analyse von Video- und Audiodateien – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
