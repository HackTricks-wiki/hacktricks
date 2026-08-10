# Analyse des fichiers vidéo et audio

La **manipulation des fichiers audio et vidéo** est un élément incontournable des **CTF forensics challenges**, exploitant la **steganography** et l'analyse des metadata pour dissimuler ou révéler des messages secrets. Des outils tels que **[mediainfo](https://mediaarea.net/en/MediaInfo)** et **`exiftool`** sont essentiels pour inspecter les metadata des fichiers et identifier les types de contenu.<sup>[[1]](#references)</sup>

Pour les challenges audio, **[Audacity](http://www.audacityteam.org/)** se distingue comme un outil de premier plan pour visualiser les formes d'onde et analyser les spectrogrammes, ce qui est essentiel pour découvrir du texte encodé dans l'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** est vivement recommandé pour une analyse détaillée des spectrogrammes. **Audacity** permet de manipuler l'audio, notamment en ralentissant ou en inversant les pistes afin de détecter des messages cachés. **[Sox](http://sox.sourceforge.net/)**, un utilitaire en ligne de commande, excelle dans la conversion et l'édition des fichiers audio.<sup>[[1]](#references)</sup>

La manipulation des **Least Significant Bits (LSB)** est une technique courante en steganography audio et vidéo, qui exploite les blocs de taille fixe des fichiers multimédias pour y intégrer discrètement des données. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** est utile pour décoder des messages dissimulés sous forme de **DTMF tones** ou de **Morse code**.<sup>[[1]](#references)</sup>

Les challenges vidéo impliquent souvent des formats conteneurs regroupant des flux audio et vidéo. **[FFmpeg](http://ffmpeg.org/)** est l'outil de référence pour analyser et manipuler ces formats, avec la capacité de démultiplexer et de lire leur contenu. Pour les développeurs, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** intègre les fonctionnalités de FFmpeg dans Python pour permettre des interactions avancées et scriptables.<sup>[[1]](#references)</sup>

Cet ensemble d'outils souligne la polyvalence requise dans les CTF challenges, où les participants doivent utiliser un large éventail de techniques d'analyse et de manipulation pour découvrir les données cachées dans les fichiers audio et vidéo.

## References

- [1] [Analyse des fichiers vidéo et audio – CTF Field Guide de Trail of Bits](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
