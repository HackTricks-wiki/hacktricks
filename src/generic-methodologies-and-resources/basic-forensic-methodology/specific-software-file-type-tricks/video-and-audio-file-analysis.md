# Analyse des fichiers vidéo et audio

{{#include ../../../banners/hacktricks-training.md}}

La **manipulation de fichiers audio et vidéo** est un élément essentiel des **CTF forensics challenges**, utilisant la **stéganographie** et l’analyse des métadonnées pour dissimuler ou révéler des messages secrets. Des outils tels que **[mediainfo](https://mediaarea.net/en/MediaInfo)** et **`exiftool`** sont essentiels pour examiner les métadonnées des fichiers et identifier les types de contenu.<sup>[[1]](#references)</sup>

Pour les challenges audio, **[Audacity](http://www.audacityteam.org/)** se distingue comme un outil de premier plan pour afficher les formes d’onde et analyser les spectrogrammes, ce qui est essentiel pour découvrir du texte encodé dans l’audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** est vivement recommandé pour une analyse détaillée des spectrogrammes. **Audacity** permet de manipuler l’audio, par exemple en ralentissant ou en inversant les pistes afin de détecter des messages cachés. **[Sox](http://sox.sourceforge.net/)**, un utilitaire en ligne de commande, est particulièrement adapté à la conversion et à l’édition de fichiers audio.<sup>[[1]](#references)</sup>

La manipulation des **Least Significant Bits (LSB)** est une technique courante en stéganographie audio et vidéo. Elle exploite les blocs de taille fixe des fichiers multimédias pour y intégrer discrètement des données. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** est utile pour décoder des messages dissimulés sous forme de **tonalités DTMF** ou de **code Morse**.<sup>[[1]](#references)</sup>

Les challenges vidéo impliquent souvent des formats conteneurs qui regroupent des flux audio et vidéo. **[FFmpeg](http://ffmpeg.org/)** est l’outil de référence pour analyser et manipuler ces formats, et il permet de démultiplexer et de lire le contenu. Pour les développeurs, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** intègre les fonctionnalités de FFmpeg dans Python pour permettre des interactions avancées et scriptables.<sup>[[1]](#references)</sup>

Cet ensemble d’outils souligne la polyvalence requise dans les challenges CTF, où les participants doivent employer un large éventail de techniques d’analyse et de manipulation pour découvrir des données cachées dans des fichiers audio et vidéo.

## Références

- [1] [Video and Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
