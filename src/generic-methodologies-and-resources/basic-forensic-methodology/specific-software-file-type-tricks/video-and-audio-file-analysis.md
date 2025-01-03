{{#include ../../../banners/hacktricks-training.md}}

**La manipulation de fichiers audio et vidéo** est un élément essentiel des **défis d'analyse judiciaire CTF**, utilisant **la stéganographie** et l'analyse des métadonnées pour cacher ou révéler des messages secrets. Des outils tels que **[mediainfo](https://mediaarea.net/en/MediaInfo)** et **`exiftool`** sont indispensables pour inspecter les métadonnées des fichiers et identifier les types de contenu.

Pour les défis audio, **[Audacity](http://www.audacityteam.org/)** se distingue comme un outil de premier plan pour visualiser les formes d'onde et analyser les spectrogrammes, essentiel pour découvrir le texte encodé dans l'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** est fortement recommandé pour une analyse détaillée des spectrogrammes. **Audacity** permet la manipulation audio comme ralentir ou inverser des pistes pour détecter des messages cachés. **[Sox](http://sox.sourceforge.net/)**, un utilitaire en ligne de commande, excelle dans la conversion et l'édition de fichiers audio.

La manipulation des **bits de poids faible (LSB)** est une technique courante en stéganographie audio et vidéo, exploitant les morceaux de taille fixe des fichiers multimédias pour intégrer des données discrètement. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** est utile pour décoder des messages cachés sous forme de **tons DTMF** ou de **code Morse**.

Les défis vidéo impliquent souvent des formats de conteneur qui regroupent des flux audio et vidéo. **[FFmpeg](http://ffmpeg.org/)** est l'outil de référence pour analyser et manipuler ces formats, capable de démultiplexer et de lire le contenu. Pour les développeurs, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** intègre les capacités de FFmpeg dans Python pour des interactions scriptables avancées.

Cette gamme d'outils souligne la polyvalence requise dans les défis CTF, où les participants doivent employer un large éventail de techniques d'analyse et de manipulation pour découvrir des données cachées dans des fichiers audio et vidéo.

## Références

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
