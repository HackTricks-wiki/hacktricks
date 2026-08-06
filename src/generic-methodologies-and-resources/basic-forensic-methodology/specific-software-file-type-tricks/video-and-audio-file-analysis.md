# Video- en oudiolêerontleding

{{#include ../../../banners/hacktricks-training.md}}

**Manipulering van audio- en videolêers** is 'n kernonderdeel van **CTF-forensicsuitdagings**, wat **steganography** en metadata-ontleding gebruik om geheime boodskappe te versteek of bloot te lê. Tools soos **[mediainfo](https://mediaarea.net/en/MediaInfo)** en **`exiftool`** is noodsaaklik om lêermetadata te inspekteer en inhoudtipes te identifiseer.<sup>[[1]](#references)</sup>

Vir audio-uitdagings staan **[Audacity](http://www.audacityteam.org/)** uit as 'n uitstekende tool om golfvorms te bekyk en spektrogramme te ontleed, wat noodsaaklik is om teks te ontdek wat in audio geënkodeer is. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** word sterk aanbeveel vir gedetailleerde spektrogramontleding. **Audacity** maak audio-manipulering moontlik, soos om snitte stadiger te maak of om te keer om versteekte boodskappe op te spoor. **[Sox](http://sox.sourceforge.net/)**, 'n command-line utility, blink uit met die omskakeling en redigering van oudiolêers.<sup>[[1]](#references)</sup>

Manipulering van **Least Significant Bits (LSB)** is 'n algemene tegniek in audio- en videosteganography, wat die vaste-grootte brokke van medialêers benut om data diskreet in te bed. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** is nuttig om boodskappe te dekodeer wat as **DTMF-tones** of **Morse-kode** versteek is.<sup>[[1]](#references)</sup>

Video-uitdagings behels dikwels container-formate wat audio- en videostrome bundel. **[FFmpeg](http://ffmpeg.org/)** is die voorkeurtool vir die ontleding en manipulering van hierdie formate, en kan inhoud demultipleks en terugspeel. Vir developers integreer **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** FFmpeg se vermoëns in Python vir gevorderde, skripteerbare interaksies.<sup>[[1]](#references)</sup>

Hierdie reeks tools beklemtoon die veelsydigheid wat in CTF-uitdagings vereis word, waar deelnemers 'n breë spektrum van ontledings- en manipuleringstegnieke moet gebruik om versteekte data binne audio- en videolêers bloot te lê.

## Verwysings

- [1] [Ontleding van video- en oudiolêers – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
