# Uchambuzi wa Faili za Video na Audio

{{#include ../../../banners/hacktricks-training.md}}

**Ubadilishaji wa faili za audio na video** ni sehemu muhimu katika **CTF forensics challenges**, ukitumia **steganography** na uchanganuzi wa metadata kuficha au kufichua ujumbe wa siri. Zana kama vile **[mediainfo](https://mediaarea.net/en/MediaInfo)** na **`exiftool`** ni muhimu kwa kukagua metadata ya faili na kutambua aina za maudhui.<sup>[[1]](#references)</sup>

Kwa challenges za audio, **[Audacity](http://www.audacityteam.org/)** ni zana bora ya kuangalia waveforms na kuchanganua spectrograms, ambazo ni muhimu kwa kugundua maandishi yaliyosimbwa kwenye audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** inapendekezwa sana kwa uchanganuzi wa kina wa spectrogram. **Audacity** inaruhusu urekebishaji wa audio, kama vile kupunguza kasi au kugeuza tracks, ili kugundua ujumbe uliofichwa. **[Sox](http://sox.sourceforge.net/)**, utility ya command-line, ni bora katika kubadilisha na kuhariri faili za audio.<sup>[[1]](#references)</sup>

Ubadilishaji wa **Least Significant Bits (LSB)** ni mbinu inayotumika sana katika steganography ya audio na video, ikitumia chunks zenye ukubwa maalum za faili za media kuingiza data kwa njia isiyotambulika kwa urahisi. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** ni muhimu kwa kusimbua ujumbe uliofichwa kama **DTMF tones** au **Morse code**.<sup>[[1]](#references)</sup>

Challenges za video mara nyingi huhusisha container formats zinazounganisha streams za audio na video. **[FFmpeg](http://ffmpeg.org/)** ndiyo zana kuu ya kuchanganua na kurekebisha formats hizi, ikiwa na uwezo wa de-multiplexing na playback ya maudhui. Kwa developers, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** huunganisha uwezo wa FFmpeg na Python kwa mwingiliano wa hali ya juu unaoweza kuandikwa kwa scripts.<sup>[[1]](#references)</sup>

Mkusanyiko huu wa zana unaonyesha uwezo mpana unaohitajika katika CTF challenges, ambapo washiriki lazima watumie mbinu mbalimbali za uchanganuzi na urekebishaji ili kufichua data iliyofichwa ndani ya faili za audio na video.

## Marejeleo

- [1] [Video and Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
