{{#include ../../../banners/hacktricks-training.md}}

**Ushughulikiaji wa faili za sauti na video** ni msingi katika **changamoto za forensics za CTF**, ikitumia **steganography** na uchambuzi wa metadata kuficha au kufichua ujumbe wa siri. Zana kama **[mediainfo](https://mediaarea.net/en/MediaInfo)** na **`exiftool`** ni muhimu kwa kukagua metadata ya faili na kubaini aina za maudhui.

Kwa changamoto za sauti, **[Audacity](http://www.audacityteam.org/)** inajitokeza kama zana bora ya kutazama mawimbi na kuchambua spectrograms, muhimu kwa kugundua maandiko yaliyoandikwa katika sauti. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** inapendekezwa sana kwa uchambuzi wa kina wa spectrogram. **Audacity** inaruhusu ushawishi wa sauti kama vile kupunguza kasi au kurudisha nyimbo ili kugundua ujumbe uliofichwa. **[Sox](http://sox.sourceforge.net/)**, zana ya amri, inajitahidi katika kubadilisha na kuhariri faili za sauti.

**Least Significant Bits (LSB)** ushawishi ni mbinu ya kawaida katika steganography ya sauti na video, ikitumia vipande vya saizi thabiti vya faili za media kuficha data kwa siri. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** ni muhimu kwa kufungua ujumbe uliofichwa kama **DTMF tones** au **Morse code**.

Changamoto za video mara nyingi zinahusisha muundo wa kontena unaounganisha mstreams ya sauti na video. **[FFmpeg](http://ffmpeg.org/)** ndiyo chaguo bora kwa kuchambua na kushughulikia muundo hizi, ikiwa na uwezo wa ku-de-multiplex na kucheza maudhui. Kwa waendelezaji, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** inachanganya uwezo wa FFmpeg ndani ya Python kwa mwingiliano wa hali ya juu wa kuandikwa.

Mfululizo huu wa zana unasisitiza ufanisi unaohitajika katika changamoto za CTF, ambapo washiriki wanapaswa kutumia anuwai ya mbinu za uchambuzi na ushawishi ili kugundua data iliyofichwa ndani ya faili za sauti na video.

## References

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
