{{#include ../../../banners/hacktricks-training.md}}

**Manipulacja plikami audio i wideo** jest podstawą w **wyzwaniach forensycznych CTF**, wykorzystując **steganografię** i analizę metadanych do ukrywania lub ujawniania tajnych wiadomości. Narzędzia takie jak **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** są niezbędne do inspekcji metadanych plików i identyfikacji typów zawartości.

W przypadku wyzwań audio, **[Audacity](http://www.audacityteam.org/)** wyróżnia się jako wiodące narzędzie do przeglądania fal dźwiękowych i analizy spektrogramów, co jest niezbędne do odkrywania tekstu zakodowanego w audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** jest gorąco polecane do szczegółowej analizy spektrogramów. **Audacity** umożliwia manipulację dźwiękiem, taką jak spowolnienie lub odwrócenie utworów w celu wykrycia ukrytych wiadomości. **[Sox](http://sox.sourceforge.net/)**, narzędzie wiersza poleceń, doskonale nadaje się do konwersji i edytowania plików audio.

Manipulacja **najmniej znaczącymi bitami (LSB)** jest powszechną techniką w steganografii audio i wideo, wykorzystującą stałe rozmiary fragmentów plików multimedialnych do dyskretnego osadzania danych. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** jest przydatne do dekodowania wiadomości ukrytych jako **tony DTMF** lub **kod Morse'a**.

Wyzwania wideo często obejmują formaty kontenerów, które łączą strumienie audio i wideo. **[FFmpeg](http://ffmpeg.org/)** jest narzędziem do analizy i manipulacji tymi formatami, zdolnym do demultipleksowania i odtwarzania zawartości. Dla programistów, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integruje możliwości FFmpeg z Pythonem dla zaawansowanych interakcji skryptowych.

Ta gama narzędzi podkreśla wszechstronność wymaganą w wyzwaniach CTF, gdzie uczestnicy muszą stosować szeroki wachlarz technik analizy i manipulacji, aby odkryć ukryte dane w plikach audio i wideo.

## References

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
