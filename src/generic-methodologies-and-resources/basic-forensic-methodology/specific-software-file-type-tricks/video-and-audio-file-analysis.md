# Analiza plików wideo i audio

**Manipulowanie plikami audio i wideo** jest podstawą **wyzwań CTF z zakresu forensics**, wykorzystujących **steganografię** i analizę metadanych do ukrywania lub ujawniania tajnych wiadomości. Narzędzia takie jak **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** są niezbędne do sprawdzania metadanych plików i identyfikowania typów zawartości.<sup>[[1]](#references)</sup>

W przypadku wyzwań audio **[Audacity](http://www.audacityteam.org/)** wyróżnia się jako doskonałe narzędzie do wyświetlania przebiegów falowych i analizowania spektrogramów, co jest niezbędne do odkrywania tekstu zakodowanego w dźwięku. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** jest zdecydowanie polecany do szczegółowej analizy spektrogramów. **Audacity** umożliwia manipulowanie dźwiękiem, na przykład spowalnianie lub odwracanie ścieżek w celu wykrycia ukrytych wiadomości. **[Sox](http://sox.sourceforge.net/)**, narzędzie wiersza poleceń, doskonale sprawdza się przy konwertowaniu i edytowaniu plików audio.<sup>[[1]](#references)</sup>

Manipulowanie **Least Significant Bits (LSB)** jest powszechną techniką w steganografii audio i wideo, wykorzystującą stały rozmiar fragmentów plików multimedialnych do dyskretnego osadzania danych. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** jest przydatne do dekodowania wiadomości ukrytych jako **tony DTMF** lub **kod Morse’a**.<sup>[[1]](#references)</sup>

Wyzwania wideo często obejmują formaty kontenerów, które łączą strumienie audio i wideo. **[FFmpeg](http://ffmpeg.org/)** jest podstawowym narzędziem do analizowania i manipulowania tymi formatami, umożliwiającym demultipleksowanie i odtwarzanie zawartości. Dla deweloperów **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integruje możliwości FFmpeg z Pythonem, umożliwiając zaawansowane interakcje obsługiwane za pomocą skryptów.<sup>[[1]](#references)</sup>

Ten zestaw narzędzi podkreśla wszechstronność wymaganą w wyzwaniach CTF, w których uczestnicy muszą stosować szeroki zakres technik analizy i manipulowania, aby odkrywać ukryte dane w plikach audio i wideo.

## References

- [1] [Analiza plików wideo i audio – przewodnik terenowy Trail of Bits CTF](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
