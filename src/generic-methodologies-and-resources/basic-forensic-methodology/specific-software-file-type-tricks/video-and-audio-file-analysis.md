# Analiza video i audio datoteka

{{#include ../../../banners/hacktricks-training.md}}

**Manipulacija audio i video datotekama** predstavlja osnovu **CTF forenzičkih izazova**, koristeći **steganography** i analizu metapodataka za skrivanje ili otkrivanje tajnih poruka. Alati kao što su **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** neophodni su za pregled metapodataka datoteke i prepoznavanje tipova sadržaja.<sup>[[1]](#references)</sup>

Za audio izazove, **[Audacity](http://www.audacityteam.org/)** se izdvaja kao vrhunski alat za prikaz talasnih oblika i analizu spektrograma, što je neophodno za otkrivanje teksta kodiranog u audio-zapisu. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** se veoma preporučuje za detaljnu analizu spektrograma. **Audacity** omogućava manipulaciju zvukom, poput usporavanja ili reprodukcije numera unazad, radi otkrivanja skrivenih poruka. **[Sox](http://sox.sourceforge.net/)**, komandnolinijski uslužni program, odličan je za konvertovanje i uređivanje audio datoteka.<sup>[[1]](#references)</sup>

Manipulacija **Least Significant Bits (LSB)** uobičajena je tehnika u audio i video steganography, koja iskorišćava blokove fiksne veličine medijskih datoteka za diskretno ugrađivanje podataka. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** je koristan za dekodiranje poruka sakrivenih kao **DTMF tonovi** ili **Morse code**.<sup>[[1]](#references)</sup>

Video izazovi često uključuju container formate koji objedinjuju audio i video stream-ove. **[FFmpeg](http://ffmpeg.org/)** je glavni alat za analizu i manipulaciju ovim formatima, sa mogućnošću demultipleksiranja i reprodukcije sadržaja. Za developere, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integriše mogućnosti FFmpeg-a u Python radi naprednih interakcija koje se mogu izvršavati kroz skripte.<sup>[[1]](#references)</sup>

Ovaj skup alata naglašava svestranost potrebnu u CTF izazovima, gde učesnici moraju da primenjuju širok spektar tehnika analize i manipulacije kako bi otkrili skrivene podatke unutar audio i video datoteka.

## References

- [1] [Analiza video i audio datoteka – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
