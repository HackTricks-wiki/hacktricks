# Analiza video i audio datoteka

**Manipulacija audio i video datotekama** predstavlja osnovu **CTF forensics izazova**, pri čemu se koriste **steganography** i analiza metapodataka za skrivanje ili otkrivanje tajnih poruka. Alati kao što su **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** neophodni su za pregled metapodataka datoteka i identifikovanje tipova sadržaja.<sup>[[1]](#references)</sup>

Za audio izazove, **[Audacity](http://www.audacityteam.org/)** se ističe kao vrhunski alat za prikaz talasnih oblika i analizu spektrograma, što je ključno za otkrivanje teksta kodiranog u zvuku. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** se veoma preporučuje za detaljnu analizu spektrograma. **Audacity** omogućava manipulaciju zvukom, kao što je usporavanje ili obrtanje numera radi otkrivanja skrivenih poruka. **[Sox](http://sox.sourceforge.net/)**, command-line alat, odličan je za konvertovanje i uređivanje audio datoteka.<sup>[[1]](#references)</sup>

Manipulacija **Least Significant Bits (LSB)** predstavlja uobičajenu tehniku u audio i video steganografiji, koja koristi blokove fiksne veličine u medijskim datotekama za diskretno umetanje podataka. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** je koristan za dekodiranje poruka skrivenih kao **DTMF tonovi** ili **Morseov kod**.<sup>[[1]](#references)</sup>

Video izazovi često obuhvataju container formate koji objedinjuju audio i video streamove. **[FFmpeg](http://ffmpeg.org/)** je standardni alat za analizu i manipulaciju ovim formatima, sa mogućnošću de-multipleksiranja i reprodukcije sadržaja. Za developere, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integriše mogućnosti FFmpeg-a u Python radi naprednih interakcija koje se mogu izvršavati kroz skripte.<sup>[[1]](#references)</sup>

Ovaj skup alata naglašava svestranost potrebnu u CTF izazovima, gde učesnici moraju da primene širok spektar tehnika za analizu i manipulaciju kako bi otkrili skrivene podatke u audio i video datotekama.

## References

- [1] [Analiza video i audio datoteka – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
