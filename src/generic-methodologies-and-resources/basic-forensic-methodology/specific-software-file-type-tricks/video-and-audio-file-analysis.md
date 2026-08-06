# Analiza video i audio datoteka

{{#include ../../../banners/hacktricks-training.md}}

**Manipulacija audio i video datotekama** predstavlja osnovu **CTF forensics izazova**, uz korišćenje **steganography** i analize metapodataka za skrivanje ili otkrivanje tajnih poruka. Alati kao što su **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** ključni su za pregled metapodataka datoteke i identifikovanje tipova sadržaja.<sup>[[1]](#references)</sup>

Za audio izazove, **[Audacity](http://www.audacityteam.org/)** se izdvaja kao vodeći alat za prikaz talasnih oblika i analizu spektrograma, što je ključno za otkrivanje teksta kodiranog u zvuku. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** se veoma preporučuje za detaljnu analizu spektrograma. **Audacity** omogućava manipulaciju zvukom, poput usporavanja ili reprodukovanja unazad, kako bi se otkrile skrivene poruke. **[Sox](http://sox.sourceforge.net/)** je alat komandne linije koji je odličan za konvertovanje i uređivanje audio datoteka.<sup>[[1]](#references)</sup>

Manipulacija **Least Significant Bits (LSB)** predstavlja uobičajenu tehniku u audio i video steganography, koja koristi blokove fiksne veličine u medijskim datotekama za diskretno ugrađivanje podataka. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** je koristan za dekodiranje poruka skrivenih kao **DTMF tonovi** ili **Morseov kod**.<sup>[[1]](#references)</sup>

Video izazovi često uključuju formate kontejnera koji objedinjuju audio i video tokove. **[FFmpeg](http://ffmpeg.org/)** je standardni alat za analizu i manipulaciju ovim formatima, sa mogućnošću demultipleksiranja i reprodukcije sadržaja. Za developere, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integriše mogućnosti FFmpeg-a u Python radi naprednih interakcija koje se mogu izvršavati kroz skripte.<sup>[[1]](#references)</sup>

Ovaj skup alata naglašava svestranost potrebnu u CTF izazovima, u kojima učesnici moraju da primene širok spektar tehnika analize i manipulacije kako bi otkrili skrivene podatke unutar audio i video datoteka.

## Reference

- [1] [Video and Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
