{{#include ../../../banners/hacktricks-training.md}}

**Manipulacija audio i video fajlovima** je osnovna komponenta u **CTF forenzičkim izazovima**, koristeći **steganografiju** i analizu metapodataka za skrivanje ili otkrivanje tajnih poruka. Alati kao što su **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** su neophodni za inspekciju metapodataka fajlova i identifikaciju tipova sadržaja.

Za audio izazove, **[Audacity](http://www.audacityteam.org/)** se ističe kao vrhunski alat za pregled talasnih oblika i analizu spektrograma, što je ključno za otkrivanje teksta kodiranog u audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** se toplo preporučuje za detaljnu analizu spektrograma. **Audacity** omogućava manipulaciju audio sadržajem kao što su usporavanje ili preokretanje pesama kako bi se otkrile skrivene poruke. **[Sox](http://sox.sourceforge.net/)**, alat za komandnu liniju, odlično se snalazi u konvertovanju i uređivanju audio fajlova.

**Manipulacija najmanje značajnim bitovima (LSB)** je uobičajena tehnika u audio i video steganografiji, koristeći fiksne veličine delova medijskih fajlova za diskretno umetanje podataka. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** je koristan za dekodiranje poruka skrivenih kao **DTMF tonovi** ili **Morseova azbuka**.

Video izazovi često uključuju kontejnerske formate koji kombinuju audio i video tokove. **[FFmpeg](http://ffmpeg.org/)** je alat koji se koristi za analizu i manipulaciju ovim formatima, sposoban za de-multiplexing i reprodukciju sadržaja. Za programere, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integriše FFmpeg-ove mogućnosti u Python za napredne skriptabilne interakcije.

Ova paleta alata naglašava svestranost potrebnu u CTF izazovima, gde učesnici moraju koristiti širok spektar tehnika analize i manipulacije kako bi otkrili skrivene podatke unutar audio i video fajlova.

## References

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
