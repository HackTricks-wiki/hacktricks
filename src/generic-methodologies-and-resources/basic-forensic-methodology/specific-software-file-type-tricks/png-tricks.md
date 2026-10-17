# PNG trikovi

{{#include ../../../banners/hacktricks-training.md}}

**PNG fajlovi** su veoma česti u **CTF-ovima**, **odgovoru na incidente** i **pripremi malware-a** jer su **bez gubitaka**, **zasnovani na chunk-ovima**, a mnogi alati će ih bez problema prikazati čak i kada sadrže **dodatne metapodatke**, **dodatne payload-ove** ili **delimično oštećene chunk-ove**.

Posmatrajte PNG kao **kontejner**, a ne samo kao sliku.

## Brza trijaža

Pre nego što pređete na LSB steganografiju, počnite proverama na nivou kontejnera. Za postupak rada sa bit-plane/LSB proverite [posebnu stranicu o steganografiji slika](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Korisne stvari koje treba potražiti:

- **Neočekivani pomoćni chunkovi** kao što su `tEXt`, `zTXt`, `iTXt`, `eXIf` ili `iCCP`
- **CRC greške** ili neispravne dužine chunkova
- **Dodatni podaci nakon `IEND`**
- **Više `IEND` oznaka** ili fragmenti `IDAT` koji se mogu oporaviti nakon zvaničnog kraja datoteke
- Datoteka koja je validan PNG **i** izgleda kao ZIP/PDF/script kada se izdvoje ugrađeni podaci

Imajte na umu da je minimalna validna struktura obično:

- `IHDR` (mora biti prvi)
- `IDAT` (jedan ili više uzastopnih chunkova)
- `IEND` (mora biti poslednji)

## Podaci nakon `IEND`

Jedan od PNG artefakata sa najviše indikativne vrednosti jesu **podaci dodati nakon poslednjeg `IEND` chunka**. Mnogi dekoderi ih ignorišu, što ih čini korisnim za:

- **Jednostavan stego / skrivene payloadove**
- **PNG poliglote**
- **Pripremu malware-a**
- **Oporavak starijih podataka slike** iz neispravnih editora

Brza provera:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Pretraga bajtova za `IEND` samo je nagoveštaj: isti bajtovi mogu se pojaviti u podacima chunk-a ili u lažiranom trailer-u. Da biste pouzdano izdvojili podatke, pratite chunk-ove sa prefiksom dužine počevši od PNG potpisa i zaustavite se na prvom strukturnom `IEND`; [walker chunk-ova ispod](#extract-ancillary-chunk-payloads) čuva i trailer.<sup>[[6]](#references)</sup>

Isprobajte i generičke parsere arhiva direktno nad PNG-om ili izdvojenim trailer-om:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Oporavak isečenih/zatamnjenih snimaka ekrana u stilu Acropalypse

Veoma praktičan noviji PNG forenzički trik jeste da proverite da li je editor snimaka ekrana **prepisao** PNG, a da prethodno nije **skratio** stari fajl. U tim slučajevima, bajtovi iz **prethodne slike** mogu ostati posle `IEND`, a ponekad se mogu delimično rekonstruisati i dodatni `IDAT` podaci.

Ovo je postalo poznato zahvaljujući problemu **aCropalypse** (Google Pixel Markup) i povezanom problemu u **Windows Snipping Tool**.<sup>[[3]](#references)</sup> U praksi, ako „isečeni“ ili „zatamnjeni“ PNG i dalje sadrži stare podatke na kraju fajla, možda ćete moći da oporavite deo originalnog snimka ekrana.<sup>[[1]](#references)</sup>

Praktični postupak:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Znaci koji snažno opravdavaju detaljniju analizu:

- `pngcheck` prijavljuje **dodatne podatke posle `IEND`**
- Pronađete **više od jednog `IEND`**
- Pronađete **dodatne `IDAT` chunks** posle prividnog kraja slike
- Screenshot je napravljen uređajem/editorom za koji se zna da je bio pogođen

Ako se to desi, prosledite fajl **aCropalypse recovery tool-u** pre nego što redakciju smatrate pouzdanom.

## Zloupotreba chunk-ova koja je važna u praksi

Najzanimljiviji PNG chunk-ovi za istrage obično nisu oni očigledni za slike, već oni koji mogu da sadrže **tekst**, **metapodatke** ili **bajtove payload-a**:

- `tEXt` / `zTXt` / `iTXt` – tekstualni metapodaci i komprimovani tekst
- `eXIf` – EXIF podaci unutar PNG-a
- `iCCP` – ugrađeni ICC profil
- `PLTE` – podaci palete u indeksiranim slikama, ali su korisni i u scenarijima za prikrivanje payload-a.<sup>[[2]](#references)</sup>

Ispišite ih pomoću:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Za postojanost ofanzivnog payload-a unutar PNG chunkova (na primer, trikovi sa **PLTE**, **IDAT** ili **tEXt** koji opstaju nakon nekih PHP transformacija slika), pogledajte detaljnije beleške usmerene na upload ovde:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Izdvajanje payload-a iz pomoćnih chunkova

Napadač može da smesti proizvoljne bajtove u **nepoznati pomoćni chunk pre `IEND`**. Uobičajeni PNG dekoderi mogu da ignorišu nepoznati pomoćni chunk, dok skripta koja preuzima sliku kao niz bajtova može da pročita i iskoristi payload; samo otvaranje PNG-a ga ne izvršava.<sup>[[4]](#references)[[6]](#references)</sup> Originalno istraživanje prikazalo je komprimovani i šifrovani prilagođeni chunk.<sup>[[4]](#references)</sup> Kasniji primer u pregledaču koristio je izdvojene bajtove za prikaz HTML-a ili preuzimanje datoteke.<sup>[[5]](#references)</sup>

Malo slovo na prvoj poziciji u nazivu chunk-a označava *pomoćni* chunk; malo slovo na drugoj poziciji označava *privatni* chunk. Na primer, `paMP` je privatan, dok `pAMP` koristi javni namespace, iako je potonji naziv izmišljen za demonstraciju.<sup>[[4]](#references)[[6]](#references)</sup> Struktura chunk-a je `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC obuhvata type i data. Parsirajte ovu strukturu umesto da tražite naziv tipa unutar komprimovanih podataka `IDAT`. Sledeći parser proverava granice i CRC-ove, izvozi payload-e pomoćnih chunkova kao sirove bajtove i upisuje sve bajtove nakon strukturnog `IEND` u `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Izdvajanje pomoćnih chunkova i PNG trailera</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Pregledajte izdvojene bajtove pomoću `file`, `strings` ili `binwalk`; dekompresujte ih samo ako je carrier zaista kompresovan.<sup>[[4]](#references)</sup> Ponovno kodiranje može ukloniti carrier, zato uporedite bajtove pre otpremanja i nakon preuzimanja pre nego što se oslonite na njega.<sup>[[2]](#references)[[6]](#references)</sup>

## Popravka oštećenog PNG-a

Za proveru integriteta i pronalaženje tačnog oštećenog dela, **pngcheck** je i dalje jedan od najboljih alata za početak:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ako je fajl oštećen, a ne namerno zlonameran, **PCRT** može biti koristan u CTF-ovima i laboratorijskom radu za otklanjanje čestih problema kao što su neispravna zaglavlja, pogrešne IHDR vrednosti, problemi sa CRC-om ili neispravno oblikovan raspored chunk-ova.

Ako vam je cilj da **sanitize** PNG koji sadrži sumnjive podatke u završnom delu, a da sačuvate vidljivu sliku, ExifTool može izričito da ukloni završne podatke:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Za osetljive dokaze uvek radite na **kopiji** i sačuvajte hash vrednosti originala pre pokušaja popravke.



## References

- [1] [Iskorišćavanje aCropalypse: oporavak skraćenih PNG datoteka](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Trajni PHP payload-i u PNG datotekama: kako ubaciti PHP kod u sliku — i zadržati ga u njoj](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Pomoćni chunk-ovi su savršeno mesto za čuvanje osetljivih informacija](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Korišćenje validnih pomoćnih chunk-ova za krijumčarenje podataka do krajnje tačke](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Specifikacija Portable Network Graphics (PNG) (treće izdanje)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
