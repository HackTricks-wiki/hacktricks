# PNG-truuks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-lêers** is baie algemeen in **CTFs**, **incident response** en **malware staging**, omdat hulle **verliesloos** en **gebaseer op chunks** is, en baie nutsmiddels hulle geredelik sal vertoon, selfs wanneer hulle **ekstra metadata**, **aangehegte payloads** of **gedeeltelik korrupte chunks** bevat.

Behandel ’n PNG as ’n **houer**, nie net as ’n beeld nie.

## Vinnige triage

Begin met kontrole op houervlak voordat jy met LSB-stego begin. Raadpleeg [die toegewyde bladsy oor beeldstego](../../../stego/images/) vir die bit-plane/LSB-werkvloei.

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Nuttige dinge om na te kyk:

- **Onverwagte aanvullende chunks** soos `tEXt`, `zTXt`, `iTXt`, `eXIf` of `iCCP`
- **CRC-foute** of verkeerd geformateerde chunk-lengtes
- **Bykomende data ná `IEND`**
- **Veelvuldige `IEND`-merkers** of herwinbare `IDAT`-fragmente ná die formele einde van die lêer
- ’n Lêer wat ’n geldige PNG is **en** ook soos ’n ZIP/PDF/script lyk wanneer dit uitgekerf word

Onthou, die minimum geldige struktuur is gewoonlik:

- `IHDR` (moet eerste wees)
- `IDAT` (een of meer opeenvolgende chunks)
- `IEND` (moet laaste wees)

## Agterblywende data ná `IEND`

Een van die duidelikste PNG-artefakte is **data wat ná die finale `IEND`-chunk aangeheg is**. Baie dekodeerders ignoreer dit, wat dit nuttig maak vir:

- **Eenvoudige stego / versteekte payloads**
- **PNG-polyglotte**
- **Malware-stadiëring**
- **Herwinning van ouer beelddata** uit foutiewe redigeerders

Vinnige opsporing:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

’n Byte-soektog na `IEND` is slegs ’n aanduiding: dieselfde grepe kan in chunk-data of in ’n vervalste sleepstuk voorkom. Om betroubaar data uit te haal, loop deur die lengtevoorafgaande chunks vanaf die PNG-handtekening en stop by die eerste strukturele `IEND`; die [chunk-walker hieronder](#extract-ancillary-chunk-payloads) stoor ook die sleepstuk.<sup>[[6]](#references)</sup>

Probeer ook generiese argiefontleders direk op die PNG of die uitgesnyde sleepstuk:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Herstel in Acropalypse-styl van afgesnyde/geredigeerde skermskote

’n Baie praktiese, onlangse PNG-forensiese truuk is om na te gaan of ’n skermskootredigeerder ’n PNG **oorskryf** het sonder om eers die ou lêer **af te sny**. In sulke gevalle kan grepe van die **vorige prent** ná `IEND` agterbly, en soms kan ekstra `IDAT`-data gedeeltelik gerekonstrueer word.

Dit het algemeen bekend geword met **aCropalypse** (Google Pixel Markup) en die verwante probleem met **Windows Snipping Tool**.<sup>[[3]](#references)</sup> In die praktyk kan jy dalk ’n deel van die oorspronklike skermskoot herwin as ’n "afgesnyde" of "geredigeerde" PNG steeds ou data aan die einde bevat.<sup>[[1]](#references)</sup>

Praktiese werkvloei:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Tekens wat sterk regverdig dat dieper ontleding gedoen word:

- `pngcheck` rapporteer **bykomende data ná `IEND`**
- Jy vind **meer as een `IEND`**
- Jy vind **ekstra `IDAT`-chunks** ná die skynbare einde van die beeld
- Die skermskoot kom van ’n toestel/redigeerder waarvan bekend is dat dit geraak is

As dit gebeur, voer die lêer deur ’n **aCropalypse recovery tool** voordat jy die redigering as betroubaar beskou.

## Chunk-misbruik wat in die praktyk saak maak

Die interessantste PNG-chunks vir ondersoeke is gewoonlik nie die ooglopende beeld-chunks nie, maar die chunks wat **teks**, **metadata** of **payload-grepe** kan bevat:

- `tEXt` / `zTXt` / `iTXt` – teksmetadata en saamgeperste teks
- `eXIf` – EXIF-data binne PNG
- `iCCP` – ingebedde ICC-profiel
- `PLTE` – paletdata in geïndekseerde beelde, maar ook nuttig in payload-smuggling-scenario’s.<sup>[[2]](#references)</sup>

Dump hulle met:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Vir volharding van offensiewe payloads binne PNG-chunks (byvoorbeeld **PLTE**-, **IDAT**- of **tEXt**-truuks wat sommige PHP-beeldtransformasies oorleef), kyk na die meer gedetailleerde notas oor oplaaie hier:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Onttrek payloads uit ancillary-chunks

’n Aanvaller kan arbitrêre grepe in ’n **onbekende ancillary-chunk voor `IEND`** plaas. Gewone PNG-dekodeerders kan ’n onbekende ancillary-chunk ignoreer, terwyl ’n script wat die beeld as grepe ophaal, die payload kan lees en gebruik; om die PNG bloot oop te maak, voer dit nie uit nie.<sup>[[4]](#references)[[6]](#references)</sup> Die oorspronklike navorsing het ’n saamgeperste en geënkripteerde pasgemaakte chunk gedemonstreer.<sup>[[4]](#references)</sup> ’n Latere blaaier-voorbeeld het die onttrekte grepe gebruik om HTML of ’n aflaai te verskaf.<sup>[[5]](#references)</sup>

’n Kleinletter as die eerste letter van die chunktipe beteken *ancillary*; ’n kleinletter as die tweede letter beteken *privaat*. `paMP` is byvoorbeeld privaat, terwyl `pAMP` die publieke naamruimte gebruik, hoewel laasgenoemde vir die demonstrasie uitgedink is.<sup>[[4]](#references)[[6]](#references)</sup> ’n Chunk het die formaat `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC dek die tipe en data. Ontleed hierdie struktuur eerder as om met grep na ’n tipenaam in saamgeperste `IDAT`-data te soek. Die volgende deurstapper valideer grense en CRC’s, voer ancillary-payloads as rou grepe uit en skryf enige grepe ná die strukturele `IEND` na `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Sny ancillary-chunks en die PNG-sleepstuk uit</summary>

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

Inspekteer gekerfde grepe met `file`, `strings` of `binwalk`; dekomprimeer dit slegs as die draer werklik saamgepers is.<sup>[[4]](#references)</sup> Herkodering kan die draer verwyder, so vergelyk die opgelaaide en teruggekryde grepe voordat jy daarop staatmaak.<sup>[[2]](#references)[[6]](#references)</sup>

## Herstel van beskadigde PNG's

Vir integriteitskontroles en om die presiese beskadigde area op te spoor, bly **pngcheck** een van die beste eerste hulpmiddels:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

As die lêer beskadig is eerder as opsetlik kwaadwillig, kan **PCRT** nuttig wees in CTF's en laboratoriumwerk om algemene probleme reg te stel, soos foutiewe opskrifte, verkeerde IHDR-waardes, CRC-probleme of verkeerd gevormde brokuitlegte.

As jou doel is om 'n PNG met verdagte sleepdata te **saneer**, terwyl die sigbare beeld behoue bly, kan ExifTool die sleepdata uitdruklik verwyder:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Vir sensitiewe bewyse, werk altyd op ’n **kopie** en bewaar hashes van die oorspronklike voordat jy herstelwerk probeer doen.



## References

- [1] [Uitbuiting van aCropalypse: Herstel van afgesnyde PNG’s](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Aanhoudende PHP-payloads in PNG’s: Hoe om PHP-kode in ’n beeld in te sluit – en dit daar te hou](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Aanvullende blokke is die perfekte plek om sensitiewe inligting weg te bêre](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Gebruik geldige aanvullende blokke om data na ’n eindpunt te smokkel](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Draagbare netwerkbeelde (PNG)-spesifikasie (derde uitgawe)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
