# Mbinu za PNG

{{#include ../../../banners/hacktricks-training.md}}

**Faili za PNG** ni za kawaida sana katika **CTFs**, **incident response**, na **malware staging** kwa sababu **hazipotezi ubora**, zimeundwa kwa **chunks**, na zana nyingi huzionyesha bila shida hata zinapokuwa na **metadata ya ziada**, **payloads zilizoongezwa mwishoni**, au **chunks zilizoharibika kwa sehemu**.

Ichukulie PNG kama **kontena**, si picha tu.

## Ukaguzi wa haraka

Anza kwa ukaguzi wa kiwango cha kontena kabla ya kuanza kutumia LSB stego. Kwa mtiririko wa kazi wa bit-plane/LSB, angalia [ukurasa maalum wa image stego](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Vitu muhimu vya kutafuta:

- **Chunks saidizi zisizotarajiwa** kama `tEXt`, `zTXt`, `iTXt`, `eXIf`, au `iCCP`
- **Hitilafu za CRC** au urefu wa chunk usio sahihi
- **Data ya ziada baada ya `IEND`**
- **Alama nyingi za `IEND`** au vipande vya `IDAT` vinavyoweza kurejeshwa baada ya mwisho rasmi wa faili
- Faili ambayo ni PNG halali **na** pia inaonekana kama ZIP/PDF/script inapochanganuliwa kwa carving

Kumbuka kwamba muundo halali wa chini kabisa kwa kawaida ni:

- `IHDR` (lazima iwe ya kwanza)
- `IDAT` (chunk moja au zaidi zinazofuatana)
- `IEND` (lazima iwe ya mwisho)

## Data inayofuata baada ya `IEND`

Mojawapo ya viashiria vya PNG vinavyoonyesha jambo kwa uwazi zaidi ni **data iliyoongezwa baada ya chunk ya mwisho ya `IEND`**. Decoders nyingi huipuuza, hivyo inafaa kwa:

- **Stego rahisi / payload zilizofichwa**
- **PNG polyglots**
- **Kuweka malware kwa hatua**
- **Kurejesha data ya zamani ya picha** kutoka kwa vihariri vyenye hitilafu

Ugunduzi wa haraka:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Utafutaji wa byte za `IEND` ni kidokezo tu: byte hizo hizo zinaweza kutokea kwenye data ya chunk au kwenye trailer ya kughushi. Ili kufanya carve kwa uhakika, fuatilia chunk zenye urefu uliotangulia kutoka kwenye saini ya PNG na usimame kwenye `IEND` ya kwanza ya kimuundo; [chunk walker iliyo hapa chini](#extract-ancillary-chunk-payloads) pia huhifadhi trailer.<sup>[[6]](#references)</sup>

Pia jaribu kutumia parser za jumla za archive moja kwa moja kwenye PNG au trailer iliyochongwa:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Urejeshaji wa picha za skrini zilizokatwa/kufichwa kwa mtindo wa Acropalypse

Mbinu ya hivi karibuni na ya vitendo ya uchunguzi wa PNG ni kuangalia ikiwa kihariri cha picha za skrini **kiliandika juu ya** PNG bila **kupunguza** ukubwa wa faili ya zamani kwanza. Katika hali hizo, baiti kutoka **picha ya awali** zinaweza kubaki baada ya `IEND`, na wakati mwingine data ya ziada ya `IDAT` inaweza kujengwa upya kwa sehemu.

Hili lilijulikana sana kupitia **aCropalypse** (Google Pixel Markup) na tatizo linalohusiana nalo la **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Kwa vitendo, ikiwa PNG "iliyokatwa" au "iliyofichwa" bado ina data ya zamani mwishoni, huenda ukaweza kurejesha sehemu ya picha ya skrini ya awali.<sup>[[1]](#references)</sup>

Mtiririko wa kazi wa vitendo:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Dalili zinazohalalisha uchunguzi wa kina:

- `pngcheck` inaripoti **data ya ziada baada ya `IEND`**
- Unapata zaidi ya `IEND` moja
- Unapata **chunks za `IDAT` za ziada** baada ya mwisho unaoonekana wa picha
- Picha ya skrini ilitoka kwenye kifaa/kihariri kinachojulikana kuwa kiliathiriwa

Hili likitokea, tumia **aCropalypse recovery tool** kuchunguza faili kabla ya kuamini kuwa maudhui yamefichwa.

## Matumizi mabaya ya chunks yanayohusika kwa vitendo

Chunks za PNG zinazovutia zaidi katika uchunguzi kwa kawaida si zile za picha zilizo wazi, bali ni chunks zinazoweza kubeba **maandishi**, **metadata**, au **byte za payload**:

- `tEXt` / `zTXt` / `iTXt` – metadata ya maandishi na maandishi yaliyobanwa
- `eXIf` – data ya EXIF ndani ya PNG
- `iCCP` – wasifu wa ICC uliopachikwa
- `PLTE` – data ya palette katika picha zenye faharasa, lakini pia inafaa katika hali za kuficha payload.<sup>[[2]](#references)</sup>

Zitupue kwa kutumia:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Kwa persistence ya offensive payload ndani ya PNG chunks (kwa mfano, mbinu za **PLTE**, **IDAT** au **tEXt** zinazoweza kustahimili baadhi ya mabadiliko ya picha ya PHP), angalia maelezo ya kina zaidi yanayolenga upload hapa:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Toa payloads za ancillary chunks

Mshambulizi anaweza kuweka bytes zozote ndani ya **unknown ancillary chunk kabla ya `IEND`**. PNG decoders za kawaida zinaweza kupuuza unknown ancillary chunk, huku script inayopata picha kama bytes ikiweza kusoma na kutumia payload; kufungua PNG peke yake hakuitekelezi.<sup>[[4]](#references)[[6]](#references)</sup> Utafiti wa awali ulionyesha custom chunk iliyobanwa na kusimbwa kwa njia fiche.<sup>[[4]](#references)</sup> Mfano wa baadaye wa browser ulitumia bytes zilizotolewa kuwasilisha HTML au faili ya kupakua.<sup>[[5]](#references)</sup>

Herufi ya kwanza ya aina ya chunk ikiwa lowercase humaanisha *ancillary*; herufi ya pili ikiwa lowercase humaanisha *private*. Kwa mfano, `paMP` ni private, ilhali `pAMP` hutumia public namespace ingawa ya pili ilibuniwa kwa ajili ya onyesho hilo.<sup>[[4]](#references)[[6]](#references)</sup> Muundo wa chunk ni `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC huhesabiwa kwa type na data. Changanua muundo huu badala ya kutafuta jina la type ndani ya data ya `IDAT` iliyobanwa. Walker ifuatayo hukagua mipaka na CRC, huhamisha payloads za ancillary kama raw bytes, na huandika bytes zozote baada ya `IEND` ya kimuundo kwenye `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Chota ancillary chunks na PNG trailer</summary>

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

Kagua baiti zilizochongwa kwa `file`, `strings`, au `binwalk`; decompression fanya tu ikiwa carrier imebanwa kweli.<sup>[[4]](#references)</sup> Ku-encode upya kunaweza kuondoa carrier, kwa hiyo linganisha baiti zilizopakiwa na zilizorejeshwa kabla ya kutegemea hilo.<sup>[[2]](#references)[[6]](#references)</sup>

## Kurekebisha PNG iliyoharibika

Kwa kukagua uadilifu na kubaini eneo hususa lililoharibika, **pngcheck** bado ni mojawapo ya zana bora za kuanzia:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ikiwa faili imeharibika badala ya kuwa hasidi kimakusudi, **PCRT** inaweza kusaidia katika CTF na kazi za maabara kurekebisha matatizo ya kawaida kama vile vichwa vibovu, thamani zisizo sahihi za IHDR, matatizo ya CRC, au mpangilio mbovu wa chunk.

Ikiwa lengo lako ni **kusafisha** PNG yenye data ya kutiliwa shaka mwishoni huku ukihifadhi picha inayoonekana, ExifTool inaweza kuondoa data hiyo ya mwisho moja kwa moja:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Kwa ushahidi nyeti, fanya kazi kila wakati kwenye **nakala** na uhifadhi hashes za faili asili kabla ya kujaribu kuirekebisha.



## References

- [1] [Kutumia aCropalypse: Kurejesha PNG zilizokatika](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PHP payloads zinazoendelea ndani ya PNG: Jinsi ya kuingiza msimbo wa PHP kwenye picha — na kuuhifadhi humo](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Chunks za ancillary ni mahali pazuri pa kuhifadhi taarifa nyeti](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Kutumia chunks halali za ancillary kusafirisha data kisiri hadi kwenye endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Vipimo vya Portable Network Graphics (PNG) (Toleo la Tatu)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
