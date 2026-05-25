# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Faili za PNG** ni za kawaida sana katika **CTFs**, **incident response**, na **malware staging** kwa sababu ni **lossless**, **chunk-based**, na zana nyingi zitazitoa kwa furaha hata zikiwa na **extra metadata**, **appended payloads**, au **partially corrupted chunks**.

Chukulia PNG kama **container**, si tu kama picha.

## Quick triage

Anza na ukaguzi wa kiwango cha container kabla ya kurukia LSB stego. Kwa workflow ya bit-plane/LSB, angalia [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Mambo muhimu ya kutafuta:

- **Chunks za ziada zisizotarajiwa** kama `tEXt`, `zTXt`, `iTXt`, `eXIf`, au `iCCP`
- **CRC errors** au urefu wa chunk ulioharibika
- **Data ya ziada baada ya `IEND`**
- **Multiple `IEND` markers** au vipande vya `IDAT` vinavyoweza kurejeshwa baada ya mwisho rasmi wa faili
- Faili ambayo ni PNG halali **na** pia inaonekana kama ZIP/PDF/script wakati inapochongwa

Kumbuka muundo wa chini unaohitajika kwa kawaida ni:

- `IHDR` (lazima iwe ya kwanza)
- `IDAT` (chunk moja au zaidi mfululizo)
- `IEND` (lazima iwe ya mwisho)

## Trailing data after `IEND`

Moja ya PNG artefacts zenye ishara kubwa zaidi ni **data iliyoongezwa baada ya chunk ya mwisho ya `IEND`**. Dekoda nyingi hui-ignore, jambo linaloifanya iwe muhimu kwa:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Kurejesha data ya zamani ya picha** kutoka kwa editors zenye bug

Ugunduzi wa haraka:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ikiwa unataka kuchonga kila kitu baada ya `IEND` ya mwisho:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Pia pia wachambuzi wa kumbukumbu wa kawaida moja kwa moja dhidi ya PNG au trailer iliyotolewa:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Urejeshaji wa aina ya Acropalypse wa screenshots zilizopunguzwa/redacted

Mbinu moja ya hivi karibuni na ya vitendo sana ya forensic ya PNG ni kuangalia kama screenshot editor **iliandika upya** PNG bila **kufanya truncate** faili ya zamani kwanza. Katika hali hizo, bytes kutoka kwenye **picha ya awali** zinaweza kubaki baada ya `IEND`, na wakati mwingine data ya ziada ya `IDAT` inaweza kujengwa upya kwa sehemu.

Hii ilijulikana sana kupitia **aCropalypse** (Google Pixel Markup) na issue inayohusiana ya **Windows Snipping Tool**. Kwa vitendo, ikiwa PNG "iliyopunguzwa" au "iliyofichwa" bado ina data ya zamani ya mwisho, unaweza kuweza kurejesha sehemu ya screenshot ya awali.

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ishara zinazohalalisha uchambuzi wa kina zaidi kwa nguvu:

- `pngcheck` inaripoti **data ya ziada baada ya `IEND`**
- Unapata **zaidi ya `IEND` moja**
- Unapata **vipande vya ziada vya `IDAT`** baada ya mwisho unaoonekana wa picha
- Screenshot ilitoka kwenye kifaa/editor kinachojulikana kuwa kiliathiriwa

Ikiwa hili linatokea, peleka faili kwenye **aCropalypse recovery tool** kabla ya kuichukulia redaction kuwa ya kuaminika.

## Chunk abuse that matters in practice

Vipande vya PNG vinavyovutia zaidi kwa uchunguzi kwa kawaida si vile vya picha vilivyo dhahiri, bali ni vipande vinavyoweza kubeba **text**, **metadata**, au **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata ya text na text iliyobanwa
- `eXIf` – EXIF data ndani ya PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data katika indexed images, lakini pia ni muhimu katika payload-smuggling scenarios

Vitoa kwa:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Kwa kudumu kwa payload ya offensive ndani ya PNG chunks (kwa mfano **PLTE**, **IDAT**, au **tEXt** tricks ambazo huendelea kuwepo kupitia baadhi ya PHP image transformations), angalia maelezo ya kina zaidi yanayolenga uploads hapa:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Urekebishaji wa PNG iliyoharibika

Kwa kuangalia integrity na kutambua eneo halisi lililoharibika, **pngcheck** bado ni mojawapo ya zana bora za awali:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ikiwa faili imeharibika badala ya kuwa malicious kwa makusudi, **PCRT** inaweza kuwa na manufaa katika CTFs na kazi za maabara kwa kurekebisha matatizo ya kawaida kama headers mbovu, thamani zisizo sahihi za IHDR, matatizo ya CRC, au chunk layouts zilizopangwa vibaya.

Ikiwa lengo lako ni **sanitize** PNG ambayo ina suspicious trailer data huku ukihifadhi picha inayoonekana, ExifTool inaweza kuondoa trailer kwa uwazi:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Kwa ushahidi nyeti, fanya kazi kila wakati kwenye **nakala** na hifadhi hashes za asili kabla ya kujaribu kurekebisha.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
