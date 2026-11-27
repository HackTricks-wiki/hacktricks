# Mbinu za ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Zana za mstari wa amri** za kusimamia **faili za zip** ni muhimu kwa kutambua matatizo, kurekebisha na kuvunja ulinzi wa faili za zip. Hizi ni baadhi ya zana muhimu:<sup>[[1]](#references)</sup>

- **`unzip`**: Huonyesha sababu zinazoweza kufanya faili ya zip ishindwe kufunguka.
- **`zipdetails -v`**: Hutoa uchanganuzi wa kina wa sehemu za muundo wa faili ya zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Huorodhesha yaliyomo kwenye faili ya zip bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Hujaribu kurekebisha faili za zip zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya mashambulizi ya kamusi na brute-force dhidi ya nywila za ZIP; uwezekano wa kufanikiwa hutegemea nafasi ya utafutaji wa nywila.<sup>[[15]](#references)</sup>

[Vipimo vya muundo wa faili ya Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) vina maelezo ya kina kuhusu muundo na viwango vya faili za zip.<sup>[[4]](#references)</sup>

Kwa kawaida, faili za ZIP zilizolindwa kwa nywila huacha majina na ukubwa wa faili zikiwa wazi, tofauti na hali za usimbaji fiche wa vichwa zinazotumika na RAR na 7z. Shambulio la known-plaintext dhidi ya ZipCrypto hurejesha **funguo za usimbaji fiche za ndani**, si lazima nywila ya awali; funguo hizo zinatosha kusimbua maingizo yaliyosimbwa kwa nywila hiyohiyo.<sup>[[13]](#references)</sup> Shambulio hilo linahitaji kujua baiti za mtiririko **kabla ya usimbaji fiche**: kwa faili iliyohifadhiwa bila kubanwa, hizi ni baiti za faili ya awali, lakini kwa faili ya DEFLATE ni baiti zilizobanwa, ambazo huenda zikahitaji kuundwa upya kwa matokeo yale yale ya ubano.<sup>[[13]](#references)[[14]](#references)</sup> Tazama [Shambulio la ZIP la known plaintext](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) kwa mwongozo wa vitendo. Kwa maelezo ya msingi kuhusu cryptanalysis, tazama [makala](https://math.ucr.edu/~mike/zipattacks.pdf) na [mwongozo wa hatua kwa hatua](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Shambulio hili la ZipCrypto halitumiki kwa maingizo ya ZIP yaliyosimbwa kwa AES.<sup>[[13]](#references)</sup>

---

## Mbinu za anti-reversing katika APK kwa kutumia vichwa vya ZIP vilivyobadilishwa

Droppers za kisasa za Android malware hutumia metadata ya ZIP yenye hitilafu kuvuruga zana za uchanganuzi tuli (jadx/apktool/unzip), huku APK ikiendelea kusakinishika kwenye kifaa. Mbinu zinazotumika zaidi ni:<sup>[[2]](#references)</sup>

- Kughushi usimbaji fiche kwa kuweka biti ya 0 ya ZIP General Purpose Bit Flag (GPBF)
- Kutumia vibaya sehemu kubwa/maalum za Extra ili kuchanganya parser
- Majina ya faili/saraka yanayogongana ili kuficha artifacts halisi (kwa mfano, saraka inayoitwa `classes.dex/` kando ya `classes.dex` halisi)

### 1) Usimbaji fiche wa kughushi (GPBF bit 0 imewekwa) bila crypto halisi

Dalili:
- `jadx-gui` hushindwa na hitilafu kama hizi: **
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` huomba nenosiri kwa faili kuu za APK, ingawa APK halali haiwezi kuwa na `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml` zilizosimbwa kwa njia fiche:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

Ugunduzi kwa kutumia zipdetails:

```bash
zipdetails -v sample.apk | less
```

Angalia General Purpose Bit Flag kwenye local na central headers. Thamani inayoashiria tatizo ni bit 0 ikiwa imewashwa (Encryption), hata kwa core entries:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristiki: Ikiwa APK inasakinishwa na kuendeshwa kwenye kifaa lakini maingizo muhimu yanaonekana kuwa "yamesimbwa kwa njia fiche" kwa zana, GPBF ilichezewa.

Rekebisha kwa kufuta bit 0 ya GPBF katika maingizo ya Local File Headers (LFH) na Central Directory (CD). Kirekebishaji kidogo cha byte:

<details>
<summary>Kirekebishaji kidogo cha kufuta bit ya GPBF</summary>

```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
    out = bytearray(buf)
    i = 0
    patched = 0
    while True:
        i = out.find(sig, i)
        if i == -1:
            break
        flags, = struct.unpack_from('<H', out, i + flag_off)
        if flags & 1:  # encryption bit set
            struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
            patched += 1
        i += 4  # move past signature to continue search
    return bytes(out), patched

if __name__ == '__main__':
    inp, outp = sys.argv[1], sys.argv[2]
    data = open(inp, 'rb').read()
    data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
    data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
    open(outp, 'wb').write(data)
    print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```

</details>

Matumizi:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

Bit 0 pekee ndiyo inapaswa kubadilika: kwa mfano, `0A09` inakuwa `0A08`, si `0000`. Patcher hii ndogo hutafuta saini za vichwa katika baiti ghafi, kwa hivyo baiti zinazofanana na saini ndani ya data ya faili zinaweza kusababisha matokeo yasiyo sahihi; fanyia kazi nakala na uthibitishe orodha ya maingizo na vichwa kabla ya kutumia matokeo.<sup>[[4]](#references)</sup>

### 2) Sehemu kubwa/maalum za Extra za kuvuruga parser

Washambuliaji hujaza sehemu za Extra zilizozidi ukubwa na vitambulisho visivyo vya kawaida kwenye vichwa ili kuvuruga decompiler. Katika mifumo halisi unaweza kuona alama maalum (kwa mfano, mifuatano kama `JADXBLOCK`) iliyopachikwa humo.

Ukaguzi:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Mifano iliyozingatiwa: ID zisizojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") zikiwa na payload kubwa.<sup>[[2]](#references)</sup>

Heuristics za DFIR:
- Toa tahadhari wakati sehemu za Extra ni kubwa isivyo kawaida kwenye entries kuu (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia ID za Extra zisizojulikana kwenye entries hizo kuwa za kutiliwa shaka.

Hatua ya vitendo ya kupunguza hatari: kujenga upya archive (kwa mfano, kufunga tena kwa zip faili zilizotolewa) huondoa sehemu za Extra hasidi. Ikiwa zana zinakataa kutoa faili kwa sababu ya usimbaji fiche wa uongo, kwanza futa bit 0 ya GPBF kama ilivyoelezwa hapo juu, kisha funga faili upya:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Migongano ya majina ya faili/saraka (kuficha artifacts halisi)

ZIP inaweza kuwa na faili `X` na saraka `X/`. Baadhi ya extractors na decompilers huchanganyikiwa na huenda zikaweka saraka juu ya faili halisi au kuificha. Hili limeonekana kwa entries zinazogongana na majina muhimu ya APK kama `classes.dex`.

Tathmini ya awali na uchimbaji salama:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Utambuzi wa kiotomatiki baada ya marekebisho:

```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
    names = z.namelist()

collisions = defaultdict(list)
for n in names:
    base = n[:-1] if n.endswith('/') else n
    collisions[base].append(n)

for base, variants in collisions.items():
    if len(variants) > 1:
        print('COLLISION', base, '->', variants)
```

Mawazo ya ugunduzi wa Blue-team:
- Weka alama kwa APK ambazo local headers zake zinaonyesha usimbaji fiche (GPBF bit 0 = 1), lakini zinaweza kusakinishwa/kuendeshwa.
- Weka alama kwa Extra fields kubwa/isiyojulikana kwenye core entries (tafuta viashiria kama `JADXBLOCK`).
- Weka alama kwa path-collisions (`X` na `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine hasidi za ZIP (2024–2026)

### Concatenated central directories (ukwepaji wa multi-EOCD)

Katika kampeni ya phishing ya 2024, washambuliaji walituma blob moja ambayo kwa hakika ilikuwa **faili mbili za ZIP zilizounganishwa**. Kila moja ilikuwa na rekodi yake ya End of Central Directory (EOCD) na central directory. Extractor tofauti zilisoma directories tofauti (7-Zip ilisoma ya kwanza, huku WinRAR ikisoma ya mwisho), na hivyo kuwawezesha washambuliaji kuficha payloads ambazo zilionyeshwa na baadhi tu ya zana; scanner zinazokagua directory moja tu zinaweza kukosa archive nyingine.<sup>[[5]](#references)[[6]](#references)</sup>

**Amri za uchunguzi wa awali**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Ikiwa zaidi ya EOCD moja itaonekana au kuna maonyo ya "data after payload", gawanya blob na ukague kila sehemu:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (zisizo za kujirudia)

Quoted-overlap ZIP bombs huunda **kernel** ndogo (block ya DEFLATE iliyobanwa sana) na kuitumia tena katika entries zinazopishana. Aina za overlap kamili huelekeza entries nyingi za central directory kwenye header moja ya ndani, ilhali aina za quoted-overlap hunukuu headers za ndani ndani ya DEFLATE streams; muundo uliochapishwa unafikia uwiano wa zaidi ya 28M:1 bila archives zilizowekwa ndani ya nyingine.<sup>[[7]](#references)</sup>

**Ugunduzi wa haraka (offsets za LFH zilizorudiwa)**

```python
# detect full-overlap variants by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
    i = buf.find(b'PK\x01\x02', off)
    if i<0: break
    rel = struct.unpack_from('<I', buf, i+42)[0]
    if rel in seen:
        print('OVERLAP at offset', rel)
        break
    seen.add(rel); off = i+4
```

**Ushughulikiaji**
- Fanya ukaguzi wa dry-run: `zipdetails -v file.zip | grep -n "Local Header Offset"` na ulinganishe offsets za local-header zilizorejelewa na safu za data iliyobanwa; offsets zinazojirudia huashiria variants zenye mwingiliano kamili.<sup>[[7]](#references)[[8]](#references)</sup>
- Weka ukomo wa jumla ya ukubwa unaokubaliwa baada ya kufunguliwa na idadi ya entries kabla ya kutoa faili kwa kutumia parser; `zipinfo -t file.zip` huripoti jumla lakini hailazimishi kikomo cha usalama.<sup>[[8]](#references)</sup>
- Unapolazimika kutoa faili, fanya hivyo ndani ya cgroup/VM yenye vikomo vya CPU na diski (epuka kuharibika kwa mfumo kutokana na upanuzi usio na kikomo).<sup>[[8]](#references)</sup>

---

### Mkanganyiko wa parser kati ya local-header na central-directory

Utafiti wa hivi karibuni wa differential-parser umeonyesha kuwa utata wa ZIP bado unaweza kutumiwa vibaya katika toolchain za kisasa. Wazo kuu ni rahisi: baadhi ya programu huamini **Local File Header (LFH)** huku nyingine zikiamini **Central Directory (CD)**, kwa hiyo archive moja inaweza kuonyesha majina ya faili, njia, maoni, offsets au seti tofauti za entries kwa zana tofauti.<sup>[[9]](#references)</sup>

Matumizi ya kiudukuzi:
- Fanya kichujio cha upload, ukaguzi wa awali wa AV au validator ya package ione faili isiyo na madhara katika CD huku extractor ikitumia jina/njia tofauti ya LFH.
- Tumia vibaya majina yanayojirudia, entries zilizopo kwenye muundo mmoja tu, au metadata ya njia ya Unicode yenye utata (kwa mfano, Info-ZIP Unicode Path Extra Field `0x7075`) ili parser tofauti zijenge upya miti tofauti.
- Changanya hili na path traversal ili kubadilisha mwonekano wa archive "isiyo na madhara" kuwa primitive ya kuandika wakati wa kutoa faili. Kwa upande wa kutoa faili, angalia [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Uchunguzi wa awali wa DFIR:

```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
    n, e = struct.unpack_from('<HH', b, i + 26)
    lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
    i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
    n = struct.unpack_from('<H', b, i + 28)[0]
    off = struct.unpack_from('<I', b, i + 42)[0]
    cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
    if off in lfh and cd != lfh[off]:
        print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
    i += 4
```

Ikamilishe kwa:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heuristics:
- Kwa uingizaji unaohusu usalama, kataa au tenga archive ambazo zina majina ya LFH/CD yasiyolingana, majina ya faili yanayojirudia, rekodi nyingi za EOCD, au baiti za ziada baada ya EOCD ya mwisho.<sup>[[9]](#references)[[10]](#references)</sup>
- Chukulia ZIP zinazotumia sehemu za ziada zisizo za kawaida za njia za Unicode au maoni yasiyolingana kuwa za kutiliwa shaka ikiwa zana tofauti hazikubaliani kuhusu mti wa faili zilizotolewa.<sup>[[4]](#references)[[9]](#references)</sup>
- Ikiwa uchanganuzi ni muhimu zaidi kuliko kuhifadhi baiti asili, fungua archive kwenye sandbox kisha uipange upya kwa kutumia parser madhubuti, na ulinganishe orodha ya faili iliyopatikana na metadata asili.

Hili ni muhimu hata nje ya mifumo ikolojia ya package: aina hiyo hiyo ya utata inaweza kuficha payloads dhidi ya mail gateway, scanner tuli na mifumo maalum ya uingizaji ambayo hukagua kwa haraka yaliyomo kwenye ZIP kabla extractor tofauti haijashughulikia archive.<sup>[[9]](#references)</sup>

---





## References

- [1] [Mwongozo wa Uchunguzi wa CTF (Blogu ya Mike, kategoria ya CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Sehemu ya 1 – Dropper ya hatua nyingi (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script ya IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Uainisho wa Umbizo la Faili la ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Muundo Unaonyumbulika wa Archive za ZIP Umetumiwa Kuficha Malware Bila Kugunduliwa (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Wadukuzi Wanaficha Malware Katika Shambulio Jipya la Faili za ZIP — Saraka za kati za ZIP zilizounganishwa](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Bomu bora zaidi la zip (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Kuelewa Mabomu ya Zip: ujenzi wa kernel unaopishana/unaorejelewa kwa nukuu](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [ZIP yangu si ZIP yako: Kutambua na Kutumia Pengo za Kisemantiki Kati ya ZIP Parser (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Kuzuia mashambulizi ya kuchanganya ZIP parser kwenye visakinishi vya package za Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Mashambulizi ya ZIP kwa Kutumia Plaintext Inayojulikana Kidogo (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Misheni Halisi ya Wavuti, Kiwango cha 15 (shambulio la ZIP linalotumia plaintext inayojulikana)](https://www.hackthissite.org/articles/read/793)
- [13] [Matumizi ya bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Mafunzo ya bkcrack ya kutumia plaintext inayojulikana](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Hifadhi ya fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
