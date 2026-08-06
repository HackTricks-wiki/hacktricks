# ZIP tricks

{{#include ../../../banners/hacktricks-training.md}}

**Zip files** yönetmek için kullanılan **Command-line tools**, zip files tanılama, onarma ve cracking işlemleri açısından gereklidir. Temel utilities şunlardır:<sup>[[1]](#references)</sup>

- **`unzip`**: Bir zip file'ın neden decompress edilemeyebileceğini gösterir.
- **`zipdetails -v`**: Zip file format alanlarının ayrıntılı analizini sunar.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Bir zip file'ın içeriğini extract etmeden listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozulmuş zip files onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zip passwords brute-force cracking için kullanılan ve yaklaşık 7 karaktere kadar olan passwords üzerinde etkili bir tool'dur.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), zip files yapısı ve standartları hakkında kapsamlı bilgiler sunar.<sup>[[4]](#references)</sup>

Password-protected zip files'ın içindeki **filenames veya file sizes bilgilerini encrypt etmediğine** dikkat etmek önemlidir. Bu, bu bilgileri encrypt eden RAR veya 7z files'ta bulunmayan bir security flaw'dur. Ayrıca eski ZipCrypto method ile encrypt edilmiş zip files, sıkıştırılmış bir file'ın unencrypted bir kopyası mevcutsa **plaintext attack** karşısında savunmasızdır.<sup>[[1]](#references)</sup> Bu attack, zip'in password'ünü crack etmek için bilinen içeriği kullanır. Bu vulnerability, [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) içinde açıklanmış ve [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) içinde daha ayrıntılı olarak ele alınmıştır.<sup>[[11]](#references)[[12]](#references)</sup> Ancak **AES-256** encryption ile korunan zip files bu plaintext attack'a karşı immune'dur. Bu da hassas data için secure encryption methods seçmenin önemini gösterir.<sup>[[1]](#references)</sup>

---

## Manipulated ZIP headers kullanan APK'lerde anti-reversing tricks

Modern Android malware droppers, APK'yi cihaz üzerine install edilebilir durumda tutarken static tools'ları (jadx/apktool/unzip) bozmak için malformed ZIP metadata kullanır. En yaygın tricks şunlardır:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak fake encryption kullanmak
- Parser'ların kafasını karıştırmak için büyük/custom Extra fields kullanmak
- Gerçek artifacts'ları gizlemek için file/directory name collisions kullanmak (ör. gerçek `classes.dex` dosyasının yanında `classes.dex/` adlı bir directory bulunması)

### 1) Gerçek crypto olmadan fake encryption (GPBF bit 0 ayarlanmış)

Belirtiler:
- `jadx-gui` aşağıdakilere benzer errors ile başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`, geçerli bir APK'de encrypted `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` bulunamayacağı halde temel APK files için password ister:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails ile detection:
```bash
zipdetails -v sample.apk | less
```
Yerel ve merkezi başlıklar için General Purpose Bit Flag değerine bakın. Belirgin bir değer, core entries için bile bit 0'ın ayarlanmış olmasıdır (Encryption):
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Sezgisel kural: Bir APK cihaz üzerine kurulup çalışıyor, ancak temel girdiler araçlara "şifrelenmiş" olarak görünüyorsa GPBF üzerinde oynanmıştır.

LFH ve CD girdilerindeki GPBF bit 0'ı temizleyerek düzeltin. Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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

Kullanım:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Artık çekirdek girdilerde `General Purpose Flag  0000` ifadesini görmelisiniz ve araçlar APK'yı yeniden ayrıştıracaktır.

### 2) Ayrıştırıcıları bozmak için büyük/özel Extra alanları

Saldırganlar, decompiler'ları tetiklemek için başlıklara aşırı büyük Extra alanları ve alışılmadık ID'ler yerleştirir. Gerçek dünyada, buraya gömülmüş özel işaretleyiciler (ör. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: büyük payload'lar taşıyan `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'ler.

DFIR heuristics:
- Çekirdek girdilerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra alanları olağandışı derecede büyük olduğunda uyarı verin.
- Bu girdilerdeki bilinmeyen Extra ID'lerini şüpheli kabul edin.

Pratik mitigation: archive'ı yeniden oluşturmak (ör. çıkarılan dosyaları yeniden zip'lemek) kötü amaçlı Extra alanlarını temizler. Fake encryption nedeniyle tools extract işlemini reddederse önce yukarıda açıklandığı gibi GPBF bit 0'ı temizleyin, ardından yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin adı çakışmaları (gerçek artifact'ları gizleme)

Bir ZIP hem `X` adlı bir dosya hem de `X/` adlı bir dizin içerebilir. Bazı extractor'lar ve decompiler'lar kafası karışabilir ve gerçek dosyayı bir dizin girdisiyle üzerine yazabilir veya gizleyebilir. Bunun, `classes.dex` gibi temel APK adlarıyla çakışan girdilerde gerçekleştiği gözlemlenmiştir.

Triage ve güvenli çıkarma:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Düzeltme sonrası programatik tespit:
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
Blue-team detection ideas:
- Yerel header'ları encryption işaretleyen (GPBF bit 0 = 1) ancak yüklenen/çalıştırılan APK'leri işaretle.
- Core entry'lerdeki büyük/bilinmeyen Extra alanlarını işaretle (`JADXBLOCK` gibi marker'ları ara).
- Özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için path-collision'ları (`X` ve `X/`) işaretle.

---

## Diğer malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Recent phishing campaigns, aslında **birleştirilmiş iki ZIP file** olan tek bir blob gönderiyor. Her birinin kendi End of Central Directory (EOCD) + central directory'si bulunuyor. Farklı extractor'lar farklı directory'leri parse ediyor (7zip ilkini, WinRAR sonuncuyu okuyor); bu da saldırganların yalnızca bazı araçların gösterdiği payload'ları gizlemesine olanak tanıyor. Bu yöntem, yalnızca ilk directory'yi inceleyen temel mail gateway AV'yi de bypass ediyor.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Birden fazla EOCD görünürse veya "payload sonrası veri" uyarıları varsa, blob'u bölün ve her parçayı inceleyin:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" builds a tiny **kernel** (highly compressed DEFLATE block) and reuses it via overlapping local headers. Every central directory entry points to the same compressed data, achieving >28M:1 oranlar without nesting archives. Libraries that trust central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) can be forced to allocate petabytes.<sup>[[7]](#references)[[8]](#references)</sup>

**Hızlı tespit (duplicate LFH offsets)**
```python
# detect overlapping entries by identical relative offsets
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
**İşleme**
- Bir dry-run walk gerçekleştirin: `zipdetails -v file.zip | grep -n "Rel Off"` ve offset'lerin kesinlikle artan ve benzersiz olduğundan emin olun.
- Extraction işleminden önce kabul edilen toplam uncompressed size ve entry count değerlerini sınırlandırın (`zipdetails -t` veya custom parser).
- Extraction yapmanız gerektiğinde bunu CPU+disk limitleri olan bir cgroup/VM içinde gerçekleştirin (sınırsız inflation crash'lerini önleyin).

---

### Local-header ve central-directory parser confusion

Recent differential-parser research, ZIP ambiguity'nin modern toolchain'lerde hâlâ exploit edilebilir olduğunu gösterdi. Temel fikir basittir: bazı software **Local File Header (LFH)**'a, diğerleri ise **Central Directory (CD)**'ye güvenir; bu nedenle tek bir archive, farklı tool'lara farklı filename'ler, path'ler, comment'ler, offset'ler veya entry set'leri sunabilir.<sup>[[9]](#references)</sup>

Practical offensive uses:
- Bir upload filter, AV pre-scan veya package validator'ın CD'de benign bir file görmesini, extractor'ın ise farklı bir LFH name/path'i kullanmasını sağlayın.
- Duplicate name'leri, yalnızca yapılardan birinde bulunan entry'leri veya ambiguous Unicode path metadata'sını (örneğin Info-ZIP Unicode Path Extra Field `0x7075`) abuse ederek farklı parser'ların farklı tree'ler oluşturmasını sağlayın.
- Bunu path traversal ile birleştirerek "harmless" bir archive görünümünü extraction sırasında write-primitive'e dönüştürün. Extraction tarafı için [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) bölümüne bakın.

DFIR triage:
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
Şunlarla tamamlayın:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- LFH/CD adları uyuşmayan, yinelenen dosya adları içeren, birden fazla EOCD kaydı bulunan veya son EOCD'den sonra kalan baytlar içeren arşivleri reddedin ya da izole edin.<sup>[[10]](#references)</sup>
- Farklı araçlar çıkarılan ağaç yapısı konusunda anlaşamıyorsa, alışılmadık Unicode-path extra fields veya tutarsız comments kullanan ZIP'leri şüpheli kabul edin.<sup>[[9]](#references)</sup>
- Analiz, orijinal baytları korumaktan daha önemliyse arşivi sandbox içinde çıkardıktan sonra strict parser ile yeniden paketleyin ve ortaya çıkan dosya listesini orijinal metadata ile karşılaştırın.

Bu durum package ecosystems'ın ötesinde de önemlidir: Aynı belirsizlik sınıfı, bir ZIP'in içeriğine farklı bir extractor tarafından işlenmeden önce "peek" yapan mail gateway'lerden, static scanner'lardan ve özel ingestion pipeline'larından payload'ları gizleyebilir.

---



## Referanslar

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
