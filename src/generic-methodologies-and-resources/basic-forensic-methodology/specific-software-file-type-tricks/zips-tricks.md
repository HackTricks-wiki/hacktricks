# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**ZIP dosyalarını** yönetmeye yönelik **command-line tools**, ZIP dosyalarını teşhis etmek, onarmak ve crack etmek için gereklidir. İşte bazı temel araçlar:<sup>[[1]](#references)</sup>

- **`unzip`**: Bir ZIP dosyasının neden açılamayacağını gösterir.
- **`zipdetails -v`**: ZIP dosyası formatı alanlarının ayrıntılı analizini sunar.
- **`zipinfo`**: Bir ZIP dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozulmuş ZIP dosyalarını onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP password'larını brute-force ile crack etmek için kullanılan ve yaklaşık 7 karaktere kadar password'larda etkili olan bir tool'dur.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), ZIP dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sağlar.<sup>[[4]](#references)</sup>

Password korumalı ZIP dosyalarının içindeki **dosya adlarını veya dosya boyutlarını encrypt etmediğini** belirtmek önemlidir; bu, bu bilgileri encrypt eden RAR veya 7z dosyalarında bulunmayan bir security flaw'dır. Ayrıca eski ZipCrypto method'u ile encrypt edilmiş ZIP dosyaları, sıkıştırılmış bir dosyanın encrypt edilmemiş bir kopyası mevcutsa **plaintext attack**'e karşı savunmasızdır.<sup>[[1]](#references)</sup> Bu attack, ZIP'in password'unu crack etmek için bilinen içeriği kullanır. Bu vulnerability, [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) içinde açıklanmış ve [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) içinde daha ayrıntılı olarak ele alınmıştır.<sup>[[11]](#references)[[12]](#references)</sup> Ancak **AES-256** encryption ile güvenliği sağlanan ZIP dosyaları bu plaintext attack'e karşı immune'dur; bu da sensitive data için güvenli encryption method'ları seçmenin önemini gösterir.<sup>[[1]](#references)</sup>

---

## Manipulated ZIP headers kullanan APK'lerde anti-reversing tricks

Modern Android malware dropper'ları, APK'yı cihaz üzerine kurulabilir durumda tutarken static tools'u (jadx/apktool/unzip) bozmak için malformed ZIP metadata kullanır. En yaygın tricks şunlardır:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak fake encryption oluşturma
- Parser'ların kafasını karıştırmak için büyük/custom Extra field'ları kötüye kullanma
- Gerçek artifact'leri gizlemek için file/directory name collision'ları kullanma (örneğin, gerçek `classes.dex` dosyasının yanında `classes.dex/` adlı bir directory bulunması)

### 1) Gerçek crypto olmadan fake encryption (GPBF bit 0 set)

Belirtiler:
- `jadx-gui` şu tür error'larla başarısız olur:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`, geçerli bir APK'da `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` encrypt edilmiş olamayacağı halde temel APK dosyaları için password ister:

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
Yerel ve merkezi header'lar için General Purpose Bit Flag değerine bakın. Belirgin bir işaret, core girdiler için bile bit 0'ın (Encryption) ayarlanmış olmasıdır:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: Bir APK cihaz üzerinde yüklenip çalışıyor ancak temel girdiler araçlara "şifrelenmiş" olarak görünüyorsa GPBF değiştirilmiştir.

Hem Local File Headers (LFH) hem de Central Directory (CD) girdilerindeki GPBF bit 0'ı temizleyerek düzeltin. Minimal byte-patcher:

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
Şimdi core entries üzerinde `General Purpose Flag  0000` ifadesini görmeli ve tools APK'yı tekrar parse edebilmelidir.

### 2) Parser'ları bozmak için büyük/özel Extra alanları

Attackers, decompiler'ları devre dışı bırakmak için header'lara aşırı büyük Extra alanları ve sıra dışı ID'ler yerleştirir. Gerçek ortamlarda, buraya gömülmüş özel işaretçiler (ör. `JADXBLOCK` gibi string'ler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: büyük payload'lar taşıyan `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'ler.

DFIR buluşsal yöntemleri:
- Core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) üzerindeki Extra fields olağandışı derecede büyük olduğunda uyarı oluşturun.
- Bu entries üzerindeki bilinmeyen Extra ID'lerini şüpheli kabul edin.

Pratik azaltma yöntemi: archive'ı yeniden oluşturmak (ör. çıkarılan dosyaları yeniden zipping) malicious Extra fields'ları temizler. Tools, fake encryption nedeniyle çıkarmayı reddederse önce GPBF bit 0'ı yukarıdaki gibi temizleyin, ardından yeniden package edin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin adı çakışmaları (gerçek artefaktları gizleme)

Bir ZIP hem `X` adlı bir dosya hem de `X/` adlı bir dizin içerebilir. Bazı extractor'lar ve decompiler'lar kafası karışabilir ve gerçek dosyayı bir dizin girdisiyle üzerine yazabilir veya gizleyebilir. Bunun `classes.dex` gibi temel APK adlarıyla çakışan girdilerde gözlemlendiği görülmüştür.

Triage ve güvenli extraction:
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
Blue-team tespit fikirleri:
- Yerel header'ları encryption işaretleyen (GPBF bit 0 = 1) ancak install/run olan APK'leri işaretleyin.
- Core entry'lerdeki büyük/bilinmeyen Extra alanlarını işaretleyin (`JADXBLOCK` gibi marker'ları arayın).
- Özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için path-collision'ları (`X` ve `X/`) işaretleyin.

---

## Diğer malicious ZIP tricks (2024–2026)

### Birleştirilmiş central directory'ler (multi-EOCD evasion)

Recent phishing campaign'leri, aslında **birleştirilmiş iki ZIP file'ı** olan tek bir blob gönderiyor. Her birinin kendi End of Central Directory (EOCD) + central directory'si bulunuyor. Farklı extractor'lar farklı directory'leri parse ediyor (7zip ilkini, WinRAR sonuncuyu okuyor); bu da saldırganların yalnızca bazı tool'ların gösterdiği payload'ları gizlemesine olanak tanıyor. Bu yöntem, yalnızca ilk directory'yi inceleyen temel mail gateway AV'lerini de bypass ediyor.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage komutları**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Birden fazla EOCD görünürse veya "data after payload" uyarıları varsa, blob'u bölün ve her bir parçayı inceleyin:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" yapıları küçük bir **kernel** (yüksek oranda sıkıştırılmış DEFLATE bloğu) oluşturur ve bunu üst üste binen local header'lar aracılığıyla yeniden kullanır. Her central directory entry aynı sıkıştırılmış veriye işaret eder ve arşivleri iç içe yerleştirmeden >28M:1 oranlarına ulaşır. Central directory boyutlarına güvenen kütüphaneler (Python `zipfile`, Java `java.util.zip`, hardened build'lerden önceki Info-ZIP), petabaytlarca alan ayırmaya zorlanabilir.<sup>[[7]](#references)[[8]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
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
- Bir dry-run taraması gerçekleştirin: `zipdetails -v file.zip | grep -n "Rel Off"` ve offset'lerin kesinlikle artan ve benzersiz olduğundan emin olun.
- Extraction işleminden önce kabul edilen toplam uncompressed size ve entry count değerlerini sınırlandırın (`zipdetails -t` veya custom parser).
- Extraction yapmanız gerektiğinde işlemi CPU+disk limitleri olan bir cgroup/VM içinde gerçekleştirin (sınırsız inflation kaynaklı crash'lerden kaçının).

---

### Local-header vs central-directory parser confusion

Son differential-parser araştırmaları, ZIP belirsizliğinin modern toolchain'lerde hâlâ exploit edilebilir olduğunu gösterdi. Ana fikir basittir: bazı software'ler **Local File Header (LFH)** bilgisine güvenirken diğerleri **Central Directory (CD)** bilgisine güvenir; bu nedenle tek bir archive, farklı tool'lara farklı filename'ler, path'ler, comment'ler, offset'ler veya entry set'leri sunabilir.<sup>[[9]](#references)</sup>

Practical offensive uses:
- Bir upload filter'ının, AV pre-scan'inin veya package validator'ının CD içinde benign bir file görmesini, extractor'ın ise farklı bir LFH name/path'ini kullanmasını sağlayın.
- Duplicate name'leri, yalnızca yapılardan birinde bulunan entry'leri veya ambiguous Unicode path metadata'sını (örneğin Info-ZIP Unicode Path Extra Field `0x7075`) kullanarak farklı parser'ların farklı tree'ler oluşturmasını sağlayın.
- Bunu path traversal ile birleştirerek "harmless" bir archive görünümünü extraction sırasında write-primitive'e dönüştürün. Extraction tarafı için bkz. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Sezgisel Kurallar:
- LFH/CD adları uyuşmayan, yinelenen dosya adları, birden fazla EOCD kaydı veya son EOCD'den sonra kalan baytlar içeren arşivleri reddedin ya da izole edin.<sup>[[10]](#references)</sup>
- Farklı araçlar çıkarılan ağaç konusunda anlaşmazlığa düşüyorsa, alışılmadık Unicode-path extra fields veya tutarsız yorumlar kullanan ZIP'leri şüpheli kabul edin.<sup>[[9]](#references)</sup>
- Analiz, özgün baytları korumaktan daha önemliyse arşivi bir sandbox içinde çıkardıktan sonra strict parser ile yeniden paketleyin ve ortaya çıkan dosya listesini özgün metadata ile karşılaştırın.

Bu durum package ecosystems ötesinde de önemlidir: aynı belirsizlik sınıfı, ZIP içeriklerine farklı bir extractor işlem yapmadan önce "peek" eden mail gateways, static scanners ve custom ingestion pipelines üzerinden payload'ları gizleyebilir.

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
