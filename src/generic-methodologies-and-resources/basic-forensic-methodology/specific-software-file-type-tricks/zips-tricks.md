# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**ZIP dosyalarını** yönetmek için kullanılan **command-line tools**, ZIP dosyalarını teşhis etmek, onarmak ve kırmak açısından gereklidir. İşte bazı temel araçlar:<sup>[[1]](#references)</sup>

- **`unzip`**: Bir ZIP dosyasının neden açılamayabileceğini gösterir.
- **`zipdetails -v`**: ZIP dosyası formatı alanlarının ayrıntılı analizini sunar.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Bir ZIP dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozulmuş ZIP dosyalarını onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP password'larını brute-force ile kırmak için kullanılan ve yaklaşık 7 karaktere kadar password'larda etkili olan bir araçtır.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), ZIP dosyalarının yapısı ve standartları hakkında kapsamlı ayrıntılar sunar.<sup>[[4]](#references)</sup>

Geleneksel password-protected ZIP dosyalarının, RAR ve 7z tarafından desteklenen header-encryption modlarının aksine, genellikle dosya adlarını ve dosya boyutlarını görünür bıraktığını belirtmek önemlidir. Ayrıca, eski ZipCrypto yöntemiyle şifrelenmiş ZIP dosyaları, sıkıştırılmış bir dosyanın unencrypted bir kopyası mevcutsa bir **plaintext attack** saldırısına karşı savunmasızdır.<sup>[[1]](#references)</sup> Bu saldırı, ZIP password'ını kırmak için bilinen içeriği kullanır; ayrıntılar [this academic paper](https://math.ucr.edu/~mike/zipattacks.pdf) içinde açıklanmış ve [this Hack This Site walk-through](https://www.hackthissite.org/articles/read/793) içinde gösterilmiştir.<sup>[[11]](#references)[[12]](#references)</sup> Ancak ZipCrypto known-plaintext attack, **AES-256** encryption ile korunan entry'ler için geçerli değildir.<sup>[[1]](#references)</sup>

---

## APKs içindeki manipulated ZIP headers ile Anti-reversing tricks

Modern Android malware droppers, APK'yı cihaz üzerine kurulabilir durumda tutarken static tools'ları (jadx/apktool/unzip) bozmak için malformed ZIP metadata kullanır. En yaygın tricks şunlardır:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak fake encryption kullanmak
- Parser'ların kafasını karıştırmak için large/custom Extra fields kullanmak
- Gerçek artifact'leri gizlemek için file/directory name collisions kullanmak (ör. gerçek `classes.dex` dosyasının yanında `classes.dex/` adlı bir directory bulunması)

### 1) Gerçek crypto olmadan fake encryption (GPBF bit 0 ayarlanmış)

Belirtiler:
- `jadx-gui` şu tür hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- Geçerli bir APK'da `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` encrypted olamayacağı hâlde `unzip`, temel APK dosyaları için bir password ister:

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
Yerel ve merkezi başlıklar için General Purpose Bit Flag değerine bakın. Belirgin bir gösterge, temel girdiler için bile bit 0'ın ayarlanmış olmasıdır (Encryption):
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Sezgisel yöntem: Bir APK cihaz üzerinde kurulup çalışıyor ancak temel girdiler araçlara "encrypted" olarak görünüyorsa GPBF üzerinde oynama yapılmıştır.

Hem Local File Headers (LFH) hem de Central Directory (CD) girdilerinde GPBF bit 0'ı temizleyerek düzeltin. Minimal byte-patcher:

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
Artık core entries üzerinde `General Purpose Flag  0000` görmelisiniz ve araçlar APK'yı tekrar ayrıştırabilmelidir.

### 2) Parser'ları bozmak için büyük/özel Extra fields

Saldırganlar, decompiler'ları tetiklemek için header'lara aşırı büyük Extra fields ve olağandışı ID'ler yerleştirir. Gerçek ortamlarda, buraya gömülmüş özel işaretleyiciler (ör. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: büyük payload’lar taşıyan `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID’ler.<sup>[[2]](#references)</sup>

DFIR heuristics:
- Core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) üzerindeki Extra fields olağandışı derecede büyük olduğunda uyarı verin.
- Bu entries üzerindeki bilinmeyen Extra ID’lerini şüpheli kabul edin.

Pratik mitigation: arşivi yeniden oluşturmak (ör. çıkarılan dosyaları yeniden zipping yapmak) malicious Extra fields öğelerini kaldırır. Tools, fake encryption nedeniyle extract işlemini reddederse önce yukarıdaki gibi GPBF bit 0’ı temizleyin, ardından repackaging yapın:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin adı çakışmaları (gerçek artefaktları gizleme)

Bir ZIP hem `X` adlı bir dosya hem de `X/` adlı bir dizin içerebilir. Bazı çıkarıcılar ve decompiler'lar kafası karışabilir ve gerçek dosyayı bir dizin girdisiyle üzerine yazarak veya gizleyerek etkisiz hâle getirebilir. Bunun `classes.dex` gibi temel APK adlarıyla çakışan girdilerde görüldüğü gözlemlenmiştir.

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
Blue-team tespit fikirleri:
- Yerel header'ları encryption işaretleyen (GPBF bit 0 = 1) ancak install/run olan APK'ları işaretleyin.
- Temel entry'lerdeki büyük/bilinmeyen Extra field'ları işaretleyin (`JADXBLOCK` gibi marker'ları arayın).
- Özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için path-collision'ları (`X` ve `X/`) işaretleyin.

---

## Diğer malicious ZIP trick'leri (2024–2026)

### Birleştirilmiş central directory'ler (multi-EOCD evasion)

2024'teki bir phishing campaign'inde saldırganlar, aslında **birleştirilmiş iki ZIP dosyası** olan tek bir blob gönderdi. Her birinin kendi End of Central Directory (EOCD) kaydı ve central directory'si vardı. Farklı extractor'lar farklı directory'leri parse etti (7-Zip ilkini, WinRAR ise sonuncuyu okudu); bu da saldırganların yalnızca bazı tool'ların gösterdiği payload'ları gizlemesine olanak sağladı. Yalnızca tek bir directory'yi inceleyen scanner'lar diğer arşivi kaçırabilir.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage komutları**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Birden fazla EOCD görünüyorsa veya "data after payload" uyarıları varsa blob'u bölün ve her bir kısmı inceleyin:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs, küçük bir **kernel** (yüksek oranda sıkıştırılmış bir DEFLATE bloğu) oluşturur ve bunu örtüşen girdiler arasında yeniden kullanır. Full-overlap varyantları, birden fazla central-directory girdisini tek bir local header'a yönlendirirken quoted-overlap varyantları, local header'ları DEFLATE stream'leri içinde quote eder; yayımlanan yapılandırma, iç içe arşivler olmadan 28M:1'den daha yüksek bir oran elde eder.<sup>[[7]](#references)</sup>

**Hızlı detection (duplicate LFH offsets)**
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
**İşleme**
- Dry-run yürüyüşü gerçekleştirin: `zipdetails -v file.zip | grep -n "Local Header Offset"` komutunu çalıştırın ve başvurulan local-header offset'lerini ve sıkıştırılmış veri aralıklarını karşılaştırın; yinelenen offset'ler tam örtüşen varyantları belirtir.<sup>[[7]](#references)[[8]](#references)</sup>
- Çıkarmadan önce bir parser ile kabul edilen toplam uncompressed boyutu ve entry sayısını sınırlayın; `zipinfo -t file.zip` toplamları raporlar, ancak bir güvenlik sınırı uygulamaz.<sup>[[8]](#references)</sup>
- Çıkarmanız gerektiğinde işlemi CPU ve disk limitleri olan bir cgroup/VM içinde gerçekleştirin (sınırsız inflation kaynaklı crash'lerden kaçının).<sup>[[8]](#references)</sup>

---

### Local-header ile central-directory parser karmaşası

Yakın tarihli differential-parser araştırmaları, ZIP belirsizliğinin modern toolchain'lerde hâlâ exploitable olduğunu gösterdi. Temel fikir basittir: bazı software'ler **Local File Header (LFH)**'a, diğerleri ise **Central Directory (CD)**'ye güvenir; bu nedenle tek bir archive, farklı tool'lara farklı filename'ler, path'ler, comment'ler, offset'ler veya entry set'leri sunabilir.<sup>[[9]](#references)</sup>

Practical offensive kullanımlar:
- Bir upload filter'ının, AV pre-scan'inin veya package validator'ının CD'de benign bir file görmesini, extractor'ın ise farklı bir LFH name/path'ini işlemesini sağlayın.
- Farklı parser'ların farklı tree'ler oluşturmasını sağlamak için duplicate name'lerden, yalnızca bir structure'da bulunan entry'lerden veya belirsiz Unicode path metadata'sından (örneğin Info-ZIP Unicode Path Extra Field `0x7075`) yararlanın.
- Bunu path traversal ile birleştirerek "harmless" bir archive görünümünü extraction sırasında write-primitive'e dönüştürün. Extraction tarafı için bkz. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR triyajı:
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
Şununla tamamlayın:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Sezgisel Kurallar:
- Security-sensitive ingestion için LFH/CD adları uyuşmayan, yinelenen dosya adları içeren, birden fazla EOCD kaydı bulunan veya son EOCD'den sonra ek baytlar içeren arşivleri reddedin ya da izole edin.<sup>[[9]](#references)[[10]](#references)</sup>
- Farklı araçlar çıkarılan ağaç yapısı konusunda anlaşmazlığa düşüyorsa, alışılmadık Unicode-path extra fields veya tutarsız comments kullanan ZIP'leri şüpheli kabul edin.<sup>[[4]](#references)[[9]](#references)</sup>
- Analiz, özgün baytları korumaktan daha önemliyse arşivi sandbox'ta çıkardıktan sonra strict parser ile yeniden paketleyin ve elde edilen dosya listesini özgün metadata ile karşılaştırın.

Bu durum package ecosystems ile sınırlı değildir: Aynı belirsizlik sınıfı, mail gateway'lerinden, static scanner'lardan ve arşivi farklı bir extractor işlemeden önce ZIP içeriğine "peek" yapan custom ingestion pipeline'larından payload'ları gizleyebilir.<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF kategorisi)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script'i)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistic Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
