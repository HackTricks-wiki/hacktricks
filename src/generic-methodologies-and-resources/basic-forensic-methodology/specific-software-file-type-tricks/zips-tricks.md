# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**Komut satırı araçları** zip dosyalarını teşhis etmek, onarmak ve kırmak için esastır. İşte bazı önemli yardımcı programlar:

- **`unzip`**: Bir zip dosyasının neden açılmadığını gösterir.
- **`zipdetails -v`**: zip dosyası formatı alanlarının detaylı analizini sunar.
- **`zipinfo`**: Zip içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını tamir etmeyi dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zip şifrelerini kaba kuvvetle kırmak için bir araç, yaklaşık 7 karaktere kadar olan parolalar için etkilidir.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip dosyalarının yapısı ve standartları hakkında kapsamlı ayrıntılar sağlar.

Şifre korumalı zip dosyalarının içindeki dosya adlarını veya dosya boyutlarını **şifrelemediğini** belirtmek önemlidir; bu, RAR veya 7z dosyalarının şifrelediği bu bilgiyle paylaşılmayan bir güvenlik açığıdır. Ayrıca, eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifresiz bir kopyası mevcutsa **plaintext attack**'e karşı savunmasızdır. Bu saldırı, bilinen içeriği kullanarak zip parolasını kırar; bu zafiyet [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) tarafından detaylandırılmış ve [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) tarafından daha ayrıntılı açıklanmıştır. Ancak, **AES-256** ile korunmuş zip dosyaları bu plaintext attack'e karşı bağışıktır; bu da hassas veriler için güvenli şifreleme yöntemlerinin seçilmesinin önemini gösterir.

---

## APK'lerde manipüle edilmiş ZIP başlıkları kullanılarak yapılan Anti-reversing tricks

Modern Android malware droppers, APK'yı cihazda kurulabilir tutarken statik araçları (jadx/apktool/unzip) bozmak için bozuk ZIP metadata'sı kullanır. En yaygın hileler şunlardır:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Belirtiler:
- `jadx-gui` şu tür hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` geçerli bir APK'nın şifrelenmiş `classes*.dex`, `resources.arsc`, veya `AndroidManifest.xml` içeremeyeceği halde temel APK dosyaları için parola ister:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Tespit için zipdetails:
```bash
zipdetails -v sample.apk | less
```
Yerel ve merkezi başlıklar için General Purpose Bit Flag'e bakın. Ayırt edici bir değer, temel girdiler için bile bit 0'ın set olması (Encryption):
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Sezgisel: Eğer bir APK cihazda kurulur ve çalıştırılır ancak çekirdek girdileri araçlara "şifrelenmiş" gibi görünüyorsa, GPBF değiştirilmiştir.

Düzeltme: GPBF bit 0'ı hem Local File Headers (LFH) hem de Central Directory (CD) girdilerinde temizlenerek yapılır. Minimal byte-patcher:

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
Artık çekirdek girdilerinde `General Purpose Flag  0000` görmelisiniz ve araçlar APK'yı tekrar ayrıştıracaktır.

### 2) Ayrıştırıcıları bozmak için büyük/özel Extra alanlar

Saldırganlar, dekompilerleri yanıltmak için başlıklara aşırı büyük Extra alanlar ve tuhaf ID'ler koyar. Gerçekte orada gömülü özel işaretler (örn. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'lerin büyük payloads taşıması.

DFIR heuristikleri:
- core girişlerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra alanları olağandışı şekilde büyük olduğunda uyarı ver.
- Bu girişlerdeki bilinmeyen Extra ID'lerini şüpheli olarak değerlendir.

Pratik hafifletme: arşivi yeniden oluşturmak (ör. çıkartılmış dosyaları yeniden ziplemek) kötü amaçlı Extra alanlarını temizler. Eğer araçlar sahte şifreleme nedeniyle çıkartmayı reddederse, önce yukarıda belirtildiği gibi GPBF bit 0'ı temizleyin, sonra yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin adı çakışmaları (gerçek artefaktları gizleme)

Bir ZIP hem bir dosya `X` hem de bir dizin `X/` içerebilir. Bazı extractors ve decompilers şaşırabilir ve gerçek dosyanın üzerine dizin girdisi yazarak onu gizleyebilir. Bu, core APK isimleriyle (ör. `classes.dex`) çakışan girdilerde gözlemlendi.

Triyaj ve güvenli çıkarma:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programatik tespit son eki:
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
- Yerel başlıkları şifreleme olarak işaretleyen (GPBF bit 0 = 1) ancak yine de yüklenen/çalıştırılan APK'leri işaretle.
- Çekirdek girdilerdeki büyük/bilinmeyen Extra alanlarını işaretle (ör. `JADXBLOCK` gibi markerlara bak).
- Yol çakışmalarını işaretle (`X` and `X/`) özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için.

---

## Diğer kötü amaçlı ZIP hileleri (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Son phishing kampanyaları, aslında arka arkaya eklenmiş iki ZIP dosyası olan tek bir blob gönderiyor. Her birinin kendi End of Central Directory (EOCD) + central directory'si var. Farklı extractors farklı dizinleri parse ediyor (7zip ilkini okur, WinRAR sonuncusunu), bu sayede saldırganlar sadece bazı araçların gösterdiği payload'ları gizleyebiliyor. Bu, yalnızca ilk dizini inceleyen temel mail gateway AV'yi de atlatıyor.

**Triage komutları**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Eğer birden fazla EOCD görünüyorsa veya "data after payload" uyarıları varsa, blob'u bölün ve her bir parçayı inceleyin:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" küçük bir **çekirdek** (yüksek oranda sıkıştırılmış DEFLATE bloğu) oluşturur ve bunu örtüşen local headers aracılığıyla tekrar kullanır. Her central directory girdisi aynı sıkıştırılmış veriye işaret eder; arşivleri iç içe sokmadan >28M:1 oranları elde edilir. Central directory boyutlarına güvenen kütüphaneler (Python `zipfile`, Java `java.util.zip`, Info-ZIP güçlendirilmiş sürümlerden önce) petabaytlarca bellek ayırmaya zorlanabilir.

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
- Bir dry-run taraması yap: `zipdetails -v file.zip | grep -n "Rel Off"` ve offsetlerin kesinlikle artan ve benzersiz olduğunu doğrula.
- Çıkarımdan önce kabul edilen toplam sıkıştırılmamış boyutu ve giriş sayısını sınırla (`zipdetails -t` veya özel ayrıştırıcı).
- Zorunlu olarak çıkarım yapmanız gerekiyorsa, bunu CPU+disk sınırları olan bir cgroup/VM içinde yap (sınırsız kaynak kullanımından kaynaklanan çökmeleri önleyin).

---

### Local-header vs central-directory parser confusion

Son differential-parser araştırmaları, ZIP belirsizliğinin modern araç zincirlerinde hâlâ sömürülebilir olduğunu gösterdi. Temel fikir basit: bazı yazılımlar **Local File Header (LFH)**'a güveniyor, bazıları ise **Central Directory (CD)**'ye güveniyor; bu yüzden tek bir arşiv farklı araçlara farklı dosya adları, yollar, açıklamalar, offsets veya entry setleri gösterebilir.

Pratik ofansif kullanım örnekleri:
- Bir upload filtresinin, AV ön-taramasının veya paket doğrulayıcısının CD'de iyi niyetli bir dosya görmesini sağlayın; ekstraktör ise farklı bir LFH adı/yolunu işler.
- Çift adları, yalnızca bir yapıda bulunan girişleri veya belirsiz Unicode yol meta verisini (örneğin, Info-ZIP Unicode Path Extra Field `0x7075`) kötüye kullanarak farklı parser'ların farklı ağaçlar oluşturmasını sağlayın.
- Bunu path traversal ile birleştirerek çıkarma sırasında "harmless" görünen bir arşivi yazma ilkeline dönüştürün. Çıkarma tarafı için bkz. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR önceliklendirmesi:
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
Eksik içeriği veya tamamlamamı istediğiniz metni gönderin; göndereceğiniz dosya içeriğini Türkçeye çevirip aynı markdown/HTML sözdizimini koruyarak döndüreceğim.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Sezgisel Kurallar:
- Eşleşmeyen LFH/CD isimleri, yinelenen dosya adları, birden fazla EOCD kaydı veya son EOCD'den sonra kalan baytlar içeren arşivleri reddedin veya izole edin.
- Farklı araçlar çıkarılan ağaç konusunda anlaşmazlığa düşerse, alışılmadık Unicode-path extra fields kullanan veya tutarsız yorumlar içeren ZIP'leri şüpheli olarak değerlendirin.
- Analizin orijinal baytların korunmasından daha önemli olduğu durumlarda, sandbox'ta çıkarımdan sonra arşivi katı bir parser ile yeniden paketleyin ve oluşan dosya listesini orijinal metadata ile karşılaştırın.

Bu, paket ekosistemlerinin ötesinde önemlidir: aynı belirsizlik sınıfı, farklı bir extractor arşivi işlemeye başlamadan önce ZIP içeriğine "peek" atan mail gateways, static scanners ve custom ingestion pipelines gibi sistemlerden payloads gizleyebilir.

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
