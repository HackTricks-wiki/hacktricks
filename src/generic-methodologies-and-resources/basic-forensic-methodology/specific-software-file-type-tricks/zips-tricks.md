# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**Komut satırı araçları** ile **zip dosyalarını** yönetmek, zip dosyalarını teşhis etmek, onarmak ve cracking için elzemdir. İşte bazı önemli yardımcılar:

- **`unzip`**: Bir zip dosyasının neden açılmadığını ortaya çıkarır.
- **`zipdetails -v`**: Zip dosyası formatı alanlarının ayrıntılı analizini sunar.
- **`zipinfo`**: Bir zip dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını onarmaya çalışır.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip şifrelerini brute-force ile kırmak için bir araç; yaklaşık 7 karaktere kadar olan şifreler için etkilidir.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sağlar.

Şunu not etmek önemlidir: parola ile korunan zip dosyaları içerideki **dosya adlarını veya dosya boyutlarını şifrelemez**, bu RAR veya 7z dosyalarının şifrelediği bilgiyi şifrelememeleri nedeniyle bir güvenlik açığıdır. Ayrıca, daha eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifresiz bir kopyası mevcutsa bir **plaintext attack**'e karşı savunmasızdır. Bu saldırı, bilinen içeriği kullanarak zip'in parolasını kırar; bu zafiyet [HackThis'in makalesinde](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) ve [bu akademik makalede](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) detaylandırılmıştır. Ancak **AES-256** ile korunmuş zip dosyaları bu plaintext attack'e karşı bağışıktır; bu da hassas veriler için güvenli şifreleme yöntemlerinin seçilmesinin önemini gösterir.

---

## Manipüle edilmiş ZIP başlıkları kullanılarak APK'larda anti-reversing hileleri

Modern Android malware droppers, bozuk ZIP metadata kullanarak statik araçları (jadx/apktool/unzip) bozar ve aynı zamanda APK'nın cihazda yüklenebilir kalmasını sağlar. En yaygın hileler şunlardır:

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak sahte şifreleme
- Parser'ları şaşırtmak için büyük/özel Extra field'ların kötüye kullanılması
- Gerçek artefaktları gizlemek için dosya/dizin adı çakışmaları (ör. gerçek `classes.dex` yanında `classes.dex/` adında bir dizin)

### 1) Gerçek kripto olmadan sahte şifreleme (GPBF bit 0 ayarlı)

Belirtiler:
- `jadx-gui` aşağıdaki gibi hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`, çekirdek APK dosyaları için parola ister; oysaki geçerli bir APK `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` gibi dosyaların şifreli olmasını içeremez:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection with zipdetails:
```bash
zipdetails -v sample.apk | less
```
Yerel ve merkezi başlıklar için General Purpose Bit Flag'e bakın. İpuçlarından biri, çekirdek girdiler için bile bit 0'ın set edilmiş olması (Encryption):
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Sezgisel kural: Eğer bir APK cihazda yüklenip çalışıyor ama çekirdek girişleri araçlarda "şifreli" görünüyorsa, GPBF üzerinde oynama yapılmıştır.

Düzeltme: hem Local File Headers (LFH) hem de Central Directory (CD) girdilerinde GPBF bit 0'ı temizleyin. Minimal byte-patcher:

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
Artık çekirdek girdilerde `General Purpose Flag  0000` görmelisiniz ve araçlar APK'yı yeniden ayrıştıracaktır.

### 2) Ayrıştırıcıları bozmak için büyük/özel Extra alanları

Saldırganlar, decompiler'ları takılmaları için başlıklara aşırı büyük Extra alanlar ve tuhaf ID'ler yerleştirir. Gerçek dünyada orada gömülü özel işaretler görebilirsiniz (ör. `JADXBLOCK` gibi dizeler).

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'lerin büyük yükler taşıması.

DFIR heuristics:
- `classes*.dex`, `AndroidManifest.xml`, `resources.arsc` gibi ana girdilerde Extra fields olağandışı büyük olduğunda uyarı oluşturun.
- Bu girdilerdeki bilinmeyen Extra ID'lerini şüpheli kabul edin.

Pratik önlem: arşivi yeniden oluşturmak (ör. çıkarılan dosyaları tekrar ziplemek) zararlı Extra alanlarını temizler. Araçlar sahte şifreleme nedeniyle çıkarmayı reddederse, önce yukarıda belirtildiği gibi GPBF bit 0'ı temizleyin, sonra yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin ad çakışmaları (gerçek artefaktları gizleme)

Bir ZIP hem bir dosya `X` hem de bir dizin `X/` içerebilir. Bazı extractors ve decompilers karışarak dizin girdisinin gerçek dosyanın üzerine yazılmasına veya gerçek dosyanın gizlenmesine neden olabilir. Bu durum, `classes.dex` gibi core APK isimleriyle çakışan girdilerde gözlemlenmiştir.

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
- Yerel header'ları şifrelemeyi işaret eden (GPBF bit 0 = 1) ancak yine de yüklenen/çalıştırılan APK'leri işaretle.
- Çekirdek girdilerde büyük/bilinmeyen Extra field'ları işaretle ( `JADXBLOCK` gibi işaretlere bak).
- Özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için yol çakışmalarını (`X` ve `X/`) işaretle.

---

## Diğer kötü amaçlı ZIP hileleri (2024–2026)

### Birleştirilmiş merkezi dizinler (multi-EOCD atlatma)

Son phishing kampanyaları tek bir blob gönderiyor; aslında bu **art arda eklenmiş iki ZIP dosyası** oluyor. Her birinin kendi End of Central Directory (EOCD) + central directory'si var. Farklı extractor'lar farklı dizinleri parse ediyor (7zip ilkini, WinRAR sonuncusunu okuyor), bu da saldırganların sadece bazı araçlarda görünen payload'ları gizlemesine izin veriyor. Bu, ayrıca sadece ilk dizini inceleyen temel mail gateway AV'lerini de atlatıyor.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Birden fazla EOCD görünüyorsa veya "data after payload" uyarıları varsa, blob'u bölün ve her bir kısmı inceleyin:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" küçük bir **kernel** (yüksek oranda sıkıştırılmış DEFLATE bloğu) oluşturur ve overlapping local headers aracılığıyla tekrar kullanır. Her central directory entry aynı sıkıştırılmış veriye işaret eder ve iç içe arşivlere ihtiyaç duymadan >28M:1 oranları elde eder. Central directory boyutlarına güvenen kütüphaneler (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) petabaytlarca bellek ayırmaya zorlanabilir.

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
- Bir dry-run yürütün: `zipdetails -v file.zip | grep -n "Rel Off"` ve offsetlerin kesinlikle artan ve benzersiz olduğundan emin olun.
- Çıkarmadan önce kabul edilen toplam sıkıştırılmamış boyutu ve giriş sayısını sınırlayın (`zipdetails -t` veya özel bir ayrıştırıcı).
- Çıkarmanız gerekiyorsa, bunu CPU+disk sınırlamaları olan bir cgroup/VM içinde yapın (sınırsız şişme çöküşlerinden kaçının).

---

### Local-header vs central-directory ayrıştırıcı karışıklığı

Son differential-parser araştırmaları, ZIP belirsizliğinin modern araç zincirlerinde hâlâ suistimal edilebilir olduğunu gösterdi. Ana fikir basit: bazı yazılımlar **Local File Header (LFH)**'a güvenirken diğerleri **Central Directory (CD)**'ye güvenir; bu yüzden tek bir arşiv farklı araçlara farklı dosya adları, yollar, yorumlar, offsetler veya giriş setleri gösterebilir.

Pratik saldırı kullanım örnekleri:
- Bir upload filtresinin, AV ön taramasının veya paket doğrulayıcısının CD'de zararsız bir dosya görmesini sağlayın, oysa extractor farklı bir LFH adı/yolunu esas alsın.
- Çift isimleri, yalnızca bir yapıda bulunan girdileri veya belirsiz Unicode yol meta verisini (örneğin Info-ZIP Unicode Path Extra Field `0x7075`) kötüye kullanın; böylece farklı ayrıştırıcılar farklı ağaçlar oluşturur.
- Bunu path traversal ile birleştirerek "zararsız" bir arşiv görünümünü çıkarma sırasında bir write-primitive'e dönüştürebilirsiniz. Çıkarma tarafı için, bkz. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
İçeriği tercüme edebilmem için lütfen src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md dosyasının içeriğini gönderin veya yapıştırın. Ayrıca “Complement it with:” ile ne eklememi istediğinizi (ek metin, örnekler, açıklama) belirtirseniz tercümeyi o yönde tamamlarım.

Not: Göndereceğiniz içeriği markdown ve belirtilen tag/bağlantı kurallarına uygun şekilde Türkçeye çevireceğim.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristikler:
- Uyumsuz LFH/CD adları, yinelenen dosya adları, birden fazla EOCD kaydı veya son EOCD'den sonra kalan baytlar içeren arşivleri reddedin veya izole edin.
- Alışılmadık Unicode-path ekstra alanları kullanan veya tutarsız yorumlara sahip ZIP'leri, farklı araçlar çıkarılan ağaçta anlaşmıyorsa şüpheli olarak değerlendirin.
- Analiz, orijinal baytları korumaktan daha önemliyse, sandbox'ta çıkarımdan sonra sıkı bir parser ile arşivi yeniden paketleyin ve ortaya çıkan dosya listesini orijinal meta verilerle karşılaştırın.

Bu durum paket ekosistemlerinin ötesinde önem taşır: aynı belirsizlik sınıfı, mail gateway'lerinden, statik tarayıcılardan ve farklı bir extractor arşivi işlemeye başlamadan önce ZIP içeriklerine "peek" atan özel ingestion pipeline'larından payload'ları gizleyebilir.

---



## Referanslar

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
