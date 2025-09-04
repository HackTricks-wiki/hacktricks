# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**Komut satırı araçları**, **zip dosyalarını** yönetmek, teşhis etmek, onarmak ve kırmak için esastır. İşte bazı önemli araçlar:

- **`unzip`**: Bir zip dosyasının neden açılmayabileceğini gösterir.
- **`zipdetails -v`**: Zip dosyası formatı alanlarının ayrıntılı analizini sunar.
- **`zipinfo`**: Bir zip dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını onarmaya çalışır.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zip parolalarını brute-force ile kırmak için bir araç; yaklaşık 7 karaktere kadar parolalar için etkilidir.

Bu [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sağlar.

Parola korumalı zip dosyalarının dosya adlarını veya dosya boyutlarını **şifrelemediğini** bilmek önemlidir; bu, bu bilgileri şifreleyen RAR veya 7z ile paylaşılan bir güvenlik açığı değildir. Ayrıca, daha eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifrelenmemiş bir kopyası mevcutsa **plaintext attack**'a karşı savunmasızdır. Bu saldırı bilinen içeriği kullanarak zip parolasını kırar; bu zafiyet [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) ve [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) adreslerinde detaylandırılmıştır. Ancak **AES-256** şifrelemesiyle korunan zip dosyaları bu **plaintext attack**'e karşı bağışıktır; bu da hassas veriler için güvenli şifreleme yöntemlerinin seçilmesinin önemini gösterir.

---

## APK'lerde manipüle edilmiş ZIP başlıkları kullanılarak anti-reversing hileleri

Modern Android malware dropları, APK'nın cihazda kurulabilir kalmasını sağlarken statik araçları (jadx/apktool/unzip) bozmak için hatalı ZIP metadata'sı kullanır. En yaygın hileler şunlardır:

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak sahte şifreleme
- Ayrıştırıcıları şaşırtmak için büyük/özel Extra fields kullanımı
- Gerçek artefaktları gizlemek için dosya/dizin adı çakışmaları (ör. gerçek `classes.dex`'in yanında `classes.dex/` adlı bir dizin)

### 1) Gerçek kriptografi olmadan sahte şifreleme (GPBF bit 0 ayarlı)

Belirtiler:
- `jadx-gui` şu gibi hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` geçerli bir APK'nın `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` dosyaları şifreli olamayacağı halde temel APK dosyaları için parola ister:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails ile tespit:
```bash
zipdetails -v sample.apk | less
```
Yerel ve merkezi başlıklar için General Purpose Bit Flag'e bakın. İpuçlarından biri, core entries için bile bit 0'ın ayarlı olmasıdır (Encryption):
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Sezgisel: Eğer bir APK cihazda yüklenip çalışıyor ama araçlar için çekirdek girdileri "şifrelenmiş" gibi görünüyorsa, GPBF üzerinde oynama yapılmıştır.

Düzeltme: Hem Local File Headers (LFH) hem de Central Directory (CD) girdilerindeki GPBF bit 0'ı temizleyin. Minimal byte-patcher:
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
Kullanım:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Artık çekirdek girdilerinde `General Purpose Flag  0000` görmelisiniz ve araçlar APK'yı yeniden ayrıştıracaktır.

### 2) Ayrıştırıcıları bozmak için büyük/özel Extra alanlar

Saldırganlar decompiler'ları bozmak için başlıklara aşırı büyük Extra alanlar ve garip ID'ler ekler. Gerçek dünyada oraya gömülü özel işaretler (ör. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'ler büyük payloads taşıyor.

DFIR heuristics:
- Core girdilerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra fields olağandışı şekilde büyükse uyarı oluşturun.
- Bu girdilerdeki bilinmeyen Extra ID'lerini şüpheli kabul edin.

Pratik hafifletme: arşivi yeniden oluşturmak (ör. çıkarılan dosyaları yeniden zip'lemek) kötü amaçlı Extra field'ları temizler. Araçlar sahte şifreleme nedeniyle çıkarmayı reddederse, önce yukarıda belirtildiği gibi GPBF bit 0'ı temizleyin, sonra yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin adı çakışmaları (gerçek artefaktların gizlenmesi)

Bir ZIP içinde hem bir dosya `X` hem de bir dizin `X/` bulunabilir. Bazı extractors ve decompilers karışıp gerçek dosyanın üzerine dizin girdisi bindirebilir veya onu gizleyebilir. Bu, `classes.dex` gibi temel APK adlarıyla çakışan girdilerde gözlemlenmiştir.

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
Blue-team tespit fikirleri:
- Yerel başlıkları şifrelemeyi işaret eden (GPBF bit 0 = 1) fakat yine de kurulan/çalıştırılan APK'ları işaretle.
- Çekirdek girişlerindeki büyük/bilinmeyen Extra fields'leri işaretle (look for markers like `JADXBLOCK`).
- Yol çakışmalarını (`X` ve `X/`) özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için işaretle.

---

## Referanslar

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
