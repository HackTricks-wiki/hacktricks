# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zip dosyalarını yönetmek için; tanılama, onarma ve şifre kırma işlemlerinde gereklidir. İşte bazı önemli araçlar:

- **`unzip`**: Bir zip dosyasının neden açılmayabileceğini ortaya çıkarır.
- **`zipdetails -v`**: zip dosyası format alanlarının ayrıntılı analizini sunar.
- **`zipinfo`**: Bir zip dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozulmuş zip dosyalarını onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Yaklaşık 7 karaktere kadar parolalar için etkili bir zip parola kırma aracı.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sağlar.

Şuna dikkat etmek önemlidir: parola korumalı zip dosyaları içinde dosya adlarını veya dosya boyutlarını şifrelemezler; bu, RAR veya 7z dosyalarının sahip olmadığı bir güvenlik açığıdır (bu formatlar bu bilgileri şifreleyebilir). Ayrıca, eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifresiz bir kopyası mevcutsa bir plaintext attack'a karşı savunmasızdır. Bu saldırı, bilinen içeriği kullanarak zip parolasını kırmayı sağlar; bu zafiyet [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) adresinde ve [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) içinde detaylandırılmıştır. Ancak, AES-256 ile korunmuş zip dosyaları bu plaintext attack'a karşı bağışıktır; bu da hassas veriler için güvenli şifreleme yöntemleri seçmenin önemini gösterir.

---

## Manipüle edilmiş ZIP başlıkları kullanılarak APK'larda anti-reversing hileleri

Modern Android malware dropper'ları, APK'nın cihazda kurulabilir kalmasını sağlarken static araçları (jadx/apktool/unzip) bozmak için bozuk ZIP metadata'sı kullanır. En yaygın hileler şunlardır:

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı set ederek sahte şifreleme
- Parser'ları şaşırtmak için büyük/özel Extra alanlarını kötüye kullanma
- Gerçek öğeleri gizlemek için dosya/klasör isim çakışmaları (örn., gerçek `classes.dex` yanında `classes.dex/` isimli bir dizin)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Belirtiler:
- `jadx-gui` şu tür hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` core APK dosyaları için parola ister, oysa geçerli bir APK `classes*.dex`, `resources.arsc`, veya `AndroidManifest.xml` dosyalarını şifreli olamaz:

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
Yerel ve merkezi başlıklar için General Purpose Bit Flag'e bakın. İhbar edici bir değer, çekirdek girdiler için bile bit 0'ın setlenmiş olması (Encryption):
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Bir APK cihazda yüklenip çalışıyorsa ama araçlara göre core girdileri "encrypted" görünüyorsa, GPBF üzerinde oynanmış demektir.

Düzeltme: Hem Local File Headers (LFH) hem de Central Directory (CD) girdilerindeki GPBF bit 0'ı temizleyerek yapılır. Minimal byte-patcher:
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
Artık çekirdek girişlerinde `General Purpose Flag  0000` görmelisiniz ve araçlar APK'yi tekrar ayrıştıracaktır.

### 2) Ayrıştırıcıları bozmak için büyük/özel Extra fields

Saldırganlar, dekompilerleri yanıltmak için başlıklara aşırı büyük Extra fields ve tuhaf ID'ler yerleştirir. Gerçek dünyada oraya gömülü özel işaretçiler (ör. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'lerin büyük payloadlar taşıması.

DFIR heuristikleri:
- Çekirdek girdilerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra fields olağandışı büyükse uyarı verin.
- Bu girdilerdeki bilinmeyen Extra ID'lerini şüpheli olarak değerlendirin.

Pratik çözüm: arşivi yeniden oluşturmak (ör. çıkarılan dosyaları yeniden ziplemek) zararlı Extra fields'leri kaldırır. Araçlar sahte şifreleme nedeniyle çıkarmayı reddediyorsa, önce yukarıda belirtildiği gibi GPBF bit 0'ı temizleyin, sonra yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin ad çakışmaları (gerçek artefaktları gizleme)

Bir ZIP hem bir dosya `X` hem de bir dizin `X/` içerebilir. Bazı extractors ve decompilers karışıklık yaşayabilir ve gerçek dosyayı bir dizin girdisiyle üst üste yazabilir veya gizleyebilir. Bu, `classes.dex` gibi çekirdek APK isimleriyle çakışan girdilerde gözlemlenmiştir.

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
- Flag, local header'ları şifrelemeyi işaret eden (GPBF bit 0 = 1) fakat yine de install/run olan APK'ler.
- Flag, core entry'lerdeki büyük/bilinmeyen Extra field'lar (ör. `JADXBLOCK` gibi marker'lara bak).
- Flag path-collisions (`X` and `X/`) özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için.

---

## Referanslar

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
