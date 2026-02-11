# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**Komut satırı araçları**, **zip dosyaları** ile çalışırken tanılama, onarım ve kırma işlemleri için gereklidir. Öne çıkan bazı yardımcı programlar:

- **`unzip`**: Bir zip dosyasının neden açılmadığını gösterir.
- **`zipdetails -v`**: Zip dosyası formatı alanlarının ayrıntılı analizini sunar.
- **`zipinfo`**: Dosyaları açmadan bir zip dosyasının içeriğini listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Yaklaşık 7 karaktere kadar şifreler için brute-force kırma aracı.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip dosyalarının yapı ve standartları hakkında kapsamlı bilgiler sağlar.

Şu önemli noktaya dikkat etmek gerekir: parola korumalı zip dosyaları içinde dosya adlarını veya dosya boyutlarını **şifrelemez**, bu RAR veya 7z gibi formatlarda bulunan bir güvenlik önlemi değildir. Ayrıca, eski ZipCrypto ile şifrelenmiş zip dosyaları, sıkıştırılmamış bir dosyanın açık bir kopyası mevcutsa bilinen bir **plaintext attack**e karşı savunmasızdır. Bu saldırı, bilinen içeriği kullanarak zip şifresini kırar; detaylar için [HackThis'in makalesine](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) ve [bu akademik makaleye](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) bakılabilir. Ancak **AES-256** ile korunmuş zip dosyaları bu plaintext attack'e karşı bağışıktır; bu da hassas veriler için güçlü şifreleme yöntemlerinin seçiminin önemini gösterir.

---

## Manipüle edilmiş ZIP başlıkları kullanılarak APK'larda anti-reversing hileleri

Modern Android malware dropper'ları, APK'yi cihazda kurulabilir tutarken statik araçları (jadx/apktool/unzip) kırmak için bozuk ZIP metadata'sı kullanır. En yaygın hileler:

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak sahte şifreleme
- Ayrıştırıcıları şaşırtmak için büyük/özel Extra alanlarını kötüye kullanma
- Gerçek öğeleri gizlemek için dosya/klasör adı çakışmaları (ör. gerçek `classes.dex` yanında `classes.dex/` adlı bir dizin)

### 1) Gerçek kripto olmadan sahte şifreleme (GPBF bit 0 set)

Belirtiler:
- `jadx-gui` şu tip hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` temel APK dosyaları için parola ister, oysa geçerli bir APK `classes*.dex`, `resources.arsc`, veya `AndroidManifest.xml` dosyalarını şifreleyemez:

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
Local ve central header'lar için General Purpose Bit Flag'e bakın. İpucu: core entry'ler için bile bit 0'ın set (Encryption) olması:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Sezgisel: Eğer bir APK cihazda yüklenip çalışıyor ancak çekirdek girdileri araçlara "şifrelenmiş" gibi görünüyorsa, GPBF ile oynanmış demektir.

Çözüm, hem Local File Headers (LFH) hem de Central Directory (CD) girdilerindeki GPBF bit 0'ı temizlemektir. Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit temizleme patcheri</summary>
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

### 2) Parsers'ı bozmak için büyük/özel Extra fields

Saldırganlar decompilerları yanıltmak için başlıklara aşırı büyük Extra fields ve tuhaf ID'ler koyar. Gerçekte orada gömülü özel işaretçiler (ör. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'lerin büyük payload'lar taşıması.

DFIR heuristikleri:
- Core entry'lerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra fields olağandışı büyük olduğunda uyarı verin.
- Bu entry'lerdeki bilinmeyen Extra ID'lerini şüpheli olarak değerlendirin.

Pratik önlem: arşivi yeniden oluşturmak (örn. çıkarılan dosyaları yeniden ziplemek) zararlı Extra fields'i temizler. Eğer araçlar sahte şifreleme nedeniyle çıkarmayı reddederse, önce yukarıda belirtildiği gibi GPBF bit 0'ı temizleyin, sonra yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin isim çakışmaları (gerçek artefaktların gizlenmesi)

Bir ZIP hem bir dosya `X` hem de bir dizin `X/` içerebilir. Bazı açıcılar ve decompiler'lar karışıklık yaşayabilir ve gerçek dosyanın üzerine bir dizin girdisi yerleştirebilir veya onu gizleyebilir. Bu, `classes.dex` gibi çekirdek APK isimleriyle çakışan girdilerde gözlemlenmiştir.

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
- APK'lerin yerel header'ları şifrelemeyi işaretlediği (GPBF bit 0 = 1) halde yine de yüklenen/çalıştırılan APK'leri işaretle.
- core girdilerindeki büyük/bilinmeyen Extra field'ları işaretle ( `JADXBLOCK` gibi işaretleri ara).
- Özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için yol çakışmalarını (`X` ve `X/`) işaretle.

---

## Diğer kötü amaçlı ZIP hileleri (2024–2025)

### Birleştirilmiş central directories (multi-EOCD evasion)

Son phishing kampanyalarında tek bir blob gönderiliyor; bu blob aslında **iki ZIP dosyasının birleştirilmiş hali**. Her birinin kendi End of Central Directory (EOCD) + central directory'si bulunuyor. Farklı extractors farklı dizinleri parse eder (7zip ilkini okur, WinRAR sonuncuyu), bu da saldırganların yalnızca bazı araçların gösterdiği payload'ları gizlemesine olanak tanıyor. Bu ayrıca yalnızca ilk dizini inceleyen temel mail gateway AV'lerini de atlatıyor.

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

Modern "better zip bomb" küçük bir **çekirdek** (yüksek oranda sıkıştırılmış DEFLATE bloğu) oluşturur ve bunu örtüşen local headers aracılığıyla yeniden kullanır. Her central directory entry aynı sıkıştırılmış veriye işaret eder; arşivleri iç içe koymadan >28M:1 oranlarına ulaşır. Central directory boyutlarına güvenen kütüphaneler (Python `zipfile`, Java `java.util.zip`, Info-ZIP, sertleştirilmiş build'lerden önce) petabaytlar ayırmaya zorlanabilir.

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
**Ele alma**
- Bir dry-run yürütün: `zipdetails -v file.zip | grep -n "Rel Off"` ve offsetlerin kesinlikle artan ve benzersiz olduğundan emin olun.
- Çıkarma işleminden önce kabul edilen toplam sıkıştırılmamış boyutu ve giriş sayısını sınırlandırın (`zipdetails -t` veya özel bir ayrıştırıcı).
- Zorunlu olarak çıkartma yapmanız gerekiyorsa, bunu CPU ve disk limitleri olan bir cgroup/VM içinde yapın (sınırsız genişleme kaynaklı çökme/şişmeyi önleyin).

---

## Kaynaklar

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
