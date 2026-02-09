# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**Komut satırı araçları** zip dosyalarını yönetmek, teşhis etmek, onarmak ve kırmak için gereklidir. İşte bazı temel yardımcı araçlar:

- **`unzip`**: Bir zip dosyasının neden açılmadığını ortaya çıkarır.
- **`zipdetails -v`**: Zip dosyası formatı alanlarının ayrıntılı analizini sunar.
- **`zipinfo`**: Dosyaları çıkarmadan bir zip dosyasının içeriğini listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip parolalarını brute-force ile kırmak için bir araç, yaklaşık 7 karaktere kadar parolalar için etkilidir.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sağlar.

Parola korumalı zip dosyalarının içindeki dosya adlarını veya dosya boyutlarını şifrelemediğini bilmek önemlidir; bu, bu bilgileri şifreleyen RAR veya 7z ile paylaşılmayan bir güvenlik açığıdır. Ayrıca, eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifrelenmemiş bir kopyası mevcutsa bir **plaintext attack**'e karşı savunmasızdır. Bu saldırı, bilinen içeriği kullanarak zip'in parolasını kırar; bu zafiyet [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) ve daha ayrıntılı olarak [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) tarafından açıklanmıştır. Ancak **AES-256** ile korunan zip dosyaları bu plaintext attack'e karşı dayanıklıdır; bu da hassas veriler için güvenli şifreleme yöntemlerinin seçilmesinin önemini gösterir.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers, APK'nin cihazda kurulabilir kalmasını sağlarken statik araçları (jadx/apktool/unzip) bozmak için hatalı ZIP metadata'sı kullanır. En yaygın hileler şunlardır:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Belirtiler:
- `jadx-gui` şu gibi hatalarla başarısız olur:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`, geçerli bir APK'nin şifrelenmiş `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` içermemesi gerektiği halde temel APK dosyaları için parola ister:

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
Yerel ve merkezi başlıklar için General Purpose Bit Flag'e bakın. İpucu veren değer, core entries için bile bit 0'ın set (Encryption) olmasıdır:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Eğer bir APK cihaza kurulup çalışıyor ancak temel girdiler araçlarda "şifrelenmiş" gibi görünüyorsa, GPBF üzerinde oynama yapılmıştır.

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
Artık core girdilerde `General Purpose Flag  0000` görmelisiniz ve araçlar APK'yı tekrar parse edecek.

### 2) Parsers'ı bozmak için büyük/özel Extra fields

Saldırganlar, decompiler'ları takılmaya zorlamak için headers içine aşırı büyük Extra fields ve tuhaf ID'ler yerleştirir. Gerçek dünyada orada gömülü özelleştirilmiş marker'lar (örn., `JADXBLOCK` gibi string'ler) görebilirsiniz.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Gözlemlenen örnekler: `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen ID'lerin büyük payloadlar taşıması.

DFIR heuristikleri:
- Ana girdilerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra alanları alışılmadık şekilde büyükse uyarı verin.
- Bu girdilerdeki bilinmeyen Extra ID'lerini şüpheli kabul edin.

Pratik hafifletme: arşivi yeniden oluşturmak (ör. çıkarılmış dosyaları yeniden ziplemek) kötü amaçlı Extra alanlarını temizler. Araçlar sahte şifreleme nedeniyle çıkarmayı reddederse, önce yukarıda belirtildiği gibi GPBF bit 0'ı temizleyin, sonra yeniden paketleyin:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Dosya/Dizin ad çakışmaları (gerçek artefaktları gizleme)

Bir ZIP, hem bir dosya `X` hem de bir dizin `X/` içerebilir. Bazı çıkarma araçları ve decompiler'lar karışıklık yaşayabilir ve dizin girdisi gerçek dosyanın üzerine bindirerek onu gizleyebilir. Bu, `classes.dex` gibi temel APK isimleriyle çakışan girdilerde gözlemlenmiştir.

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
Blue-team algılama fikirleri:
- Yerel başlıkları şifreleme işareti taşıyan (GPBF bit 0 = 1) ancak yine de yüklenen/çalıştırılan APK'ları işaretle.
- Çekirdek girdilerde büyük/bilinmeyen Extra fields'ları işaretle (örn. `JADXBLOCK` gibi işaretleri ara).
- Yol çakışmalarını (`X` ve `X/`) özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için işaretle.

---

## Diğer kötü amaçlı ZIP hileleri (2024–2025)

### Birleştirilmiş merkezi dizinler (multi-EOCD kaçışı)

Son phishing kampanyaları, aslında arka arkaya eklenmiş **iki ZIP dosyasını** içeren tek bir blob gönderiyor. Her birinin kendi End of Central Directory (EOCD) + central directory'si bulunuyor. Farklı extractors farklı dizinleri parse ediyor (7zip ilkini okur, WinRAR sonuncusunu), bu da saldırganların yalnızca bazı araçların gösterdiği payload'ları gizlemesine izin veriyor. Bu ayrıca yalnızca ilk dizini inceleyen temel mail gateway AV'yi atlatıyor.

**Triage komutları**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Birden fazla EOCD görünüyorsa veya "data after payload" uyarıları varsa, blob'u bölün ve her parçayı inceleyin:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" küçük bir **kernel** (highly compressed DEFLATE block) oluşturur ve bunu overlapping local headers aracılığıyla yeniden kullanır. Every central directory entry aynı compressed data'ya işaret eder, nesting archives olmadan >28M:1 oranlarına ulaşır. Libraries that trust central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) petabytes allocate etmeye zorlanabilir.

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
- Kuru çalışma (dry-run) yürüyüşü yapın: `zipdetails -v file.zip | grep -n "Rel Off"` ve offset'lerin sıralı olarak artan ve benzersiz olduğundan emin olun.
- Çıkarma öncesi kabul edilen toplam sıkıştırılmamış boyutu ve giriş sayısını sınırlandırın (`zipdetails -t` veya özel bir parser).
- Çıkarmanız gerektiğinde, bunu CPU ve disk limitleri olan bir cgroup/VM içinde yapın (sınırsız kaynak artışıyla oluşan çökmeleri önleyin).

---

## Kaynaklar

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
