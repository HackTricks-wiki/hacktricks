# ZIP hileleri

{{#include ../../../banners/hacktricks-training.md}}

**ZIP dosyalarını** yönetmeye yönelik **komut satırı araçları**, ZIP dosyalarını teşhis etmek, onarmak ve kırmak için gereklidir. Önemli araçlardan bazıları:<sup>[[1]](#references)</sup>

- **`unzip`**: Bir ZIP dosyasının neden açılamadığını gösterir.
- **`zipdetails -v`**: ZIP dosya biçimi alanlarının ayrıntılı analizini sunar.<sup>[[3]](#references)</sup>
- **`zipinfo`**: ZIP dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozulmuş ZIP dosyalarını onarmayı dener.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP parolalarına yönelik sözlük ve brute-force saldırıları için bir araçtır; saldırının uygulanabilirliği parola arama alanına bağlıdır.<sup>[[15]](#references)</sup>

[ZIP dosya biçimi belirtimi](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), ZIP dosyalarının yapısı ve standartları hakkında kapsamlı ayrıntılar sunar.<sup>[[4]](#references)</sup>

Geleneksel parola korumalı ZIP dosyalarında, RAR ve 7z tarafından desteklenen başlık şifreleme modlarının aksine, dosya adları ve boyutları genellikle görünür kalır. ZipCrypto known-plaintext attack, özgün parolayı değil, **dahili şifreleme anahtarlarını** kurtarır; aynı parolayla şifrelenmiş girdilerin şifresini çözmek için bu anahtarlar yeterlidir.<sup>[[13]](#references)</sup> Saldırı için akışın **şifrelenmeden önceki** baytlarının bilinmesi gerekir: sıkıştırılmadan saklanan bir üye için bunlar özgün dosya baytlarıdır; DEFLATE üyesi içinse sıkıştırılmış baytlardır ve bunları elde etmek için sıkıştırma çıktısının aynısını yeniden oluşturmak gerekebilir.<sup>[[13]](#references)[[14]](#references)</sup> Uygulamalı bir iş akışı için [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) sayfasına bakın. Kriptanaliz hakkında arka plan bilgisi için [makaleye](https://math.ucr.edu/~mike/zipattacks.pdf) ve [adım adım açıklamaya](https://www.hackthissite.org/articles/read/793) bakın.<sup>[[11]](#references)[[12]](#references)</sup> Bu ZipCrypto saldırısı, AES ile şifrelenmiş ZIP girdileri için geçerli değildir.<sup>[[13]](#references)</sup>

---

## Değiştirilmiş ZIP başlıklarıyla APK'larda anti-reversing hileleri

Modern Android malware dropper'ları, APK'nın cihazda yüklenebilir kalmasını sağlarken statik analiz araçlarını (jadx/apktool/unzip) bozmak için hatalı ZIP metadata'sı kullanır. En yaygın hileler şunlardır:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) bit 0'ı ayarlayarak sahte şifreleme oluşturmak
- Ayrıştırıcıların kafasını karıştırmak için büyük/özel Extra alanlarını kötüye kullanmak
- Gerçek izleri gizlemek için dosya/dizin adı çakışmaları oluşturmak (ör. gerçek `classes.dex` dosyasının yanında `classes.dex/` adlı bir dizin bulunması)

### 1) Gerçek şifreleme olmadan sahte şifreleme (GPBF bit 0 ayarlı)

Belirtiler:
- `jadx-gui` şu tür hatalarla başarısız olur:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip`, geçerli bir APK'de şifrelenmiş `classes*.dex`, `resources.arsc` veya `AndroidManifest.xml` bulunamayacak olsa da temel APK dosyaları için parola ister:
  
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

Yerel ve merkezi başlıklardaki General Purpose Bit Flag'e bakın. Core girdiler için bile bit 0'ın ayarlanmış olması (Encryption) tipik bir göstergedir:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Sezgisel: Bir APK cihaza yüklenip çalışıyor ancak temel girdiler araçlara "şifrelenmiş" gibi görünüyorsa, GPBF kurcalanmıştır.

Düzeltmek için hem Local File Headers (LFH) hem de Central Directory (CD) girdilerindeki GPBF bit 0'ı temizleyin. Minimal bayt düzelticisi:

<details>
<summary>Minimal GPBF bit temizleme düzelticisi</summary>

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

Yalnızca 0. bit değişmelidir: örneğin, `0A09` değeri `0000` değil, `0A08` olur. Bu minimal patcher, ham baytlarda header imzalarını tarar; bu nedenle dosya verilerindeki imzaya benzeyen baytlar yanlış eşleşmelere yol açabilir. Çıktıyı kullanmadan önce bir kopya üzerinde çalışın ve sonuçtaki giriş listesini ve header’ları doğrulayın.<sup>[[4]](#references)</sup>

### 2) Parser’ları bozmak için büyük/özel Extra alanları

Saldırganlar, decompiler’ları yanıltmak için header’lara aşırı büyük Extra alanları ve alışılmadık ID’ler yerleştirir. Gerçek dünyada, buraya gömülmüş özel işaretleyiciler (ör. `JADXBLOCK` gibi dizeler) görebilirsiniz.

İnceleme:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Gözlemlenen örnekler: büyük payload'lar taşıyan `0xCAFE` ("Java Executable") veya `0x414A` ("JA:") gibi bilinmeyen kimlikler.<sup>[[2]](#references)</sup>

DFIR buluşsal yöntemleri:
- Temel girdilerde (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) Extra alanları alışılmadık derecede büyükse uyarı verin.
- Bu girdilerdeki bilinmeyen Extra kimliklerini şüpheli kabul edin.

Uygulamada azaltma: arşivi yeniden oluşturmak (ör. çıkarılan dosyaları yeniden zip'lemek) kötü amaçlı Extra alanlarını kaldırır. Sahte şifreleme nedeniyle araçlar dosyaları çıkarmayı reddederse, önce yukarıda açıklandığı gibi GPBF bit 0'ı temizleyin, ardından yeniden paketleyin:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Dosya/Dizin adı çakışmaları (gerçek artefaktları gizleme)

Bir ZIP hem `X` adlı bir dosya hem de `X/` adlı bir dizin içerebilir. Bazı çıkarıcılar ve decompiler'lar kafası karışabilir ve dizin girdisiyle gerçek dosyanın üzerine yazabilir veya onu gizleyebilir. Bunun `classes.dex` gibi temel APK adlarıyla çakışan girdilerde görüldüğü gözlemlenmiştir.

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
- Yerel header'larında şifreleme işaretli (GPBF bit 0 = 1) olmasına rağmen yüklenen/çalışan APK'ları işaretleyin.
- Temel girdilerdeki büyük/bilinmeyen Extra alanlarını işaretleyin (`JADXBLOCK` gibi işaretlere bakın).
- Özellikle `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` için yol çakışmalarını (`X` ve `X/`) işaretleyin.

---

## Diğer kötü amaçlı ZIP hileleri (2024–2026)

### Birleştirilmiş central directory'ler (multi-EOCD atlatma)

2024'teki bir phishing kampanyasında saldırganlar, aslında **birleştirilmiş iki ZIP dosyasından** oluşan tek bir blob dağıttı. Her birinin kendi End of Central Directory (EOCD) kaydı ve central directory'si vardı. Farklı çıkarıcılar farklı dizinleri ayrıştırdı (7-Zip ilkini, WinRAR ise sonuncusunu okudu); böylece saldırganlar yalnızca bazı araçların gösterdiği payload'ları gizleyebildi. Yalnızca tek bir dizini inceleyen tarayıcılar diğer arşivi gözden kaçırabilir.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage komutları**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Birden fazla EOCD görünüyorsa veya "payload'dan sonra veri" uyarıları varsa, blob'u bölün ve her parçayı inceleyin:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bomb'ları (özyinelemesiz)

Quoted-overlap ZIP bomb'ları, küçük bir **kernel** (yüksek oranda sıkıştırılmış bir DEFLATE bloğu) oluşturur ve bunu örtüşen girdiler arasında yeniden kullanır. Full-overlap varyantları birden fazla central-directory girdisini tek bir yerel başlığa yönlendirirken, quoted-overlap varyantları DEFLATE akışlarının içine yerel başlıkları alıntılar; yayımlanan yapı, iç içe arşivler kullanmadan 28M:1'in üzerinde bir oran elde eder.<sup>[[7]](#references)</sup>

**Hızlı tespit (yinelenen LFH offset'leri)**

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
- Bir dry-run incelemesi yapın: `zipdetails -v file.zip | grep -n "Local Header Offset"` çıktısındaki başvurulan local-header offset’lerini ve sıkıştırılmış veri aralıklarını karşılaştırın; yinelenen offset’ler tam örtüşme varyantlarına işaret eder.<sup>[[7]](#references)[[8]](#references)</sup>
- Çıkarmadan önce bir parser ile kabul edilen toplam açılmış boyutu ve girdi sayısını sınırlandırın; `zipinfo -t file.zip` toplamları bildirir ancak bir güvenlik sınırı uygulamaz.<sup>[[8]](#references)</sup>
- Çıkarma işlemi yapmanız gerekiyorsa, CPU ve disk sınırları olan bir cgroup/VM içinde gerçekleştirin (sınırsız açılmanın yol açacağı çökmeleri önleyin).<sup>[[8]](#references)</sup>

---

### Local-header ile central-directory parser’ları arasındaki karışıklık

Parser’lar arasındaki farklar üzerine yapılan yakın tarihli araştırmalar, ZIP belirsizliklerinin modern toolchain’lerde hâlâ istismar edilebildiğini gösterdi. Temel fikir basit: Bazı yazılımlar **Local File Header (LFH)** verisine güvenirken diğerleri **Central Directory (CD)** verisine güvenir; böylece tek bir arşiv farklı araçlara farklı dosya adları, yollar, yorumlar, offset’ler veya girdi kümeleri sunabilir.<sup>[[9]](#references)</sup>

Pratik saldırı amaçlı kullanımlar:
- Bir upload filtresinin, AV ön taramasının veya paket doğrulayıcısının CD’de zararsız bir dosya görmesini, extractor’ın ise farklı bir LFH adı/yolunu esas almasını sağlayın.
- Farklı parser’ların farklı ağaçlar oluşturmasına yol açmak için yinelenen adlardan, yalnızca bir yapıda bulunan girdilerden veya belirsiz Unicode yol metadata’sından (örneğin, Info-ZIP Unicode Path Extra Field `0x7075`) yararlanın.
- "Zararsız" görünen bir arşivi çıkarma sırasında bir yazma ilkel işlemine dönüştürmek için bunu path traversal ile birleştirin. Çıkarma tarafı için bkz. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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

Şunlarla tamamlayın:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Sezgisel Kurallar:
- Güvenlik açısından hassas veri alımında, LFH/CD adları uyuşmayan, yinelenen dosya adları içeren, birden fazla EOCD kaydı bulunan veya son EOCD'den sonra ek baytlar içeren arşivleri reddedin ya da yalıtın.<sup>[[9]](#references)[[10]](#references)</sup>
- Farklı araçlar çıkarılan dosya ağacı konusunda anlaşmazlığa düşüyorsa alışılmadık Unicode-yol ek alanları veya tutarsız açıklamalar kullanan ZIP'leri şüpheli kabul edin.<sup>[[4]](#references)[[9]](#references)</sup>
- Özgün baytları korumaktan çok analiz önemliyse, arşivi sandbox'ta çıkardıktan sonra katı bir parser kullanarak yeniden paketleyin ve elde edilen dosya listesini özgün metadata ile karşılaştırın.

Bu konu paket ekosistemlerinin ötesinde de önem taşır: aynı belirsizlik sınıfı, bir ZIP'in içeriğini farklı bir çıkarıcı arşivi işlerken önceden "inceleyen" e-posta ağ geçitlerinden, statik tarayıcılardan ve özel veri alım hatlarından payload'ları gizleyebilir.<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF Adli Bilişim Saha Rehberi (Mike's Blog, CTF kategorisi)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Bölüm 1 – Çok aşamalı dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress betiği)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP Dosya Biçimi Spesifikasyonu (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [ZIP Arşivlerinin Esnek Yapısı, Kötü Amaçlı Yazılımları Tespit Edilmeden Gizlemek İçin Kullanıldı (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hacker'lar yeni ZIP dosyası saldırısında kötü amaçlı yazılımları gizliyor — birleştirilmiş ZIP merkezi dizinleri](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Daha iyi bir zip bombası (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zip Bombalarını Anlamak: örtüşen/tırnak içine alınmış örtüşme çekirdeği oluşturma](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Benim ZIP'im senin ZIP'in değil: ZIP parser'ları arasındaki anlamsal boşlukları belirleme ve istismar etme (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Python paket yükleyicilerinde ZIP parser'ı karıştırma saldırılarını önleme](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Azaltılmış Bilinen Açık Metinle ZIP Saldırıları (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Gerçekçi Web Görevi, Seviye 15 (bilinen açık metin ZIP saldırısı)](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack kullanımı](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack bilinen açık metin öğreticisi](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip deposu](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
