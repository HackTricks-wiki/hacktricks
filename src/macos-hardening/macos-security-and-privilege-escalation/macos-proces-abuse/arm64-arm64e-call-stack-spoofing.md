# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Metadata odaklı stack unwinding neden spoof edilebilir?

Bazı macOS güvenlik araçları thread stack'lerini toplamayı `/usr/sbin/spindump` aracına devreder veya başka şekilde geleneksel, metadata odaklı bir unwinder'a güvenir. Bir implant, stack'ine ABI ile uyumlu sentetik kayıtlar yerleştirerek bu güven sınırından yararlanabilir; böylece hassas bir API'ye, desteklenmeyen implant kodundan değil de dyld ve yüklenmiş Apple framework'lerindeki saldırganın seçtiği fonksiyonlar üzerinden ulaşılmış gibi görünür. Bu, telemetry aldatmacasıdır; yürütülebilir dosyada veya unwind metadata'sında değişiklik yapmaz.<sup>[[1]](#references)</sup>

Toplama tarafının bağlamı için [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) sayfasına bakın.

Bir unwinder, kaydın compiler tarafından oluşturulmuş bir prologue ile yaratıldığını kanıtlamaz. Unwinder, geçerli `PC` değerini kullanarak bir Mach-O tarifini seçer; bu tarifi `SP`, `x29`, `x30`, stack belleği ve bildirilmiş nonvolatile register'lara uygular; ardından kurtarılan caller `PC` değerini kullanarak sıradaki tarifi seçer. Saldırganın kontrolündeki bellek, seçilen her tarifi karşılıyorsa, bu çağrılar hiç gerçekleşmemiş olsa bile ortaya çıkan zincir yapısal olarak geçerli ve sembollerle çözümlenebilir olabilir.<sup>[[1]](#references)</sup>

## ARM64 frame durumu

[ARM64 assembly overview](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md), register rollerini ve calling convention'ı ele alır. `stp x29, x30, [sp, #-16]!` komutunun ardından `mov x29, sp` ile oluşturulan geleneksel bir frame için, caller'ın giriş `SP` değerini temsil eden Canonical Frame Address (CFA), `FP+0x10` değeridir:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame kayıtları `[FP]` üzerinden bağlı bir liste oluşturur, ancak bu listeyi körü körüne izlemek yeterli değildir: yaprak fonksiyonlar frameless olabilir, tail call'lar mantıksal geçişleri ortadan kaldırabilir ve alışılmadık yerleşimler DWARF CFI kullanır. Unwinder'ın FP zincirini okuyup okumayacağını mevcut adres için seçilen recipe belirler.<sup>[[1]](#references)[[4]](#references)</sup>

## Mach-O unwind recipe seçimi

Son linklenmiş imajlar compact unwind verilerini `__TEXT,__unwind_info` içinde saklar. Section header, first-level function index'ini gösterir; her index aralığı normal (`kind=2`) veya sıkıştırılmış (`kind=3`) second-level page'e işaret eder. Compact unwind ile tanımlanamayan yerleşimler, `__eh_frame` içindeki bir FDE ve call-frame instructions kullanır.<sup>[[1]](#references)[[2]](#references)</sup>

Her aday runtime PC için:<sup>[[1]](#references)[[2]](#references)</sup>

1. Yalnızca arama için ARM64e PAC bitlerini ayıkla veya normalize et.
2. Çalıştırılabilir `__TEXT` aralığı adresi içeren yüklenmiş Mach-O'yu bul.
3. `functionOffset = normalizedPC - loadedImageBase` değerini hesapla ve negatif sonuçları ya da `UINT32_MAX` üzerindeki değerleri reddet.
4. `index[i].functionOffset <= functionOffset < index[i+1].functionOffset` koşulunu sağlayan first-level aralığını seç.
5. Referans verilen second-level page'i parse et, başlangıcı offset'i aşmayan en yakın girdiyi seç ve adresin sonraki girdiden veya first-level aralığının sonundan önce olduğunu doğrula.
6. Bu girdiyi decode et ve tanımladığı tam durumu oluştur.

Adres kaydedilmiş bir LR'den geldiyse, çağrıdan hemen sonraki bir adresin çağıranın kapsama aralığında kalması için aramada `PC-1` kullanılabilir. Bu, stack offset'lerini değil, recipe seçimini değiştirir.<sup>[[1]](#references)</sup>

Bir parser her header ve dizinin sınırlarını denetlemeli, section version değerinin `1` olmasını şart koşmalı, son first-level sentinel'ını hesaba katmalı, sıfır second-level-page offset'ini reddetmeli ve normal sayfaları sıkıştırılmış sayfalardan ayırmalıdır. Normal bir sayfada `entryPageOffset`, o sayfanın başlangıcına göredir; first-level page offset'i ise `__unwind_info` başlangıcına göredir.<sup>[[1]](#references)[[2]](#references)</sup>

Genel mod `encoding & 0x0F000000` değeridir. Güncel LLVM tanımları aşağıdaki modları içerir; parser, DWARF olmayan her değeri klasik bir frame olarak değerlendirmemelidir:<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Caller recovery |
| --- | --- | --- |
| Compact recipe yok | `0x00000000` | Dur veya bağımsız bir fallback kullan. |
| Frameless | `0x02000000` | Kodlanmış stack boyutunu mevcut `SP`'ye ekle; caller PC, live LR'dir. |
| DWARF | `0x03000000` | Alt 24 bitin tanımladığı FDE/CFI'yi çalıştır. |
| Frame | `0x04000000` | Geleneksel `x29` frame kaydını oku. |
| Authenticated LR aralığına sahip arm64e frame | `0x05000000` | `UNWIND_ARM64_MODE_FRAME_PAUTH_LR` değerini işle; offset alanı, kapsanan aralık içindeki `pacibsppc` konumunu belirtir. |

Frameless modda `stackSize = ((encoding & 0x00FFF000) >> 12) * 16` olur. Frame modunda, beş alt bit `x19/x20` ile `x27/x28` arasındaki bitişik kaydedilmiş GPR çiftlerini belirtir; `0x100-0x800` bitleri de benzer şekilde `d8-d15` çiftlerini belirtir. Sonraki PC'yi bulmak için bu kaydedilmiş register'lar gerekmeyebilir, ancak inandırıcı bir sanal caller durumu, tüketicinin yeniden oluşturduğu her alanı karşılamalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

## Synthetic frame-mode kayıtları oluşturma

Oluşturma süreci, stack'i adres benzeri değerler için taramak yerine unwinder'ın işlemlerini tersine çevirir:<sup>[[1]](#references)</sup>

1. Şu anda yüklenmiş bir imajda gerçek ve çalıştırılabilir bir PC seç.
2. Bu kesin PC'yi veya call-site adresini kapsayan recipe'yi decode et.
3. Gerekli hizalamaya ve CFA ilişkisine sahip bir synthetic kayıt ayır.
4. Sonraki synthetic FP'yi `[FP]` konumuna, o frame'in kaydedilmiş caller PC'sini `[FP+8]` konumuna ve encoding'in FP'nin altında bildirdiği her GPR/FPR kaydını belleğe yaz.
5. Birkaç kaydı birbirine bağla ve ilk kaydı live `x29` içine yerleştir.
6. Unwinding'in seçilen zincire girmesini, yürütmenin ise güvenli biçimde geri yüklenebilmesini sağlayacak şekilde live LR'yi ve API dönüş yolunu düzenle.

Örneğin `0x04000001`, frame modu ile `x19/x20` çiftini belirtir. Buna karşılık gelen durum dönüşümü ve gereken bellek şöyledir:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Bu nedenle meşru görünen bir adres tek başına yeterli değildir. Kurtarılan her PC, sonraki arama için anahtar olur; dolayısıyla kodlaması uydurulmuş yerleşimle uyuşmayan tek bir adres bile zinciri bozar veya tüketicinin tutarsız bir register durumunu yeniden oluşturmasına yol açar.<sup>[[1]](#references)</sup>

## ARM64e PAC gereksinimleri

PAC, adresi şifrelemez; anahtarlı bir bütünlük değerini işaretçi bitlerindeki kullanılmayan alanlarda saklar. Clang'in arm64e dönüş adresi şeması, ayırt edici olarak B talimat anahtarını ve fonksiyon girişindeki yığın işaretçisini kullanır. Geleneksel bir frame'de girişteki `SP`, CFA'dır; bu nedenle `[FP+8]` konumundaki kaydedilmiş LR, `FP+0x10` değerine bağlanır.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Her sentetik LR bağımsız olarak imzalanmalıdır; çünkü önceden imzalanmış bir LR'yi farklı CFA'ya sahip bir frame'e taşımak discriminator'ı değiştirir ve authentication işleminin başarısız olmasına neden olur. `ptrauth_strip()`, adres normalizasyonu ve sembol araması için uygundur ancak **authenticity** sağlamaz; gerçek bir return veya authenticated indirect branch, tam olarak o geçişte beklenen key ve modifier'ı kullanmalıdır.<sup>[[1]](#references)[[3]](#references)</sup>

Tipik bir non-leaf arm64e function, LR'yi saklamadan önce imzalar ve giriş SP'sini geri yükledikten sonra authentication işlemi yapar:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline and restore bridge

Sentetik kayıtların yalnızca unwinder'ı karşılaması gerekir; eksiksiz bir yürütme bağlamı içermezler. Hassas API'den doğrudan sahte çağıranlara dönmek normalde çökmeye neden olur. Bu nedenle pratik tasarımda API'nin hemen altına bir gadget frame yerleştirilir: API, yüklenmiş bir framework'teki yürütülebilir koda döner ve bu gadget, denetlenen bir callee-saved register üzerinden implant'taki bir restore bridge'e dallanır.<sup>[[1]](#references)</sup>

Kullanışlı bir gadget, LR'yi korur ve denetlenen bir register üzerinden aktarım yapar; örneğin uygun bir `br`, `braa` veya `brab` dizisi kullanır. Restore bridge, implant yürütmesine devam etmeden önce özgün `x19-x30` değerlerini ve `SP`'yi geri yüklemelidir. arm64e'de API'den gadget'a, gadget'tan bridge'e ve bridge'den implant'a giden yoldaki her kimliği doğrulanmış dönüş veya dallanma için, ilgili talimatın kullandığı key ve discriminator ile imzalanmış bir pointer gerekir.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Sonuç, stack tabanlı tespitler için önemli bir güven sınırı hatasıdır: Bir chain yalnızca eşlenmiş ve sembolleştirilebilir Apple framework PC’leri içerebilir, ancak yine de gerçek kontrol akışını temsil etmeyebilir. Bu nedenle unwind çıktısı, bir yürütme izi olarak kabul edilmek yerine, iş parçacığının yürütülebilir bellek kökeni ve hassas API çevresindeki gerçek geçişler hakkındaki bağımsız kanıtlarla doğrulanmalıdır.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Apple Silicon'da ARM64 stack iç yapısı ve obfuscation](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Mach-O compact unwind encoding tanımları](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Arm 64-bit Architecture için Procedure Call Standard](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
