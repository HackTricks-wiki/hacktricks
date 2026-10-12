# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Metadata-driven unwinding को spoof क्यों किया जा सकता है

कुछ macOS security tooling thread-stack collection का काम `/usr/sbin/spindump` को सौंपते हैं या अन्यथा पारंपरिक metadata-driven unwinder पर भरोसा करते हैं। एक implant इस trust boundary का फायदा उठाकर अपने stack पर ABI-correct synthetic records रख सकता है, ताकि ऐसा लगे कि किसी sensitive API तक पहुँच attacker द्वारा चुने गए dyld और loaded Apple frameworks के functions के ज़रिए हुई है, न कि unbacked implant code से। यह telemetry deception है, executable या उसके unwind metadata में बदलाव नहीं।<sup>[[1]](#references)</sup>

Collection-side context के लिए [macOS stackshots और `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) देखें।

Unwinder यह साबित नहीं करता कि compiler-generated prologue ने कोई record बनाया था। यह बार-बार मौजूदा `PC` का इस्तेमाल करके Mach-O recipe चुनता है, उस recipe को `SP`, `x29`, `x30`, stack memory और घोषित nonvolatile registers पर लागू करता है, फिर recovered caller `PC` का इस्तेमाल करके अगली recipe चुनता है। अगर attacker-controlled memory चुनी गई हर recipe की शर्तें पूरी करती है, तो परिणामी chain संरचनात्मक रूप से valid और symbolizable हो सकती है, भले ही वे calls कभी हुई ही न हों।<sup>[[1]](#references)</sup>

## ARM64 frame state

[ARM64 assembly overview](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) में register roles और calling convention का विवरण है। `stp x29, x30, [sp, #-16]!` के बाद `mov x29, sp` से बनाए गए पारंपरिक frame के लिए, caller के entry `SP` को दर्शाने वाला Canonical Frame Address (CFA), `FP+0x10` होता है:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame records `[FP]` के माध्यम से linked list बनाते हैं, लेकिन उस list को बिना सोचे-समझे follow करना पर्याप्त नहीं है: leaf functions में frame नहीं हो सकता, tail calls logical transitions हटा सकती हैं, और असामान्य layouts में DWARF CFI का उपयोग होता है। मौजूदा address से चुना गया recipe तय करता है कि unwinder FP chain को पढ़ेगा भी या नहीं।<sup>[[1]](#references)[[4]](#references)</sup>

## Mach-O unwind recipe चुनना

अंतिम linked images compact unwind data को `__TEXT,__unwind_info` में रखते हैं। Section header पहले first-level function index की ओर इशारा करता है; हर index range एक regular (`kind=2`) या compressed (`kind=3`) second-level page की ओर इशारा करती है। जिन layouts का वर्णन compact unwind नहीं कर सकता, वे `__eh_frame` में FDE और call-frame instructions का उपयोग करते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

हर candidate runtime PC के लिए:<sup>[[1]](#references)[[2]](#references)</sup>

1. केवल lookup के लिए ARM64e PAC bits हटाएँ या normalize करें।
2. उस loaded Mach-O को ढूँढें जिसकी executable `__TEXT` range में यह address आता है।
3. `functionOffset = normalizedPC - loadedImageBase` की गणना करें और negative results या `UINT32_MAX` से बड़े values को reject करें।
4. उस first-level range को चुनें जिसके लिए `index[i].functionOffset <= functionOffset < index[i+1].functionOffset` हो।
5. Referenced second-level page parse करें, ऐसी निकटतम entry चुनें जिसका start offset से बड़ा न हो, और सत्यापित करें कि address अगली entry या first-level range के अंत से नीचे है।
6. उस entry को decode करें और उसके द्वारा वर्णित सटीक state बनाएँ।

जब कोई address saved LR से आया हो, तो lookup में `PC-1` का उपयोग किया जा सकता है, ताकि call के ठीक बाद का address caller की covered range में रहे। इससे recipe का चयन बदलता है, stack offset नहीं।<sup>[[1]](#references)</sup>

Parser को हर header और array की bounds जाँचनी चाहिए, section version `1` अनिवार्य करना चाहिए, अंतिम first-level sentinel को ध्यान में रखना चाहिए, zero second-level-page offset को reject करना चाहिए, और regular तथा compressed pages के बीच अंतर पहचानना चाहिए। Regular page में `entryPageOffset`, उस page की शुरुआत के सापेक्ष होता है, जबकि first-level page offset `__unwind_info` की शुरुआत के सापेक्ष होता है।<sup>[[1]](#references)[[2]](#references)</sup>

व्यापक mode `encoding & 0x0F000000` है। मौजूदा LLVM definitions में निम्न modes शामिल हैं; parser को हर non-DWARF value को classic frame नहीं मानना चाहिए:<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Caller recovery |
| --- | --- | --- |
| कोई compact recipe नहीं | `0x00000000` | रुकें या स्वतंत्र fallback का उपयोग करें। |
| Frameless | `0x02000000` | Encoded stack size को मौजूदा `SP` में जोड़ें; caller PC, live LR है। |
| DWARF | `0x03000000` | Low 24 bits से पहचाने गए FDE/CFI को execute करें। |
| Frame | `0x04000000` | Conventional `x29` frame record पढ़ें। |
| Authenticated LR range वाला arm64e frame | `0x05000000` | `UNWIND_ARM64_MODE_FRAME_PAUTH_LR` को handle करें; इसका offset field, covered range में `pacibsppc` का स्थान बताता है। |

Frameless mode के लिए, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`। Frame mode में, पाँच low bits, लगातार saved GPR pairs `x19/x20` से `x27/x28` तक घोषित करते हैं; bits `0x100-0x800` इसी तरह `d8-d15` pairs घोषित करते हैं। अगला PC ढूँढने के लिए इन saved registers की आवश्यकता न भी हो, फिर भी विश्वसनीय virtual caller state में consumer द्वारा reconstruct किए गए हर field को संतुष्ट करना ज़रूरी है।<sup>[[1]](#references)[[2]](#references)</sup>

## Synthetic frame-mode records बनाना

यह प्रक्रिया stack में address-जैसी values खोजने के बजाय unwinder के काम को उलटती है:<sup>[[1]](#references)</sup>

1. मौजूदा loaded image में एक वास्तविक executable PC चुनें।
2. उस सटीक PC या call-site address को cover करने वाले recipe को decode करें।
3. आवश्यक alignment और CFA relationship के साथ एक synthetic record allocate करें।
4. अगला synthetic FP `[FP]` पर, उस frame का saved caller PC `[FP+8]` पर, और encoding द्वारा घोषित हर GPR/FPR save को FP के नीचे store करें।
5. कई records link करें और पहला record live `x29` में रखें।
6. Live LR और API return path को इस तरह व्यवस्थित करें कि unwinding चुनी गई chain में प्रवेश करे, और execution को सुरक्षित रूप से restore भी किया जा सके।

उदाहरण के लिए, `0x04000001` का अर्थ है frame mode और `x19/x20` pair। इससे संबंधित state transformation और आवश्यक memory यह हैं:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

इसलिए, केवल एक वैध दिखने वाला address पर्याप्त नहीं है। हर बरामद PC अगले lookup की key बन जाता है, इसलिए यदि किसी एक address की encoding गढ़े गए layout से मेल नहीं खाती, तो यह chain टूट जाती है या consumer असंगत register state को फिर से बनाता है।<sup>[[1]](#references)</sup>

## ARM64e PAC की आवश्यकताएँ

PAC, pointer के अन्यथा खाली bits में keyed integrity value संग्रहीत करता है; यह address को encrypt नहीं करता। Clang का arm64e return-address schema, function entry पर instruction key B और stack pointer को discriminator के रूप में इस्तेमाल करता है। पारंपरिक frame में, entry `SP` ही CFA होता है, इसलिए `[FP+8]` पर saved LR, `FP+0x10` से bound होता है।<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

हर synthetic LR को स्वतंत्र रूप से sign करना आवश्यक है, क्योंकि पहले से signed LR को अलग CFA वाले frame में ले जाने से discriminator बदल जाता है और authentication विफल हो जाता है। `ptrauth_strip()` address normalization और symbol lookup के लिए उपयुक्त है, लेकिन यह authenticity स्थापित **नहीं** करता; किसी भी वास्तविक return या authenticated indirect branch में उसी key और modifier का उपयोग होना चाहिए जिसकी उस सटीक transition पर अपेक्षा होती है।<sup>[[1]](#references)[[3]](#references)</sup>

एक सामान्य non-leaf arm64e function, LR को store करने से पहले sign करता है और entry SP restore करने के बाद authenticate करता है:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline और restore bridge

Synthetic records को केवल unwinder की ज़रूरतें पूरी करनी होती हैं; उनमें पूरा execution context नहीं होता। Sensitive API से सीधे fabricated callers पर लौटने से आमतौर पर crash होगा। इसलिए व्यावहारिक डिज़ाइन में API के ठीक नीचे एक gadget frame रखा जाता है: API, loaded framework के executable code पर लौटता है, और वह gadget एक नियंत्रित callee-saved register के ज़रिए implant में मौजूद restore bridge पर branch करता है।<sup>[[1]](#references)</sup>

एक उपयोगी gadget LR को सुरक्षित रखता है और नियंत्रित register के ज़रिए transfer करता है, उदाहरण के लिए उपयुक्त `br`, `braa` या `brab` sequence। Implant का execution फिर से शुरू करने से पहले restore bridge को मूल `x19-x30` values और `SP` बहाल करने होंगे। arm64e पर, API-to-gadget, gadget-to-bridge और bridge-to-implant path में हर authenticated return या branch के लिए ऐसा pointer ज़रूरी है, जिस पर उस instruction द्वारा उपयोग की जाने वाली key और discriminator के साथ signature किया गया हो।<sup>[[1]](#references)</sup>

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

इसका परिणाम stack-based detections के लिए trust-boundary की एक गंभीर विफलता है: किसी chain में केवल mapped, symbolizable Apple-framework PCs हो सकते हैं, फिर भी वह वास्तविक control flow को दर्शाए, यह ज़रूरी नहीं। इसलिए Unwind output को execution trace मानने के बजाय, thread की executable-memory provenance और sensitive API के आसपास होने वाले वास्तविक transitions के स्वतंत्र प्रमाणों से corroborate किया जाना चाहिए।<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Apple Silicon पर ARM64 stack internals और obfuscation](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Mach-O compact unwind encoding की परिभाषाएँ](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Arm 64-bit Architecture के लिए Procedure Call Standard](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
