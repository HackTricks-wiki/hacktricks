# KernelFlirt के साथ Windows Kernel Debugging

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt नियंत्रित reverse-engineering labs के लिए Windows x64 debugger है। Host-side WPF UI या `KfConsole.exe`, test-signed Windows VM में `KfRelay.exe` को commands भेजता है। Relay इन्हें `KernelFlirt.sys` के लिए `DeviceIoControl` requests में बदलता है। यह driver memory, registers, breakpoints, execution control और kernel-module operations उपलब्ध कराता है। Driver `KdpStub`/`KdTrap` inline hook के ज़रिए kernel debugging path को भी modify करता है, इसलिए इसका उपयोग केवल disposable VM में करें।<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Relay सामान्य remote service के बजाय एक privileged debugging boundary है। TCP `31337` को isolated host-only network पर रखें और test-signed driver या relay को कभी भी untrusted network पर expose न करें।<sup>[[1]](#references)</sup>

संबंधित Windows exploitation techniques:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Lab setup और पहला पड़ाव

Build के लिए Windows 10/11 x64, C++ के साथ Visual Studio 2022, WDK 10.0.26100.0 या बाद का संस्करण, और .NET 9 आवश्यक हैं। Driver और relay को VM के अंदर load करें, फिर host से connect करें। UI किसी remote EXE या SYS को खोल सकता है, और **Kernel Modules** view पहले से loaded drivers में breakpoints सेट कर सकता है।<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Lab पूरा होने पर `KfLoader.exe unload` का उपयोग करें। Console unconnected REPL, direct local-device access और relay access को support करता है; नीचे बताए गए deterministic `open` workflow को केवल relay mode लागू करता है।<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

एक न्यूनतम कंसोल वर्कफ़्लो है:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Addresses expressions होते हैं। Bare numbers hexadecimal होते हैं, और expressions में registers, arithmetic, `[rsp]` जैसे dereferences और `ntdll!NtCreateFile` जैसे symbols हो सकते हैं। Symbol breakpoints केवल `open` या `attach` के modules enumerate करने और उनके PDBs load करने के बाद ही जोड़ने चाहिए।<sup>[[2]](#references)</sup>

## `EB FE` से deterministic entry-point trapping

Relay-side `open` target को suspended अवस्था में बनाता है, उसके पहले entry-point bytes save करता है, `EB FE` लिखता है, entry thread को resume करता है और तब तक poll करता है, जब तक उसका instruction pointer उस address तक न पहुँच जाए। `EB FE` खुद पर वापस जाने वाला two-byte short jump है, इसलिए यह user-mode debug exception के delivery पर निर्भर हुए बिना execution को trap करता है। फिर relay original bytes restore करता है और target को उसके entry point पर रुका हुआ छोड़ता है।<sup>[[2]](#references)</sup>

यह pattern तब भी उपयोगी है, जब normal debugger setup पूरा होने से पहले किसी शुरुआती loader path को observe करना हो।<sup>[[2]](#references)</sup>

1. Process को suspended अवस्था में बनाएँ और image mapping के बाद उसका वास्तविक entry point resolve करें।
2. Original entry-point bytes save करें और उन्हें two-byte self-loop से बदलें।
3. Entry thread को resume करें और उसके instruction pointer को तब तक poll करें, जब तक वह patched address तक न पहुँच जाए।
4. Target को suspend करें और analysis जारी रखने से पहले बिल्कुल वही original bytes restore करें।

यह technique जानबूझकर intrusive है। यदि restoration से पहले debugger या relay बंद हो जाए, तो target लगातार loop करता रह सकता है। KernelFlirt local mode relay-side entry patching उपलब्ध नहीं कराता; इसके बजाय process को manually start करें और `attach <pid>` का उपयोग करें।<sup>[[2]](#references)</sup>

## Breakpoint primitive चुनें

KernelFlirt कई breakpoint mechanisms उपलब्ध कराता है, जिनके side effects अलग-अलग होते हैं। Packed code के खुद को rewrite करने पर, executable pages के read-only होने पर या software breakpoint bytes के integrity-checked होने पर analyst primitives बदलने के लिए नीचे दिए गए commands का उपयोग कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

| Primitive | Command | Mechanism और उपयोग |
| --- | --- | --- |
| Software | `bp <expr>` | MDL-backed `INT3`; RX `.text` pages को instrument कर सकता है |
| Conditional software | `bp <expr> if <condition>` | हर hit पर evaluate करता है और condition false होने पर चुपचाप resume करता है |
| Hardware execute | `ba e1 <expr>` | Code bytes बदले बिना DR0-DR3 में से एक का उपयोग करता है |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | 1, 2, 4 या 8 bytes के writes या reads/writes को watch करता है |
| Guard page | `bm <expr> [size]` | Memory-range breakpoint के लिए `PAGE_GUARD` का उपयोग करता है |
| Temporary | `g <expr>`, `p`, or `o` | Run-to-address, step-over और step-out helper breakpoint |

Software, hardware, memory और temporary entries में अंतर जानने के लिए `bl` का उपयोग करें, और उन्हें हटाने के लिए `bc <address|handle|all>` का। Hardware slots सीमित होते हैं और debug-register state के ज़रिए लागू होते हैं, जबकि guard pages बड़ा range cover करते हैं, लेकिन उसी page पर होने वाले असंबंधित accesses पर भी trigger होते हैं।

## Native x64 बनाम WoW64 stepping

Native x64 single-step, `IOCTL_KF_SINGLE_STEP` के ज़रिए processor trap flag सेट करता है। Step Over मौजूदा instruction को decode करता है और उसके संभावित अगले addresses पर temporary breakpoints लगाता है। Step Out मौजूदा stack के top से return address पढ़ता है। Function prologue पर stack की यह धारणा गलत हो सकती है, इसलिए किसी ज्ञात internal breakpoint को प्राथमिकता दें।<sup>[[2]](#references)</sup>

`KdTrap` hook 32-bit exceptions को उसी तरह नहीं पकड़ता। WoW64 targets के लिए debugger Iced से instruction को decode करता है, गणना किए गए अगले `EIP` पर `EB FE` लिखता है और thread instruction pointers को poll करता है। इसलिए WoW64 के लिए `g <address>` उपलब्ध नहीं है, और सादा `g` breakpoint आने तक console को block करता है। पहले ऐसा breakpoint सेट करें, जहाँ पहुँचना संभव हो, और अनिश्चित अवधि तक run करने से बचें—क्योंकि `Ctrl+C` poll रद्द करने के बजाय console को terminate करता है।<sup>[[2]](#references)</sup>

## Memory, register और symbol-assisted analysis

Console symbolic stop को memory inspection और नियंत्रित patch के साथ जोड़ सकता है। Search calls byte wildcards, ASCII या UTF-16 स्वीकार करते हैं और 4 MB तक सीमित हैं; अधिकतम 256 matches report किए जाते हैं। Allocation और protection commands driver के allocate, free और protect IOCTLs से map होते हैं।<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB loading हर remote module की PE debug directory पढ़ता है, उसका RSDS identifier निकालता है, DbgHelp/SymSrv के ज़रिए matching PDB ढूँढता है, और पुष्टि करता है कि वह PDB के रूप में लोड हुआ है। Private PDBs को relay machine पर target के पास रखें या host पर उनकी directory को `_NT_SYMBOL_PATH` में जोड़ें।<sup>[[2]](#references)</sup>

## Kernel-backed anti-debug state changes

Kernel access से debugger उन indicators को हटा सकता है जिन्हें user-mode debugger विश्वसनीय रूप से छिपा नहीं सकता। एक बार में एक बदलाव लागू करें, target check की पुष्टि करें, और session समाप्त करने से पहले संबंधित hook को revert करें।<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` `EPROCESS.DebugPort` को साफ़ करता है।
- `clr_thread_hide` target threads से `HideFromDebugger` हटाता है।
- `ntqsi on` `NtQuerySystemInformation` class `0x23` (`SystemKernelDebuggerInformation`) को spoof करता है।
- `spoof on` user-mode reads में `KUSER_SHARED_DATA.KdDebuggerEnabled` का मान false दिखाता है, जबकि trap mechanism के लिए आवश्यक kernel state बनी रहती है।
- `stats` hook counters और दर्ज की गई `KiDebugRoutine`, `KdpStub` तथा `KdTrap` state की जाँच करता है।

ये operations process और kernel state में बदलाव करते हैं। Crash, stale inline hook, गलत structure offset या patch restoration अधूरा रहने से VM अस्थिर हो सकती है। इसी कारण snapshots और isolated test-signing environment अनिवार्य हैं।<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt repository और मुख्य दस्तावेज़](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt console संदर्भ](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
