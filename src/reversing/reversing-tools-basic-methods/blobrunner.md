# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner)은 디버깅을 위한 작은 Windows **shellcode loader**입니다: RWX 메모리를 할당하고, blob을 복사한 뒤, base address / entry point를 출력하고, 그곳으로 execution을 넘깁니다. 이는 sample이 **raw shellcode**, malware에서 추출한 **decrypted stage**, 또는 PE header가 없는 **position-independent blob**일 때 유용합니다.

아래 snippet은 원래 아이디어를 유지하지만, 출력되는 포인터에 **`%p`**를 사용하므로 x64 build에서 debugger를 attach하거나 RE tool에서 blob을 rebase하는 동안 address가 잘리지 않습니다.

## Build

원본 project를 build하는 가장 간단한 방법은 **Visual Studio Developer Command Prompt**에서 하는 것입니다:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
작은 Visual Studio / VS Code C 프로젝트에 코드를 붙여넣고 거기서 컴파일할 수도 있습니다.

## 유용한 사용 패턴
```bash
# Execute from the beginning of the blob
BlobRunner.exe shellcode.bin

# Start from a known offset inside the blob
BlobRunner.exe shellcode.bin --offset 0x100

# Don't stop before transferring execution
BlobRunner.exe shellcode.bin --nopause

# Force an access violation and let the configured JIT debugger catch it
BlobRunner.exe shellcode.bin --jit
```
- **x86**에서는 BlobRunner가 일시 중지한 뒤 blob entry point로 직접 점프합니다.
- **x64**에서는 **suspended thread**를 생성하므로, 실행을 재개하기 전에 thread start address에 브레이크를 걸 수 있습니다.
- `--offset`은 덤프된 blob이 **decoder / unpacking stub**으로 시작하고, 이미 실제 entry point를 알고 있을 때 특히 유용합니다.

## Practical notes

### x64 labs에서 출력되는 주소 수정하기

이전 BlobRunner 코드는 `(int)(size_t)lpvBase`와 `%08x` / `%016x` 같은 캐스트를 통해 주소를 출력합니다. 64-bit 워크플로에서는 이로 인해 pointer의 상위 절반이 잘려 rebasing / breakpoint placement가 번거로워질 수 있습니다. 아래 snippet은 **`%p`** 값을 직접 출력하도록 이미 이를 수정합니다.

### `--jit`은 first-instruction breakpoints에 유용합니다

`--jit`은 shellcode의 첫 번째 byte에서 execute access를 제거하고, blob이 실행을 시작할 때 Windows가 **access violation**을 발생시키도록 합니다. 이는 수동으로 attach를 서두르는 대신, **configured JIT debugger**(예: x64dbg)가 첫 실행 시도를 잡아내게 하고 싶을 때 유용합니다. debugger가 break한 뒤에는 execute 권한을 복원하고 계속 진행합니다.

실용적인 **x64dbg** 흐름은 다음과 같습니다:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
첫 두 명령은 x64dbg를 JIT 디버거로 등록하고, `setpagerights`는 디버거가 access violation을 잡은 뒤 BlobRunner가 출력한 영역의 execute 권한을 복원합니다.

### live로 single-stepping하는 대신 shellcode를 time-travel하기

매우 실용적인 최근 workflow는 BlobRunner를 **TTD**로 기록한 다음 **Binary Ninja** / **WinDbg**에서 trace를 검사하는 것입니다. blob이 스스로 decrypt하거나, APIs를 동적으로 resolve하거나, 여러 짧은 stage를 수행할 때 특히 유용합니다. **Binary Ninja 4.1**부터는 TTD 지원이 더 이상 beta 수준만이 아니며, reverse-debugging을 구동하고 Binary Ninja에서 직접 WinDbg / TTD workflow를 단순화할 수 있습니다.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
중요한 부분은 **BlobRunner가 출력한 할당된 base address를 기록**한 다음, trace를 다시 재생하기 전에 shellcode view를 그 주소로 **rebase**하는 것이다. 또한 Microsoft는 TTD recording을 **invasive**하다고 문서화한다: **elevated** prompt에서 실행하고, 눈에 띄는 성능 저하를 예상하며, 대규모 trace 파일을 피하려면 recording window를 짧게 유지하라.

### blob에 companion data가 필요하면, 대신 PE wrapper를 사용하라

일부 shellcode는 메모리 안에 **second blob**, **mapped file**, 또는 다른 **structured content**가 존재하길 기대한다. BlobRunner는 의도적으로 최소 기능만 제공하므로, 이런 경우에는 **SCLauncher** 같은 runner가 더 편리할 수 있는데, 다음이 가능하기 때문이다:

- 실행 전에 pause,
- `INT3` breakpoint 삽입,
- 메모리로 **additional content** 로드,
- 그 extra content를 memory-map,
- 또는 shellcode를 임시 **PE** 안에 감싸서 normal executables를 선호하는 tools에서 더 쉽게 분석.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
For complementary workflows such as **jmp2it**, **Cutter** emulation, or **scdbg**-based shellcode tracing, check the [parent shellcode reversing page](README.md).

## Source code

The only modified lines from the [original code](https://github.com/OALabs/BlobRunner) are the pointer-printing lines used to avoid x64 address truncation.
In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.
```c
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

#ifdef _WIN64
#include <WinBase.h>
#endif

// Define bool
#pragma warning(disable:4996)
#define true 1
#define false 0

const char* _version = "0.0.5";

const char* _banner = " __________.__        ___.  __________\n"
" \\______   \\  |   ____\\_ |__\\______   \\__ __  ____   ____   ___________     \n"
"  |    |  _/  |  /  _ \\| __ \\|       _/  |  \\/    \\ /    \\_/ __ \\_  __ \\  \n"
"  |    |   \\  |_(  <_> ) \\_\\ \\    |   \\  |  /   |  \\   |  \\  ___/|  | \\/ \n"
"  |______  /____/\\____/|___  /____|_  /____/|___|  /___|  /\\___  >__|          \n"
"         \\/                \\/       \\/           \\/     \\/     \\/    \n\n"
"                                                                     %s    \n\n";


void banner() {
system("cls");
printf(_banner, _version);
return;
}

LPVOID process_file(char* inputfile_name, bool jit, int offset, bool debug) {
LPVOID lpvBase;
FILE* file;
unsigned long fileLen;
char* buffer;
DWORD dummy;

file = fopen(inputfile_name, "rb");

if (!file) {
printf(" [!] Error: Unable to open %s\n", inputfile_name);

return (LPVOID)NULL;
}

printf(" [*] Reading file...\n");
fseek(file, 0, SEEK_END);
fileLen = ftell(file); //Get Length

printf(" [*] File Size: 0x%04x\n", fileLen);
fseek(file, 0, SEEK_SET); //Reset

fileLen += 1;

buffer = (char*)malloc(fileLen); //Create Buffer
fread(buffer, fileLen, 1, file);
fclose(file);

printf(" [*] Allocating Memory...");

lpvBase = VirtualAlloc(NULL, fileLen, 0x3000, 0x40);

printf(".Allocated!\n");
printf(" [*]   |-Base: %p\n", lpvBase);
printf(" [*] Copying input data...\n");

CopyMemory(lpvBase, buffer, fileLen);
return lpvBase;
}

void execute(LPVOID base, int offset, bool nopause, bool jit, bool debug)
{
LPVOID shell_entry;

#ifdef _WIN64
DWORD   thread_id;
HANDLE  thread_handle;
const char msg[] = " [*] Navigate to the Thread Entry and set a breakpoint. Then press any key to resume the thread.\n";
#else
const char msg[] = " [*] Navigate to the EP and set a breakpoint. Then press any key to jump to the shellcode.\n";
#endif

shell_entry = (LPVOID)((UINT_PTR)base + offset);

#ifdef _WIN64

printf(" [*] Creating Suspended Thread...\n");
thread_handle = CreateThread(
NULL,          // Attributes
0,             // Stack size (Default)
shell_entry,         // Thread EP
NULL,          // Arguments
0x4,           // Create Suspended
&thread_id);   // Thread identifier

if (thread_handle == NULL) {
printf(" [!] Error Creating thread...");
return;
}
printf(" [*] Created Thread: [%d]\n", thread_id);
printf(" [*] Thread Entry: %p\n", shell_entry);

#endif

if (nopause == false) {
printf("%s", msg);
getchar();
}
else
{
if (jit == true) {
// Force an exception by making the first byte not executable.
// This will cause
DWORD oldp;

printf(" [*] Removing EXECUTE access to trigger exception...\n");

VirtualProtect(shell_entry, 1 , PAGE_READWRITE, &oldp);
}
}

#ifdef _WIN64
printf(" [*] Resuming Thread..\n");
ResumeThread(thread_handle);
#else
printf(" [*] Entry: %p\n", shell_entry);
printf(" [*] Jumping to shellcode\n");
__asm jmp shell_entry;
#endif
}

void print_help() {
printf(" [!] Error: No file!\n\n");
printf("     Required args: <inputfile>\n\n");
printf("     Optional Args:\n");
printf("         --offset <offset> The offset to jump into.\n");
printf("         --nopause         Don't pause before jumping to shellcode. Danger!!! \n");
printf("         --jit             Forces an exception by removing the EXECUTE permission from the alloacted memory.\n");
printf("         --debug           Verbose logging.\n");
printf("         --version         Print version and exit.\n\n");
}

int main(int argc, char* argv[])
{
LPVOID base;
int i;
int offset = 0;
bool nopause = false;
bool debug = false;
bool jit = false;
char* nptr;

banner();

if (argc < 2) {
print_help();
return -1;
}

printf(" [*] Using file: %s \n", argv[1]);

for (i = 2; i < argc; i++) {
if (strcmp(argv[i], "--offset") == 0) {
printf(" [*] Parsing offset...\n");
i = i + 1;
if (strncmp(argv[i], "0x", 2) == 0) {
offset = strtol(argv[i], &nptr, 16);
}
else {
offset = strtol(argv[i], &nptr, 10);
}
}
else if (strcmp(argv[i], "--nopause") == 0) {
nopause = true;
}
else if (strcmp(argv[i], "--jit") == 0) {
jit = true;
nopause = true;
}
else if (strcmp(argv[i], "--debug") == 0) {
debug = true;
}
else if (strcmp(argv[i], "--version") == 0) {
printf("Version: %s", _version);
}
else {
printf("[!] Warning: Unknown arg: %s\n", argv[i]);
}
}

base = process_file(argv[1], jit, offset, debug);
if (base == NULL) {
printf(" [!] Exiting...");
return -1;
}
printf(" [*] Using offset: 0x%08x\n", offset);
execute(base, offset, nopause, jit, debug);
printf("Pausing - Press any key to quit.\n");
getchar();
return 0;
}
```
## References

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
