# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner)는 메모리를 RWX로 할당하고, blob을 복사한 다음, base address / entry point를 출력하고 해당 위치로 실행을 전달하는 작은 Windows **debugging용 shellcode loader**입니다. 샘플이 **raw shellcode**, **malware에서 추출한 decrypted stage**, 또는 PE header가 없는 **position-independent blob**인 경우 유용합니다.

아래 snippet은 원래 아이디어를 유지하면서, debugger를 attach하거나 RE tool에서 blob을 rebase하는 동안 x64 build가 address를 truncate하지 않도록 출력되는 pointer에 **`%p`**를 사용합니다.

## Build

원본 project를 build하는 가장 간단한 방법은 **Visual Studio Developer Command Prompt**에서 실행하는 것입니다:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
작은 Visual Studio / VS Code C 프로젝트에 코드를 붙여넣고 그곳에서 컴파일할 수도 있습니다.

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
- **x86**에서 BlobRunner는 일시 중지한 다음 blob entry point로 직접 jump합니다.
- **x64**에서는 **suspended thread**를 생성하므로, execution을 재개하기 전에 thread start address에 break를 걸 수 있습니다.
- `--offset`은 dumped blob이 **decoder / unpacking stub**으로 시작하고 실제 entry point를 이미 알고 있을 때 특히 유용합니다.

## 실용적인 참고 사항

### x64 lab에서 출력되는 address 수정

이전 BlobRunner code는 `(int)(size_t)lpvBase` 및 `%08x` / `%016x`와 같은 cast를 사용해 address를 출력합니다. 64-bit workflow에서는 이 방식이 pointer의 상위 절반을 truncate하여 rebase / breakpoint 설정을 번거롭게 만들 수 있습니다. 아래 snippet은 **`%p`** 값을 직접 출력하도록 이미 수정되어 있습니다.

### 첫 instruction breakpoint에는 `--jit` 사용

`--jit`은 shellcode의 첫 byte에서 execute access를 제거하고, blob이 execution을 시작할 때 Windows가 **access violation**을 발생시키도록 합니다. 이를 사용하면 수동으로 attach할 타이밍을 맞추는 대신, **configured JIT debugger**(예: x64dbg)가 첫 execution 시도를 catch하도록 할 수 있습니다. debugger가 break한 후 execute rights를 복원하고 계속 진행합니다.

실용적인 **x64dbg** flow는 다음과 같습니다:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
처음 두 명령은 x64dbg를 JIT debugger로 등록하고, `setpagerights`는 debugger가 access violation을 포착한 후 BlobRunner가 출력한 영역의 execute 권한을 복원합니다.

### shellcode를 실시간으로 single-step하는 대신 Time-travel하기

최근 매우 실용적인 workflow는 **TTD**에서 BlobRunner를 record한 다음 **Binary Ninja** / **WinDbg**에서 trace를 inspect하는 것입니다. 이는 blob이 스스로를 decrypt하거나, API를 동적으로 resolve하거나, 여러 개의 짧은 stage를 수행할 때 매우 유용합니다. **Binary Ninja 4.1**부터는 TTD support가 더 이상 단순한 beta quality가 아니며, reverse-debugging을 수행하고 WinDbg / TTD workflow를 Binary Ninja에서 직접 간소화할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
중요한 부분은 **BlobRunner가 출력한 할당된 base address를 기록한 다음**, trace를 다시 재생하기 전에 shellcode view를 해당 주소로 **rebase**하는 것입니다. 또한 Microsoft는 TTD recording을 **invasive**한 작업으로 문서화하고 있습니다. **elevated** prompt에서 실행하고, 눈에 띄는 slowdown을 예상하며, massive한 trace file이 생성되지 않도록 recording window를 짧게 유지하세요.<sup>[[1]](#references)</sup>

### blob에 companion data가 필요한 경우 PE wrapper 사용

일부 shellcode는 **두 번째 blob**, **mapped file** 또는 기타 **structured content**가 memory에 존재해야 합니다. BlobRunner는 의도적으로 minimal하게 설계되었으므로, 다음 작업이 가능한 **SCLauncher**와 같은 runner가 이러한 경우 더 편리할 수 있습니다.<sup>[[2]](#references)</sup>

- execution 전에 pause,
- `INT3` breakpoint 삽입,
- **additional content**를 memory에 load,
- 해당 additional content를 memory-map하거나,
- 일반 executable을 선호하는 tools에서 더 쉽게 분석할 수 있도록 shellcode를 임시 **PE** 내부에 wrap합니다.

예시:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
보완적인 workflow인 **jmp2it**, **Cutter** emulation 또는 **scdbg** 기반 shellcode tracing은 [parent shellcode reversing page](README.md)를 확인하세요.

## Source code

[original code](https://github.com/OALabs/BlobRunner)에서 수정된 부분은 x64 address truncation을 방지하기 위해 사용된 pointer-printing lines뿐입니다.  
컴파일하려면 **Visual Studio Code에서 C/C++ project를 생성하고, code를 copy and paste한 후 build하면 됩니다**.
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
## 참고 문헌

- [1] [Binary Ninja로 Shellcode Time Travel Debugging](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [SCLauncher로 Shellcode 분석](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)

{{#include ../../banners/hacktricks-training.md}}
