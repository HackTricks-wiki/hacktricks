# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 是一个用于调试的微型 Windows **shellcode loader**：它分配 RWX 内存，复制 blob，打印基址 / 入口点，然后将执行流转移过去。当样本是 **raw shellcode**、从 malware 中提取的**解密 stage**，或者是不带 PE header 的**position-independent blob**时，这非常方便。

下面的代码片段保留了原始思路，但对打印的指针使用了 **`%p`**，这样 x64 构建在你尝试附加 debugger 或在 RE 工具中重新定位 blob 时就不会截断地址。

## Build

构建原始项目最简单的方法是使用 **Visual Studio Developer Command Prompt**：
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
你也可以将代码粘贴到一个小型 Visual Studio / VS Code C 项目中，然后在那里编译它。

## Useful usage patterns
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
- 在 **x86** 中，BlobRunner 会暂停，然后直接跳转到 blob 的入口点。
- 在 **x64** 中，它会创建一个 **suspended thread**，因此你可以在恢复执行之前，先在线程起始地址上断下。
- `--offset` 在 dumped blob 以 **decoder / unpacking stub** 开头，并且你已经知道真实入口点时，尤其有用。

## 实用说明

### 修复 x64 实验中的打印地址

较旧的 BlobRunner 代码通过诸如 `(int)(size_t)lpvBase` 和 `%08x` / `%016x` 这类强制转换来打印地址。在 64-bit 工作流中，这可能会截断指针的高 32 位，从而让 rebasing / breakpoint placement 变得麻烦。下面的代码片段已经通过直接打印 **`%p`** 值修复了这个问题。

### `--jit` 对首条指令断点很有用

`--jit` 会移除 shellcode 第一字节的 execute access，并让 Windows 在 blob 开始执行时抛出一个 **access violation**。当你希望 **configured JIT debugger**（例如 x64dbg）捕获第一次执行尝试，而不是手动抢着附加调试器时，这个选项很有用。调试器断下后，恢复 execute rights 然后继续执行。

一个实用的 **x64dbg** 流程是：
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
前两个命令将 x64dbg 注册为 JIT debugger，而 `setpagerights` 会在 debugger 捕获 access violation 后，恢复 BlobRunner 打印出的区域的执行权限。

### 通过时间回溯 shellcode，而不是实时单步执行它

一种非常实用的近期工作流是用 **TTD** 记录 BlobRunner，然后在 **Binary Ninja** / **WinDbg** 中检查 trace。当 blob 自行解密、动态解析 APIs，或者执行多个短生命周期阶段时，这非常有用。自 **Binary Ninja 4.1** 起，TTD 支持不再只是 beta 级别：它可以直接从 Binary Ninja 驱动 reverse-debugging，并简化 WinDbg / TTD 工作流。
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
重要的是要**记下 BlobRunner 打印的已分配基址**，然后在回放 trace 之前将 shellcode 视图**rebase**到该地址。还要注意，Microsoft 将 TTD 录制描述为**侵入性**的：请从**提升权限**的提示符运行它，预期会有明显变慢，并保持录制窗口尽可能短，以避免生成巨大的 trace 文件。

### 如果 blob 需要配套数据，改用 PE wrapper

有些 shellcode 期望内存中存在**第二个 blob**、一个**mapped file**，或其他某种**structured content**。BlobRunner 设计上非常精简，所以在这些情况下，像 **SCLauncher** 这样的 runner 可能更方便，因为它可以：

- 在执行前暂停，
- 插入一个 `INT3` breakpoint，
- 将**additional content**加载到内存中，
- 将该额外内容进行 memory-map，或者
- 将 shellcode 包装在一个临时 **PE** 中，以便在更偏好正常可执行文件的工具里更容易分析。

示例：
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
对于诸如 **jmp2it**、**Cutter** 仿真或基于 **scdbg** 的 shellcode 跟踪等互补工作流，请查看 [parent shellcode reversing page](README.md)。

## Source code

从 [original code](https://github.com/OALabs/BlobRunner) 中唯一修改的行是用于避免 x64 地址截断的指针打印行。
为了编译它，只需**在 Visual Studio Code 中创建一个 C/C++ 项目，复制并粘贴代码，然后构建它**。
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
