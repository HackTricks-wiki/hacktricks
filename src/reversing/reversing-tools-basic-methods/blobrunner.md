# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 是一个小型 Windows **用于调试的 shellcode loader**：它会分配 RWX 内存、复制 blob、打印基地址 / 入口点，然后将执行流转移到该地址。当样本是 **raw shellcode**、从 malware 中提取的**已解密 stage**，或不包含 PE header 的**位置无关 blob** 时，这非常实用。

下面的代码片段保留了原始思路，但使用 **`%p` 打印指针**，这样在尝试附加 debugger 或在 RE tool 中对 blob 进行 rebase 时，x64 构建不会截断地址。

## 构建

构建原始项目最简单的方法是使用 **Visual Studio Developer Command Prompt**：
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
你也可以将代码粘贴到一个小型 Visual Studio / VS Code C 项目中，并在那里进行编译。

## 常用使用模式
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
- 在 **x86** 中，BlobRunner 会暂停，然后直接跳转到 blob entry point。
- 在 **x64** 中，它会创建一个 **suspended thread**，因此你可以在恢复执行前，针对 thread start address 设置断点。
- 当转储的 blob 以 **decoder / unpacking stub** 开头，且你已经知道真实 entry point 时，`--offset` 尤其有用。

## 实用说明

### 修复 x64 labs 中打印的地址

旧版 BlobRunner 代码会通过 `(int)(size_t)lpvBase` 和 `%08x` / `%016x` 等 cast 打印地址。在 64-bit workflows 中，这可能截断指针的高半部分，从而使 rebasing / breakpoint placement 变得麻烦。下面的代码片段已经通过直接打印 **`%p`** 值修复了这一问题。

### `--jit` 适用于 first-instruction breakpoints

`--jit` 会移除 shellcode 第一个字节的 execute 权限，并让 Windows 在 blob 开始执行时触发 **access violation**。当你希望配置的 **JIT debugger**（例如 x64dbg）捕获第一次执行尝试，而不是手动争取 attach 时机，这非常有用。debugger 断下后，恢复 execute 权限并继续执行。

一个实用的 **x64dbg** 流程是：
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
前两个命令会将 x64dbg 注册为 JIT debugger，而 `setpagerights` 会在 debugger 捕获 access violation 后，恢复 BlobRunner 输出的内存区域的 execute 权限。

### 对 shellcode 执行 time-travel，而不是实时单步执行

一种非常实用的新近 workflow，是在 **TTD** 下记录 BlobRunner，然后在 **Binary Ninja** / **WinDbg** 中检查 trace。当 blob 会自行解密、动态解析 APIs，或执行多个短暂阶段时，这种方法非常有效。自 **Binary Ninja 4.1** 起，TTD 支持已不再只是 beta quality：它可以驱动 reverse-debugging，并直接从 Binary Ninja 简化 WinDbg / TTD workflow。<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
重要的是要**记录 BlobRunner 打印的已分配基址**，然后在重放 trace 之前，将 shellcode 视图 **rebase** 到该地址。另外请注意，Microsoft 将 TTD recording 记录为 **invasive**：请从**提升权限的**命令提示符运行，预期会出现明显的 slowdown，并将 recording 窗口保持较短，以避免生成 massive trace files。<sup>[[1]](#references)</sup>

### 如果 blob 需要 companion data，请改用 PE wrapper

某些 shellcode 需要内存中存在**第二个 blob**、**mapped file** 或其他**结构化内容**。BlobRunner 刻意保持 minimal，因此在这些情况下，使用类似 **SCLauncher** 的 runner 可能更加方便，因为它可以：<sup>[[2]](#references)</sup>

- 在 execution 前暂停，
- 插入 `INT3` breakpoint，
- 将**额外内容**加载到内存中，
- 对额外内容进行 memory-map，或
- 将 shellcode 包装进临时 **PE**，以便在偏好使用普通 executable 的 tools 中进行更轻松的分析。

示例：
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
对于 **jmp2it**、**Cutter** emulation 或基于 **scdbg** 的 shellcode tracing 等辅助工作流，请查看 [parent shellcode reversing page](README.md)。

## 源代码

与 [original code](https://github.com/OALabs/BlobRunner) 相比，唯一修改的代码行是用于避免 x64 地址截断的 pointer-printing 行。
要进行编译，只需在 Visual Studio Code 中**创建一个 C/C++ project，复制并粘贴代码，然后构建即可**。
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
## 参考资料

- [1] [使用 Binary Ninja 对 Shellcode 进行 Time Travel Debugging](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [使用 SCLauncher 分析 Shellcode](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)

{{#include ../../banners/hacktricks-training.md}}
