# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は、**debugging 用の小型 Windows shellcode loader** です。RWX memory を割り当てて blob をコピーし、base address / entry point を表示して、そこへ execution を移します。これは、サンプルが **raw shellcode**、**malware から抽出した decrypted stage**、または PE header を持たない **position-independent blob** の場合に便利です。

以下の snippet は元のアイデアを維持しつつ、表示する pointer に **`%p`** を使用しています。これにより、debugger を attach したり、RE tool で blob を rebase したりする際に、x64 build で address が truncate されることを防げます。

## ビルド

元の project をビルドする最も簡単な方法は、**Visual Studio Developer Command Prompt** から実行することです。
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
コードを小さな Visual Studio / VS Code C project に貼り付けて、そこで compile することもできます。

## 便利な使用パターン
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
- **x86** では、BlobRunner は一時停止した後、blob のエントリポイントへ直接ジャンプします。
- **x64** では、**suspended thread** を作成するため、実行を再開する前にスレッドの開始アドレスで break できます。
- `--offset` は、dump した blob が **decoder / unpacking stub** で始まっており、実際のエントリポイントがすでに分かっている場合に特に便利です。

## 実用上の注意

### x64 lab で表示されるアドレスを修正する

古い BlobRunner のコードでは、`(int)(size_t)lpvBase` や `%08x` / `%016x` などの cast を使ってアドレスを表示します。64-bit workflow では、これによりポインタの上位 half が切り捨てられ、rebase や breakpoint の設定が面倒になることがあります。以下の snippet では、アドレスを **`%p`** の値として直接表示することで、この問題を修正しています。

### `--jit` は first-instruction breakpoint に便利

`--jit` は shellcode の最初の byte から execute access を削除し、blob が実行を開始したときに Windows が **access violation** を発生させるようにします。これにより、手動で attach のタイミングを競う代わりに、設定済みの **JIT debugger**（たとえば x64dbg）で最初の実行試行を捕捉できます。debugger が break した後、execute rights を復元して続行します。

実用的な **x64dbg** の flow は次のとおりです。
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
最初の2つのコマンドは x64dbg を JIT debugger として登録し、`setpagerights` は、debugger が access violation を捕捉した後に BlobRunner が出力した領域の execute rights を復元します。

### shellcode を live で single-stepping する代わりに time-travel する

非常に実用的な最近の workflow は、**TTD** で BlobRunner を記録し、その後 **Binary Ninja** / **WinDbg** で trace を調査する方法です。blob が自身を decrypt したり、API を動的に解決したり、短時間で終了する複数の stage を実行したりする場合に特に有効です。**Binary Ninja 4.1** 以降、TTD support はもはや beta quality にとどまらず、reverse-debugging を実行し、WinDbg / TTD workflow を Binary Ninja から直接簡略化できます。<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
重要なのは、**BlobRunner によって出力された割り当て済みのベースアドレスを記録し**、trace を再生する前に shellcode view をそのアドレスへ **rebase** することです。また、Microsoft は TTD の記録を **invasive** と説明しています。**elevated** prompt から実行し、 noticeable な slowdown を想定してください。さらに、巨大な trace file の生成を避けるため、recording window は短く保ってください。

### blob に companion data が必要な場合は、PE wrapper を使用する

一部の shellcode は、**second blob**、**mapped file**、またはその他の **structured content** がメモリ上に存在することを前提とします。BlobRunner は意図的に最小構成となっているため、このような場合は **SCLauncher** のような runner の方が便利です。SCLauncher では次の操作が可能です。<sup>[[2]](#references)</sup>

- execution の前に pause する
- `INT3` breakpoint を挿入する
- **additional content** をメモリに load する
- その追加 content を memory-map する、または
- shellcode を一時的な **PE** 内に wrap し、通常の executable を優先する tools で analysis しやすくする

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
補完的な workflow として **jmp2it**、**Cutter** emulation、または **scdbg** ベースの shellcode tracing を使用する場合は、[parent shellcode reversing page](README.md) を確認してください。

## Source code

[original code](https://github.com/OALabs/BlobRunner) から変更したのは、x64 address truncation を回避するための pointer-printing lines のみです。
compile するには、**Visual Studio Code で C/C++ project を作成し、code を copy and paste して build するだけです**。
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
## 参考文献

- [1] [Binary NinjaでShellcodeをTime Travel Debuggingする](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [SCLauncherでShellcodeを解析する](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
