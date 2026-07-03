# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は、デバッグ用の小さな Windows **shellcode loader** です。RWX メモリを確保し、blob をコピーし、ベースアドレス / エントリポイントを表示してから、その場所へ実行を移します。これは、サンプルが **raw shellcode**、**malware から抽出された復号済みステージ**、または PE ヘッダーを持たない **position-independent blob** の場合に便利です。

以下のスニペットは元の考え方を保ちつつ、表示するポインタに **`%p`** を使用しています。そのため、デバッガを attach したり、RE tool で blob を rebasing しようとしている間に、x64 ビルドでアドレスが切り捨てられることがありません。

## Build

元のプロジェクトを build する最も簡単な方法は、**Visual Studio Developer Command Prompt** から行うことです：
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
小さな Visual Studio / VS Code の C プロジェクトにコードを貼り付けて、そこでコンパイルすることもできます。

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
- **x86** では、BlobRunner は一時停止したあと、blob の entry point へ直接ジャンプします。
- **x64** では、**suspended thread** を作成するので、実行を再開する前に thread start address にブレークできます。
- `--offset` は、ダンプした blob の先頭が **decoder / unpacking stub** で、実際の entry point をすでに分かっている場合に特に便利です。

## 実践メモ

### x64 ラボで表示されるアドレスを修正する

古い BlobRunner のコードは、`(int)(size_t)lpvBase` や `%08x` / `%016x` のようなキャストでアドレスを表示します。64-bit のワークフローでは、これによりポインタの上位半分が切り捨てられ、rebase や breakpoint の配置が面倒になります。下のスニペットでは、**`%p`** の値を直接表示することで、すでにこれを修正しています。

### `--jit` は first-instruction breakpoints に便利

`--jit` は shellcode の先頭 1 バイトから execute access を取り除き、blob の実行開始時に Windows に **access violation** を発生させます。これは、手動で attach を急ぐのではなく、**configured JIT debugger**（たとえば x64dbg）に最初の実行試行を捕まえさせたい場合に便利です。debugger が break したら、execute 権限を復元して続行します。

実用的な **x64dbg** の流れは次のとおりです:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
最初の2つのコマンドは x64dbg を JIT debugger として登録し、`setpagerights` は debugger が access violation を検知した後に BlobRunner が出力した領域の execute 権限を復元します。

### shellcode をライブで single-stepping する代わりに time-travel する

最近の非常に実用的なワークフローは、BlobRunner を **TTD** で記録してから、**Binary Ninja** / **WinDbg** で trace を確認することです。blob が自己復号し、API を動的に解決し、または複数の短命な stage を実行する場合に特に有効です。**Binary Ninja 4.1** 以降、TTD サポートはもはや beta 品質ではありません。reverse-debugging を実行でき、Binary Ninja から直接 WinDbg / TTD ワークフローを簡略化できます。
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
重要なのは、**BlobRunner が表示する割り当て済みのベースアドレスを記録し**、そのアドレスに合わせてシェルコードのビューを**rebase**してからトレースを再生することです。また、Microsoft は TTD の記録を**invasive**と文書化しています。**elevated** なプロンプトから実行し、目立つ低速化を想定し、巨大なトレースファイルを避けるため記録時間は短く保ってください。

### blob に companion data が必要な場合は、代わりに PE wrapper を使う

一部の shellcode は、メモリ上に **second blob**、**mapped file**、または他の **structured content** が存在することを想定しています。BlobRunner は意図的に最小限なので、こうしたケースでは **SCLauncher** のような runner の方が便利です。SCLauncher は次のことができます。

- 実行前に pause する
- `INT3` breakpoint を挿入する
- **additional content** をメモリに load する
- その追加コンテンツを memory-map する
- あるいは shellcode を一時的な **PE** でラップして、通常の executable を前提にした tools で分析しやすくする

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
補完的なワークフローとして、**jmp2it**、**Cutter** emulation、または **scdbg** ベースの shellcode tracing については、[parent shellcode reversing page](README.md) を確認してください。

## Source code

[original code](https://github.com/OALabs/BlobRunner) から変更されている唯一の行は、x64 address truncation を避けるために使われている pointer-printing の行です。
コンパイルするには、**Visual Studio Code で C/C++ project を作成し、コードをコピーして貼り付けてビルドするだけです**。
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
## 参考資料

- [Binary Ninja で Shellcode を Time Travel Debugging する](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [SCLauncher で Shellcode を解析する](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
