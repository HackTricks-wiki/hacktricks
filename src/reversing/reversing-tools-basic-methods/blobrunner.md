# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) — це маленький Windows **shellcode loader for debugging**: він виділяє RWX memory, копіює blob, виводить base address / entry point і передає туди виконання. Це зручно, коли зразок є **raw shellcode**, **decrypted stage extracted from malware**, або **position-independent blob**, який не має PE header.

Наведений нижче фрагмент зберігає початкову ідею, але використовує **`%p` для надрукованих вказівників**, щоб x64 build не обрізав addresses, поки ви намагаєтеся attach debugger або rebase blob у вашому RE tool.

## Build

Найпростіший спосіб зібрати original project — з **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Ви також можете вставити code у невеликий Visual Studio / VS Code C project і скомпілювати його там.

## Корисні patterns використання
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
- В **x86**, BlobRunner робить паузу, а потім виконує прямий jump до entry point blob.
- В **x64**, він створює **suspended thread**, тож ви можете поставити break on адресу старту thread before відновлення виконання.
- `--offset` особливо корисний, коли dumped blob починається з **decoder / unpacking stub** і ви вже знаєте real entry point.

## Практичні нотатки

### Виправлення надрукованих адрес у x64 labs

Старіший код BlobRunner виводить адреси через casts на кшталт `(int)(size_t)lpvBase` і `%08x` / `%016x`. У 64-bit workflows це може обрізати верхню половину pointer і ускладнювати rebasing / breakpoint placement. Фрагмент нижче вже виправляє це, друкуючи значення **`%p`** напряму.

### `--jit` корисний для breakpoints на першій інструкції

`--jit` прибирає execute access у першого байта shellcode і дозволяє Windows згенерувати **access violation**, коли blob починає виконуватися. Це корисно, коли ви хочете, щоб **configured JIT debugger** (наприклад x64dbg) спіймав першу спробу виконання замість того, щоб вручну встигати attach. Після того як debugger зупиниться, відновіть execute rights і продовжіть.

Практичний **x64dbg** flow такий:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Перші дві команди реєструють x64dbg як JIT debugger, а `setpagerights` відновлює права на виконання для області, яку BlobRunner виводить після того, як debugger перехоплює access violation.

### Перемотайте shellcode у часі замість того, щоб single-stepити його в реальному часі

Дуже практичний нещодавній workflow — записати BlobRunner під **TTD**, а потім аналізувати trace у **Binary Ninja** / **WinDbg**. Це чудово, коли blob розшифровує себе, динамічно розв’язує API або виконує кілька короткоживучих stage. Починаючи з **Binary Ninja 4.1**, підтримка TTD уже не є лише beta quality: вона може керувати reverse-debugging і спрощувати workflow WinDbg / TTD безпосередньо з Binary Ninja.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Важливо **звернути увагу на базову адресу, яку виводить BlobRunner**, а потім **rebase** перегляд shellcode на цю адресу перед відтворенням trace. Також note, що Microsoft document TTD recording як **invasive**: запускайте його з **elevated** prompt, очікуйте помітне уповільнення, і тримайте вікно recording коротким, щоб уникнути величезних trace files.

### Якщо blob потребує companion data, use a PE wrapper instead

Деякі shellcode очікують, що в memory існуватиме **second blob**, **mapped file** або якийсь інший **structured content**. BlobRunner навмисно minimal, тож для таких cases runner на кшталт **SCLauncher** може бути зручнішим, тому що він може:

- pause перед execution,
- insert `INT3` breakpoint,
- load **additional content** into memory,
- memory-map that extra content, або
- wrap shellcode всередині temporary **PE** для easier analysis у tools, які prefer normal executables.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Для complementary workflows, таких як **jmp2it**, емулювання **Cutter** або shellcode tracing на основі **scdbg**, дивіться [parent shellcode reversing page](README.md).

## Source code

Єдині змінені рядки з [original code](https://github.com/OALabs/BlobRunner) — це рядки друку вказівника, які використовуються, щоб уникнути обрізання адрес x64.
Щоб скомпілювати його, просто **створіть C/C++ project у Visual Studio Code, скопіюйте й вставте код і зберіть його**.
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
## Посилання

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
