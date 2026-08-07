# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) — це невеликий Windows **shellcode loader для debugging**: він виділяє RWX-пам'ять, копіює blob, виводить base address / entry point і передає туди виконання. Це зручно, коли зразок є **raw shellcode**, **decrypted stage, extracted from malware**, або **position-independent blob**, який не має PE header.

Наведений нижче фрагмент зберігає оригінальну ідею, але використовує **`%p` для виведення pointers**, щоб x64 build не обрізав addresses, поки ви намагаєтеся під'єднати debugger або змінити базу blob у своєму RE tool.

## Build

Найпростіший спосіб зібрати оригінальний project — скористатися **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Ви також можете вставити код у невеликий проєкт C у Visual Studio / VS Code і скомпілювати його там.

## Корисні шаблони використання
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
- В **x86** BlobRunner призупиняється, а потім виконує прямий перехід до точки входу blob.
- В **x64** він створює **призупинений потік**, тому можна встановити breakpoint на адресі запуску потоку до відновлення виконання.
- `--offset` особливо корисний, коли dumped blob починається з **decoder / unpacking stub**, а справжня точка входу вже відома.

## Практичні примітки

### Виправлення надрукованих адрес у x64 labs

Старіший код BlobRunner виводить адреси за допомогою приведень на кшталт `(int)(size_t)lpvBase` і `%08x` / `%016x`. У 64-бітних workflow це може обрізати старшу половину pointer, через що rebasing / встановлення breakpoint стає незручним. Наведений нижче фрагмент уже виправляє це, виводячи значення **`%p`** безпосередньо.

### `--jit` корисний для breakpoint на першій інструкції

`--jit` прибирає доступ на виконання з першого байта shellcode і дозволяє Windows викликати **access violation**, коли blob починає виконуватися. Це корисно, коли потрібно, щоб **налаштований JIT debugger** (наприклад, x64dbg) перехопив першу спробу виконання замість того, щоб вручну встигати під’єднатися. Після зупинки debugger відновіть права на виконання та продовжіть роботу.

Практична **послідовність дій у x64dbg**:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Перші дві команди реєструють x64dbg як JIT debugger, а `setpagerights` відновлює права на виконання для області, надрукованої BlobRunner після того, як debugger перехоплює access violation.

### Виконуйте time-travel для shellcode замість покрокового виконання наживо

Дуже практичний сучасний workflow — записати BlobRunner під **TTD**, а потім перевірити trace у **Binary Ninja** / **WinDbg**. Це особливо корисно, коли blob розшифровує себе, динамічно визначає API або виконує кілька короткоживучих етапів. Починаючи з **Binary Ninja 4.1**, підтримка TTD більше не має лише beta-якості: вона може виконувати reverse-debugging і безпосередньо з Binary Ninja спрощувати workflow WinDbg / TTD.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Важливо **записати базову адресу, виділену BlobRunner**, а потім виконати **rebase** view shellcode на цю адресу перед повторним відтворенням trace. Також зверніть увагу, що Microsoft описує запис TTD як **інвазивний**: запускайте його з **підвищеної** консолі, очікуйте помітного уповільнення та тримайте вікно запису коротким, щоб уникнути величезних файлів trace.<sup>[[1]](#references)</sup>

### Якщо blob потребує супровідних даних, використовуйте PE wrapper

Деякий shellcode очікує наявності в пам’яті **другого blob**, **mapped file** або іншого **структурованого вмісту**. BlobRunner навмисно мінімалістичний, тому в таких випадках runner на кшталт **SCLauncher** може бути зручнішим, оскільки він може:<sup>[[2]](#references)</sup>

- призупинити виконання перед запуском,
- вставити breakpoint `INT3`,
- завантажити **додатковий вміст** у пам’ять,
- виконати memory-map цього додаткового вмісту або
- обгорнути shellcode у тимчасовий **PE** для зручнішого аналізу в tools, які надають перевагу звичайним executable.

Приклад:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Для додаткових робочих процесів, таких як **jmp2it**, емуляція **Cutter** або трасування shellcode на основі **scdbg**, перегляньте [батьківську сторінку реверсу shellcode](README.md).

## Вихідний код

Єдині змінені рядки в [оригінальному коді](https://github.com/OALabs/BlobRunner) — це рядки виведення вказівників, додані для уникнення обрізання адрес x64.  
Щоб скомпілювати код, просто **створіть C/C++-проєкт у Visual Studio Code, скопіюйте та вставте код і виконайте його збірку**.
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

- [1] [Налагодження Shellcode з перемотуванням у часі за допомогою Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Аналіз Shellcode за допомогою SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)

{{#include ../../banners/hacktricks-training.md}}
