# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) — це невеликий Windows **shellcode loader для налагодження**: він виділяє пам'ять RWX, копіює blob, виводить базову адресу / entry point і передає туди виконання. Це зручно, коли зразок є **raw shellcode**, **розшифрованою стадією, отриманою з malware**, або **position-independent blob**, який не має PE header.

Наведений нижче фрагмент зберігає оригінальну ідею, але використовує **`%p` для виведення вказівників**, щоб x64-збірка не обрізала адреси, коли ви намагаєтеся під'єднати debugger або змінити базову адресу blob у своєму RE tool.

## Збірка

Найпростіший спосіб зібрати оригінальний проєкт — скористатися **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Ви також можете вставити код у невеликий C-проєкт у Visual Studio / VS Code і скомпілювати його там.

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
- У **x86** BlobRunner призупиняється, а потім виконує прямий перехід до entry point blob.
- У **x64** він створює **suspended thread**, тож можна встановити breakpoint на thread start address до відновлення виконання.
- `--offset` особливо корисний, коли dumped blob починається з **decoder / unpacking stub**, а справжній entry point вам уже відомий.

## Практичні примітки

### Виправлення надрукованих адрес у лабораторних роботах для x64

Старіший код BlobRunner виводить адреси через такі casts, як `(int)(size_t)lpvBase`, і `%08x` / `%016x`. У 64-бітних workflow це може обрізати старшу половину pointer, що ускладнює rebasing / встановлення breakpoint. Наведений нижче snippet уже виправляє це, безпосередньо виводячи значення `%p`.

### `--jit` корисний для breakpoint на першій інструкції

`--jit` прибирає execute access із першого байта shellcode і дозволяє Windows викликати **access violation**, коли blob починає виконуватися. Це корисно, якщо потрібно, щоб **configured JIT debugger** (наприклад, x64dbg) перехопив першу спробу виконання замість ручного змагання під час attach. Після того як debugger зупиниться, відновіть execute rights і продовжіть виконання.

Практичний workflow у **x64dbg** такий:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Перші дві команди реєструють x64dbg як JIT debugger, а `setpagerights` відновлює права на виконання для області, виведеної BlobRunner після того, як debugger перехоплює порушення доступу.

### Переміщення в часі shellcode замість покрокового виконання наживо

Дуже практичний сучасний workflow полягає в записі BlobRunner під **TTD**, а потім перевірці trace у **Binary Ninja** / **WinDbg**. Це особливо корисно, коли blob розшифровує сам себе, динамічно знаходить API або виконує кілька короткоживучих етапів. Починаючи з **Binary Ninja 4.1**, підтримка TTD більше не має лише beta-якості: вона може керувати reverse-debugging і безпосередньо спрощувати workflow WinDbg / TTD у Binary Ninja.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Важливо **зафіксувати виділену базову адресу, надруковану BlobRunner**, а потім виконати **rebase** перегляду shellcode на цю адресу перед повторним відтворенням trace. Також зверніть увагу, що Microsoft описує запис TTD як **invasive**: запускайте його з **підвищеними привілеями**, очікуйте помітного сповільнення та тримайте вікно запису коротким, щоб уникнути величезних trace-файлів.

### Якщо blob потребує супровідних даних, використовуйте PE-wrapper

Деякий shellcode очікує наявності в пам’яті **другого blob**, **mapped file** або іншого **структурованого вмісту**. BlobRunner навмисно мінімалістичний, тому в таких випадках runner на кшталт **SCLauncher** може бути зручнішим, оскільки він може:<sup>[[2]](#references)</sup>

- призупинити виконання перед запуском,
- вставити breakpoint `INT3`,
- завантажити **додатковий вміст** у пам’ять,
- memory-map цей додатковий вміст, або
- обгорнути shellcode у тимчасовий **PE** для спрощення аналізу в tools, які надають перевагу звичайним executable-файлам.

Приклад:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Для додаткових робочих процесів, таких як **jmp2it**, емуляція **Cutter** або трасування shellcode на основі **scdbg**, дивіться [батьківську сторінку з реверсингу shellcode](README.md).

## Вихідний код

Єдині змінені рядки в [оригінальному коді](https://github.com/OALabs/BlobRunner) — це рядки виведення вказівників, використані для запобігання обрізанню адрес x64.
Щоб скомпілювати його, просто **створіть проєкт C/C++ у Visual Studio Code, скопіюйте та вставте код і виконайте його збірку**.
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

- [1] [Налагодження shellcode за допомогою Time Travel Debugging у Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Аналіз shellcode за допомогою SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
