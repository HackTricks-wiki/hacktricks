# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) to mały Windows **shellcode loader do debugowania**: alokuje pamięć RWX, kopiuje blob, wypisuje adres bazowy / punkt wejścia i przekazuje tam wykonanie. To przydatne, gdy próbka jest **raw shellcode**, **odszyfrowanym stage wyodrębnionym z malware**, albo **position-independent blob**, który nie ma nagłówka PE.

Poniższy fragment zachowuje oryginalny pomysł, ale używa **`%p` dla wypisywanych wskaźników**, dzięki czemu build x64 nie ucina adresów, gdy próbujesz podłączyć debugger albo zmienić bazę blobu w swoim RE tool.

## Build

Najprostszy sposób zbudowania oryginalnego projektu to użycie **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Możesz też wkleić kod do małego projektu C w Visual Studio / VS Code i skompilować go tam.

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
- W **x86**, BlobRunner pauzuje, a następnie wykonuje bezpośredni skok do punktu wejścia blob.
- W **x64**, tworzy **suspended thread**, więc możesz ustawić breakpoint na adresie startu thread przed wznowieniem wykonania.
- `--offset` jest szczególnie przydatny, gdy zrzut blob zaczyna się od **decoder / unpacking stub** i już znasz rzeczywisty punkt wejścia.

## Practical notes

### Fix the printed addresses in x64 labs

Starszy kod BlobRunner wypisuje adresy przez rzutowania takie jak `(int)(size_t)lpvBase` oraz `%08x` / `%016x`. W 64-bit workflows może to uciąć wyższą połowę wskaźnika i utrudnić rebasing / breakpoint placement. Poniższy snippet już to naprawia, wypisując bezpośrednio wartości **`%p`**.

### `--jit` is useful for first-instruction breakpoints

`--jit` usuwa execute access z pierwszego bajtu shellcode i pozwala Windows zgłosić **access violation**, gdy blob zaczyna się wykonywać. Jest to przydatne, gdy chcesz, aby **configured JIT debugger** (na przykład x64dbg) przechwycił pierwszą próbę wykonania zamiast ręcznie ścigać się z attach. Po zatrzymaniu przez debugger przywróć execute rights i kontynuuj.

Praktyczny flow **x64dbg** to:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Pierwsze dwa polecenia rejestrują x64dbg jako debugger JIT, a `setpagerights` przywraca prawa wykonywania dla regionu wypisanego przez BlobRunner po tym, jak debugger przechwyci access violation.

### Cofnij shellcode w czasie zamiast wykonywać go krok po kroku na żywo

Bardzo praktyczny, niedawny workflow to nagranie BlobRunner pod **TTD**, a następnie analiza trace w **Binary Ninja** / **WinDbg**. Jest to świetne, gdy blob sam się odszyfrowuje, dynamicznie rozwiązuje API albo wykonuje kilka krótkotrwałych etapów. Od **Binary Ninja 4.1** wsparcie dla TTD nie jest już tylko jakości beta: może obsługiwać reverse-debugging i uprościć workflow WinDbg / TTD bezpośrednio z Binary Ninja.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Ważne jest, aby **zanotować przydzielony adres bazowy wypisany przez BlobRunner** i następnie **przestawić bazę** widoku shellcode na ten adres przed odtworzeniem trace. Zwróć też uwagę, że Microsoft dokumentuje nagrywanie TTD jako **invasive**: uruchamiaj je z **elevated** prompt, spodziewaj się zauważalnego spowolnienia i utrzymuj okno nagrywania krótkie, aby uniknąć ogromnych plików trace.

### Jeśli blob potrzebuje danych towarzyszących, użyj zamiast tego wrappera PE

Niektóre shellcode oczekują, że w pamięci będzie dostępny **second blob**, **mapped file** albo jakaś inna **structured content**. BlobRunner jest celowo minimalistyczny, więc w takich przypadkach runner taki jak **SCLauncher** może być wygodniejszy, ponieważ może:

- wstrzymać się przed wykonaniem,
- wstawić breakpoint **INT3**,
- załadować **additional content** do pamięci,
- zamapować to dodatkowe content w pamięci, albo
- opakować shellcode w tymczasowy **PE**, aby łatwiej analizować go w narzędziach, które preferują zwykłe executables.

Przykład:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Dla uzupełniających workflows, takich jak **jmp2it**, emulacja **Cutter** lub śledzenie shellcode oparte na **scdbg**, sprawdź [parent shellcode reversing page](README.md).

## Source code

Jedynymi zmodyfikowanymi liniami z [original code](https://github.com/OALabs/BlobRunner) są linie drukujące wskaźniki, użyte, aby uniknąć obcięcia adresów x64.
Aby go skompilować, po prostu **utwórz project C/C++ w Visual Studio Code, skopiuj i wklej code, a potem go zbuduj**.
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
