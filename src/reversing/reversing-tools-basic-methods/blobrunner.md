# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) to niewielki Windows **shellcode loader do debuggingu**: alokuje pamięć RWX, kopiuje blob, wypisuje adres bazowy / punkt wejścia i przekazuje tam wykonanie. Jest to przydatne, gdy próbka jest **surowym shellcode**, **odszyfrowanym stage wyodrębnionym z malware** lub **blobiem niezależnym od pozycji**, który nie ma nagłówka PE.

Poniższy snippet zachowuje oryginalną ideę, ale używa **`%p` do wypisywania wskaźników**, dzięki czemu build x64 nie obcina adresów podczas próby podłączenia debuggera lub zmiany bazy bloba w narzędziu RE.

## Build

Najprostszym sposobem zbudowania oryginalnego projektu jest użycie **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Możesz również wkleić kod do małego projektu C w Visual Studio / VS Code i skompilować go tam.

## Przydatne wzorce użycia
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
- W **x86** BlobRunner wstrzymuje działanie, a następnie wykonuje bezpośredni skok do punktu wejścia blobu.
- W **x64** tworzy **suspended thread**, dzięki czemu można ustawić breakpoint na adresie startowym wątku przed wznowieniem wykonania.
- `--offset` jest szczególnie przydatne, gdy zdumpowany blob rozpoczyna się od **decoder / unpacking stub** i znasz już rzeczywisty punkt wejścia.

## Uwagi praktyczne

### Naprawianie wyświetlanych adresów w laboratoriach x64

Starszy kod BlobRunner wyświetla adresy za pomocą rzutowań takich jak `(int)(size_t)lpvBase` oraz `%08x` / `%016x`. W workflow 64-bitowych może to obciąć starszą połowę wskaźnika i utrudnić rebasing / ustawianie breakpointów. Poniższy snippet już to naprawia, wyświetlając bezpośrednio wartości **`%p`**.

### `--jit` jest przydatne przy breakpointach na pierwszej instrukcji

`--jit` usuwa uprawnienie execute z pierwszego bajtu shellcode i pozwala systemowi Windows zgłosić **access violation**, gdy blob rozpocznie wykonywanie. Jest to przydatne, gdy chcesz, aby **skonfigurowany debugger JIT** (na przykład x64dbg) przechwycił pierwszą próbę wykonania zamiast ręcznie próbować zdążyć z podłączeniem. Po zatrzymaniu przez debugger przywróć uprawnienia execute i kontynuuj.

Praktyczny **x64dbg** flow wygląda następująco:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Pierwsze dwa polecenia rejestrują x64dbg jako debugger JIT, a `setpagerights` przywraca prawa wykonywania w regionie wskazanym przez BlobRunner po przechwyceniu przez debugger wyjątku naruszenia dostępu.

### Prześledź shellcode w czasie zamiast wykonywać go krokowo na żywo

Bardzo praktyczny, nowszy workflow polega na zarejestrowaniu BlobRunner za pomocą **TTD**, a następnie przeanalizowaniu trace w **Binary Ninja** / **WinDbg**. Jest to świetne rozwiązanie, gdy blob odszyfrowuje się sam, dynamicznie rozwiązuje API lub wykonuje kilka krótkotrwałych etapów. Od wersji **Binary Ninja 4.1** obsługa TTD nie ma już wyłącznie statusu beta: może obsługiwać reverse-debugging i upraszczać workflow WinDbg / TTD bezpośrednio z poziomu Binary Ninja.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Najważniejsze jest, aby **zanotować przydzielony adres bazowy wydrukowany przez BlobRunner**, a następnie **wykonać rebase** widoku shellcode do tego adresu przed ponownym odtworzeniem trace. Należy również pamiętać, że Microsoft określa nagrywanie TTD jako **inwazyjne**: uruchamiaj je z **podniesionego** wiersza polecenia, spodziewaj się zauważalnego spowolnienia i utrzymuj krótki czas nagrywania, aby uniknąć ogromnych plików trace.

### Jeśli blob wymaga dodatkowych danych, użyj PE wrapper

Niektóre shellcode oczekują, że w pamięci będzie znajdować się **drugi blob**, **zmapowany plik** lub inna **ustrukturyzowana zawartość**. BlobRunner jest celowo minimalistyczny, dlatego w takich przypadkach wygodniejszy może być runner taki jak **SCLauncher**, ponieważ może:<sup>[[2]](#references)</sup>

- wstrzymać wykonanie,
- wstawić breakpoint `INT3`,
- załadować **dodatkową zawartość** do pamięci,
- zmapować tę dodatkową zawartość w pamięci lub
- opakować shellcode w tymczasowy **PE**, aby ułatwić analizę w narzędziach preferujących zwykłe pliki wykonywalne.

Przykład:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Dla uzupełniających workflowów, takich jak **jmp2it**, emulacja **Cutter** lub śledzenie shellcode oparte na **scdbg**, zobacz [parent shellcode reversing page](README.md).

## Kod źródłowy

Jedyne zmodyfikowane linie względem [oryginalnego kodu](https://github.com/OALabs/BlobRunner) to linie wyświetlające wskaźniki, użyte w celu uniknięcia obcinania adresów x64.  
Aby go skompilować, wystarczy **utworzyć projekt C/C++ w Visual Studio Code, skopiować i wkleić kod, a następnie go zbudować**.
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
## Odnośniki

- [1] [Debugowanie shellcode za pomocą Binary Ninja z wykorzystaniem Time Travel](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Analiza shellcode za pomocą SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
