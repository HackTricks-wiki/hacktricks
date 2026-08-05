# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) is 'n klein Windows **shellcode loader for debugging**: dit allokeer RWX-geheue, kopieer die blob, druk die basisadres / entry point, en dra uitvoering daarheen oor. Dit is handig wanneer die sample **raw shellcode**, 'n **decrypted stage extracted from malware**, of 'n **position-independent blob** is wat nie 'n PE header het nie.

Die snippet hieronder behou die oorspronklike idee, maar gebruik **`%p` vir printed pointers** sodat die x64 build nie adresse afkap terwyl jy probeer om 'n debugger aan te heg of die blob in jou RE tool te rebase nie.

## Bou

Die eenvoudigste manier om die oorspronklike projek te bou, is vanuit 'n **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Jy kan die code ook in ’n klein Visual Studio / VS Code C-projek plak en dit daar compileer.

## Nuttige gebruikspatrone
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
- In **x86** pouseer BlobRunner en voer dit daarna ’n direkte sprong na die blob se entry point uit.
- In **x64** skep dit ’n **suspended thread**, sodat jy op die thread start address kan breek voordat uitvoering hervat word.
- `--offset` is besonder nuttig wanneer die gedumpte blob met ’n **decoder / unpacking stub** begin en jy reeds die werklike entry point ken.

## Praktiese notas

### Maak die gedrukte adresse in x64-labs reg

Ouer BlobRunner-kode druk adresse deur casts soos `(int)(size_t)lpvBase` en `%08x` / `%016x` te gebruik. In 64-bis-workflows kan dit die hoë helfte van die pointer afkap en rebasing / breakpoint-plasing lastig maak. Die snippet hieronder los dit reeds op deur **`%p`**-waardes direk te druk.

### `--jit` is nuttig vir breakpoints op die eerste instruksie

`--jit` verwyder execute-toegang van die eerste byte van die shellcode en laat Windows ’n **access violation** genereer wanneer die blob begin uitvoer. Dit is nuttig wanneer jy wil hê dat die **gekonfigureerde JIT-debugger** (byvoorbeeld x64dbg) die eerste uitvoeringspoging moet opvang, in plaas daarvan om handmatig te probeer attach. Nadat die debugger breek, herstel execute-regte en gaan voort.

’n Praktiese **x64dbg**-vloei is:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Die eerste twee opdragte registreer x64dbg as die JIT-debugger, en `setpagerights` herstel uitvoerregte op die streek wat deur BlobRunner afgedruk word nadat die debugger die access violation opvang.

### Tydreis deur die shellcode in plaas daarvan om dit intyds stap vir stap uit te voer

’n Baie praktiese onlangse workflow is om BlobRunner onder **TTD** op te neem en dan die trace in **Binary Ninja** / **WinDbg** te inspekteer. Dit is uitstekend wanneer die blob homself decrypt, APIs dinamies resolve, of verskeie kortstondige stages uitvoer. Sedert **Binary Ninja 4.1** is TTD-ondersteuning nie meer bloot beta-gehalte nie: dit kan reverse-debugging uitvoer en die WinDbg / TTD-workflow direk vanuit Binary Ninja vereenvoudig.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Die belangrike deel is om die **toegekende basisadres wat deur BlobRunner gedruk word, aan te teken** en dan die shellcode-aansig na daardie adres te **rebase** voordat jy die trace herspeel. Let ook daarop dat Microsoft TTD-opname as **invasive** dokumenteer: voer dit vanuit ’n **elevated** prompt uit, verwag ’n merkbare verlangsaming, en hou die opnamevenster kort om massiewe trace-lêers te vermy.

### As die blob companion data benodig, gebruik eerder ’n PE wrapper

Sommige shellcode verwag dat ’n **tweede blob**, ’n **gemapte lêer**, of ander **gestruktureerde inhoud** in memory bestaan. BlobRunner is doelbewus minimaal, dus kan ’n runner soos **SCLauncher** geriefliker wees vir hierdie gevalle omdat dit:<sup>[[2]](#references)</sup>

- voor execution kan pause,
- ’n `INT3` breakpoint kan invoeg,
- **additional content** in memory kan laai,
- daardie additional content kan memory-map, of
- die shellcode binne ’n tydelike **PE** kan wrap vir makliker analysis in tools wat normale executables verkies.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Vir aanvullende workflows soos **jmp2it**, **Cutter**-emulasie of **scdbg**-gebaseerde shellcode-tracing, kyk na die [ouer shellcode reversing-bladsy](README.md).

## Bronkode

Die enigste gewysigde lyne vanaf die [oorspronklike kode](https://github.com/OALabs/BlobRunner) is die pointer-printing-lyne wat gebruik word om x64-adresafkapping te voorkom.  
Om dit te compile, **skep eenvoudig ’n C/C++-projek in Visual Studio Code, kopieer en plak die kode, en build dit**.
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
## Verwysings

- [1] [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Ontleding van Shellcode met SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
