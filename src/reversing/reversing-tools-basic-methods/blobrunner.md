# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) is 'n klein Windows **shellcode loader vir debugging**: dit allokeer RWX memory, kopieer die blob, druk die basisadres / entry point, en dra uitvoering daarheen oor. Dit is handig wanneer die sample **raw shellcode** is, 'n **decrypted stage extracted from malware**, of 'n **position-independent blob** wat nie 'n PE header het nie.

The snippet below keeps the original idea, but uses **`%p` for printed pointers** so the x64 build doesn't truncate addresses while you are trying to attach a debugger or rebase the blob in your RE tool.

## Build

Die eenvoudigste manier om die oorspronklike project te build is vanaf 'n **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Jy kan ook die kode in 'n klein Visual Studio / VS Code C-projek plak en dit daar kompileer.

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
- In **x86**, BlobRunner pauseer en doen dan ’n direkte sprong na die blob entry point.
- In **x64**, dit skep ’n **suspended thread**, so jy kan op die thread start address breek voordat uitvoering hervat.
- `--offset` is veral nuttig wanneer die dumped blob begin met ’n **decoder / unpacking stub** en jy reeds die werklike entry point ken.

## Practical notes

### Fix the printed addresses in x64 labs

Ouer BlobRunner-kode druk addresses uit via casts soos `(int)(size_t)lpvBase` en `%08x` / `%016x`. In 64-bit workflows kan dit die hoë helfte van die pointer afkap en rebasing / breakpoint placement lastig maak. Die snippet hieronder fix dit reeds deur **`%p`** values direk te print.

### `--jit` is useful for first-instruction breakpoints

`--jit` verwyder execute access van die eerste byte van die shellcode en laat Windows ’n **access violation** gooi wanneer die blob begin execute. Dit is nuttig wanneer jy wil hê die **configured JIT debugger** (byvoorbeeld x64dbg) moet die eerste execution attempt vang in plaas daarvan om handmatig te probeer attach. Nadat die debugger breek, herstel execute rights en continue.

A practical **x64dbg** flow is:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Die eerste twee commands registreer x64dbg as die JIT debugger, en `setpagerights` herstel execute rights op die region wat deur BlobRunner gedruk is nadat die debugger die access violation vang.

### Tydreis die shellcode in plaas daarvan om dit live stap-vir-stap te volg

’n Baie praktiese onlangse workflow is om BlobRunner onder **TTD** op te neem en dan die trace in **Binary Ninja** / **WinDbg** te inspekteer. Dit is uitstekend wanneer die blob homself decrypt, APIs dinamies resolve, of verskeie kortstondige stages uitvoer. Sedert **Binary Ninja 4.1** is TTD support nie meer net beta quality nie: dit kan reverse-debugging dryf en die WinDbg / TTD workflow direk vanuit Binary Ninja vereenvoudig.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Die belangrike deel is om die **toegekende basisadres wat deur BlobRunner gedruk word** op te let en dan die shellcode-aansig na daardie adres te **rebase** voordat jy die trace herhaal. Let ook daarop dat Microsoft TTD-opname as **invasive** dokumenteer: laat dit vanaf ’n **elevated** prompt loop, verwag merkbare vertraging, en hou die opnamevenster kort om massiewe trace-lêers te vermy.

### As die blob companion data nodig het, gebruik eerder ’n PE wrapper

Sommige shellcode verwag dat ’n **second blob**, ’n **mapped file**, of ander **structured content** in memory bestaan. BlobRunner is doelbewus minimal, so vir hierdie gevalle kan ’n runner soos **SCLauncher** geriefliker wees omdat dit kan:

- pause voor execution,
- ’n `INT3` breakpoint insit,
- **additional content** in memory laai,
- daardie ekstra content memory-map, of
- die shellcode binne-in ’n tydelike **PE** wrap vir makliker analysis in tools wat gewone executables verkies.

Voorbeeld:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Vir aanvullende werkvloeie soos **jmp2it**, **Cutter** emulasie, of **scdbg**-gebaseerde shellcode-tracing, kyk na die [parent shellcode reversing page](README.md).

## Source code

Die enigste gewysigde reëls van die [original code](https://github.com/OALabs/BlobRunner) is die pointer-printing reëls wat gebruik word om x64 address truncation te vermy.
Om dit te compileer, **skep net ’n C/C++ project in Visual Studio Code, kopieer en plak die code, en build dit**.
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

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
