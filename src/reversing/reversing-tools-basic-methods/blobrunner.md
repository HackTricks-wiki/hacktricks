# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ist ein kleines Windows-**shellcode loader for debugging**: Es reserviert RWX-Speicher, kopiert den blob, gibt die Base-Adresse / den Entry Point aus und übergibt dort die Ausführung. Das ist nützlich, wenn das Sample **raw shellcode**, eine **decrypted stage extracted from malware** oder ein **position-independent blob** ist, das keinen PE-Header hat.

Das folgende Snippet behält die ursprüngliche Idee bei, verwendet aber **`%p` für ausgegebene Pointer**, damit der x64-Build Adressen nicht abschneidet, während du versuchst, einen debugger anzuhängen oder den blob in deinem RE-Tool neu zu basen.

## Build

Der einfachste Weg, das ursprüngliche Projekt zu bauen, ist über eine **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Du kannst den Code auch in ein kleines Visual-Studio-/VS-Code-C-Projekt einfügen und dort kompilieren.

## Nützliche Nutzungsmuster
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
- In **x86**, BlobRunner pausiert und springt dann direkt zum Blob-Entry-Point.
- In **x64**, es erstellt einen **suspended thread**, sodass du auf die Thread-Startadresse breaken kannst, bevor die Ausführung fortgesetzt wird.
- `--offset` ist besonders nützlich, wenn der gedumpte Blob mit einem **decoder / unpacking stub** beginnt und du den echten Entry-Point bereits kennst.

## Praktische Hinweise

### Die ausgegebenen Adressen in x64-Labs korrigieren

Älterer BlobRunner-Code gibt Adressen über Casts wie `(int)(size_t)lpvBase` und `%08x` / `%016x` aus. In 64-bit-Workflows kann das die obere Hälfte des Pointers abschneiden und Rebasing / Breakpoint-Placement umständlich machen. Das folgende Snippet behebt das bereits, indem es **`%p`**-Werte direkt ausgibt.

### `--jit` ist nützlich für Breakpoints auf der ersten Instruktion

`--jit` entfernt Execute-Zugriff vom ersten Byte des Shellcode und lässt Windows eine **access violation** auslösen, wenn der Blob mit der Ausführung beginnt. Das ist nützlich, wenn du möchtest, dass der **konfigurierte JIT debugger** (zum Beispiel x64dbg) den ersten Ausführungsversuch abfängt, statt manuell beim Attach zu hetzen. Nachdem der Debugger anhält, stelle die Execute-Rechte wieder her und fahre fort.

Ein praktischer **x64dbg**-Ablauf ist:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Die ersten beiden Befehle registrieren x64dbg als JIT-Debugger, und `setpagerights` stellt die Execute-Rechte auf dem von BlobRunner ausgegebenen Bereich wieder her, nachdem der Debugger die access violation abgefangen hat.

### Time-travel the shellcode statt es live per single-stepping zu debuggen

Ein sehr praktischer aktueller Workflow ist, BlobRunner unter **TTD** aufzuzeichnen und dann den Trace in **Binary Ninja** / **WinDbg** zu untersuchen. Das ist großartig, wenn der blob sich selbst entschlüsselt, APIs dynamisch auflöst oder mehrere kurzlebige Stages ausführt. Seit **Binary Ninja 4.1** ist TTD-Support nicht mehr nur Beta-Qualität: Er kann Reverse-Debugging steuern und den WinDbg / TTD-Workflow direkt aus Binary Ninja heraus vereinfachen.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Der wichtige Teil ist, die von BlobRunner ausgegebene **zugewiesene Basisadresse zu notieren** und dann die Shellcode-Ansicht auf diese Adresse zu **rebasen**, bevor der Trace erneut abgespielt wird. Beachte außerdem, dass Microsoft TTD-Aufzeichnung als **invasive** dokumentiert: Starte sie aus einer **erhöhten** Eingabeaufforderung, rechne mit spürbarer Verlangsamung und halte das Aufzeichnungsfenster kurz, um massive Trace-Dateien zu vermeiden.

### Wenn der blob Begleitdaten benötigt, verwende stattdessen einen PE-Wrapper

Einige Shellcodes erwarten, dass ein **zweiter blob**, eine **gemappte Datei** oder ein anderer **strukturierter Inhalt** im Speicher vorhanden ist. BlobRunner ist absichtlich minimal gehalten, daher kann für diese Fälle ein Runner wie **SCLauncher** bequemer sein, weil er:

- vor der Ausführung pausieren kann,
- einen **INT3**-Breakpoint einfügen kann,
- **zusätzlichen Inhalt** in den Speicher laden kann,
- diesen zusätzlichen Inhalt per Memory-Mapping einbinden kann, oder
- den Shellcode in ein temporäres **PE** einpacken kann, um die Analyse in Tools zu erleichtern, die normale Executables bevorzugen.

Beispiel:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Für ergänzende Workflows wie **jmp2it**, **Cutter**-Emulation oder **scdbg**-basiertes Shellcode-Tracing, siehe die [parent shellcode reversing page](README.md).

## Source code

Die einzigen geänderten Zeilen vom [original code](https://github.com/OALabs/BlobRunner) sind die Pointer-Print-Zeilen, die verwendet werden, um x64-Adress-Trunkierung zu vermeiden.
Um es zu kompilieren, musst du einfach **ein C/C++-Projekt in Visual Studio Code erstellen, den Code kopieren und einfügen und es bauen**.
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
## Referenzen

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
