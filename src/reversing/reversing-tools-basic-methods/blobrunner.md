# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ist ein winziger Windows-**shellcode loader for debugging**: Er reserviert RWX-Speicher, kopiert den Blob, gibt die Basisadresse / den Entry Point aus und übergibt dorthin die Ausführung. Dies ist hilfreich, wenn es sich bei dem Sample um **raw shellcode**, eine **aus Malware extrahierte entschlüsselte Stage** oder einen **position-independent Blob** ohne PE-Header handelt.

Das folgende Snippet behält die ursprüngliche Idee bei, verwendet aber **`%p` für ausgegebene Pointer**, damit der x64-Build Adressen nicht abschneidet, während du versuchst, einen Debugger anzuhängen oder den Blob in deinem RE-Tool neu zu basieren.

## Build

Die einfachste Möglichkeit, das ursprüngliche Projekt zu bauen, ist über eine **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Du kannst den Code auch in ein kleines Visual Studio- oder VS Code-C-Projekt einfügen und dort kompilieren.

## Nützliche Verwendungsmuster
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
- In **x86** pausiert BlobRunner und führt anschließend einen direkten Sprung zum Blob-Einstiegspunkt aus.
- In **x64** erstellt es einen **suspended thread**, sodass du am Thread-Startadresspunkt einen Breakpoint setzen kannst, bevor du die Ausführung fortsetzt.
- `--offset` ist besonders nützlich, wenn der gedumpte Blob mit einem **decoder / unpacking stub** beginnt und du den tatsächlichen Einstiegspunkt bereits kennst.

## Praktische Hinweise

### Die ausgegebenen Adressen in x64-Labs korrigieren

Älterer BlobRunner-Code gibt Adressen über Casts wie `(int)(size_t)lpvBase` und `%08x` / `%016x` aus. In 64-Bit-Workflows kann dadurch die obere Hälfte des Pointers abgeschnitten werden, was das Rebasing und das Platzieren von Breakpoints erschwert. Das folgende Snippet behebt dies bereits, indem es direkt **`%p`**-Werte ausgibt.

### `--jit` ist für Breakpoints auf der ersten Instruktion nützlich

`--jit` entfernt den Execute-Zugriff vom ersten Byte des shellcode und veranlasst Windows, eine **access violation** auszulösen, wenn der Blob mit der Ausführung beginnt. Das ist nützlich, wenn der **konfigurierte JIT-Debugger** (zum Beispiel x64dbg) den ersten Ausführungsversuch abfangen soll, anstatt dass du manuell versuchen musst, rechtzeitig eine Verbindung herzustellen. Nachdem der Debugger angehalten hat, stelle die Execute-Rechte wieder her und setze die Ausführung fort.

Ein praktischer **x64dbg**-Ablauf ist:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Die ersten beiden Befehle registrieren x64dbg als JIT-Debugger, und `setpagerights` stellt die Ausführungsrechte für den von BlobRunner ausgegebenen Bereich wieder her, nachdem der Debugger den Zugriffsverstoß abgefangen hat.

### Shellcode per Time-Travel untersuchen, statt ihn live per Single-Stepping auszuführen

Ein sehr praktischer neuerer Workflow besteht darin, BlobRunner unter **TTD** aufzuzeichnen und den Trace anschließend in **Binary Ninja** / **WinDbg** zu untersuchen. Das ist besonders nützlich, wenn der Blob sich selbst entschlüsselt, APIs dynamisch auflöst oder mehrere kurzlebige Stages ausführt. Seit **Binary Ninja 4.1** befindet sich die TTD-Unterstützung nicht mehr nur in Beta-Qualität: Sie kann Reverse-Debugging steuern und den WinDbg- / TTD-Workflow direkt aus Binary Ninja vereinfachen.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Der wichtige Punkt ist, die von BlobRunner ausgegebene **Basisadresse zu notieren** und anschließend die Shellcode-Ansicht auf diese Adresse zu **rebasen**, bevor der Trace erneut abgespielt wird. Beachte außerdem, dass Microsoft die TTD-Aufzeichnung als **invasiv** dokumentiert: Führe sie in einer **erhöhten** Eingabeaufforderung aus, rechne mit einer merklichen Verlangsamung und halte das Aufzeichnungsfenster kurz, um massive Trace-Dateien zu vermeiden.

### Wenn der Blob Begleitdaten benötigt, verwende stattdessen einen PE-Wrapper

Manche Shellcode erwarten, dass ein **zweiter Blob**, eine **gemappte Datei** oder anderer **strukturierter Inhalt** im Speicher vorhanden ist. BlobRunner ist absichtlich minimal gehalten. Für diese Fälle kann ein Runner wie **SCLauncher** praktischer sein, da er Folgendes ermöglicht:<sup>[[2]](#references)</sup>

- vor der Ausführung zu pausieren,
- einen `INT3`-Breakpoint einzufügen,
- **zusätzliche Inhalte** in den Speicher zu laden,
- diese zusätzlichen Inhalte per Memory-Mapping einzubinden oder
- den Shellcode zur einfacheren Analyse in Tools, die normale Executables bevorzugen, in einen temporären **PE** einzubetten.

Beispiel:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Für ergänzende Workflows wie **jmp2it**, die **Cutter**-Emulation oder das auf **scdbg** basierende Shellcode-Tracing siehe die [übergeordnete Shellcode-Reversing-Seite](README.md).

## Quellcode

Die einzigen geänderten Zeilen gegenüber dem [Originalcode](https://github.com/OALabs/BlobRunner) sind die Zeilen zur Ausgabe von Pointern, um eine Adresskürzung unter x64 zu vermeiden.  
Um ihn zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code und füge ihn ein und führe den Build aus**.
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

- [1] [Time Travel Debugging von Shellcode mit Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Analyse von Shellcode mit SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
