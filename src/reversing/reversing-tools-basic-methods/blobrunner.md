# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) è un piccolo **shellcode loader per il debugging** di Windows: alloca memoria RWX, copia il blob, stampa l’indirizzo base / punto di ingresso e trasferisce lì l’esecuzione. Questo è utile quando il sample è **raw shellcode**, uno **stage decriptato estratto da malware**, o un **blob position-independent** che non ha un header PE.

Lo snippet qui sotto mantiene l’idea originale, ma usa **`%p` per i puntatori stampati** così la build x64 non tronca gli indirizzi mentre stai cercando di collegare un debugger o rebasare il blob nel tuo RE tool.

## Build

Il modo più semplice per compilare il progetto originale è da un **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Puoi anche incollare il codice in un piccolo progetto C di Visual Studio / VS Code e compilarlo lì.

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
- In **x86**, BlobRunner mette in pausa e poi esegue un salto diretto al blob entry point.
- In **x64**, crea un **thread sospeso**, così puoi mettere un breakpoint all'indirizzo di inizio del thread prima di riprendere l'esecuzione.
- `--offset` è particolarmente utile quando il blob dumpato inizia con un **decoder / unpacking stub** e conosci già il vero entry point.

## Note pratiche

### Correggi gli indirizzi stampati nei lab x64

Il codice BlobRunner più vecchio stampa gli indirizzi tramite cast come `(int)(size_t)lpvBase` e `%08x` / `%016x`. Nei workflow a 64 bit questo può troncare la parte alta del puntatore e rendere fastidiosi il rebasing / il posizionamento dei breakpoint. Lo snippet qui sotto lo corregge già stampando direttamente valori **`%p`**.

### `--jit` è utile per breakpoint alla prima istruzione

`--jit` rimuove l'accesso in esecuzione dal primo byte della shellcode e permette a Windows di sollevare una **access violation** quando il blob inizia a eseguirsi. Questo è utile quando vuoi che il **configured JIT debugger** (per esempio x64dbg) catturi il primo tentativo di esecuzione invece di correre manualmente per agganciarti. Dopo che il debugger si ferma, ripristina i diritti di esecuzione e continua.

Un flusso pratico con **x64dbg** è:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
I primi due comandi registrano x64dbg come debugger JIT, e `setpagerights` ripristina i diritti di esecuzione sulla regione stampata da BlobRunner dopo che il debugger intercetta l'access violation.

### Fai time-travel dello shellcode invece di eseguirlo live single-step

Un workflow recente molto pratico è registrare BlobRunner sotto **TTD** e poi ispezionare la trace in **Binary Ninja** / **WinDbg**. Questo è ottimo quando il blob si decritta da solo, risolve le API dinamicamente o esegue più stage di breve durata. Dalla **Binary Ninja 4.1**, il supporto TTD non è più solo di qualità beta: può gestire il reverse-debugging e semplificare direttamente da Binary Ninja il workflow **WinDbg / TTD**.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
La parte importante è **annotare l'indirizzo base allocato stampato da BlobRunner** e poi **rebase** della vista dello shellcode su quell'indirizzo prima di riprodurre il trace. Nota anche che Microsoft documenta la registrazione TTD come **invasive**: eseguila da un prompt **elevated**, aspettati un rallentamento evidente e mantieni breve la finestra di registrazione per evitare file di trace enormi.

### Se il blob ha bisogno di dati companion, usa invece un wrapper PE

Alcuni shellcode si aspettano che in memoria esista un **second blob**, un **mapped file** o qualche altro **structured content**. BlobRunner è volutamente minimale, quindi per questi casi un runner come **SCLauncher** può essere più comodo perché può:

- mettere in pausa prima dell'esecuzione,
- inserire un breakpoint `INT3`,
- caricare **additional content** in memoria,
- memory-map di quel contenuto extra, oppure
- avvolgere lo shellcode in un temporaneo **PE** per facilitarne l'analisi in tool che preferiscono eseguibili normali.

Esempio:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Per workflow complementari come **jmp2it**, emulazione di **Cutter**, o tracing dello shellcode basato su **scdbg**, consulta la [parent shellcode reversing page](README.md).

## Source code

Le uniche linee modificate dal [original code](https://github.com/OALabs/BlobRunner) sono le linee di stampa dei puntatori usate per evitare il troncamento degli indirizzi x64.
Per compilarlo basta solo **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e compilarlo**.
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
## Riferimenti

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
