# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) è un piccolo **shellcode loader per il debugging su Windows**: alloca memoria RWX, copia il blob, stampa l'indirizzo base / entry point e trasferisce lì l'esecuzione. È utile quando il sample è **raw shellcode**, uno **stage decrittografato estratto da malware** o un **blob position-independent** che non dispone di un header PE.

Lo snippet seguente mantiene l'idea originale, ma usa **`%p` per i puntatori stampati**, così la build x64 non tronca gli indirizzi mentre si cerca di collegare un debugger o di effettuare il rebase del blob nel proprio tool di RE.

## Build

Il modo più semplice per eseguire la build del progetto originale è usare un **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Puoi anche incollare il codice in un piccolo progetto C di Visual Studio / VS Code e compilarlo lì.

## Pattern di utilizzo utili
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
- In **x86**, BlobRunner si mette in pausa e poi esegue un direct jump verso l’entry point del blob.
- In **x64**, crea un **suspended thread**, consentendoti di impostare un breakpoint sull’indirizzo di avvio del thread prima di riprendere l’esecuzione.
- `--offset` è particolarmente utile quando il blob dumpato inizia con uno **stub di decoding / unpacking** e conosci già il vero entry point.

## Note pratiche

### Correggere gli indirizzi stampati nei lab x64

Il vecchio codice di BlobRunner stampa gli indirizzi tramite cast come `(int)(size_t)lpvBase` e `%08x` / `%016x`. Nei workflow a 64 bit, questo può troncare la metà alta del puntatore e rendere scomodo il rebasing / il posizionamento dei breakpoint. Lo snippet seguente risolve già il problema stampando direttamente valori **`%p`**.

### `--jit` è utile per i breakpoint sulla prima istruzione

`--jit` rimuove i permessi di esecuzione dal primo byte dello shellcode e consente a Windows di generare una **access violation** quando il blob inizia l’esecuzione. È utile quando vuoi che il **JIT debugger configurato** (ad esempio x64dbg) intercetti il primo tentativo di esecuzione invece di dover effettuare manualmente il attach. Dopo che il debugger si è interrotto, ripristina i permessi di esecuzione e continua.

Un flusso pratico in **x64dbg** è:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
I primi due comandi registrano x64dbg come debugger JIT, mentre `setpagerights` ripristina i diritti di esecuzione sulla regione stampata da BlobRunner dopo che il debugger intercetta l'access violation.

### Eseguire il time-travel dello shellcode invece di eseguirlo live con il single-stepping

Un workflow recente molto pratico consiste nel registrare BlobRunner sotto **TTD** e quindi ispezionare la trace in **Binary Ninja** / **WinDbg**. È particolarmente utile quando il blob si decritta da solo, risolve dinamicamente le API o esegue diverse fasi di breve durata. A partire da **Binary Ninja 4.1**, il supporto a TTD non è più soltanto di qualità beta: può eseguire il reverse-debugging e semplificare direttamente da Binary Ninja il workflow WinDbg / TTD.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
La parte importante è **annotare l'indirizzo di base allocato stampato da BlobRunner** e quindi **ribasing** la vista dello shellcode a quell'indirizzo prima di riprodurre la trace. Si noti inoltre che Microsoft documenta la registrazione TTD come **invasiva**: eseguirla da un prompt **elevato**, prevedere un rallentamento significativo e mantenere breve la finestra di registrazione per evitare file di trace enormi.

### Se il blob necessita di dati complementari, usare un wrapper PE

Alcuni shellcode si aspettano che in memoria siano presenti un **secondo blob**, un **file mappato** o altro **contenuto strutturato**. BlobRunner è intenzionalmente minimale, quindi in questi casi un runner come **SCLauncher** può essere più comodo perché può:<sup>[[2]](#references)</sup>

- mettere in pausa prima dell'esecuzione,
- inserire un breakpoint `INT3`,
- caricare **contenuto aggiuntivo** in memoria,
- mappare in memoria quel contenuto aggiuntivo, oppure
- racchiudere lo shellcode in un **PE** temporaneo per facilitare l'analisi negli strumenti che preferiscono eseguibili normali.

Esempio:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Per workflow complementari come **jmp2it**, l’emulazione con **Cutter** o il tracing dello shellcode basato su **scdbg**, consulta la [pagina principale sul reversing dello shellcode](README.md).

## Codice sorgente

Le uniche righe modificate rispetto al [codice originale](https://github.com/OALabs/BlobRunner) sono quelle per la stampa dei puntatori, utilizzate per evitare il troncamento degli indirizzi x64.  
Per compilarlo, è sufficiente **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e compilarlo**.
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

- [1] [Time Travel Debugging Shellcode con Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Analisi di Shellcode con SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
