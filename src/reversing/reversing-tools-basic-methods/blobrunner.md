# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) je mali Windows **shellcode loader za debugging**: alocira RWX memoriju, kopira blob, ispisuje baznu adresu / entry point, i prebacuje izvršavanje tamo. Ovo je korisno kada je sample **raw shellcode**, **decrypted stage extracted from malware**, ili **position-independent blob** koji nema PE header.

Iskaz ispod zadržava originalnu ideju, ali koristi **`%p` za ispisane pointers** tako da x64 build ne skraćuje adrese dok pokušavate da priključite debugger ili rebase-ujete blob u svom RE tool-u.

## Build

Najjednostavniji način da se originalni project izgradi je iz **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Možete takođe nalepiti kod u mali Visual Studio / VS Code C projekat i kompajlirati ga tamo.

## Korisni obrasci korišćenja
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
- U **x86**, BlobRunner pauzira, a zatim izvršava direktan jump na blob entry point.
- U **x64**, kreira **suspended thread**, tako da možete da postavite breakpoint na thread start address pre nego što nastavite izvršavanje.
- `--offset` je posebno koristan kada dumped blob počinje sa **decoder / unpacking stub** i već znate pravi entry point.

## Praktične napomene

### Ispravite ispisane adrese u x64 labovima

Stariji BlobRunner kod ispisuje adrese preko castova poput `(int)(size_t)lpvBase` i `%08x` / `%016x`. U 64-bit workflow-ovima ovo može da skrati gornju polovinu pointera i učini rebasing / breakpoint placement nezgodnim. Snippet ispod to već ispravlja tako što direktno ispisuje **`%p`** vrednosti.

### `--jit` je koristan za breakpoints na prvoj instrukciji

`--jit` uklanja execute access sa prvog bajta shellcode-a i dozvoljava Windows-u da prijavi **access violation** kada blob počne da se izvršava. Ovo je korisno kada želite da **configured JIT debugger** (na primer x64dbg) uhvati prvi pokušaj izvršavanja umesto da ručno žurite da se nakačite. Nakon što debugger break-uje, vratite execute rights i nastavite.

Praktičan **x64dbg** flow je:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Prve dve komande registruju x64dbg kao JIT debugger, a `setpagerights` vraća execute prava na region koji BlobRunner ispiše nakon što debugger uhvati access violation.

### Vratite shellcode kroz vreme umesto da ga single-stepujete uživo

Veoma praktičan recentan workflow je da se BlobRunner snimi pod **TTD** i zatim pregleda trace u **Binary Ninja** / **WinDbg**. Ovo je odlično kada blob sam sebe dekriptuje, dinamički rešava API-je, ili izvodi nekoliko kratkotrajnih faza. Od **Binary Ninja 4.1**, TTD support više nije samo beta kvaliteta: može da pokreće reverse-debugging i pojednostavi WinDbg / TTD workflow direktno iz Binary Ninja.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Važan deo je da **zabeležite dodeljenu baznu adresu koju ispisuje BlobRunner** i zatim **rebase**-ujete shellcode prikaz na tu adresu pre nego što ponovo pustite trace. Takođe imajte na umu da Microsoft dokumentuje TTD recording kao **invasive**: pokrećite ga iz **elevated** prompta, očekujte primetno usporenje i držite prozor snimanja kratak da biste izbegli ogromne trace fajlove.

### Ako blobu trebaju prateći podaci, umesto toga koristite PE wrapper

Neki shellcode očekuju da postoji **second blob**, **mapped file**, ili neki drugi **structured content** u memoriji. BlobRunner je namerno minimalan, pa za ove slučajeve runner kao što je **SCLauncher** može biti praktičniji zato što može da:

- pauzira pre izvršavanja,
- ubaci **INT3** breakpoint,
- učita **additional content** u memoriju,
- memory-map-uje taj dodatni content, ili
- upakuje shellcode unutar privremenog **PE** radi lakše analize u alatima koji više vole normalne executables.

Primer:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Za dopunske workflow-ove kao što su **jmp2it**, **Cutter** emulacija, ili praćenje shellcode-a bazirano na **scdbg**, pogledaj [parent shellcode reversing page](README.md).

## Source code

Jedine izmenjene linije iz [original code](https://github.com/OALabs/BlobRunner) su linije za ispis pokazivača, koje se koriste da bi se izbeglo truncation x64 adresa.
Da bi ga kompajlirao, samo **napravi C/C++ project u Visual Studio Code, copy and paste code i build it**.
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
## Reference

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
