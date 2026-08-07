# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) je mali Windows **shellcode loader za debugging**: alocira RWX memoriju, kopira blob, ispisuje baznu adresu / entry point i tamo preusmerava izvršavanje. Ovo je korisno kada je uzorak **raw shellcode**, **decrypted stage extracted from malware** ili **position-independent blob** koji nema PE header.

Isječak u nastavku zadržava originalnu ideju, ali koristi **`%p` za ispis pointera** kako x64 build ne bi skratio adrese dok pokušavate da prikačite debugger ili rebazirate blob u svom RE alatu.

## Build

Najjednostavniji način za build originalnog projekta jeste iz **Visual Studio Developer Command Prompt** okruženja:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Možete takođe nalepiti code u mali Visual Studio / VS Code C project i tamo ga kompajlirati.

## Korisni obrasci upotrebe
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
- U **x86**, BlobRunner pravi pauzu, a zatim vrši direktan skok na početnu tačku blob-a.
- U **x64**, kreira **suspended thread**, tako da možete postaviti prekid na početnu adresu thread-a pre nego što nastavite izvršavanje.
- `--offset` je naročito koristan kada dump-ovani blob počinje sa **decoder / unpacking stub** delom, a već znate stvarnu početnu tačku.

## Praktične napomene

### Ispravite ispisane adrese u x64 laboratorijama

Stariji BlobRunner kod ispisuje adrese pomoću cast-ova kao što su `(int)(size_t)lpvBase` i `%08x` / `%016x`. U 64-bitnim workflow-ima to može skratiti višu polovinu pointer-a i otežati rebase / postavljanje breakpoint-a. Ispravka u isečku ispod već rešava ovaj problem direktnim ispisivanjem vrednosti pomoću **`%p`**.

### `--jit` je koristan za breakpoint-e na prvoj instrukciji

`--jit` uklanja execute pristup sa prvog bajta shellcode-a i omogućava Windows-u da podigne **access violation** kada blob počne sa izvršavanjem. Ovo je korisno kada želite da **konfigurisani JIT debugger** (na primer x64dbg) uhvati prvi pokušaj izvršavanja, umesto da ručno pokušavate da se priključite na vreme. Nakon što debugger zaustavi izvršavanje, vratite execute prava i nastavite.

Praktičan **x64dbg** tok je:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Prve dve komande registruju x64dbg kao JIT debugger, a `setpagerights` vraća prava izvršavanja na region koji BlobRunner ispisuje nakon što debugger uhvati access violation.

### Vremenski pratite shellcode umesto da ga pratite korak po korak uživo

Veoma praktičan noviji workflow jeste snimanje BlobRunner-a pod **TTD**, a zatim pregledanje trace-a u alatima **Binary Ninja** / **WinDbg**. Ovo je odlično kada blob sam sebe dešifruje, dinamički razrešava API-je ili izvršava nekoliko kratkotrajnih faza. Od verzije **Binary Ninja 4.1**, TTD podrška više nije samo beta kvaliteta: može da pokreće reverse-debugging i direktno iz alata Binary Ninja pojednostavi WinDbg / TTD workflow.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Važno je **zabeležiti dodeljenu osnovnu adresu koju BlobRunner ispisuje**, a zatim **rebase-ovati** prikaz shellcode-a na tu adresu pre ponovnog reprodukovanja trace-a. Takođe imajte na umu da Microsoft dokumentuje TTD snimanje kao **invasive**: pokrenite ga iz **elevated** prompt-a, očekujte primetno usporavanje i neka period snimanja bude kratak kako biste izbegli ogromne trace datoteke.<sup>[[1]](#references)</sup>

### Ako blob zahteva prateće podatke, koristite PE wrapper

Neki shellcode očekuje da u memoriji postoji **drugi blob**, **mapirana datoteka** ili neki drugi **strukturirani sadržaj**. BlobRunner je namerno minimalan, pa u tim slučajevima runner kao što je **SCLauncher** može biti praktičniji jer može da:<sup>[[2]](#references)</sup>

- pauzira pre izvršavanja,
- umetne `INT3` breakpoint,
- učita **dodatni sadržaj** u memoriju,
- memory-map-uje taj dodatni sadržaj ili
- obuhvati shellcode privremenim **PE** fajlom radi lakše analize u alatima koji preferiraju uobičajene izvršne datoteke.

Primer:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Za dopunske workflows kao što su **jmp2it**, emulacija pomoću alata **Cutter** ili praćenje shellcode-a zasnovano na alatu **scdbg**, pogledajte [parent shellcode reversing page](README.md).

## Izvorni kod

Jedine izmenjene linije u odnosu na [originalni kod](https://github.com/OALabs/BlobRunner) jesu linije za ispis pokazivača, koje se koriste za izbegavanje skraćivanja x64 adresa.  
Da biste ga kompajlirali, samo **kreirajte C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, a zatim ga izgradite**.
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

- [1] [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Analiziranje Shellcode-a pomoću SCLauncher-a](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)

{{#include ../../banners/hacktricks-training.md}}
