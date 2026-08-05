# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) je mali Windows **shellcode loader za debugging**: alocira RWX memoriju, kopira blob, ispisuje base address / entry point i prebacuje izvršavanje na tu adresu. Ovo je korisno kada je uzorak **raw shellcode**, **dekriptovana faza izdvojena iz malware-a** ili **position-independent blob** koji nema PE header.

Ispod je isečak koji zadržava originalnu ideju, ali koristi **`%p` za ispis pointera**, tako da x64 build ne skraćuje adrese dok pokušavate da attach-ujete debugger ili promenite bazu blob-a u svom RE alatu.

## Build

Najjednostavniji način da build-ujete originalni projekat jeste iz **Visual Studio Developer Command Prompt** okruženja:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Kod takođe možete nalepiti u mali Visual Studio / VS Code C projekat i tamo ga kompajlirati.

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
- U **x86**, BlobRunner pravi pauzu, a zatim vrši direktan skok na ulaznu tačku blob-a.
- U **x64**, kreira **suspended thread**, tako da možete postaviti breakpoint na adresu početka thread-a pre nastavljanja izvršavanja.
- `--offset` je naročito koristan kada dumped blob počinje sa **decoder / unpacking stub**-om, a već znate stvarnu ulaznu tačku.

## Praktične napomene

### Ispravite ispisane adrese u x64 labovima

Stariji BlobRunner kod ispisuje adrese pomoću cast-ova kao što su `(int)(size_t)lpvBase` i `%08x` / `%016x`. U 64-bitnim workflow-ima to može skratiti gornju polovinu pointer-a i otežati rebasing / postavljanje breakpoint-a. Isječak ispod to već ispravlja direktnim ispisom **`%p`** vrednosti.

### `--jit` je koristan za breakpoint-e na prvoj instrukciji

`--jit` uklanja execute access sa prvog bajta shellcode-a i omogućava Windows-u da podigne **access violation** kada blob počne da se izvršava. Ovo je korisno kada želite da **konfigurisani JIT debugger** (na primer x64dbg) uhvati prvi pokušaj izvršavanja, umesto da ručno pokušavate da se nakačite na vreme. Nakon što debugger napravi prekid, vratite execute prava i nastavite izvršavanje.

Praktičan **x64dbg** tok je:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Prve dve komande registruju x64dbg kao JIT debugger, a `setpagerights` vraća prava izvršavanja na region koji BlobRunner ispisuje nakon što debugger uhvati access violation.

### Vremenski pratite shellcode umesto da ga pratite korak po korak uživo

Veoma praktičan noviji workflow jeste snimanje BlobRunner-a pod **TTD**, a zatim pregledanje trace-a u **Binary Ninja** / **WinDbg**. Ovo je odlično kada blob sam dešifruje svoj sadržaj, dinamički razrešava API-je ili izvršava nekoliko kratkotrajnih faza. Od verzije **Binary Ninja 4.1**, podrška za TTD više nije samo beta kvaliteta: ona može da pokreće reverse-debugging i direktno iz Binary Ninja pojednostavi WinDbg / TTD workflow.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Važno je da **zabeležite dodeljenu osnovnu adresu koju BlobRunner ispisuje** i zatim izvršite **rebase** prikaza shellcode-a na tu adresu pre ponovnog reprodukovanja trace-a. Takođe imajte na umu da Microsoft TTD recording dokumentuje kao **invasive**: pokrenite ga iz **elevated** prompt-a, očekujte primetno usporavanje i ograničite trajanje recording-a kako biste izbegli ogromne trace fajlove.

### Ako blob zahteva prateće podatke, koristite PE wrapper

Neki shellcode očekuje da u memoriji postoji **drugi blob**, **mapped file** ili neki drugi **structured content**. BlobRunner je namerno minimalan, pa za ove slučajeve runner kao što je **SCLauncher** može biti praktičniji jer može da:<sup>[[2]](#references)</sup>

- pauzira pre izvršavanja,
- ubaci `INT3` breakpoint,
- učita **additional content** u memoriju,
- memory-map-uje taj dodatni sadržaj ili
- obmota shellcode unutar privremenog **PE** fajla radi lakše analize u alatima koji preferiraju normalne executable fajlove.

Primer:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Za dopunske workflow-e kao što su **jmp2it**, emulacija pomoću alata **Cutter** ili praćenje shellcode-a zasnovano na alatu **scdbg**, pogledajte [matičnu stranicu za reverse engineering shellcode-a](README.md).

## Izvorni kod

Jedine izmenjene linije u odnosu na [originalni kod](https://github.com/OALabs/BlobRunner) jesu linije za ispis pokazivača, koje se koriste za izbegavanje skraćivanja x64 adresa.  
Da biste ga kompajlirali, samo **kreirajte C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i izgradite ga**.
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

- [1] [Debugging Shellcode-a pomoću Time Travel Debugging-a u alatu Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Analiza Shellcode-a pomoću alata SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
