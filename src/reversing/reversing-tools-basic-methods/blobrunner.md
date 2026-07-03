# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ni **shellcode loader ya debugging** ndogo ya Windows: inatenga kumbukumbu ya RWX, inanakili blob, inaonyesha anwani ya msingi / entry point, na kuhamisha utekelezaji huko. Hii ni muhimu wakati sampuli ni **raw shellcode**, **decrypted stage iliyotolewa kutoka malware**, au **position-independent blob** ambayo haina PE header.

Sehemu ya chini inaweka wazo la asili, lakini hutumia **`%p` kwa pointers zilizochapishwa** ili build ya x64 isikate anwani wakati unajaribu kuattach debugger au kurebase blob kwenye RE tool yako.

## Build

Njia rahisi zaidi ya kubuild project ya awali ni kutoka kwa **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Unaweza pia kubandika code kwenye project ndogo ya Visual Studio / VS Code C na ku-compile huko.

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
- Katika **x86**, BlobRunner husitisha kisha hufanya **direct jump** kwenda kwenye blob entry point.
- Katika **x64**, huunda **suspended thread**, hivyo unaweza kuweka break kwenye thread start address kabla ya kuendelea na execution.
- `--offset` ni muhimu hasa wakati dumped blob inaanza na **decoder / unpacking stub** na tayari unajua real entry point.

## Practical notes

### Rekebisha addresses zilizochapishwa katika x64 labs

Msimbo wa zamani wa BlobRunner huchapisha addresses kupitia casts kama `(int)(size_t)lpvBase` na `%08x` / `%016x`. Katika 64-bit workflows hii inaweza kukata sehemu ya juu ya pointer na kufanya rebasing / breakpoint placement iwe ya kero. Snippet iliyo hapa chini tayari inarekebisha hilo kwa kuchapisha **`%p`** values moja kwa moja.

### `--jit` ni muhimu kwa first-instruction breakpoints

`--jit` huondoa execute access kutoka kwenye byte ya kwanza ya shellcode na huacha Windows itoe **access violation** wakati blob inaanza executing. Hii ni muhimu wakati unataka **configured JIT debugger** (kwa mfano x64dbg) ishike jaribio la kwanza la execution badala ya kuattach manually kwa mbio. Baada ya debugger ku-break, rejesha execute rights na endelea.

Mtiririko wa vitendo wa **x64dbg** ni:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Amri mbili za kwanza husajili x64dbg kama JIT debugger, na `setpagerights` hurejesha execute rights kwenye eneo lililochapishwa na BlobRunner baada ya debugger kukamata access violation.

### Time-travel the shellcode badala ya kui-step moja kwa moja live

Workflow ya hivi karibuni na ya vitendo sana ni kurekodi BlobRunner chini ya **TTD** kisha kukagua trace kwenye **Binary Ninja** / **WinDbg**. Hii ni nzuri sana wakati blob inajifungua yenyewe kwa decrypt, inaresolve APIs dynamically, au inatekeleza stages kadhaa za muda mfupi. Tangu **Binary Ninja 4.1**, usaidizi wa TTD si tena wa kiwango cha beta tu: unaweza kuendesha reverse-debugging na kurahisisha workflow ya WinDbg / TTD moja kwa moja kutoka Binary Ninja.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Jambo muhimu ni **kuandika anwani ya msingi iliyotengwa iliyochapishwa na BlobRunner** kisha **kurebase** shellcode view hadi kwenye anwani hiyo kabla ya kucheza tena trace. Pia kumbuka kuwa Microsoft inaandika TTD recording kama **invasive**: iendeshe kutoka kwenye prompt ya **elevated**, tarajia kupungua kwa kasi kunakoonekana, na fanya recording window iwe fupi ili kuepuka trace files kubwa sana.

### Ikiwa blob inahitaji companion data, tumia PE wrapper badala yake

Baadhi ya shellcode hutegemea **second blob**, **mapped file**, au **structured content** nyingine kuwepo kwenye memory. BlobRunner ni ya minimal kimakusudi, hivyo kwa kesi hizi runner kama **SCLauncher** inaweza kuwa rahisi zaidi kwa sababu inaweza:

- kusitisha kabla ya execution,
- kuingiza **INT3** breakpoint,
- kupakia **additional content** kwenye memory,
- ku-memory-map content hiyo ya ziada, au
- kufunga shellcode ndani ya temporary **PE** kwa uchambuzi rahisi zaidi kwenye tools zinazopendelea normal executables.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Kwa workflows za ziada kama **jmp2it**, emulation ya **Cutter**, au tracing ya shellcode inayotegemea **scdbg**, angalia [parent shellcode reversing page](README.md).

## Source code

Mistari pekee iliyobadilishwa kutoka kwenye [original code](https://github.com/OALabs/BlobRunner) ni mistari ya kuchapisha pointer inayotumika kuzuia truncation ya anwani ya x64.
Ili kui-compile, tu **unda C/C++ project katika Visual Studio Code, nakili na bandika code, kisha build it**.
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
## Marejeleo

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
