# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) एक छोटा Windows **shellcode loader for debugging** है: यह RWX memory allocate करता है, blob को copy करता है, base address / entry point print करता है, और execution को वहाँ transfer करता है। यह तब useful है जब sample **raw shellcode** हो, **malware से extracted decrypted stage** हो, या एक **position-independent blob** हो जिसमें PE header न हो।

नीचे दिया गया snippet original idea को बनाए रखता है, लेकिन printed pointers के लिए **`%p`** का use करता है, ताकि x64 build addresses truncate न करे, जबकि आप debugger attach करने या अपने RE tool में blob rebase करने की कोशिश कर रहे हों।

## Build

Original project को build करने का सबसे simple तरीका एक **Visual Studio Developer Command Prompt** से है:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
आप code को एक छोटे Visual Studio / VS Code C project में भी paste कर सकते हैं और उसे वहाँ compile कर सकते हैं।

## उपयोगी usage patterns
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
- **x86** में, BlobRunner pause करता है और फिर blob entry point पर direct jump करता है।
- **x64** में, यह एक **suspended thread** बनाता है, इसलिए execution resume करने से पहले आप thread start address पर break कर सकते हैं।
- `--offset` खास तौर पर तब useful होता है जब dumped blob की शुरुआत **decoder / unpacking stub** से होती है और आपको पहले से real entry point पता हो।

## Practical notes

### x64 labs में printed addresses ठीक करें

पुराना BlobRunner code addresses को `(int)(size_t)lpvBase` और `%08x` / `%016x` जैसी casts के जरिए print करता है। 64-bit workflows में इससे pointer का high half truncate हो सकता है और rebasing / breakpoint placement annoying हो जाती है। नीचे दिया गया snippet पहले ही **`%p`** values को सीधे print करके इसे ठीक करता है।

### `--jit` first-instruction breakpoints के लिए useful है

`--jit` shellcode के पहले byte से execute access हटा देता है और Windows को blob execute होना शुरू करते ही एक **access violation** raise करने देता है। यह तब useful होता है जब आप चाहते हैं कि **configured JIT debugger** (जैसे x64dbg) manually attach करने की race करने के बजाय first execution attempt को catch करे। debugger के break करने के बाद, execute rights restore करें और continue करें।

एक practical **x64dbg** flow है:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
पहले दो commands x64dbg को JIT debugger के रूप में register करते हैं, और `setpagerights` debugger द्वारा access violation पकड़ने के बाद BlobRunner द्वारा printed region पर execute rights restore करता है।

### shellcode को live single-stepping करने के बजाय time-travel करें

एक बहुत practical recent workflow है BlobRunner को **TTD** under record करना और फिर trace को **Binary Ninja** / **WinDbg** में inspect करना। यह तब बहुत अच्छा है जब blob खुद को decrypt करता है, APIs को dynamically resolve करता है, या कई short-lived stages perform करता है। **Binary Ninja 4.1** के since, TTD support अब सिर्फ beta quality नहीं है: यह reverse-debugging drive कर सकता है और Binary Ninja से सीधे WinDbg / TTD workflow को simplify कर सकता है।
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
महत्वपूर्ण हिस्सा यह है कि **BlobRunner द्वारा प्रिंट किए गए allocated base address को नोट करें** और फिर trace को replay करने से पहले shellcode view को उस address पर **rebase** करें। यह भी ध्यान दें कि Microsoft TTD recording को **invasive** के रूप में दस्तावेज़ करता है: इसे **elevated** prompt से चलाएँ, noticeable slowdown की उम्मीद रखें, और massive trace files से बचने के लिए recording window को छोटा रखें।

### If the blob needs companion data, use a PE wrapper instead

कुछ shellcode को memory में मौजूद **second blob**, **mapped file**, या कोई अन्य **structured content** चाहिए होता है। BlobRunner intentionally minimal है, इसलिए ऐसे मामलों में **SCLauncher** जैसा runner अधिक convenient हो सकता है क्योंकि यह:

- execution से पहले pause कर सकता है,
- एक `INT3` breakpoint insert कर सकता है,
- memory में **additional content** load कर सकता है,
- उस extra content को memory-map कर सकता है, या
- shellcode को easier analysis के लिए temporary **PE** के अंदर wrap कर सकता है, खासकर उन tools में जो normal executables को prefer करती हैं।

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
For complementary workflows such as **jmp2it**, **Cutter** emulation, or **scdbg**-based shellcode tracing, check the [parent shellcode reversing page](README.md).

## Source code

[original code](https://github.com/OALabs/BlobRunner) से केवल बदली गई lines pointer-printing lines हैं, जिनका उपयोग x64 address truncation से बचने के लिए किया गया है।
इसे compile करने के लिए बस **Visual Studio Code में एक C/C++ project बनाएं, code को copy और paste करें, और build करें**।
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
## संदर्भ

- [Binary Ninja के साथ Shellcode का Time Travel Debugging](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [SCLauncher के साथ Shellcode का विश्लेषण](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
