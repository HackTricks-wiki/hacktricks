# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) debugging के लिए एक छोटा Windows **shellcode loader** है: यह RWX memory allocate करता है, blob को copy करता है, base address / entry point प्रिंट करता है और execution वहाँ transfer कर देता है। यह तब उपयोगी है जब sample **raw shellcode**, **malware से निकाला गया decrypted stage**, या ऐसा **position-independent blob** हो जिसमें PE header न हो।

नीचे दिया गया snippet मूल विचार को बनाए रखता है, लेकिन printed pointers के लिए **`%p`** का उपयोग करता है, ताकि debugger attach करते समय या अपने RE tool में blob को rebase करते समय x64 build addresses को truncate न करे।

## Build

मूल project को build करने का सबसे सरल तरीका **Visual Studio Developer Command Prompt** से है:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
आप code को एक छोटे Visual Studio / VS Code C project में भी paste करके वहाँ compile कर सकते हैं।

## उपयोग के उपयोगी पैटर्न
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
- **x86** में, BlobRunner रुकता है और फिर blob entry point पर direct jump करता है।
- **x64** में, यह एक **suspended thread** बनाता है, इसलिए execution resume करने से पहले आप thread start address पर break कर सकते हैं।
- `--offset` विशेष रूप से तब उपयोगी है जब dumped blob **decoder / unpacking stub** से शुरू होता है और आपको real entry point पहले से पता हो।

## Practical notes

### x64 labs में printed addresses ठीक करें

BlobRunner के पुराने code में `(int)(size_t)lpvBase` और `%08x` / `%016x` जैसे casts के माध्यम से addresses print किए जाते हैं। 64-bit workflows में इससे pointer का high half truncate हो सकता है और rebasing / breakpoint placement कठिन हो सकता है। नीचे दिया गया snippet सीधे **`%p`** values print करके इसे पहले ही ठीक करता है।

### First-instruction breakpoints के लिए `--jit` उपयोगी है

`--jit` shellcode के first byte से execute access हटा देता है और blob के execution शुरू करने पर Windows को **access violation** raise करने देता है। यह तब उपयोगी है जब आप चाहते हैं कि configured JIT debugger (उदाहरण के लिए x64dbg) manually attach करने की कोशिश करने के बजाय first execution attempt को catch करे। Debugger के break करने के बाद, execute rights restore करें और continue करें।

एक practical **x64dbg** flow है:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
पहले दो commands x64dbg को JIT debugger के रूप में register करते हैं, और `setpagerights` उस region पर execute rights को restore करता है जिसे debugger के access violation पकड़ने के बाद BlobRunner print करता है।

### shellcode को live single-stepping करने के बजाय time-travel करें

एक बहुत practical recent workflow BlobRunner को **TTD** के अंतर्गत record करना और फिर trace को **Binary Ninja** / **WinDbg** में inspect करना है। यह तब बहुत उपयोगी है जब blob खुद को decrypt करता है, APIs को dynamically resolve करता है, या कई short-lived stages execute करता है। **Binary Ninja 4.1** के बाद से, TTD support अब केवल beta quality तक सीमित नहीं है: यह reverse-debugging को drive कर सकता है और WinDbg / TTD workflow को सीधे Binary Ninja से सरल बना सकता है।<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
महत्वपूर्ण भाग यह है कि **BlobRunner द्वारा प्रिंट किए गए allocated base address को note करें** और trace को replay करने से पहले shellcode view को उस address पर **rebase** करें। यह भी ध्यान रखें कि Microsoft TTD recording को **invasive** के रूप में document करता है: इसे **elevated** prompt से run करें, noticeable slowdown की अपेक्षा रखें, और massive trace files से बचने के लिए recording window को छोटा रखें।

### यदि blob को companion data की आवश्यकता हो, तो इसके बजाय PE wrapper का उपयोग करें

कुछ shellcode को memory में मौजूद **दूसरे blob**, **mapped file**, या किसी अन्य **structured content** की आवश्यकता होती है। BlobRunner जानबूझकर minimal है, इसलिए इन मामलों में **SCLauncher** जैसे runner का उपयोग अधिक सुविधाजनक हो सकता है, क्योंकि यह कर सकता है:<sup>[[2]](#references)</sup>

- execution से पहले pause करना,
- `INT3` breakpoint insert करना,
- memory में **additional content** load करना,
- उस अतिरिक्त content को memory-map करना, या
- shellcode को आसान analysis के लिए एक अस्थायी **PE** के अंदर wrap करना, उन tools में जो normal executables को प्राथमिकता देते हैं।

उदाहरण:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
पूरक workflows जैसे **jmp2it**, **Cutter** emulation या **scdbg**-आधारित shellcode tracing के लिए [parent shellcode reversing page](README.md) देखें।

## Source code

[original code](https://github.com/OALabs/BlobRunner) से केवल pointer-printing वाली lines modified हैं, ताकि x64 address truncation से बचा जा सके।
इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएं, code को copy और paste करें और build करें**।
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

- [1] [Binary Ninja के साथ Shellcode की Time Travel Debugging](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [SCLauncher के साथ Shellcode का विश्लेषण](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
