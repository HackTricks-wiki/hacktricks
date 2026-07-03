# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) είναι ένας μικρός Windows **shellcode loader for debugging**: δεσμεύει μνήμη RWX, αντιγράφει το blob, εκτυπώνει το base address / entry point, και μεταφέρει εκεί την εκτέλεση. Αυτό είναι χρήσιμο όταν το sample είναι **raw shellcode**, ένα **decrypted stage extracted from malware**, ή ένα **position-independent blob** που δεν έχει PE header.

Το παρακάτω snippet κρατά την αρχική ιδέα, αλλά χρησιμοποιεί **`%p` for printed pointers** ώστε το x64 build να μην περικόπτει addresses ενώ προσπαθείς να attach έναν debugger ή να rebase το blob στο RE tool σου.

## Build

Ο πιο απλός τρόπος να κάνεις build το original project είναι από ένα **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Μπορείς επίσης να επικολλήσεις τον κώδικα σε ένα μικρό Visual Studio / VS Code C project και να το κάνεις compile εκεί.

## Χρήσιμα patterns χρήσης
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
- Στο **x86**, το BlobRunner κάνει παύση και μετά εκτελεί ένα direct jump στο blob entry point.
- Στο **x64**, δημιουργεί ένα **suspended thread**, ώστε να μπορείς να βάλεις breakpoint στο thread start address πριν συνεχιστεί η εκτέλεση.
- Το `--offset` είναι ιδιαίτερα χρήσιμο όταν το dumped blob ξεκινά με ένα **decoder / unpacking stub** και ήδη ξέρεις το πραγματικό entry point.

## Practical notes

### Fix the printed addresses in x64 labs

Παλιότερος κώδικας του BlobRunner εκτυπώνει addresses μέσω casts όπως `(int)(size_t)lpvBase` και `%08x` / `%016x`. Σε 64-bit workflows αυτό μπορεί να περικόψει το high half του pointer και να κάνει το rebasing / breakpoint placement ενοχλητικό. Το παρακάτω snippet το διορθώνει ήδη, εκτυπώνοντας απευθείας τιμές **`%p`**.

### `--jit` is useful for first-instruction breakpoints

Το `--jit` αφαιρεί execute access από το πρώτο byte του shellcode και αφήνει τα Windows να κάνουν raise ένα **access violation** όταν το blob αρχίσει να εκτελείται. Αυτό είναι χρήσιμο όταν θέλεις ο **configured JIT debugger** (για παράδειγμα x64dbg) να πιάσει την πρώτη απόπειρα εκτέλεσης αντί να τρέχεις χειροκίνητα να συνδεθείς. Αφού ο debugger κάνει break, επανέφερε τα execute rights και συνέχισε.

Ένα πρακτικό flow στο **x64dbg** είναι:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Οι δύο πρώτες εντολές καταχωρούν το x64dbg ως το JIT debugger, και το `setpagerights` επαναφέρει τα δικαιώματα εκτέλεσης στην περιοχή που εκτυπώνει το BlobRunner αφού ο debugger συλλάβει το access violation.

### Time-travel the shellcode instead of single-stepping it live

Ένα πολύ πρακτικό πρόσφατο workflow είναι να καταγράψετε το BlobRunner υπό **TTD** και μετά να επιθεωρήσετε το trace στο **Binary Ninja** / **WinDbg**. Αυτό είναι εξαιρετικό όταν το blob αποκρυπτογραφεί τον εαυτό του, επιλύει APIs δυναμικά ή εκτελεί αρκετά σύντομα stages. Από το **Binary Ninja 4.1**, η υποστήριξη TTD δεν είναι πλέον μόνο beta quality: μπορεί να οδηγήσει reverse-debugging και να απλοποιήσει το WinDbg / TTD workflow απευθείας από το Binary Ninja.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Το σημαντικό είναι να **σημειώσετε τη διεύθυνση βάσης που εκτυπώνει το BlobRunner** και μετά να κάνετε **rebase** το view του shellcode σε αυτή τη διεύθυνση πριν ξαναπαίξετε το trace. Σημειώστε επίσης ότι η Microsoft τεκμηριώνει την καταγραφή TTD ως **invasive**: εκτελέστε την από ένα **elevated** prompt, περιμένετε αισθητή επιβράδυνση και κρατήστε το παράθυρο καταγραφής μικρό για να αποφύγετε τεράστια trace files.

### Αν το blob χρειάζεται companion data, χρησιμοποιήστε αντί αυτού ένα PE wrapper

Κάποιο shellcode περιμένει να υπάρχει στη μνήμη ένα **second blob**, ένα **mapped file** ή κάποιο άλλο **structured content**. Το BlobRunner είναι σκόπιμα minimal, οπότε για αυτές τις περιπτώσεις ένας runner όπως ο **SCLauncher** μπορεί να είναι πιο βολικός επειδή μπορεί να:

- παύσει πριν από την εκτέλεση,
- εισαγάγει ένα **INT3** breakpoint,
- φορτώσει **additional content** στη μνήμη,
- κάνει memory-map αυτό το πρόσθετο content, ή
- τυλίξει το shellcode μέσα σε ένα προσωρινό **PE** για ευκολότερη ανάλυση σε tools που προτιμούν κανονικά executables.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Για συμπληρωματικά workflows όπως **jmp2it**, emulation του **Cutter**, ή shellcode tracing με βάση το **scdbg**, δες τη [parent shellcode reversing page](README.md).

## Source code

Οι μόνες τροποποιημένες γραμμές από τον [original code](https://github.com/OALabs/BlobRunner) είναι οι γραμμές εκτύπωσης pointer που χρησιμοποιούνται για να αποφευχθεί το x64 address truncation.
Για να το κάνεις compile, απλώς **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.
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
## Αναφορές

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
