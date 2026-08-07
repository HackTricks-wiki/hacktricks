# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) είναι ένα μικρό Windows **shellcode loader για debugging**: δεσμεύει μνήμη RWX, αντιγράφει το blob, εμφανίζει τη base address / entry point και μεταφέρει εκεί την εκτέλεση. Είναι χρήσιμο όταν το δείγμα είναι **raw shellcode**, ένα **decrypted stage extracted από malware** ή ένα **position-independent blob** που δεν διαθέτει PE header.

Το παρακάτω snippet διατηρεί την αρχική ιδέα, αλλά χρησιμοποιεί **`%p` για την εκτύπωση pointers**, ώστε το x64 build να μην περικόπτει τις διευθύνσεις ενώ προσπαθείτε να συνδεθείτε με debugger ή να κάνετε rebase το blob στο RE tool σας.

## Build

Ο απλούστερος τρόπος για να κάνετε build το αρχικό project είναι από ένα **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Μπορείτε επίσης να επικολλήσετε τον κώδικα σε ένα μικρό C project του Visual Studio / VS Code και να τον κάνετε compile εκεί.

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
- Στο **x86**, το BlobRunner κάνει pause και στη συνέχεια εκτελεί direct jump στο entry point του blob.
- Στο **x64**, δημιουργεί ένα **suspended thread**, ώστε να μπορείτε να κάνετε break στη διεύθυνση εκκίνησης του thread πριν συνεχίσετε την εκτέλεση.
- Το `--offset` είναι ιδιαίτερα χρήσιμο όταν το dumped blob ξεκινά με ένα **decoder / unpacking stub** και γνωρίζετε ήδη το πραγματικό entry point.

## Πρακτικές σημειώσεις

### Διόρθωση των εκτυπωμένων διευθύνσεων σε x64 labs

Ο παλαιότερος κώδικας του BlobRunner εκτυπώνει διευθύνσεις μέσω casts όπως `(int)(size_t)lpvBase` και `%08x` / `%016x`. Σε 64-bit workflows, αυτό μπορεί να περικόψει το υψηλό μισό του pointer και να κάνει το rebasing / breakpoint placement ενοχλητικό. Το παρακάτω snippet το διορθώνει ήδη, εκτυπώνοντας απευθείας τιμές **`%p`**.

### Το `--jit` είναι χρήσιμο για breakpoints στην πρώτη instruction

Το `--jit` αφαιρεί την execute access από το πρώτο byte του shellcode και επιτρέπει στα Windows να προκαλέσουν ένα **access violation** όταν το blob ξεκινήσει την εκτέλεση. Αυτό είναι χρήσιμο όταν θέλετε ο **configured JIT debugger** (για παράδειγμα το x64dbg) να εντοπίσει την πρώτη απόπειρα εκτέλεσης αντί να προσπαθείτε χειροκίνητα να κάνετε attach εγκαίρως. Αφού ο debugger κάνει break, επαναφέρετε τα execute rights και συνεχίστε.

Μια πρακτική ροή στο **x64dbg** είναι:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Οι δύο πρώτες εντολές καταχωρίζουν το x64dbg ως JIT debugger, ενώ η `setpagerights` επαναφέρει τα δικαιώματα εκτέλεσης στην περιοχή που εκτυπώνει το BlobRunner αφού ο debugger εντοπίσει την access violation.

### Time-travel του shellcode αντί για single-stepping σε πραγματικό χρόνο

Μια πολύ πρακτική σύγχρονη ροή εργασίας είναι να καταγράψετε το BlobRunner υπό **TTD** και, στη συνέχεια, να επιθεωρήσετε το trace στο **Binary Ninja** / **WinDbg**. Αυτό είναι εξαιρετικά χρήσιμο όταν το blob αποκρυπτογραφεί τον εαυτό του, επιλύει δυναμικά APIs ή εκτελεί αρκετά σύντομα στάδια. Από το **Binary Ninja 4.1**, η υποστήριξη TTD δεν είναι πλέον απλώς beta quality: μπορεί να εκτελεί reverse-debugging και να απλοποιεί απευθείας τη ροή εργασίας WinDbg / TTD μέσα από το Binary Ninja.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Το σημαντικό είναι να **σημειώσετε τη base address που έχει εκχωρηθεί και εκτυπωθεί από το BlobRunner** και, στη συνέχεια, να κάνετε **rebase** στην προβολή του shellcode σε αυτήν τη διεύθυνση πριν αναπαράγετε το trace. Σημειώστε επίσης ότι η Microsoft τεκμηριώνει την εγγραφή TTD ως **invasive**: εκτελέστε την από ένα **elevated** prompt, αναμένετε αισθητή επιβράδυνση και διατηρήστε σύντομο το παράθυρο εγγραφής, ώστε να αποφύγετε τεράστια αρχεία trace.<sup>[[1]](#references)</sup>

### Αν το blob χρειάζεται συνοδευτικά δεδομένα, χρησιμοποιήστε ένα PE wrapper

Ορισμένα shellcode αναμένουν να υπάρχει στη μνήμη ένα **δεύτερο blob**, ένα **mapped file** ή άλλο **structured content**. Το BlobRunner είναι σκόπιμα minimal, επομένως σε αυτές τις περιπτώσεις ένα runner όπως το **SCLauncher** μπορεί να είναι πιο πρακτικό, επειδή μπορεί να:<sup>[[2]](#references)</sup>

- κάνει pause πριν από την εκτέλεση,
- εισαγάγει ένα `INT3` breakpoint,
- φορτώσει **additional content** στη μνήμη,
- κάνει memory-map σε αυτό το επιπλέον περιεχόμενο ή
- περιτυλίξει το shellcode μέσα σε ένα προσωρινό **PE**, για ευκολότερη ανάλυση σε tools που προτιμούν κανονικά executables.

Παράδειγμα:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Για συμπληρωματικά workflows όπως τα **jmp2it**, το emulation του **Cutter** ή το shellcode tracing με βάση το **scdbg**, ανατρέξτε στη [γονική σελίδα shellcode reversing](README.md).

## Source code

Οι μόνες τροποποιημένες γραμμές από τον [original code](https://github.com/OALabs/BlobRunner) είναι οι γραμμές εκτύπωσης pointers, που χρησιμοποιούνται για την αποφυγή truncation διευθύνσεων x64.  
Για να το κάνετε compile, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.
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

- [1] [Αποσφαλμάτωση Shellcode με Time Travel με το Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Ανάλυση Shellcode με SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)

{{#include ../../banners/hacktricks-training.md}}
